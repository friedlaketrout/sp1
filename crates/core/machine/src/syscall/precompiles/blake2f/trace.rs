use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use sp1_stark::{air::MachineAir, Word};
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord, Blake2fCompressEvent, PrecompileEvent, SyscallEvent},
    syscalls::SyscallCode,
    ExecutionRecord, Program,
};
use crate::utils::pad_rows_fixed;
use p3_maybe_rayon::prelude::ParallelSlice;
use p3_maybe_rayon::prelude::ParallelIterator;
use hashbrown::HashMap;
use itertools::Itertools;

use std::borrow::BorrowMut;

use super::{
    columns::{Blake2fCompressColumns, NUM_BLAKE2F_COMPRESS_COLS},
    Blake2fCompressChip,
};

impl<F: PrimeField32> MachineAir<F> for Blake2fCompressChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Blake2fCompress".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        println!("Generating trace for Blake2fCompress");

        let rows = Vec::new();

        let mut wrapped_rows = Some(rows);
        for (_, event) in input.get_precompile_events(SyscallCode::BLAKE2F_COMPRESS) {
            let event = if let PrecompileEvent::Blake2fCompress(event) = event {
                event
            } else {
                unreachable!()
            };
            // blake2f todo: Event needs reference here, but other examples don't have it
            self.event_to_rows(&event, &mut wrapped_rows, &mut Vec::new());
        }
        let mut rows = wrapped_rows.unwrap();

        println!("Rows: {:?}", rows.len());
        println!("Rows: {:?}", rows);

        let num_real_rows = rows.len();

        pad_rows_fixed(
            &mut rows,
            || [F::zero(); NUM_BLAKE2F_COMPRESS_COLS],
            input.fixed_log2_rows::<F, _>(self),
        );

        // Filler
        let rows: Vec<[F; 64]> = Vec::new();

        // Blake2f todo: Properly generate matrix
        RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), 0)
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let events = input.get_precompile_events(SyscallCode::BLAKE2F_COMPRESS);
        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);

        let blu_batches = events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                events.iter().for_each(|(_, event)| {
                    let event = if let PrecompileEvent::Blake2fCompress(event) = event {
                        event
                    } else {
                        unreachable!()
                    };
                    self.event_to_rows::<F>(&event, &mut None, &mut blu);
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_batches.iter().collect_vec());
    }
    
    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.get_precompile_events(SyscallCode::BLAKE2F_COMPRESS).is_empty()
        }
    }
}

impl Blake2fCompressChip {
    fn event_to_rows<F: PrimeField32>(
        &self,
        event: &Blake2fCompressEvent,
        rows: &mut Option<Vec<[F; NUM_BLAKE2F_COMPRESS_COLS]>>,
        blu: &mut impl ByteRecord,
    ) {
        println!("Generating rows for Blake2fCompress");

        let og_h = event.h;

        ////////////////
        // First row //
        ////////////////
        let mut row = [F::zero(); NUM_BLAKE2F_COMPRESS_COLS];
        let cols: &mut Blake2fCompressColumns<F> = row.as_mut_slice().borrow_mut();

        cols.shard = F::from_canonical_u32(event.shard);
        cols.clk = F::from_canonical_u32(event.clk);
        cols.base_ptr = F::from_canonical_u32(event.base_ptr);

        cols.is_first_row = F::one();
        cols.is_last_row = F::zero();

        // Initial rounds
        // Set rounds to max value for first row so they wrap around starting at second row (i.e. first compress step)
        let mut inner_round = 7;
        let mut outer_round = 9;
        Self::set_round_columns(cols, inner_round, outer_round);

        let initial_v = event.v_mutations[0];
        Self::set_v_values(cols, &initial_v);

        cols.f_flag = F::from_bool(event.f);

        // Write row
        if rows.as_ref().is_some() {
            rows.as_mut().unwrap().push(row);
        }

        ///////////////////
        // Compress rows //
        ///////////////////
        for i in 1..(event.v_mutations.len() - 1) {
            let mut row = [F::zero(); NUM_BLAKE2F_COMPRESS_COLS];
            let cols: &mut Blake2fCompressColumns<F> = row.as_mut_slice().borrow_mut();

            cols.shard = F::from_canonical_u32(event.shard);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.base_ptr = F::from_canonical_u32(event.base_ptr);

            cols.is_first_row = F::zero();
            cols.is_last_row = F::zero();

            // Increment rounds
            inner_round = (inner_round + 1) % 8;
            if (inner_round == 0) {
                outer_round = (outer_round + 1) % 10;
            }
            Self::set_round_columns(cols, inner_round, outer_round);

            // Get current mutations
            let v_mutation = event.v_mutations[i];
            Self::set_v_values(cols, &v_mutation);


            cols.f_flag = F::from_bool(event.f);

            // Write row
            if rows.as_ref().is_some() {
                rows.as_mut().unwrap().push(row);
            }
        }

        ///////////////
        // Final row //
        ///////////////
        let mut row = [F::zero(); NUM_BLAKE2F_COMPRESS_COLS];
        let cols: &mut Blake2fCompressColumns<F> = row.as_mut_slice().borrow_mut();

        cols.shard = F::from_canonical_u32(event.shard);
        cols.clk = F::from_canonical_u32(event.clk);
        cols.base_ptr = F::from_canonical_u32(event.base_ptr);

        cols.is_first_row = F::zero();
        cols.is_last_row = F::one();

        // Increment rounds
        inner_round = (inner_round + 1) % 8;
        if (inner_round == 0) {
            outer_round = (outer_round + 1) % 10;
        }
        Self::set_round_columns(cols, inner_round, outer_round);

        let final_v = event.v_mutations[event.v_mutations.len() - 1];
        Self::set_v_values(cols, &final_v);

        cols.f_flag = F::from_bool(event.f);

        // Write row
        if rows.as_ref().is_some() {
            rows.as_mut().unwrap().push(row);
        }
    }

    fn set_v_values<F: PrimeField32>(cols: &mut Blake2fCompressColumns<F>, v_mutation: &[u64; 16]) {
        cols.v0 = F::from_canonical_u64(v_mutation[0]);
        cols.v1 = F::from_canonical_u64(v_mutation[1]);
        cols.v2 = F::from_canonical_u64(v_mutation[2]);
        cols.v3 = F::from_canonical_u64(v_mutation[3]);
        cols.v4 = F::from_canonical_u64(v_mutation[4]);
        cols.v5 = F::from_canonical_u64(v_mutation[5]);
        cols.v6 = F::from_canonical_u64(v_mutation[6]);
        cols.v7 = F::from_canonical_u64(v_mutation[7]);
        cols.v8 = F::from_canonical_u64(v_mutation[8]);
        cols.v9 = F::from_canonical_u64(v_mutation[9]);
        cols.v10 = F::from_canonical_u64(v_mutation[10]);
        cols.v11 = F::from_canonical_u64(v_mutation[11]);
        cols.v12 = F::from_canonical_u64(v_mutation[12]);
        cols.v13 = F::from_canonical_u64(v_mutation[13]);
        cols.v14 = F::from_canonical_u64(v_mutation[14]);
        cols.v15 = F::from_canonical_u64(v_mutation[15]);
    }

    fn set_round_columns<F: PrimeField32>(cols: &mut Blake2fCompressColumns<F>, inner_round: usize, outer_round: usize) {
        cols.inner_round = Self::generate_inner_round_columns(inner_round);
        cols.outer_round = Self::generate_outer_round_columns(outer_round);
    }

    fn generate_outer_round_columns<F: PrimeField32>(true_column: usize) -> [F; 10] {
        return Self::generate_round_columns::<F, 10>(true_column);
    }

    fn generate_inner_round_columns<F: PrimeField32>(true_column: usize) -> [F; 8] {
        return Self::generate_round_columns::<F, 8>(true_column);
    }

    fn generate_round_columns<F: PrimeField32, const N: usize>(true_column: usize) -> [F; N] {
        let mut columns = [F::zero(); N];
        columns[true_column] = F::one();
        columns
    }
}