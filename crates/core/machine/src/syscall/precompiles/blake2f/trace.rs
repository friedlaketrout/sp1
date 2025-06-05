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
        let mut inner_round = 0;
        let mut outer_round = 0;

        for (_, event) in input.get_precompile_events(SyscallCode::BLAKE2F_COMPRESS) {
            let event = if let PrecompileEvent::Blake2fCompress(event) = event {
                event
            } else {
                unreachable!()
            };

            // blake2f todo: Event needs reference here, but other examples don't have it
            let [last_inner_round, last_outer_round] = self.event_to_rows(&event, &mut wrapped_rows, &mut Vec::new());
            inner_round = last_inner_round;
            outer_round = last_outer_round;
        }
        let mut rows = wrapped_rows.unwrap();

        println!("Rows: {:?}", rows.len());
        println!("Rows: {:?}", rows);

        /////////////////
        // Padded rows //
        /////////////////
        
        let num_real_rows = rows.len();

        pad_rows_fixed(
            &mut rows,
            || [F::zero(); NUM_BLAKE2F_COMPRESS_COLS],
            input.fixed_log2_rows::<F, _>(self),
        );
        
        // Set the octet_num and octet columns for the padded rows.
        for row in rows[num_real_rows..].iter_mut() {
            let cols: &mut Blake2fCompressColumns<F> = row.as_mut_slice().borrow_mut();
            cols.outer_round[outer_round] = F::one();
            cols.inner_round[inner_round] = F::one();

            inner_round = (inner_round + 1) % 8;
            if (inner_round == 0) {
                outer_round = (outer_round + 1) % 10;
            }
            Self::set_round_columns(cols, inner_round, outer_round);
        };

        println!("Rows: {:?}", rows.len());

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_BLAKE2F_COMPRESS_COLS)
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
    ) -> [usize; 2] {
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

        let initial_mutation = event.mutations[0];
        Self::set_v_values(cols, &initial_mutation.v);

        cols.f_flag = F::from_bool(event.f);

        // Write row
        if rows.as_ref().is_some() {
            rows.as_mut().unwrap().push(row);
        }

        ///////////////////
        // Compress rows //
        ///////////////////
        for i in 1..(event.mutations.len() - 1) {
            let mut row = [F::zero(); NUM_BLAKE2F_COMPRESS_COLS];
            let cols: &mut Blake2fCompressColumns<F> = row.as_mut_slice().borrow_mut();

            cols.shard = F::from_canonical_u32(event.shard);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.base_ptr = F::from_canonical_u32(event.base_ptr);

            cols.is_first_row = F::zero();
            cols.is_last_row = F::zero();

            // Increment rounds
            inner_round = (inner_round + 1) % 8;
            if inner_round == 0 {
                outer_round = (outer_round + 1) % 10;
            }
            Self::set_round_columns(cols, inner_round, outer_round);

            // Get current mutations
            let mutation = event.mutations[i];
            Self::set_v_values(cols, &mutation.v);

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
        if inner_round == 0 {
            outer_round = (outer_round + 1) % 10;
        }
        Self::set_round_columns(cols, inner_round, outer_round);

        let final_mutation = event.mutations[event.mutations.len() - 1];
        Self::set_v_values(cols, &final_mutation.v);

        let final_v_xor = final_mutation.final_v_xor.unwrap();
        println!("Final v xor: {:?}", final_v_xor);
        Self::set_final_v_xor(cols, &final_v_xor);

        cols.f_flag = F::from_bool(event.f);

        // Write row
        if rows.as_ref().is_some() {
            rows.as_mut().unwrap().push(row);
        }

        [inner_round, outer_round]
    }

    fn set_final_v_xor<F: PrimeField32>(cols: &mut Blake2fCompressColumns<F>, final_v_xor: &[u64; 8]) {
        let v0_sliced = u64_slice_to_words_le::<2>(&[final_v_xor[0]]);
        let v0_pair = [Word::from(v0_sliced[0]), Word::from(v0_sliced[1])];
        let v1_sliced = u64_slice_to_words_le::<2>(&[final_v_xor[1]]);
        let v1_pair = [Word::from(v1_sliced[0]), Word::from(v1_sliced[1])];
        let v2_sliced = u64_slice_to_words_le::<2>(&[final_v_xor[2]]);
        let v2_pair = [Word::from(v2_sliced[0]), Word::from(v2_sliced[1])];
        let v3_sliced = u64_slice_to_words_le::<2>(&[final_v_xor[3]]);
        let v3_pair = [Word::from(v3_sliced[0]), Word::from(v3_sliced[1])];
        let v4_sliced = u64_slice_to_words_le::<2>(&[final_v_xor[4]]);
        let v4_pair = [Word::from(v4_sliced[0]), Word::from(v4_sliced[1])];
        let v5_sliced = u64_slice_to_words_le::<2>(&[final_v_xor[5]]);
        let v5_pair = [Word::from(v5_sliced[0]), Word::from(v5_sliced[1])];
        let v6_sliced = u64_slice_to_words_le::<2>(&[final_v_xor[6]]);
        let v6_pair = [Word::from(v6_sliced[0]), Word::from(v6_sliced[1])];
        let v7_sliced = u64_slice_to_words_le::<2>(&[final_v_xor[7]]);
        let v7_pair = [Word::from(v7_sliced[0]), Word::from(v7_sliced[1])];

        cols.final_v_xor = [v0_pair, v1_pair, v2_pair, v3_pair, v4_pair, v5_pair, v6_pair, v7_pair];
    }

    fn set_v_values<F: PrimeField32>(cols: &mut Blake2fCompressColumns<F>, v_mutation: &[u64; 16]) {
        let v0_sliced = u64_slice_to_words_le::<2>(&[v_mutation[0]]);
        let v0_pair = [Word::from(v0_sliced[0]), Word::from(v0_sliced[1])];
        let v1_sliced = u64_slice_to_words_le::<2>(&[v_mutation[1]]);
        let v1_pair = [Word::from(v1_sliced[0]), Word::from(v1_sliced[1])];
        let v2_sliced = u64_slice_to_words_le::<2>(&[v_mutation[2]]);
        let v2_pair = [Word::from(v2_sliced[0]), Word::from(v2_sliced[1])];
        let v3_sliced = u64_slice_to_words_le::<2>(&[v_mutation[3]]);
        let v3_pair = [Word::from(v3_sliced[0]), Word::from(v3_sliced[1])];
        let v4_sliced = u64_slice_to_words_le::<2>(&[v_mutation[4]]);
        let v4_pair = [Word::from(v4_sliced[0]), Word::from(v4_sliced[1])];
        let v5_sliced = u64_slice_to_words_le::<2>(&[v_mutation[5]]);
        let v5_pair = [Word::from(v5_sliced[0]), Word::from(v5_sliced[1])];
        let v6_sliced = u64_slice_to_words_le::<2>(&[v_mutation[6]]);
        let v6_pair = [Word::from(v6_sliced[0]), Word::from(v6_sliced[1])];
        let v7_sliced = u64_slice_to_words_le::<2>(&[v_mutation[7]]);
        let v7_pair = [Word::from(v7_sliced[0]), Word::from(v7_sliced[1])];
        let v8_sliced = u64_slice_to_words_le::<2>(&[v_mutation[8]]);
        let v8_pair = [Word::from(v8_sliced[0]), Word::from(v8_sliced[1])];
        let v9_sliced = u64_slice_to_words_le::<2>(&[v_mutation[9]]);
        let v9_pair = [Word::from(v9_sliced[0]), Word::from(v9_sliced[1])];
        let v10_sliced = u64_slice_to_words_le::<2>(&[v_mutation[10]]);
        let v10_pair = [Word::from(v10_sliced[0]), Word::from(v10_sliced[1])];
        let v11_sliced = u64_slice_to_words_le::<2>(&[v_mutation[11]]);
        let v11_pair = [Word::from(v11_sliced[0]), Word::from(v11_sliced[1])];
        let v12_sliced = u64_slice_to_words_le::<2>(&[v_mutation[12]]);
        let v12_pair = [Word::from(v12_sliced[0]), Word::from(v12_sliced[1])];
        let v13_sliced = u64_slice_to_words_le::<2>(&[v_mutation[13]]);
        let v13_pair = [Word::from(v13_sliced[0]), Word::from(v13_sliced[1])];
        let v14_sliced = u64_slice_to_words_le::<2>(&[v_mutation[14]]);
        let v14_pair = [Word::from(v14_sliced[0]), Word::from(v14_sliced[1])];
        let v15_sliced = u64_slice_to_words_le::<2>(&[v_mutation[15]]);
        let v15_pair = [Word::from(v15_sliced[0]), Word::from(v15_sliced[1])];

        cols.v = [v0_pair, v1_pair, v2_pair, v3_pair, v4_pair, v5_pair, v6_pair, v7_pair, v8_pair, v9_pair, v10_pair, v11_pair, v12_pair, v13_pair, v14_pair, v15_pair];
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

/// Converts a slice of `u64` values into a `Vec<u32>` maintaining byte ordering.
fn u64_slice_to_words_le<const N: usize>(words: &[u64]) -> [u32; N] {
    assert_eq!(words.len(), N / 2, "Expected {} u64s for {} u32s", N / 2, N);

    let mut result = [0u32; N];
    for i in 0..(N / 2) {
        result[2 * i] = (words[i] >> 32) as u32; // high 32 bits
        result[2 * i + 1] = words[i] as u32; // low 32 bits
    }
    result
}