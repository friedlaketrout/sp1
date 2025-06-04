use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use sp1_stark::{air::MachineAir, Word};
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord, Blake2fCompressEvent, PrecompileEvent, SyscallEvent},
    syscalls::SyscallCode,
    ExecutionRecord, Program,
};
use crate::utils::pad_rows_fixed;

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
       // panic!("fuck!");
        /*

        */

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
        
    }
    
    fn included(&self, shard: &Self::Record) -> bool {
        // if let Some(shape) = shard.shape.as_ref() {
        //     shape.included::<F, _>(self)
        // } else {
        //     !shard.get_precompile_events(SyscallCode::BLAKE2F_COMPRESS).is_empty()
        // }
        true
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

        for i in 0..event.v_mutations.len() {
            let v_mutation = event.v_mutations[i];

            let mut row = [F::zero(); NUM_BLAKE2F_COMPRESS_COLS];
            let cols: &mut Blake2fCompressColumns<F> = row.as_mut_slice().borrow_mut();

            cols.shard = F::from_canonical_u32(event.shard);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.w_ptr = F::from_canonical_u32(event.base_ptr);

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

            cols.f_flag = F::from_bool(event.f);
        }
    }
}