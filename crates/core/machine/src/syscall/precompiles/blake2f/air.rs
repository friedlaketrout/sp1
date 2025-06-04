use std::borrow::Borrow;
use p3_air::{Air, BaseAir, AirBuilder};
use p3_field::AbstractField;
use p3_matrix::Matrix;
use sp1_stark::air::SP1AirBuilder;
use sp1_stark::air::BaseAirBuilder;

use crate::syscall::precompiles::blake2f::columns::Blake2fCompressColumns;

use super::columns::NUM_BLAKE2F_COMPRESS_COLS;
use super::Blake2fCompressChip;

const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

const ABCD: [[usize; 4]; 8] = [
    [0, 4, 8, 12],
    [1, 5, 9, 13],
    [2, 6, 10, 14],
    [3, 7, 11, 15],
    [0, 5, 10, 15],
    [1, 6, 11, 12],
    [2, 7, 8, 13],
    [3, 4, 9, 14],
];

const XY_INDICES: [[i32; 2]; 8] = [
    [0, 1],
    [2, 3],
    [4, 5],
    [6, 7],
    [8, 9],
    [10, 11],
    [12, 13],
    [14, 15],
];

impl<F> BaseAir<F> for Blake2fCompressChip {
    fn width(&self) -> usize {
        NUM_BLAKE2F_COMPRESS_COLS
    }
}

impl<AB> Air<AB> for Blake2fCompressChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &Blake2fCompressColumns<AB::Var> = (*local).borrow();
        let next: &Blake2fCompressColumns<AB::Var> = (*next).borrow();

        self.eval_control_flow_flags(builder, local, next);
    }
}

impl Blake2fCompressChip {
    fn eval_control_flow_flags<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &Blake2fCompressColumns<AB::Var>,
        next: &Blake2fCompressColumns<AB::Var>,
    ) {
        // Check all of the inner_round columns are bool
        for i in 0..8 {
            builder.assert_bool(local.inner_round[i]);
        }

        // Check exactly one of the inner_round columns is true
        let mut inner_round_sum = AB::Expr::zero();
        for i in 0..8 {
            inner_round_sum = inner_round_sum.clone() + local.inner_round[i].into();
        }
        builder.assert_one(inner_round_sum);

        // Check proper transition for inner_round
        for i in 0..8 {
            builder.when_transition().when(local.inner_round[i]).assert_one(next.inner_round[(i + 1) % 8])
        }

        // Check all of the outer_round columns are bool
        for i in 0..10 {
            builder.assert_bool(local.outer_round[i]);
        }

        // Check exactly one of the outer_round columns is true
        let mut outer_round_sum = AB::Expr::zero();
        for i in 0..10 {
            outer_round_sum = outer_round_sum.clone() + local.outer_round[i].into();
        }
        builder.assert_one(outer_round_sum);

        // Check proper transition for outer_round
        // If inner round is not last, outer round should be the same
        for i in 0..10 {
            builder
                .when_transition()
                .when_not(local.inner_round[7])
                .assert_eq(local.outer_round[i], next.outer_round[i]);
        }

        // If inner round is last, outer round should increment mod 10
        for i in 0..10 {
            builder
                .when_transition()
                .when(local.inner_round[7])
                .assert_eq(local.outer_round[i], next.outer_round[(i + 1) % 10]);
        }

        // Check that first row inner_round is set properly to wrap around to zero
        builder.when_first_row().assert_one(local.inner_round[7]);

        // Check that first row outer_round is set properly to wrap around to zero
        builder.when_first_row().assert_one(local.outer_round[9]);
    }

    fn eval_first_row<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &Blake2fCompressColumns<AB::Var>,
        next: &Blake2fCompressColumns<AB::Var>,
    ) {
        // Check first eight words match h

        // Check next 4 words match IV

        // Check last word matches IV

        // Check 13th and 14th word properly handle offset

        // Check 15th word is inverted if f_flag is set
    }

    fn eval_compress<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &Blake2fCompressColumns<AB::Var>,
        next: &Blake2fCompressColumns<AB::Var>,
    ) {
        // Get correct SIGMA vector
        // Start with 0 vector, fold sum each vector multiplied by associated outer_round boolean
        let mut correct_sigma = [0u64; 16];
        for i in 0..10 {
            // Take outer_round[i] * SIGMA[i]
            // Add into v
            // outer_round is a sparse vector, only one element is true
        }

        // Get correct SIGMA pair
        let mut correct_sigma_pair = [0u64; 2];
        // Get correct XY indices
        // Start with (0,0) fold sum each tuple multipled by associated inner_round boolean
        for i in 0..8 {
            // Take inner_round[i] * XY_INDICES[i]
            // Add into correct_sigma_pair
            // Take indices pair and pull values from correct_sigma
            // inner_round is a sparse vector, only one element is true
        }

        // Get correct ABCD
        let mut correct_abcd = [0u64; 4];
        // Start with (0,0,0,0) fold sum each tuple multipled by associated inner_round boolean
        for i in 0..8 {
            // Take inner_round[i] * ABCD[i]
            // Add into correct_abcd
            // inner_round is a sparse vector, only one element is true
        }
    }

    fn eval_final_row<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &Blake2fCompressColumns<AB::Var>,
        next: &Blake2fCompressColumns<AB::Var>,
    ) {

    }
}
