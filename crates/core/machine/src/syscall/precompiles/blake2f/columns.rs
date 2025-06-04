use sp1_derive::AlignedBorrow;
use sp1_stark::Word;

pub const NUM_BLAKE2F_COMPRESS_COLS: usize = size_of::<Blake2fCompressColumns<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct  Blake2fCompressColumns<T> {
    /// Inputs.
    pub shard: T,
    pub clk: T,
    pub w_ptr: T,

    /// Column control flows
    /// First row
    pub is_first_row: T,
    pub is_second_row: T,

    /// Top level round index, selects SIGMA mod 10
    pub is_round_mod1: T,
    pub is_round_mod2: T,
    pub is_round_mod3: T,
    pub is_round_mod4: T,
    pub is_round_mod5: T,
    pub is_round_mod6: T,
    pub is_round_mod7: T,
    pub is_round_mod8: T,
    pub is_round_mod9: T,
    pub is_round_mod10: T,

    /// Subround index, selects a,b,c,d,x,y
    pub is_subround_mod1: T,
    pub is_subround_mod2: T,
    pub is_subround_mod3: T,
    pub is_subround_mod4: T,
    pub is_subround_mod5: T,
    pub is_subround_mod6: T,
    pub is_subround_mod7: T,
    pub is_subround_mod8: T,

    /// Last row
    pub is_last_row: T,

    pub v0: T,
    pub v1: T,
    pub v2: T,
    pub v3: T,
    pub v4: T,
    pub v5: T,
    pub v6: T,
    pub v7: T,
    pub v8: T,
    pub v9: T,
    pub v10: T,
    pub v11: T,
    pub v12: T,
    pub v13: T,
    pub v14: T,
    pub v15: T,

    /// Final block flag (used as a selector/flag in AIR)
    pub f_flag: T,
}