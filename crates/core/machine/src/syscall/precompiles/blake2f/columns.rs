use sp1_derive::AlignedBorrow;
use sp1_stark::Word;

pub const NUM_BLAKE2F_COMPRESS_COLS: usize = size_of::<Blake2fCompressColumns<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct  Blake2fCompressColumns<T> {
    /// Inputs.
    pub shard: T,
    pub clk: T,
    pub base_ptr: T,

    /// Column control flows
    /// First row
    pub is_first_row: T,

    /// Which cycle within the octet we are currently processing.
    pub inner_round: [T; 8],

    /// This will specify which octet we are currently processing.
    ///  - The first octet is for initialize.
    ///  - The next 8 octets are for compress.
    ///  - The last octet is for finalize.
    pub outer_round: [T; 10],

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