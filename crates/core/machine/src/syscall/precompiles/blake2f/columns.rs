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

    pub v0: [Word<T>; 2],
    pub v1: [Word<T>; 2],
    pub v2: [Word<T>; 2],
    pub v3: [Word<T>; 2],
    pub v4: [Word<T>; 2],
    pub v5: [Word<T>; 2],
    pub v6: [Word<T>; 2],
    pub v7: [Word<T>; 2],
    pub v8: [Word<T>; 2],
    pub v9: [Word<T>; 2],
    pub v10: [Word<T>; 2],
    pub v11: [Word<T>; 2],
    pub v12: [Word<T>; 2],
    pub v13: [Word<T>; 2],
    pub v14: [Word<T>; 2],
    pub v15: [Word<T>; 2],

    pub final_v_xor: [[Word<T>; 2]; 8],

    /// Final block flag (used as a selector/flag in AIR)
    pub f_flag: T,
}