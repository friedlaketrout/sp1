use sp1_derive::AlignedBorrow;
use sp1_stark::Word;
use crate::operations::XorOperation;

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

    pub v: [[Word<T>; 2]; 16],

    pub final_v_xor: [[XorOperation<T>; 2]; 8],

    /// Final block flag (used as a selector/flag in AIR)
    pub f_flag: T,
}