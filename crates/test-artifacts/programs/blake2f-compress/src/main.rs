#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_zkvm::syscalls::syscall_blake2f_compress;

pub fn main() {
    // Parse the hex string into bytes
    let input = "0000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001";
    let expected = "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923";
    let mut bytes = Vec::new();
    for i in 0..input.len() / 2 {
        let byte = u8::from_str_radix(&input[i*2..i*2+2], 16).unwrap();
        bytes.push(byte);
    }

    // Convert bytes to u32 array for state
    let mut state = [0u32; 54];
    for i in 0..bytes.len() / 4 {
        state[i] = u32::from_le_bytes([
            bytes[i*4],
            bytes[i*4+1],
            bytes[i*4+2],
            bytes[i*4+3],
        ]);
    }
    state[53] = u32::from_le_bytes([
        bytes[bytes.len() - 1], 0, 0, 0
    ]);

    syscall_blake2f_compress(&mut state);

    // Print the result
    println!("Expected Result: {}", expected);
}
