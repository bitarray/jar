//! PVM bitmask packer.
//!
//! Internally the transpiler tracks instruction starts as a `Vec<u8>`
//! parallel to the code bytes (one byte per code byte; 0 =
//! continuation, 1 = instruction start). The chain Image's wire
//! format uses the compact bit-packed form (one bit per code byte).
//! [`pack_bitmask`] converts.

/// Pack a bitmask array (one byte per bit, 0 or 1) into packed bytes (LSB first).
pub fn pack_bitmask(bitmask: &[u8]) -> Vec<u8> {
    let packed_len = bitmask.len().div_ceil(8);
    let mut packed = vec![0u8; packed_len];
    for (i, &bit) in bitmask.iter().enumerate() {
        if bit != 0 {
            packed[i / 8] |= 1 << (i % 8);
        }
    }
    packed
}
