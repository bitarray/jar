//! Crypto test vectors: blake2b-256, keccak-256.
//!
//! Input: raw message bytes. Output: 32-byte hash. Each suite hashes
//! a small corpus of fixed inputs and XOR-folds the resulting digests
//! into a single u64 fingerprint.

use crate::fold_bytes_to_u64;
use blake2::digest::consts::U32;
use blake2::digest::Digest as _;
use blake2::Blake2b;

type Blake2b256 = Blake2b<U32>;

const HASH_INPUTS: &[&[u8]] = &[
    &[],
    b"abc",
    b"The quick brown fox jumps over the lazy dog",
    &[0u8; 64],
];

pub fn blake2b_256(input: &[u8], output: &mut [u8]) -> usize {
    let mut hasher = Blake2b256::new();
    hasher.update(input);
    let result = hasher.finalize();
    output[..32].copy_from_slice(&result);
    32
}

pub fn keccak_256(input: &[u8], output: &mut [u8]) -> usize {
    use sha3::Digest as _;
    let mut hasher = sha3::Keccak256::new();
    hasher.update(input);
    let result = hasher.finalize();
    output[..32].copy_from_slice(&result);
    32
}

// -- Suites --------------------------------------------------------------------

pub fn blake2b_256_suite() -> u64 {
    let mut acc = 0u64;
    let mut output = [0u8; 32];
    for input in HASH_INPUTS {
        let len = blake2b_256(input, &mut output);
        debug_assert_eq!(len, 32);
        acc ^= fold_bytes_to_u64(&output);
    }
    acc
}

pub fn keccak_256_suite() -> u64 {
    let mut acc = 0u64;
    let mut output = [0u8; 32];
    for input in HASH_INPUTS {
        let len = keccak_256(input, &mut output);
        debug_assert_eq!(len, 32);
        acc ^= fold_bytes_to_u64(&output);
    }
    acc
}
