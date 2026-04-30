//! Crypto test vectors: blake2b-256, keccak-256.
//!
//! Input: raw message bytes. Output: 32-byte hash.

use blake2::digest::consts::U32;
use blake2::digest::Digest as _;
use blake2::Blake2b;

type Blake2b256 = Blake2b<U32>;

/// Blake2b-256 hash of input. Output: 32 bytes.
pub fn blake2b_256(input: &[u8], output: &mut [u8]) -> usize {
    let mut hasher = Blake2b256::new();
    hasher.update(input);
    let result = hasher.finalize();
    output[..32].copy_from_slice(&result);
    32
}

/// Keccak-256 hash of input. Output: 32 bytes.
pub fn keccak_256(input: &[u8], output: &mut [u8]) -> usize {
    use sha3::Digest as _;
    let mut hasher = sha3::Keccak256::new();
    hasher.update(input);
    let result = hasher.finalize();
    output[..32].copy_from_slice(&result);
    32
}
