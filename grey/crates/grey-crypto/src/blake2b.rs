//! Blake2b-256 hash function H (Section 3.8.1).

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use grey_types::Hash;

/// Compute the Blake2b-256 hash of the given data.
///
/// H(m ∈ B) ∈ H
pub fn blake2b_256(data: &[u8]) -> Hash {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    Hash(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake2b_256_empty() {
        let hash = blake2b_256(b"");
        // Blake2b-256 of empty string is a known value
        assert_ne!(hash, Hash::ZERO);
    }

    #[test]
    fn test_blake2b_256_deterministic() {
        let hash1 = blake2b_256(b"jam");
        let hash2 = blake2b_256(b"jam");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_blake2b_256_different_inputs() {
        let hash1 = blake2b_256(b"hello");
        let hash2 = blake2b_256(b"world");
        assert_ne!(hash1, hash2);
    }
}
