//! Keccak-256 hash function HK (Section 3.8.1).

use grey_types::Hash;
use sha3::{Digest, Keccak256};

/// Compute the Keccak-256 hash of the given data.
///
/// HK(m ∈ B) ∈ H
pub fn keccak_256(data: &[u8]) -> Hash {
    let mut hasher = Keccak256::new();
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
    fn test_keccak_256_empty() {
        let hash = keccak_256(b"");
        // Keccak-256 of empty string
        let expected = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
        assert_eq!(hex::encode(hash.0), expected);
    }

    #[test]
    fn test_keccak_256_deterministic() {
        let hash1 = keccak_256(b"jam");
        let hash2 = keccak_256(b"jam");
        assert_eq!(hash1, hash2);
    }

    /// Known-answer test: keccak-256("abc") from NIST test vectors.
    #[test]
    fn test_keccak_256_kat_abc() {
        let hash = keccak_256(b"abc");
        let expected = "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45";
        assert_eq!(hex::encode(hash.0), expected);
    }

    #[test]
    fn test_keccak_256_different_inputs() {
        let hash1 = keccak_256(b"hello");
        let hash2 = keccak_256(b"world");
        assert_ne!(hash1, hash2);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Keccak-256 is deterministic.
        #[test]
        fn keccak_deterministic(data in proptest::collection::vec(any::<u8>(), 0..128)) {
            prop_assert_eq!(keccak_256(&data), keccak_256(&data));
        }

        /// Keccak-256 output is always 32 bytes.
        #[test]
        fn keccak_output_size(data in proptest::collection::vec(any::<u8>(), 0..64)) {
            let hash = keccak_256(&data);
            prop_assert_eq!(hash.0.len(), 32);
        }

        /// Different inputs produce different hashes.
        #[test]
        fn keccak_different_inputs(
            a in proptest::collection::vec(any::<u8>(), 1..64),
            b in proptest::collection::vec(any::<u8>(), 1..64)
        ) {
            prop_assume!(a != b);
            prop_assert_ne!(keccak_256(&a), keccak_256(&b));
        }

        /// Flipping any bit changes the hash (avalanche property).
        #[test]
        fn keccak_avalanche(
            data in proptest::collection::vec(any::<u8>(), 1..64),
            flip_idx in 0usize..64,
            flip_bit in 0u8..8
        ) {
            let flip_idx = flip_idx % data.len();
            let mut modified = data.clone();
            modified[flip_idx] ^= 1 << flip_bit;
            prop_assert_ne!(keccak_256(&data), keccak_256(&modified));
        }

        /// H(a) != H(b) even when a is a prefix of b.
        #[test]
        fn keccak_prefix_distinct(
            data in proptest::collection::vec(any::<u8>(), 2..64),
            extra in proptest::collection::vec(any::<u8>(), 1..32)
        ) {
            let mut extended = data.clone();
            extended.extend(&extra);
            prop_assert_ne!(keccak_256(&data), keccak_256(&extended));
        }
    }
}
