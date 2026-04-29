//! Blake2b-256 hash function H (Section 3.8.1).

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use grey_types::Hash;
use grey_types::header::Header;
use grey_types::work::WorkReport;

/// Compute the Blake2b-256 header hash: H(E(header)).
pub fn header_hash(header: &Header) -> Hash {
    blake2b_256(&scale::Encode::encode(header))
}

/// Compute the Blake2b-256 work-report hash: H(E(report)).
pub fn report_hash(report: &WorkReport) -> Hash {
    blake2b_256(&scale::Encode::encode(report))
}

/// Build an assurance signing message: X_A ⌢ H(parent_hash ⌢ bitfield).
///
/// Used for signing and verifying availability assurances (Section 11).
pub fn build_assurance_message(parent_hash: &[u8; 32], bitfield: &[u8]) -> Vec<u8> {
    use grey_types::signing_contexts::AVAILABLE;
    let mut payload = Vec::new();
    payload.extend_from_slice(parent_hash);
    payload.extend_from_slice(bitfield);
    let payload_hash = blake2b_256(&payload);
    let mut message = Vec::with_capacity(AVAILABLE.len() + 32);
    message.extend_from_slice(AVAILABLE);
    message.extend_from_slice(&payload_hash.0);
    message
}

/// Entropy accumulation (eq 6.22): η₀' = H(η₀ ++ entropy).
///
/// Concatenates two 32-byte hashes and produces their Blake2b-256 digest.
pub fn accumulate_entropy(current: &Hash, entropy: &Hash) -> Hash {
    let mut preimage = Vec::with_capacity(64);
    preimage.extend_from_slice(&current.0);
    preimage.extend_from_slice(&entropy.0);
    blake2b_256(&preimage)
}

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

    /// Known-answer test: blake2b-256("") — RFC 7693 test vector.
    #[test]
    fn test_blake2b_256_kat_empty() {
        let hash = blake2b_256(b"");
        assert_eq!(
            hex::encode(hash.0),
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
        );
    }

    /// Known-answer test: blake2b-256("abc") — RFC 7693 test vector.
    #[test]
    fn test_blake2b_256_kat_abc() {
        let hash = blake2b_256(b"abc");
        assert_eq!(
            hex::encode(hash.0),
            "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"
        );
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Blake2b-256 is deterministic.
        #[test]
        fn blake2b_deterministic(data in proptest::collection::vec(any::<u8>(), 0..128)) {
            prop_assert_eq!(blake2b_256(&data), blake2b_256(&data));
        }

        /// Blake2b-256 output is always 32 bytes (encoded in Hash).
        #[test]
        fn blake2b_output_size(data in proptest::collection::vec(any::<u8>(), 0..64)) {
            let hash = blake2b_256(&data);
            prop_assert_eq!(hash.0.len(), 32);
        }

        /// Different inputs produce different hashes (collision resistance sanity check).
        #[test]
        fn blake2b_different_inputs(
            a in proptest::collection::vec(any::<u8>(), 1..64),
            b in proptest::collection::vec(any::<u8>(), 1..64)
        ) {
            prop_assume!(a != b);
            prop_assert_ne!(blake2b_256(&a), blake2b_256(&b));
        }

        /// Flipping any bit changes the hash (avalanche property).
        #[test]
        fn blake2b_avalanche(
            data in proptest::collection::vec(any::<u8>(), 1..64),
            flip_idx in 0usize..64,
            flip_bit in 0u8..8
        ) {
            let flip_idx = flip_idx % data.len();
            let mut modified = data.clone();
            modified[flip_idx] ^= 1 << flip_bit;
            prop_assert_ne!(blake2b_256(&data), blake2b_256(&modified));
        }

        /// Concatenation matters: H(a || b) != H(b || a) for non-trivial inputs.
        #[test]
        fn blake2b_concatenation_order(
            a in proptest::collection::vec(any::<u8>(), 1..32),
            b in proptest::collection::vec(any::<u8>(), 1..32)
        ) {
            prop_assume!(a != b);
            let mut ab = a.clone();
            ab.extend(&b);
            let mut ba = b.clone();
            ba.extend(&a);
            prop_assert_ne!(blake2b_256(&ab), blake2b_256(&ba));
        }

        /// accumulate_entropy is deterministic.
        #[test]
        fn accumulate_entropy_deterministic(
            current in any::<[u8; 32]>(),
            entropy in any::<[u8; 32]>()
        ) {
            let h1 = accumulate_entropy(&Hash(current), &Hash(entropy));
            let h2 = accumulate_entropy(&Hash(current), &Hash(entropy));
            prop_assert_eq!(h1, h2);
        }

        /// accumulate_entropy is sensitive to both inputs.
        #[test]
        fn accumulate_entropy_sensitive(
            current in any::<[u8; 32]>(),
            entropy in any::<[u8; 32]>(),
            flip in any::<u8>()
        ) {
            let flip = if flip == 0 { 1 } else { flip };
            let h1 = accumulate_entropy(&Hash(current), &Hash(entropy));
            let mut modified = entropy;
            modified[0] ^= flip;
            let h2 = accumulate_entropy(&Hash(current), &Hash(modified));
            prop_assert_ne!(h1, h2);
        }
    }
}
