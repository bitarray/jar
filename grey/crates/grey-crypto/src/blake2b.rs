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
