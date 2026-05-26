//! Hash trait and default Blake2b-256 implementation.
//!
//! All v3 hash computations (image_hash chain, BMT, content-addressing)
//! go through the `Hash` trait. `Blake2b256` is the spec default.
//! The trait exists so we can swap in a mock hash for testing or
//! a different hash function later without churning call sites.

use alloc::vec::Vec;

/// Hash function abstraction.
///
/// Implementations are stateless types (typically unit structs);
/// `hash` is a pure function from bytes to a fixed-size digest.
pub trait Hash {
    /// Digest type. Must be `Copy` for use in BMT and cap fields.
    type Out: Copy + Eq + core::fmt::Debug;

    /// Hash a byte slice.
    fn hash(bytes: &[u8]) -> Self::Out;

    /// Hash the concatenation of two byte slices, without
    /// materializing the concatenation. Default impl just allocates;
    /// implementations should override for efficiency where possible.
    fn hash_pair(a: &[u8], b: &[u8]) -> Self::Out {
        let mut buf = Vec::with_capacity(a.len() + b.len());
        buf.extend_from_slice(a);
        buf.extend_from_slice(b);
        Self::hash(&buf)
    }
}

/// Default v3 hash: Blake2b-256 (32-byte output).
pub struct Blake2b256;

impl Hash for Blake2b256 {
    type Out = [u8; 32];

    fn hash(bytes: &[u8]) -> Self::Out {
        use blake2::digest::{Update, VariableOutput};
        let mut hasher = blake2::Blake2bVar::new(32).expect("32 ≤ Blake2b max output");
        hasher.update(bytes);
        let mut out = [0u8; 32];
        hasher.finalize_variable(&mut out).expect("32-byte buffer");
        out
    }

    fn hash_pair(a: &[u8], b: &[u8]) -> Self::Out {
        use blake2::digest::{Update, VariableOutput};
        let mut hasher = blake2::Blake2bVar::new(32).expect("32 ≤ Blake2b max output");
        hasher.update(a);
        hasher.update(b);
        let mut out = [0u8; 32];
        hasher.finalize_variable(&mut out).expect("32-byte buffer");
        out
    }
}
