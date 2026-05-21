//! SimpleSerialize (SSZ) codec with `hash_tree_root`.
//!
//! Implements the Ethereum consensus SSZ wire format plus two jar-specific
//! extensions ([`MissingOr`], [`SparseList`]) that allow precomputed subtree
//! roots to substitute transparently for materialized leaves.
//!
//! The default hash function is SHA-256 (via the optional `sha2` feature);
//! the [`HashTreeRoot`] trait is generic over any `digest::Digest` with a
//! 32-byte output, so callers can plug in alternative hashes at compile time.
//!
//! # Allocator-genericity
//!
//! Public encode paths take `&mut Vec<u8, A>` (from `allocator-api2`) so a
//! caller in talc-allocated memory can serialize without bouncing through
//! `Global`.
//!
//! # Wire format
//!
//! See [`encoding`](https://github.com/ethereum/consensus-specs/blob/dev/ssz/simple-serialize.md)
//! for the spec we implement. Notable deviations:
//!
//! - [`Option`] / SSZ Union: byte 0 = None (no payload), byte 1 = Some(T) + T's bytes.
//! - [`MissingOr`]: byte 0 = Materialized + T's bytes, byte 1 = Missing + 32 raw bytes.
//! - [`SparseList`]: same wire format as a `List<T, N>` plus a length prefix.

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

use allocator_api2::alloc::{Allocator, Global};
use allocator_api2::vec::Vec;
use digest::Digest;
use digest::typenum::U32;

pub mod bits;
pub mod collections;
mod error;
pub mod list;
pub mod merkle;
pub mod missing;
pub mod primitives;
pub mod sparse;
pub mod union;
pub mod vector;

pub use bits::{Bitlist, Bitvector};
pub use error::DecodeError;
pub use list::List;
pub use merkle::{merkleize, mix_in_length, mix_in_selector, pack_bytes, zero_hash};
pub use missing::MissingOr;
pub use primitives::U256;
pub use sparse::SparseList;
pub use vector::FixedVector;

#[cfg(feature = "derive")]
pub use ssz_derive::{Decode, Encode, HashTreeRoot};

/// The number of bytes used to encode a variable-length list offset.
///
/// SSZ fixes this at 4 (a little-endian `u32`).
pub const BYTES_PER_LENGTH_OFFSET: usize = 4;

/// Chunk size in bytes for SSZ merkleization.
pub const BYTES_PER_CHUNK: usize = 32;

/// SSZ encoding trait.
///
/// `ssz_append` is the primary primitive: every other method delegates to it.
/// Callers in foreign allocators (e.g. talc) pass their `Allocator` via the
/// `A` type parameter on `ssz_append` and `as_ssz_bytes_in`.
pub trait Encode {
    /// `true` iff this type is fixed-length (no variable-length fields).
    fn is_ssz_fixed_len() -> bool;

    /// Number of bytes this type occupies in the fixed-length portion of a
    /// container encoding. For variable-length types this returns
    /// [`BYTES_PER_LENGTH_OFFSET`] (i.e. the size of the offset slot).
    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }

    /// `true` for "basic" SSZ types (uintN, bool), which pack adjacent
    /// elements into shared 32-byte chunks for merkleization. Composite
    /// types (containers, lists, structs) return `false` (the default).
    fn is_basic_type() -> bool {
        false
    }

    /// Total size of `self` when serialized.
    fn ssz_bytes_len(&self) -> usize;

    /// Append the encoding of `self` to `buf`.
    fn ssz_append<A: Allocator + Clone>(&self, buf: &mut Vec<u8, A>);

    /// Serialize into a fresh buffer allocated from `alloc`.
    fn as_ssz_bytes_in<A: Allocator + Clone>(&self, alloc: A) -> Vec<u8, A> {
        let mut v = Vec::new_in(alloc);
        self.ssz_append(&mut v);
        v
    }

    /// Serialize into a fresh `Global`-allocated `alloc::vec::Vec`.
    ///
    /// This is provided for convenience in callers that don't care about
    /// allocator threading. The default impl encodes into an
    /// `allocator_api2::vec::Vec<u8, Global>` and copies into a standard
    /// `alloc::vec::Vec<u8>`. Implementations may override for efficiency.
    fn as_ssz_bytes(&self) -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec::Vec::with_capacity(self.ssz_bytes_len());
        let buf: Vec<u8, Global> = self.as_ssz_bytes_in(Global);
        out.extend_from_slice(&buf);
        out
    }
}

/// SSZ decoding trait.
pub trait Decode: Sized {
    /// `true` iff this type is fixed-length.
    fn is_ssz_fixed_len() -> bool;

    /// Number of bytes this type occupies in the fixed-length portion of a
    /// container encoding. Variable-length types return
    /// [`BYTES_PER_LENGTH_OFFSET`].
    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }

    /// Decode a full instance from `bytes`, rejecting trailing input. Uses
    /// the [`Global`] allocator for any internal buffers.
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Self::from_ssz_bytes_in(bytes, Global)
    }

    /// Decode a full instance from `bytes`, using `alloc` for owned buffers.
    fn from_ssz_bytes_in<A: Allocator + Clone>(
        bytes: &[u8],
        alloc: A,
    ) -> Result<Self, DecodeError>;
}

/// Computes a 32-byte hash tree root for SSZ types.
///
/// Generic over the hash function so callers can plug in SHA-256, Blake2b,
/// etc. Requires `OutputSize = U32`, i.e. a 32-byte digest.
pub trait HashTreeRoot {
    /// Compute the hash tree root using `D` as the underlying hash.
    fn hash_tree_root<D: Digest<OutputSize = U32>>(&self) -> [u8; 32];
}

/// Convenience SHA-256 entry point.
///
/// Rust forbids default type parameters on free functions, so this is the
/// SHA-256-specialised companion to [`HashTreeRoot::hash_tree_root`].
#[cfg(feature = "sha2")]
pub fn hash_tree_root<T: HashTreeRoot + ?Sized>(value: &T) -> [u8; 32] {
    value.hash_tree_root::<sha2::Sha256>()
}

// --------------------------------------------------------------------------
// Internal helpers
// --------------------------------------------------------------------------

/// Wraps a slice index check that returns [`DecodeError::UnexpectedEof`] on
/// out-of-bounds.
#[inline]
pub(crate) fn read_slice(
    bytes: &[u8],
    offset: usize,
    len: usize,
) -> Result<&[u8], DecodeError> {
    let end = offset.checked_add(len).ok_or(DecodeError::UnexpectedEof {
        expected: len,
        actual: bytes.len().saturating_sub(offset),
    })?;
    if end > bytes.len() {
        return Err(DecodeError::UnexpectedEof {
            expected: len,
            actual: bytes.len().saturating_sub(offset),
        });
    }
    Ok(&bytes[offset..end])
}

/// Reads a little-endian u32 length offset from `bytes[off..off+4]`.
#[inline]
pub(crate) fn read_offset(bytes: &[u8], off: usize) -> Result<usize, DecodeError> {
    let slice = read_slice(bytes, off, BYTES_PER_LENGTH_OFFSET)?;
    let arr: [u8; 4] = slice.try_into().expect("len checked");
    Ok(u32::from_le_bytes(arr) as usize)
}

