//! `MissingOr<T>` — first-class summary placeholder for SSZ subtree
//! substitution.
//!
//! Two variants:
//! * `Materialized(T)` — the full value is present.
//! * `Missing([u8; 32])` — only the precomputed `hash_tree_root` is known.
//!
//! Hash invariant (the load-bearing property):
//! ```text
//! Missing(h).hash_tree_root::<D>()      == h
//! Materialized(t).hash_tree_root::<D>() == t.hash_tree_root::<D>()
//! ```
//! No `mix_in_selector` is applied — that would defeat substitution.
//!
//! Wire form (jar-specific extension; not standard SSZ):
//! * byte 0 = `0` + payload bytes (Materialized)
//! * byte 0 = `1` + 32 raw hash bytes (Missing)

use allocate::Allocator;
use allocate::Vec;
use core::fmt;
use digest::Digest;
use digest::typenum::U32;

use crate::{BYTES_PER_LENGTH_OFFSET, Decode, DecodeError, Encode, HashTreeRoot, read_slice};

/// Either a fully materialized value or a precomputed hash placeholder.
pub enum MissingOr<T> {
    Materialized(T),
    Missing([u8; 32]),
}

impl<T: fmt::Debug> fmt::Debug for MissingOr<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Materialized(t) => f.debug_tuple("Materialized").field(t).finish(),
            Self::Missing(h) => f.debug_tuple("Missing").field(h).finish(),
        }
    }
}

impl<T: Clone> Clone for MissingOr<T> {
    fn clone(&self) -> Self {
        match self {
            Self::Materialized(t) => Self::Materialized(t.clone()),
            Self::Missing(h) => Self::Missing(*h),
        }
    }
}

impl<T: PartialEq> PartialEq for MissingOr<T> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Materialized(a), Self::Materialized(b)) => a == b,
            (Self::Missing(a), Self::Missing(b)) => a == b,
            _ => false,
        }
    }
}

impl<T: Eq> Eq for MissingOr<T> {}

impl<T: Encode> Encode for MissingOr<T> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }
    fn ssz_bytes_len(&self) -> usize {
        1 + match self {
            Self::Materialized(t) => t.ssz_bytes_len(),
            Self::Missing(_) => 32,
        }
    }
    fn ssz_append<A: Allocator + Clone>(&self, buf: &mut Vec<u8, A>) {
        match self {
            Self::Materialized(t) => {
                buf.push(0);
                t.ssz_append(buf);
            }
            Self::Missing(h) => {
                buf.push(1);
                buf.extend_from_slice(h);
            }
        }
    }
}

impl<T: Decode> Decode for MissingOr<T> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }
    fn from_ssz_bytes_in<A: Allocator + Clone>(
        bytes: &[u8],
        alloc: A,
    ) -> Result<Self, DecodeError> {
        let tag = read_slice(bytes, 0, 1)?[0];
        match tag {
            0 => Ok(Self::Materialized(T::from_ssz_bytes_in(
                &bytes[1..],
                alloc,
            )?)),
            1 => {
                if bytes.len() != 33 {
                    return Err(DecodeError::TrailingBytes {
                        expected: 33,
                        actual: bytes.len(),
                    });
                }
                let mut h = [0u8; 32];
                h.copy_from_slice(&bytes[1..33]);
                Ok(Self::Missing(h))
            }
            v => Err(DecodeError::InvalidSelector(v)),
        }
    }
}

impl<T: HashTreeRoot> HashTreeRoot for MissingOr<T> {
    fn hash_tree_root<D: Digest<OutputSize = U32>>(&self) -> [u8; 32] {
        // CRITICAL: no mix_in_selector. Substitution requires identity.
        match self {
            Self::Materialized(t) => t.hash_tree_root::<D>(),
            Self::Missing(h) => *h,
        }
    }
}
