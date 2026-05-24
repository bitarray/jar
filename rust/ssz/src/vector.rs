//! `FixedVector<T, N>` — homogeneous list with compile-time-fixed length.
//!
//! Wire format: fixed-len T → simple concatenation of N elements;
//! variable-len T → N×4-byte offset table followed by variable payloads.
//! No length prefix.

use allocate::vec::Vec;
use allocate::{Allocator, Global};
use core::fmt;
use digest::Digest;
use digest::typenum::U32;

use crate::list::encode_var_list_payloads;
use crate::merkle::{merkleize, pack_bytes};
use crate::{BYTES_PER_LENGTH_OFFSET, Decode, DecodeError, Encode, HashTreeRoot, read_offset};

/// SSZ vector with a compile-time length of `N`.
///
/// Invariant: `inner.len() == N`.
pub struct FixedVector<T, const N: usize, A: Allocator + Clone = Global> {
    inner: Vec<T, A>,
}

impl<T, const N: usize, A: Allocator + Clone> FixedVector<T, N, A> {
    /// Build a `FixedVector` from an existing `Vec`, verifying the length.
    pub fn from_vec(v: Vec<T, A>) -> Result<Self, DecodeError> {
        if v.len() != N {
            return Err(DecodeError::LengthMismatch {
                expected: N,
                actual: v.len(),
            });
        }
        Ok(Self { inner: v })
    }

    /// Borrow the underlying storage.
    pub fn as_slice(&self) -> &[T] {
        &self.inner
    }

    /// Length of the vector (always `N`).
    pub const fn len(&self) -> usize {
        N
    }

    /// `true` iff `N == 0`.
    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    /// Returns the inner storage.
    pub fn into_inner(self) -> Vec<T, A> {
        self.inner
    }
}

impl<T: Clone, const N: usize> FixedVector<T, N, Global> {
    /// Convenience: build from a slice using the `Global` allocator.
    pub fn from_slice(items: &[T]) -> Result<Self, DecodeError> {
        if items.len() != N {
            return Err(DecodeError::LengthMismatch {
                expected: N,
                actual: items.len(),
            });
        }
        let mut v: Vec<T, Global> = Vec::with_capacity_in(N, Global);
        for t in items {
            v.push(t.clone());
        }
        Ok(Self { inner: v })
    }
}

impl<T, const N: usize, A: Allocator + Clone> core::ops::Deref for FixedVector<T, N, A> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.inner
    }
}

impl<T: fmt::Debug, const N: usize, A: Allocator + Clone> fmt::Debug for FixedVector<T, N, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FixedVector")
            .field("len", &N)
            .field("inner", &&self.inner[..])
            .finish()
    }
}

impl<T: Clone, const N: usize, A: Allocator + Clone> Clone for FixedVector<T, N, A> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T: PartialEq, const N: usize, A: Allocator + Clone> PartialEq for FixedVector<T, N, A> {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl<T: Eq, const N: usize, A: Allocator + Clone> Eq for FixedVector<T, N, A> {}

// --------------------------------------------------------------------------
// Encode / Decode / HashTreeRoot
// --------------------------------------------------------------------------

impl<T: Encode, const N: usize, A: Allocator + Clone> Encode for FixedVector<T, N, A> {
    fn is_ssz_fixed_len() -> bool {
        T::is_ssz_fixed_len()
    }
    fn ssz_fixed_len() -> usize {
        if T::is_ssz_fixed_len() {
            T::ssz_fixed_len() * N
        } else {
            BYTES_PER_LENGTH_OFFSET
        }
    }
    fn ssz_bytes_len(&self) -> usize {
        if T::is_ssz_fixed_len() {
            T::ssz_fixed_len() * N
        } else {
            let mut total = N * BYTES_PER_LENGTH_OFFSET;
            for item in &self.inner {
                total += item.ssz_bytes_len();
            }
            total
        }
    }
    fn ssz_append<A2: Allocator + Clone>(&self, buf: &mut Vec<u8, A2>) {
        encode_fixed_vector(self.inner.iter(), buf);
    }
}

impl<T: Decode, const N: usize, A: Allocator + Clone + Default> Decode for FixedVector<T, N, A> {
    fn is_ssz_fixed_len() -> bool {
        T::is_ssz_fixed_len()
    }
    fn ssz_fixed_len() -> usize {
        if T::is_ssz_fixed_len() {
            T::ssz_fixed_len() * N
        } else {
            BYTES_PER_LENGTH_OFFSET
        }
    }
    fn from_ssz_bytes_in<A2: Allocator + Clone>(
        bytes: &[u8],
        alloc: A2,
    ) -> Result<Self, DecodeError> {
        let decoded = decode_fixed_vector::<T, A2>(bytes, N, alloc)?;
        // The FixedVector storage is in A, not A2. We use A::default()
        // because A2 may differ from A (e.g., decode into a Global
        // FixedVector using a talc-backed scratch). Callers that need to
        // pin storage to a specific allocator should decode into a typed
        // `Vec<T, A>` directly and call `FixedVector::from_vec`.
        let storage_alloc = A::default();
        let mut inner: Vec<T, A> = Vec::with_capacity_in(N, storage_alloc);
        for t in decoded {
            inner.push(t);
        }
        Ok(Self { inner })
    }
}

impl<T: HashTreeRoot + Encode, const N: usize, A: Allocator + Clone> HashTreeRoot
    for FixedVector<T, N, A>
{
    fn hash_tree_root<D: Digest<OutputSize = U32>>(&self) -> [u8; 32] {
        if T::is_basic_type() {
            // Basic-type vector: pack encoded bytes into chunks and merkleize.
            let mut buf: Vec<u8, Global> = Vec::new_in(Global);
            for t in &self.inner {
                t.ssz_append(&mut buf);
            }
            let chunks = pack_bytes(&buf);
            let total_bytes = N.saturating_mul(T::ssz_fixed_len());
            let chunk_limit = total_bytes.div_ceil(32).max(1);
            merkleize::<D>(&chunks, chunk_limit)
        } else {
            // Composite vector: merkleize per-element roots.
            let roots: alloc::vec::Vec<[u8; 32]> =
                self.inner.iter().map(|t| t.hash_tree_root::<D>()).collect();
            merkleize::<D>(&roots, N.max(1))
        }
    }
}

// --------------------------------------------------------------------------
// Free helpers (shared with [T; N] impls)
// --------------------------------------------------------------------------

pub(crate) fn encode_fixed_vector<'a, T, I, A2>(items: I, buf: &mut Vec<u8, A2>)
where
    T: Encode + 'a,
    I: Iterator<Item = &'a T>,
    A2: Allocator + Clone,
{
    let items_vec: alloc::vec::Vec<&T> = items.collect();
    if T::is_ssz_fixed_len() {
        for item in &items_vec {
            item.ssz_append(buf);
        }
    } else {
        encode_var_list_payloads(&items_vec, buf);
    }
}

pub(crate) fn decode_fixed_vector<T: Decode, A: Allocator + Clone>(
    bytes: &[u8],
    n: usize,
    alloc: A,
) -> Result<alloc::vec::Vec<T>, DecodeError> {
    if T::is_ssz_fixed_len() {
        let elem_size = T::ssz_fixed_len();
        let expected = elem_size.saturating_mul(n);
        if bytes.len() != expected {
            return Err(DecodeError::LengthMismatch {
                expected,
                actual: bytes.len(),
            });
        }
        let mut out = alloc::vec::Vec::with_capacity(n);
        for i in 0..n {
            let start = i * elem_size;
            out.push(T::from_ssz_bytes_in(
                &bytes[start..start + elem_size],
                alloc.clone(),
            )?);
        }
        Ok(out)
    } else {
        decode_var_collection::<T, A>(bytes, Some(n), alloc)
    }
}

/// Shared variable-length collection decoder.
///
/// If `expected_len` is `Some(n)`, the decoder enforces exactly `n`
/// elements (vector mode). Otherwise the length is inferred from the first
/// offset (list mode).
pub(crate) fn decode_var_collection<T: Decode, A: Allocator + Clone>(
    bytes: &[u8],
    expected_len: Option<usize>,
    alloc: A,
) -> Result<alloc::vec::Vec<T>, DecodeError> {
    if bytes.is_empty() {
        return match expected_len {
            None | Some(0) => Ok(alloc::vec::Vec::new()),
            Some(n) => Err(DecodeError::LengthMismatch {
                expected: n,
                actual: 0,
            }),
        };
    }
    let first = read_offset(bytes, 0)?;
    if first % BYTES_PER_LENGTH_OFFSET != 0 {
        return Err(DecodeError::InvalidOffset {
            offset: first,
            len: bytes.len(),
            fixed: 0,
        });
    }
    if first > bytes.len() {
        return Err(DecodeError::InvalidOffset {
            offset: first,
            len: bytes.len(),
            fixed: 0,
        });
    }
    let n = first / BYTES_PER_LENGTH_OFFSET;
    if let Some(expected) = expected_len
        && n != expected
    {
        return Err(DecodeError::LengthMismatch {
            expected,
            actual: n,
        });
    }
    let mut offsets = alloc::vec::Vec::with_capacity(n + 1);
    offsets.push(first);
    for i in 1..n {
        let off = read_offset(bytes, i * BYTES_PER_LENGTH_OFFSET)?;
        if off < offsets[i - 1] {
            return Err(DecodeError::OffsetsNotMonotonic {
                prev: offsets[i - 1],
                curr: off,
            });
        }
        if off > bytes.len() {
            return Err(DecodeError::InvalidOffset {
                offset: off,
                len: bytes.len(),
                fixed: first,
            });
        }
        offsets.push(off);
    }
    offsets.push(bytes.len());

    let mut out = alloc::vec::Vec::with_capacity(n);
    for i in 0..n {
        let slice = &bytes[offsets[i]..offsets[i + 1]];
        out.push(T::from_ssz_bytes_in(slice, alloc.clone())?);
    }
    Ok(out)
}
