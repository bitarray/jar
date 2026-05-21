//! `List<T, N>` — variable-length list with compile-time cap of `N` elements.

use allocator_api2::alloc::{Allocator, Global};
use allocator_api2::vec::Vec;
use core::fmt;
use digest::Digest;
use digest::typenum::U32;

use crate::merkle::{merkleize, mix_in_length, pack_bytes};
use crate::vector::decode_var_collection;
use crate::{BYTES_PER_LENGTH_OFFSET, Decode, DecodeError, Encode, HashTreeRoot};

/// SSZ list with a maximum length of `N` elements.
///
/// Invariant: `inner.len() <= N`.
pub struct List<T, const N: u64, A: Allocator + Clone = Global> {
    inner: Vec<T, A>,
}

impl<T, const N: u64, A: Allocator + Clone> List<T, N, A> {
    /// Build from an existing `Vec`, enforcing the cap.
    pub fn from_vec(v: Vec<T, A>) -> Result<Self, DecodeError> {
        if (v.len() as u64) > N {
            return Err(DecodeError::BoundExceeded {
                len: v.len() as u64,
                bound: N,
            });
        }
        Ok(Self { inner: v })
    }

    /// Build an empty list using the given allocator.
    pub fn new_in(alloc: A) -> Self {
        Self {
            inner: Vec::new_in(alloc),
        }
    }

    /// Borrow the underlying storage.
    pub fn as_slice(&self) -> &[T] {
        &self.inner
    }

    /// Length of the list.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// `true` iff the list contains no elements.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Append an element. Returns an error if the cap would be exceeded.
    pub fn push(&mut self, item: T) -> Result<(), DecodeError> {
        if (self.inner.len() as u64) >= N {
            return Err(DecodeError::BoundExceeded {
                len: self.inner.len() as u64 + 1,
                bound: N,
            });
        }
        self.inner.push(item);
        Ok(())
    }

    /// Returns the inner storage.
    pub fn into_inner(self) -> Vec<T, A> {
        self.inner
    }
}

impl<T, const N: u64> List<T, N, Global> {
    /// Build an empty `Global`-allocated list.
    pub fn new() -> Self {
        Self {
            inner: Vec::new_in(Global),
        }
    }
}

impl<T, const N: u64> Default for List<T, N, Global> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone, const N: u64> List<T, N, Global> {
    /// Convenience: build from a slice using the `Global` allocator.
    pub fn from_slice(items: &[T]) -> Result<Self, DecodeError> {
        if (items.len() as u64) > N {
            return Err(DecodeError::BoundExceeded {
                len: items.len() as u64,
                bound: N,
            });
        }
        let mut v: Vec<T, Global> = Vec::with_capacity_in(items.len(), Global);
        for t in items {
            v.push(t.clone());
        }
        Ok(Self { inner: v })
    }
}

impl<T, const N: u64, A: Allocator + Clone> core::ops::Deref for List<T, N, A> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.inner
    }
}

impl<T: fmt::Debug, const N: u64, A: Allocator + Clone> fmt::Debug for List<T, N, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("List")
            .field("cap", &N)
            .field("inner", &&self.inner[..])
            .finish()
    }
}

impl<T: Clone, const N: u64, A: Allocator + Clone> Clone for List<T, N, A> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T: PartialEq, const N: u64, A: Allocator + Clone> PartialEq for List<T, N, A> {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl<T: Eq, const N: u64, A: Allocator + Clone> Eq for List<T, N, A> {}

// --------------------------------------------------------------------------
// Encode / Decode / HashTreeRoot
// --------------------------------------------------------------------------

impl<T: Encode, const N: u64, A: Allocator + Clone> Encode for List<T, N, A> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }
    fn ssz_bytes_len(&self) -> usize {
        if T::is_ssz_fixed_len() {
            T::ssz_fixed_len() * self.inner.len()
        } else {
            let mut total = self.inner.len() * BYTES_PER_LENGTH_OFFSET;
            for item in &self.inner {
                total += item.ssz_bytes_len();
            }
            total
        }
    }
    fn ssz_append<A2: Allocator + Clone>(&self, buf: &mut Vec<u8, A2>) {
        if T::is_ssz_fixed_len() {
            for item in &self.inner {
                item.ssz_append(buf);
            }
        } else {
            let items: alloc::vec::Vec<&T> = self.inner.iter().collect();
            encode_var_list_payloads(&items, buf);
        }
    }
}

impl<T: Decode, const N: u64, A: Allocator + Clone + Default> Decode for List<T, N, A> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }
    fn from_ssz_bytes_in<A2: Allocator + Clone>(
        bytes: &[u8],
        alloc: A2,
    ) -> Result<Self, DecodeError> {
        let decoded = decode_list::<T, A2>(bytes, N, alloc)?;
        let mut inner: Vec<T, A> = Vec::with_capacity_in(decoded.len(), A::default());
        for t in decoded {
            inner.push(t);
        }
        Ok(Self { inner })
    }
}

impl<T: HashTreeRoot + Encode, const N: u64, A: Allocator + Clone> HashTreeRoot for List<T, N, A> {
    fn hash_tree_root<D: Digest<OutputSize = U32>>(&self) -> [u8; 32] {
        let len = self.inner.len() as u64;
        let inner_root = if T::is_basic_type() {
            // Basic-type list: pack encoded bytes into chunks, merkleize
            // with limit = ceil(N * size_of_T / 32).
            let mut buf: Vec<u8, Global> = Vec::new_in(Global);
            for t in &self.inner {
                t.ssz_append(&mut buf);
            }
            let chunks = pack_bytes(&buf);
            let cap_bytes = (N as usize).saturating_mul(T::ssz_fixed_len());
            let chunk_limit = cap_bytes.div_ceil(32).max(1);
            merkleize::<D>(&chunks, chunk_limit)
        } else {
            let roots: alloc::vec::Vec<[u8; 32]> =
                self.inner.iter().map(|t| t.hash_tree_root::<D>()).collect();
            merkleize::<D>(&roots, (N as usize).max(1))
        };
        mix_in_length::<D>(inner_root, len)
    }
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

/// Encode a slice of variable-length items as an SSZ list payload (no
/// length prefix — the count is recovered from the first offset on
/// decode). Used by both `List<T, N>` (for variable T) and `FixedVector<T,
/// N>` (for variable T).
pub(crate) fn encode_var_list_payloads<T: Encode + ?Sized, A: Allocator + Clone>(
    items: &[&T],
    buf: &mut Vec<u8, A>,
) {
    let n = items.len();
    let header_size = n * BYTES_PER_LENGTH_OFFSET;
    // Reserve space for the offset table.
    let initial_len = buf.len();
    buf.resize(initial_len + header_size, 0);

    let mut running = header_size as u32;
    for (i, item) in items.iter().enumerate() {
        let off_pos = initial_len + i * BYTES_PER_LENGTH_OFFSET;
        let off_bytes = running.to_le_bytes();
        buf[off_pos..off_pos + 4].copy_from_slice(&off_bytes);
        let before = buf.len();
        item.ssz_append(buf);
        let after = buf.len();
        running = running
            .checked_add((after - before) as u32)
            .expect("ssz offset overflow");
    }
}

/// Decode a list from an SSZ-encoded slice. `cap` is the compile-time
/// maximum length (in elements). Returns a `Vec<T, Global>`-equivalent
/// `alloc::vec::Vec<T>` for ease of conversion at the call site.
fn decode_list<T: Decode, A: Allocator + Clone>(
    bytes: &[u8],
    cap: u64,
    alloc: A,
) -> Result<alloc::vec::Vec<T>, DecodeError> {
    if T::is_ssz_fixed_len() {
        let elem_size = T::ssz_fixed_len();
        if elem_size == 0 {
            // A list of zero-sized fixed-length elements would need an
            // explicit length prefix to be unambiguous. SSZ doesn't define
            // that, so reject.
            return Err(DecodeError::Custom("zero-sized fixed-length list element"));
        }
        if !bytes.len().is_multiple_of(elem_size) {
            return Err(DecodeError::LengthMismatch {
                expected: bytes.len().div_ceil(elem_size) * elem_size,
                actual: bytes.len(),
            });
        }
        let n = bytes.len() / elem_size;
        if (n as u64) > cap {
            return Err(DecodeError::BoundExceeded {
                len: n as u64,
                bound: cap,
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
        let out = decode_var_collection::<T, A>(bytes, None, alloc)?;
        if (out.len() as u64) > cap {
            return Err(DecodeError::BoundExceeded {
                len: out.len() as u64,
                bound: cap,
            });
        }
        Ok(out)
    }
}
