//! SSZ blanket impls for `alloc::collections::BTreeMap`.
//!
//! Wire format: equivalent to `List<(K, V), MAX_BTREE_LEN>` — i.e., a flat
//! list of sorted `(K, V)` pairs. Decode rejects out-of-order or duplicate
//! keys.
//!
//! Hash form: same as `List<(K, V), MAX_BTREE_LEN>` — merkleize the pair
//! roots, mix in length.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use digest::Digest;
use digest::typenum::U32;

use crate::merkle::{merkleize, mix_in_length};
use crate::vector::decode_var_collection;
use crate::{
    BYTES_PER_LENGTH_OFFSET, Decode, DecodeError, Encode, HashTreeRoot, read_offset, read_slice,
};

/// Implicit cap on `BTreeMap` length, in elements. Chosen as `1 << 32`
/// (matches the SCALE `u32` count-prefix cap).
pub const MAX_BTREE_LEN: u64 = 1u64 << 32;

// --------------------------------------------------------------------------
// (K, V) tuple impls — used by BTreeMap as the element type.
// --------------------------------------------------------------------------

impl<A: Encode, B: Encode> Encode for (A, B) {
    fn is_ssz_fixed_len() -> bool {
        A::is_ssz_fixed_len() && B::is_ssz_fixed_len()
    }
    fn ssz_fixed_len() -> usize {
        if Self::is_ssz_fixed_len() {
            A::ssz_fixed_len() + B::ssz_fixed_len()
        } else {
            BYTES_PER_LENGTH_OFFSET
        }
    }
    fn ssz_bytes_len(&self) -> usize {
        if Self::is_ssz_fixed_len() {
            A::ssz_fixed_len() + B::ssz_fixed_len()
        } else {
            let mut total = 0usize;
            // Fixed slot for each field (offsets for var-length).
            total += if A::is_ssz_fixed_len() {
                A::ssz_fixed_len()
            } else {
                BYTES_PER_LENGTH_OFFSET
            };
            total += if B::is_ssz_fixed_len() {
                B::ssz_fixed_len()
            } else {
                BYTES_PER_LENGTH_OFFSET
            };
            // Variable payloads.
            if !A::is_ssz_fixed_len() {
                total += self.0.ssz_bytes_len();
            }
            if !B::is_ssz_fixed_len() {
                total += self.1.ssz_bytes_len();
            }
            total
        }
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        if Self::is_ssz_fixed_len() {
            self.0.ssz_append(buf);
            self.1.ssz_append(buf);
            return;
        }
        encode_container_pair(&self.0, &self.1, buf);
    }
}

fn encode_container_pair<A: Encode, B: Encode>(a: &A, b: &B, buf: &mut Vec<u8>) {
    // SSZ container layout: fixed-region first (with placeholders for
    // variable-field offsets), then variable-region.
    let a_fixed = if A::is_ssz_fixed_len() {
        A::ssz_fixed_len()
    } else {
        BYTES_PER_LENGTH_OFFSET
    };
    let b_fixed = if B::is_ssz_fixed_len() {
        B::ssz_fixed_len()
    } else {
        BYTES_PER_LENGTH_OFFSET
    };
    let fixed_region_size = a_fixed + b_fixed;
    let start = buf.len();
    // Reserve fixed region.
    buf.resize(start + fixed_region_size, 0u8);

    let mut running = fixed_region_size as u32;

    // Field A.
    if A::is_ssz_fixed_len() {
        // Encode directly into the placeholder region.
        let mut tmp: Vec<u8> = Vec::new();
        a.ssz_append(&mut tmp);
        debug_assert_eq!(tmp.len(), a_fixed);
        buf[start..start + a_fixed].copy_from_slice(&tmp);
    } else {
        // Write offset, append payload.
        buf[start..start + 4].copy_from_slice(&running.to_le_bytes());
        let before = buf.len();
        a.ssz_append(buf);
        let after = buf.len();
        running = running
            .checked_add((after - before) as u32)
            .expect("ssz offset overflow");
    }

    // Field B.
    let b_start = start + a_fixed;
    if B::is_ssz_fixed_len() {
        let mut tmp: Vec<u8> = Vec::new();
        b.ssz_append(&mut tmp);
        debug_assert_eq!(tmp.len(), b_fixed);
        buf[b_start..b_start + b_fixed].copy_from_slice(&tmp);
    } else {
        buf[b_start..b_start + 4].copy_from_slice(&running.to_le_bytes());
        b.ssz_append(buf);
    }
}

impl<A: Decode, B: Decode> Decode for (A, B) {
    fn is_ssz_fixed_len() -> bool {
        A::is_ssz_fixed_len() && B::is_ssz_fixed_len()
    }
    fn ssz_fixed_len() -> usize {
        if Self::is_ssz_fixed_len() {
            A::ssz_fixed_len() + B::ssz_fixed_len()
        } else {
            BYTES_PER_LENGTH_OFFSET
        }
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if Self::is_ssz_fixed_len() {
            let af = A::ssz_fixed_len();
            let bf = B::ssz_fixed_len();
            if bytes.len() != af + bf {
                return Err(DecodeError::UnexpectedEof {
                    expected: af + bf,
                    actual: bytes.len(),
                });
            }
            let a = A::from_ssz_bytes(&bytes[..af])?;
            let b = B::from_ssz_bytes(&bytes[af..])?;
            return Ok((a, b));
        }
        decode_container_pair::<A, B>(bytes)
    }
}

fn decode_container_pair<A: Decode, B: Decode>(bytes: &[u8]) -> Result<(A, B), DecodeError> {
    let a_fixed = if A::is_ssz_fixed_len() {
        A::ssz_fixed_len()
    } else {
        BYTES_PER_LENGTH_OFFSET
    };
    let b_fixed = if B::is_ssz_fixed_len() {
        B::ssz_fixed_len()
    } else {
        BYTES_PER_LENGTH_OFFSET
    };
    let fixed_region_size = a_fixed + b_fixed;
    if bytes.len() < fixed_region_size {
        return Err(DecodeError::UnexpectedEof {
            expected: fixed_region_size,
            actual: bytes.len(),
        });
    }

    // Compute variable-region offsets in order, then slices.
    let mut a_var_off: Option<usize> = None;
    let mut b_var_off: Option<usize> = None;
    if !A::is_ssz_fixed_len() {
        a_var_off = Some(read_offset(bytes, 0)?);
    }
    if !B::is_ssz_fixed_len() {
        b_var_off = Some(read_offset(bytes, a_fixed)?);
    }
    if let Some(off) = a_var_off
        && off < fixed_region_size
    {
        return Err(DecodeError::InvalidOffset {
            offset: off,
            len: bytes.len(),
            fixed: fixed_region_size,
        });
    }
    if let Some(off) = b_var_off
        && off < fixed_region_size
    {
        return Err(DecodeError::InvalidOffset {
            offset: off,
            len: bytes.len(),
            fixed: fixed_region_size,
        });
    }
    if let (Some(a), Some(b)) = (a_var_off, b_var_off)
        && b < a
    {
        return Err(DecodeError::OffsetsNotMonotonic { prev: a, curr: b });
    }

    // Decode A.
    let a_val = if A::is_ssz_fixed_len() {
        A::from_ssz_bytes(&bytes[..a_fixed])?
    } else {
        let start = a_var_off.unwrap();
        let end = b_var_off.unwrap_or(bytes.len());
        if end > bytes.len() || start > end {
            return Err(DecodeError::InvalidOffset {
                offset: start,
                len: bytes.len(),
                fixed: fixed_region_size,
            });
        }
        A::from_ssz_bytes(&bytes[start..end])?
    };

    // Decode B.
    let b_val = if B::is_ssz_fixed_len() {
        B::from_ssz_bytes(&bytes[a_fixed..a_fixed + b_fixed])?
    } else {
        let start = b_var_off.unwrap();
        let end = bytes.len();
        if start > end {
            return Err(DecodeError::InvalidOffset {
                offset: start,
                len: bytes.len(),
                fixed: fixed_region_size,
            });
        }
        B::from_ssz_bytes(&bytes[start..end])?
    };

    // Reject trailing bytes in the variable region.
    let _ = read_slice;

    Ok((a_val, b_val))
}

impl<A: HashTreeRoot, B: HashTreeRoot> HashTreeRoot for (A, B) {
    fn hash_tree_root<D: Digest<OutputSize = U32>>(&self) -> [u8; 32] {
        let roots = [self.0.hash_tree_root::<D>(), self.1.hash_tree_root::<D>()];
        merkleize::<D>(&roots, 2)
    }
}

// --------------------------------------------------------------------------
// BTreeMap<K, V>
// --------------------------------------------------------------------------

impl<K: Encode + Ord, V: Encode> Encode for BTreeMap<K, V> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }
    fn ssz_bytes_len(&self) -> usize {
        let elem_fixed = <(K, V) as Encode>::is_ssz_fixed_len();
        if elem_fixed {
            <(K, V) as Encode>::ssz_fixed_len() * self.len()
        } else {
            let n = self.len();
            let mut total = n * BYTES_PER_LENGTH_OFFSET;
            for (k, v) in self {
                total += pair_len(k, v);
            }
            total
        }
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let elem_fixed = <(K, V) as Encode>::is_ssz_fixed_len();
        if elem_fixed {
            // List<(K, V)> with fixed element → simple concatenation.
            for (k, v) in self {
                let pair: (&K, &V) = (k, v);
                let _ = pair;
                k.ssz_append(buf);
                v.ssz_append(buf);
            }
            return;
        }
        // List<(K, V)> with variable element → offset table + payloads.
        let entries: Vec<(&K, &V)> = self.iter().collect();
        let header = entries.len() * BYTES_PER_LENGTH_OFFSET;
        let start = buf.len();
        buf.resize(start + header, 0u8);
        let mut running = header as u32;
        for (i, (k, v)) in entries.iter().enumerate() {
            let off_pos = start + i * BYTES_PER_LENGTH_OFFSET;
            buf[off_pos..off_pos + 4].copy_from_slice(&running.to_le_bytes());
            let before = buf.len();
            encode_container_pair(*k, *v, buf);
            let after = buf.len();
            running = running
                .checked_add((after - before) as u32)
                .expect("ssz offset overflow");
        }
    }
}

fn pair_len<K: Encode, V: Encode>(k: &K, v: &V) -> usize {
    // Mirror the tuple `(K, V)`'s `ssz_bytes_len` accounting.
    let a_fixed = if K::is_ssz_fixed_len() {
        K::ssz_fixed_len()
    } else {
        BYTES_PER_LENGTH_OFFSET
    };
    let b_fixed = if V::is_ssz_fixed_len() {
        V::ssz_fixed_len()
    } else {
        BYTES_PER_LENGTH_OFFSET
    };
    let mut total = a_fixed + b_fixed;
    if !K::is_ssz_fixed_len() {
        total += k.ssz_bytes_len();
    }
    if !V::is_ssz_fixed_len() {
        total += v.ssz_bytes_len();
    }
    total
}

impl<K: Decode + Ord, V: Decode> Decode for BTreeMap<K, V> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let entries: Vec<(K, V)> = if <(K, V) as Decode>::is_ssz_fixed_len() {
            let elem = <(K, V) as Decode>::ssz_fixed_len();
            if elem == 0 {
                return Err(DecodeError::Custom(
                    "zero-sized fixed-length BTreeMap element",
                ));
            }
            if !bytes.len().is_multiple_of(elem) {
                return Err(DecodeError::LengthMismatch {
                    expected: bytes.len().div_ceil(elem) * elem,
                    actual: bytes.len(),
                });
            }
            let n = bytes.len() / elem;
            let mut out = Vec::with_capacity(n);
            for i in 0..n {
                let s = i * elem;
                out.push(<(K, V) as Decode>::from_ssz_bytes(&bytes[s..s + elem])?);
            }
            out
        } else {
            decode_var_collection::<(K, V)>(bytes, None)?
        };

        let mut map = BTreeMap::new();
        let mut prev: Option<&K> = None;
        // BTreeMap doesn't let us peek prev by reference cleanly while
        // inserting, so do the sorted-order check before insertion.
        let mut staged: Vec<(K, V)> = Vec::with_capacity(entries.len());
        for (k, v) in entries {
            if let Some(p) = prev
                && &k <= p
            {
                return Err(DecodeError::NotSorted);
            }
            staged.push((k, v));
            prev = staged.last().map(|(k, _)| k);
        }
        for (k, v) in staged {
            map.insert(k, v);
        }
        Ok(map)
    }
}

impl<K: HashTreeRoot + Ord + Encode, V: HashTreeRoot + Encode> HashTreeRoot for BTreeMap<K, V> {
    fn hash_tree_root<D: Digest<OutputSize = U32>>(&self) -> [u8; 32] {
        let roots: Vec<[u8; 32]> = self
            .iter()
            .map(|(k, v)| {
                let pair = [k.hash_tree_root::<D>(), v.hash_tree_root::<D>()];
                merkleize::<D>(&pair, 2)
            })
            .collect();
        let inner = merkleize::<D>(&roots, (MAX_BTREE_LEN as usize).max(1));
        mix_in_length::<D>(inner, self.len() as u64)
    }
}

// --------------------------------------------------------------------------
// alloc::vec::Vec<T> — blanket SSZ impl
//
// Treated as `List<T, MAX_VEC_LEN>` semantically: variable-length list with
// the same cap used for `BTreeMap`. Convenient for migrating struct fields
// that hold plain `Vec<T>` without changing their type. Use `ssz::List<T,
// N>` directly for types where a tighter type-level cap is desired.
// --------------------------------------------------------------------------

/// Implicit cap on `alloc::vec::Vec` length, in elements. Matches the legacy
/// SCALE `u32` count-prefix cap (`1 << 32`).
pub const MAX_VEC_LEN: u64 = 1u64 << 32;

impl<T: Encode> Encode for Vec<T> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }
    fn ssz_bytes_len(&self) -> usize {
        if T::is_ssz_fixed_len() {
            T::ssz_fixed_len() * self.len()
        } else {
            let mut total = self.len() * BYTES_PER_LENGTH_OFFSET;
            for item in self {
                total += item.ssz_bytes_len();
            }
            total
        }
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        if T::is_ssz_fixed_len() {
            for item in self {
                item.ssz_append(buf);
            }
            return;
        }
        // Variable-length element: offset table + payloads.
        let n = self.len();
        let header = n * BYTES_PER_LENGTH_OFFSET;
        let start = buf.len();
        buf.resize(start + header, 0u8);
        let mut running = header as u32;
        for (i, item) in self.iter().enumerate() {
            let off_pos = start + i * BYTES_PER_LENGTH_OFFSET;
            buf[off_pos..off_pos + 4].copy_from_slice(&running.to_le_bytes());
            let before = buf.len();
            item.ssz_append(buf);
            let after = buf.len();
            running = running
                .checked_add((after - before) as u32)
                .expect("ssz offset overflow");
        }
    }
}

impl<T: Decode> Decode for Vec<T> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if T::is_ssz_fixed_len() {
            let elem = T::ssz_fixed_len();
            if elem == 0 {
                return Err(DecodeError::Custom("zero-sized fixed-length Vec element"));
            }
            if !bytes.len().is_multiple_of(elem) {
                return Err(DecodeError::LengthMismatch {
                    expected: bytes.len().div_ceil(elem) * elem,
                    actual: bytes.len(),
                });
            }
            let n = bytes.len() / elem;
            if (n as u64) > MAX_VEC_LEN {
                return Err(DecodeError::BoundExceeded {
                    len: n as u64,
                    bound: MAX_VEC_LEN,
                });
            }
            let mut out = Vec::with_capacity(n);
            for i in 0..n {
                let s = i * elem;
                out.push(T::from_ssz_bytes(&bytes[s..s + elem])?);
            }
            Ok(out)
        } else {
            let out: Vec<T> = decode_var_collection::<T>(bytes, None)?;
            if (out.len() as u64) > MAX_VEC_LEN {
                return Err(DecodeError::BoundExceeded {
                    len: out.len() as u64,
                    bound: MAX_VEC_LEN,
                });
            }
            Ok(out)
        }
    }
}

impl<T: HashTreeRoot + Encode> HashTreeRoot for Vec<T> {
    fn hash_tree_root<D: Digest<OutputSize = U32>>(&self) -> [u8; 32] {
        let len = self.len() as u64;
        let inner_root = if T::is_basic_type() {
            let mut buf: Vec<u8> = Vec::new();
            for t in self {
                t.ssz_append(&mut buf);
            }
            let chunks = crate::merkle::pack_bytes(&buf);
            let cap_bytes = (MAX_VEC_LEN as usize).saturating_mul(T::ssz_fixed_len());
            let chunk_limit = cap_bytes.div_ceil(32).max(1);
            merkleize::<D>(&chunks, chunk_limit)
        } else {
            let roots: Vec<[u8; 32]> = self.iter().map(|t| t.hash_tree_root::<D>()).collect();
            merkleize::<D>(&roots, (MAX_VEC_LEN as usize).max(1))
        };
        mix_in_length::<D>(inner_root, len)
    }
}
