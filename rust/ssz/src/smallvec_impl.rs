//! SSZ blanket impls for [`smallvec::SmallVec<A>`].
//!
//! The wire format and hash-tree-root are **byte/root-identical to
//! `Vec<A::Item>`** (see the `Vec<T>` impl in [`crate::collections`]): a
//! variable-length list capped at [`MAX_VEC_LEN`]. `SmallVec` only changes
//! the in-memory storage (inline-then-spill); its serialized and merkleized
//! forms must not diverge from `Vec`, so this mirrors the `Vec<T>` impl
//! field-for-field. Keep the two in sync — a divergence would silently fork
//! the hash of any cap embedding a `SmallVec`-backed field.
//!
//! `javm-cap`'s `Key` (`SmallVec<[u8; N]>`) and `SlotPath`
//! (`SmallVec<[Key; M]>`) are `#[ssz(transparent)]` newtypes that forward
//! to these impls — one generic impl covers both the basic-element (byte key)
//! and composite-element (key path) cases.

use alloc::vec::Vec;
use digest::Digest;
use digest::typenum::U32;
use smallvec::{Array, SmallVec};

use crate::collections::MAX_VEC_LEN;
use crate::merkle::{merkleize, mix_in_length, pack_bytes};
use crate::vector::decode_var_collection;
use crate::{BYTES_PER_LENGTH_OFFSET, Decode, DecodeError, Encode, HashTreeRoot};

impl<A: Array> Encode for SmallVec<A>
where
    A::Item: Encode,
{
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }
    fn ssz_bytes_len(&self) -> usize {
        if A::Item::is_ssz_fixed_len() {
            A::Item::ssz_fixed_len() * self.len()
        } else {
            let mut total = self.len() * BYTES_PER_LENGTH_OFFSET;
            for item in self {
                total += item.ssz_bytes_len();
            }
            total
        }
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        if A::Item::is_ssz_fixed_len() {
            for item in self {
                item.ssz_append(buf);
            }
            return;
        }
        // Variable-length element: offset table + payloads (mirrors `Vec<T>`).
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

impl<A: Array> Decode for SmallVec<A>
where
    A::Item: Decode,
{
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let items: Vec<A::Item> = if A::Item::is_ssz_fixed_len() {
            let elem = A::Item::ssz_fixed_len();
            if elem == 0 {
                return Err(DecodeError::Custom(
                    "zero-sized fixed-length SmallVec element",
                ));
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
                out.push(A::Item::from_ssz_bytes(&bytes[s..s + elem])?);
            }
            out
        } else {
            let out: Vec<A::Item> = decode_var_collection::<A::Item>(bytes, None)?;
            if (out.len() as u64) > MAX_VEC_LEN {
                return Err(DecodeError::BoundExceeded {
                    len: out.len() as u64,
                    bound: MAX_VEC_LEN,
                });
            }
            out
        };
        // `from_vec` reuses the heap allocation when the list spilled and
        // inlines otherwise — never reallocates.
        Ok(SmallVec::from_vec(items))
    }
}

impl<A: Array> HashTreeRoot for SmallVec<A>
where
    A::Item: HashTreeRoot + Encode,
{
    fn hash_tree_root<D: Digest<OutputSize = U32>>(&self) -> [u8; 32] {
        let len = self.len() as u64;
        let inner_root = if A::Item::is_basic_type() {
            let mut buf: Vec<u8> = Vec::new();
            for t in self {
                t.ssz_append(&mut buf);
            }
            let chunks = pack_bytes(&buf);
            let cap_bytes = (MAX_VEC_LEN as usize).saturating_mul(A::Item::ssz_fixed_len());
            let chunk_limit = cap_bytes.div_ceil(32).max(1);
            merkleize::<D>(&chunks, chunk_limit)
        } else {
            let roots: Vec<[u8; 32]> = self.iter().map(|t| t.hash_tree_root::<D>()).collect();
            merkleize::<D>(&roots, (MAX_VEC_LEN as usize).max(1))
        };
        mix_in_length::<D>(inner_root, len)
    }
}
