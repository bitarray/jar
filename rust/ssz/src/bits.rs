//! `Bitvector<N>` and `Bitlist<N>` — bit-packed homogeneous boolean storage.
//!
//! Both use big-endian bit packing within each byte: bit `i` of the
//! logical bitstream is stored at `bytes[i / 8] & (1 << (i % 8))`.
//!
//! * `Bitvector<N>` has length exactly `N`, takes `(N + 7) / 8` bytes; any
//!   bits beyond `N` in the final byte must be zero.
//! * `Bitlist<N>` has variable length up to `N`. The wire form appends a
//!   sentinel `1` bit immediately after the data bits; the decoder finds
//!   the highest set bit in the final byte to recover the length.

use allocate::Vec;
use allocate::{Allocator, Global};
use core::fmt;
use digest::Digest;
use digest::typenum::U32;

use crate::merkle::{merkleize, mix_in_length, pack_bytes};
use crate::{BYTES_PER_LENGTH_OFFSET, Decode, DecodeError, Encode, HashTreeRoot};

// --------------------------------------------------------------------------
// Bitvector<N>
// --------------------------------------------------------------------------

/// SSZ Bitvector with a compile-time length of `N` bits.
///
/// Storage is a heap-allocated byte vector of length `(N + 7) / 8`. Using a
/// `Vec` avoids `generic_const_exprs` (still unstable) while keeping the
/// invariant at the type level.
#[derive(Clone, PartialEq, Eq)]
pub struct Bitvector<const N: usize> {
    bytes: alloc::vec::Vec<u8>,
}

#[inline]
const fn bitvec_bytes(n: usize) -> usize {
    n.div_ceil(8)
}

impl<const N: usize> Default for Bitvector<N> {
    fn default() -> Self {
        Self {
            bytes: alloc::vec![0u8; bitvec_bytes(N)],
        }
    }
}

impl<const N: usize> Bitvector<N> {
    /// Build from a slice (must have exact length `(N+7)/8`).
    pub fn from_slice(bytes: &[u8]) -> Result<Self, DecodeError> {
        let needed = bitvec_bytes(N);
        if bytes.len() != needed {
            return Err(DecodeError::UnexpectedEof {
                expected: needed,
                actual: bytes.len(),
            });
        }
        validate_trailing_zero_bits(bytes, N)?;
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Get bit `i`. Panics if `i >= N`.
    pub fn get(&self, i: usize) -> bool {
        assert!(i < N, "bit index out of bounds");
        (self.bytes[i / 8] >> (i % 8)) & 1 == 1
    }

    /// Set bit `i` to `v`. Panics if `i >= N`.
    pub fn set(&mut self, i: usize, v: bool) {
        assert!(i < N, "bit index out of bounds");
        let mask = 1u8 << (i % 8);
        if v {
            self.bytes[i / 8] |= mask;
        } else {
            self.bytes[i / 8] &= !mask;
        }
    }

    /// Borrow the raw packed bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Length in bits (always `N`).
    pub const fn len(&self) -> usize {
        N
    }

    /// `true` iff `N == 0`.
    pub const fn is_empty(&self) -> bool {
        N == 0
    }
}

impl<const N: usize> fmt::Debug for Bitvector<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bitvector")
            .field("n", &N)
            .field("bytes", &&self.bytes[..])
            .finish()
    }
}

impl<const N: usize> Encode for Bitvector<N> {
    fn is_ssz_fixed_len() -> bool {
        true
    }
    fn ssz_fixed_len() -> usize {
        bitvec_bytes(N)
    }
    fn ssz_bytes_len(&self) -> usize {
        bitvec_bytes(N)
    }
    fn ssz_append<A: Allocator + Clone>(&self, buf: &mut Vec<u8, A>) {
        buf.extend_from_slice(&self.bytes);
    }
}

impl<const N: usize> Decode for Bitvector<N> {
    fn is_ssz_fixed_len() -> bool {
        true
    }
    fn ssz_fixed_len() -> usize {
        bitvec_bytes(N)
    }
    fn from_ssz_bytes_in<A: Allocator + Clone>(
        bytes: &[u8],
        _alloc: A,
    ) -> Result<Self, DecodeError> {
        Self::from_slice(bytes)
    }
}

impl<const N: usize> HashTreeRoot for Bitvector<N> {
    fn hash_tree_root<D: Digest<OutputSize = U32>>(&self) -> [u8; 32] {
        let chunks = pack_bytes(&self.bytes);
        let chunk_limit = bitvec_bytes(N).div_ceil(32).max(1);
        merkleize::<D>(&chunks, chunk_limit)
    }
}

#[inline]
fn validate_trailing_zero_bits(bytes: &[u8], n: usize) -> Result<(), DecodeError> {
    if n == 0 {
        // Even with N=0 we expect a zero-length byte slice; if any byte
        // exists it must be all zeros (defensive).
        if bytes.iter().any(|&b| b != 0) {
            return Err(DecodeError::ExcessBits);
        }
        return Ok(());
    }
    let last_byte_bits = n % 8;
    if last_byte_bits == 0 {
        return Ok(());
    }
    let mask = !((1u8 << last_byte_bits) - 1);
    let last = bytes[bytes.len() - 1];
    if last & mask != 0 {
        return Err(DecodeError::ExcessBits);
    }
    Ok(())
}

// --------------------------------------------------------------------------
// Bitlist<N>
// --------------------------------------------------------------------------

/// SSZ Bitlist with a compile-time bit cap of `N`.
///
/// Wire format: packed bits (LSB-first within bytes), followed by a
/// sentinel `1` bit immediately after the data bits. The sentinel marks
/// the end of the logical bitstream and is not part of the bit content.
pub struct Bitlist<const N: u64, A: Allocator + Clone = Global> {
    bytes: Vec<u8, A>,
    bit_len: u64,
}

impl<const N: u64> Bitlist<N, Global> {
    /// Build an empty `Global`-allocated bitlist.
    pub fn new() -> Self {
        Self {
            bytes: Vec::new_in(Global),
            bit_len: 0,
        }
    }

    /// Build from a logical bit vector.
    pub fn from_bits(bits: &[bool]) -> Result<Self, DecodeError> {
        Self::from_bits_in(bits, Global)
    }
}

impl<const N: u64> Default for Bitlist<N, Global> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: u64, A: Allocator + Clone> Bitlist<N, A> {
    /// Build from a logical bit vector with a caller-provided allocator.
    pub fn from_bits_in(bits: &[bool], alloc: A) -> Result<Self, DecodeError> {
        if (bits.len() as u64) > N {
            return Err(DecodeError::BoundExceeded {
                len: bits.len() as u64,
                bound: N,
            });
        }
        let byte_len = bits.len().div_ceil(8);
        let mut bytes: Vec<u8, A> = Vec::with_capacity_in(byte_len, alloc);
        bytes.resize(byte_len, 0u8);
        for (i, b) in bits.iter().enumerate() {
            if *b {
                bytes[i / 8] |= 1 << (i % 8);
            }
        }
        Ok(Self {
            bytes,
            bit_len: bits.len() as u64,
        })
    }

    /// Logical bit length.
    pub fn len(&self) -> u64 {
        self.bit_len
    }

    /// `true` iff there are no bits.
    pub fn is_empty(&self) -> bool {
        self.bit_len == 0
    }

    /// Get bit `i`. Returns `None` if `i >= len`.
    pub fn get(&self, i: u64) -> Option<bool> {
        if i >= self.bit_len {
            return None;
        }
        let byte = self.bytes[(i / 8) as usize];
        Some((byte >> (i % 8)) & 1 == 1)
    }

    /// Borrow the raw packed data bytes (without the sentinel layer).
    pub fn data_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Total wire byte length (data + sentinel byte if no spare bit).
    fn wire_byte_len(&self) -> usize {
        ((self.bit_len + 1) as usize).div_ceil(8)
    }
}

impl<const N: u64, A: Allocator + Clone> fmt::Debug for Bitlist<N, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bitlist")
            .field("cap", &N)
            .field("bit_len", &self.bit_len)
            .field("bytes", &&self.bytes[..])
            .finish()
    }
}

impl<const N: u64, A: Allocator + Clone> Clone for Bitlist<N, A> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            bit_len: self.bit_len,
        }
    }
}

impl<const N: u64, A: Allocator + Clone> PartialEq for Bitlist<N, A> {
    fn eq(&self, other: &Self) -> bool {
        if self.bit_len != other.bit_len {
            return false;
        }
        self.bytes == other.bytes
    }
}

impl<const N: u64, A: Allocator + Clone> Eq for Bitlist<N, A> {}

impl<const N: u64, A: Allocator + Clone> Encode for Bitlist<N, A> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }
    fn ssz_bytes_len(&self) -> usize {
        self.wire_byte_len()
    }
    fn ssz_append<A2: Allocator + Clone>(&self, buf: &mut Vec<u8, A2>) {
        // Layout: copy data bytes, then set sentinel bit at position `bit_len`.
        let wire_len = self.wire_byte_len();
        let start = buf.len();
        buf.resize(start + wire_len, 0u8);
        // Copy data bits.
        for i in 0..self.bit_len {
            if (self.bytes[(i / 8) as usize] >> (i % 8)) & 1 == 1 {
                buf[start + (i / 8) as usize] |= 1 << (i % 8);
            }
        }
        // Sentinel.
        let sb = start + (self.bit_len / 8) as usize;
        buf[sb] |= 1u8 << (self.bit_len % 8);
    }
}

impl<const N: u64, A: Allocator + Clone + Default> Decode for Bitlist<N, A> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }
    fn from_ssz_bytes_in<A2: Allocator + Clone>(
        bytes: &[u8],
        _alloc: A2,
    ) -> Result<Self, DecodeError> {
        if bytes.is_empty() {
            return Err(DecodeError::MissingBitlistSentinel);
        }
        let last = bytes[bytes.len() - 1];
        if last == 0 {
            return Err(DecodeError::MissingBitlistSentinel);
        }
        let sentinel_bit_in_byte = 7 - last.leading_zeros() as usize; // highest set bit
        let bit_len = ((bytes.len() - 1) * 8 + sentinel_bit_in_byte) as u64;
        if bit_len > N {
            return Err(DecodeError::BoundExceeded {
                len: bit_len,
                bound: N,
            });
        }

        // Extract data: copy all bytes, then clear the sentinel bit and the
        // bits above it in the last byte.
        let mut data: Vec<u8, A> = Vec::with_capacity_in(bytes.len(), A::default());
        data.extend_from_slice(bytes);
        if let Some(last_byte) = data.last_mut() {
            let keep_mask = (1u8 << sentinel_bit_in_byte).wrapping_sub(1);
            *last_byte &= keep_mask;
        }
        // Trim the trailing data byte if it ended up all-zero AND we don't
        // need it for data bits.
        let needed_data_bytes = (bit_len as usize).div_ceil(8);
        while data.len() > needed_data_bytes {
            data.pop();
        }
        // If the needed data byte count is shorter than the wire byte count
        // by 1 and we already popped, the data array now holds exactly
        // `needed_data_bytes` bytes. Otherwise we keep `data.len() ==
        // bytes.len()` (sentinel was alone in its byte, masked off).
        Ok(Self {
            bytes: data,
            bit_len,
        })
    }
}

impl<const N: u64, A: Allocator + Clone> HashTreeRoot for Bitlist<N, A> {
    fn hash_tree_root<D: Digest<OutputSize = U32>>(&self) -> [u8; 32] {
        let data = &self.bytes[..];
        let chunks = pack_bytes(data);
        let cap_bytes = (N as usize).div_ceil(8);
        let chunk_limit = cap_bytes.div_ceil(32).max(1);
        let inner = merkleize::<D>(&chunks, chunk_limit);
        mix_in_length::<D>(inner, self.bit_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha256;

    #[test]
    fn bitvector_set_get() {
        let mut bv: Bitvector<10> = Bitvector::default();
        bv.set(0, true);
        bv.set(9, true);
        assert!(bv.get(0));
        assert!(!bv.get(1));
        assert!(bv.get(9));
    }

    #[test]
    fn bitvector_round_trip() {
        let mut bv: Bitvector<10> = Bitvector::default();
        bv.set(0, true);
        bv.set(3, true);
        bv.set(9, true);
        let bytes = bv.as_ssz_bytes();
        let decoded = Bitvector::<10>::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(bv, decoded);
    }

    #[test]
    fn bitvector_rejects_excess_bits() {
        // N=4, but high nibble has a set bit
        let raw = [0b00010000u8];
        assert!(Bitvector::<4>::from_slice(&raw).is_err());
    }

    #[test]
    fn bitlist_empty_round_trip() {
        let bl: Bitlist<256> = Bitlist::new();
        let bytes = bl.as_ssz_bytes();
        // Empty bitlist: sentinel bit at position 0 → byte 0x01.
        assert_eq!(bytes, vec![0x01]);
        let decoded = Bitlist::<256>::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(bl, decoded);
        assert_eq!(decoded.len(), 0);
    }

    #[test]
    fn bitlist_round_trip() {
        let bits = [true, false, true, true, false, true, false, false, true];
        let bl: Bitlist<256> = Bitlist::from_bits(&bits).unwrap();
        let bytes = bl.as_ssz_bytes();
        let decoded = Bitlist::<256>::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(bl, decoded);
        assert_eq!(decoded.len(), 9);
        for (i, b) in bits.iter().enumerate() {
            assert_eq!(decoded.get(i as u64), Some(*b));
        }
    }

    #[test]
    fn bitlist_hash_matches_after_round_trip() {
        let bits = [true, false, true, false, true];
        let bl: Bitlist<256> = Bitlist::from_bits(&bits).unwrap();
        let h1 = bl.hash_tree_root::<Sha256>();
        let bytes = bl.as_ssz_bytes();
        let bl2 = Bitlist::<256>::from_ssz_bytes(&bytes).unwrap();
        let h2 = bl2.hash_tree_root::<Sha256>();
        assert_eq!(h1, h2);
    }
}
