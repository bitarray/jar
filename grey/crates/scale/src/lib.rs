//! SCALE codec without compact encoding.
//!
//! All integers are fixed-width little-endian. Variable-length arrays use
//! a u32 LE count prefix. Fixed-size arrays encode with no prefix.
//!
//! Convention:
//! - `[T; N]` (compile-time known N): no prefix, just N elements concatenated
//! - `Vec<T>` (dynamic length): u32 LE count prefix + elements
//! - `Option<T>`: discriminator byte (0=None, 1=Some) + payload
//! - Enums: u8 discriminator + variant payload

mod error;

pub use error::DecodeError;
pub use scale_derive::{Decode, Encode};

/// Encode a value to bytes.
pub trait Encode {
    /// Encode self, appending to `buf`.
    fn encode_to(&self, buf: &mut Vec<u8>);

    /// Encode self into a new Vec.
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode_to(&mut buf);
        buf
    }
}

/// Decode a value from bytes.
pub trait Decode: Sized {
    /// Decode from `data`, returning `(value, bytes_consumed)`.
    fn decode(data: &[u8]) -> Result<(Self, usize), DecodeError>;
}

// ============================================================================
// Primitive Encode impls — fixed-width LE
// ============================================================================

impl Encode for u8 {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.push(*self);
    }
}

impl Encode for u16 {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_le_bytes());
    }
}

impl Encode for u32 {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_le_bytes());
    }
}

impl Encode for u64 {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_le_bytes());
    }
}

impl Encode for bool {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.push(if *self { 1 } else { 0 });
    }
}

// ============================================================================
// Primitive Decode impls — fixed-width LE
// ============================================================================

impl Decode for u8 {
    fn decode(data: &[u8]) -> Result<(Self, usize), DecodeError> {
        if data.is_empty() {
            return Err(DecodeError::UnexpectedEof);
        }
        Ok((data[0], 1))
    }
}

impl Decode for u16 {
    fn decode(data: &[u8]) -> Result<(Self, usize), DecodeError> {
        if data.len() < 2 {
            return Err(DecodeError::UnexpectedEof);
        }
        Ok((u16::from_le_bytes(data[..2].try_into().unwrap()), 2))
    }
}

impl Decode for u32 {
    fn decode(data: &[u8]) -> Result<(Self, usize), DecodeError> {
        if data.len() < 4 {
            return Err(DecodeError::UnexpectedEof);
        }
        Ok((u32::from_le_bytes(data[..4].try_into().unwrap()), 4))
    }
}

impl Decode for u64 {
    fn decode(data: &[u8]) -> Result<(Self, usize), DecodeError> {
        if data.len() < 8 {
            return Err(DecodeError::UnexpectedEof);
        }
        Ok((u64::from_le_bytes(data[..8].try_into().unwrap()), 8))
    }
}

impl Decode for bool {
    fn decode(data: &[u8]) -> Result<(Self, usize), DecodeError> {
        if data.is_empty() {
            return Err(DecodeError::UnexpectedEof);
        }
        match data[0] {
            0 => Ok((false, 1)),
            1 => Ok((true, 1)),
            v => Err(DecodeError::InvalidDiscriminator(v)),
        }
    }
}

// ============================================================================
// U24 — 3-byte little-endian unsigned integer
// ============================================================================

/// A 3-byte (24-bit) unsigned integer, stored as u32 but encoded as 3 bytes LE.
/// Used in PVM program headers for ro_size, rw_size, stack_size.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct U24(pub u32);

impl U24 {
    pub const MAX: u32 = 0xFF_FFFF;

    pub fn new(val: u32) -> Self {
        debug_assert!(val <= Self::MAX, "U24 overflow: {val}");
        Self(val & Self::MAX)
    }

    pub fn as_u32(self) -> u32 {
        self.0
    }

    pub fn as_usize(self) -> usize {
        self.0 as usize
    }
}

impl Encode for U24 {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        let bytes = self.0.to_le_bytes();
        buf.extend_from_slice(&bytes[..3]);
    }
}

impl Decode for U24 {
    fn decode(data: &[u8]) -> Result<(Self, usize), DecodeError> {
        if data.len() < 3 {
            return Err(DecodeError::UnexpectedEof);
        }
        let val = data[0] as u32 | ((data[1] as u32) << 8) | ((data[2] as u32) << 16);
        Ok((U24(val), 3))
    }
}

impl From<u32> for U24 {
    fn from(val: u32) -> Self {
        Self::new(val)
    }
}

impl From<U24> for u32 {
    fn from(val: U24) -> Self {
        val.0
    }
}

// ============================================================================
// Fixed-size arrays — [T; N] (no length prefix)
// ============================================================================

impl<T: Encode, const N: usize> Encode for [T; N] {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        for item in self {
            item.encode_to(buf);
        }
    }
}

impl<const N: usize> Decode for [u8; N] {
    fn decode(data: &[u8]) -> Result<(Self, usize), DecodeError> {
        if data.len() < N {
            return Err(DecodeError::UnexpectedEof);
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&data[..N]);
        Ok((arr, N))
    }
}

// Note: Generic [T; N] Decode is not implemented because it conflicts
// with [u8; N]. Use the derive macro or manual impl for specific types.
// The derive macro handles fixed-size arrays of non-u8 types.

// ============================================================================
// Vec<T> — u32 LE count prefix + elements
// ============================================================================

impl<T: Encode> Encode for Vec<T> {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        (self.len() as u32).encode_to(buf);
        for item in self {
            item.encode_to(buf);
        }
    }
}

impl<T: Decode> Decode for Vec<T> {
    fn decode(data: &[u8]) -> Result<(Self, usize), DecodeError> {
        let (count, mut off) = u32::decode(data)?;
        let count = count as usize;
        // Sanity check: prevent allocating gigabytes on corrupt data
        if count > data.len() {
            return Err(DecodeError::SequenceTooLong {
                count: count as u32,
                remaining: data.len() as u32,
            });
        }
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            let (item, c) = T::decode(&data[off..])?;
            off += c;
            items.push(item);
        }
        Ok((items, off))
    }
}

// ============================================================================
// Option<T> — discriminator byte (0=None, 1=Some) + payload
// ============================================================================

impl<T: Encode> Encode for Option<T> {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        match self {
            None => buf.push(0),
            Some(val) => {
                buf.push(1);
                val.encode_to(buf);
            }
        }
    }
}

impl<T: Decode> Decode for Option<T> {
    fn decode(data: &[u8]) -> Result<(Self, usize), DecodeError> {
        if data.is_empty() {
            return Err(DecodeError::UnexpectedEof);
        }
        match data[0] {
            0 => Ok((None, 1)),
            1 => {
                let (val, c) = T::decode(&data[1..])?;
                Ok((Some(val), 1 + c))
            }
            v => Err(DecodeError::InvalidDiscriminator(v)),
        }
    }
}

// ============================================================================
// BTreeSet<T> — u32 count + sorted elements
// ============================================================================

impl<T: Encode + Ord> Encode for std::collections::BTreeSet<T> {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        (self.len() as u32).encode_to(buf);
        for item in self {
            item.encode_to(buf);
        }
    }
}

impl<T: Decode + Ord> Decode for std::collections::BTreeSet<T> {
    fn decode(data: &[u8]) -> Result<(Self, usize), DecodeError> {
        let (count, mut off) = u32::decode(data)?;
        let count = count as usize;
        if count > data.len() {
            return Err(DecodeError::SequenceTooLong {
                count: count as u32,
                remaining: data.len() as u32,
            });
        }
        let mut set = std::collections::BTreeSet::new();
        for _ in 0..count {
            let (item, c) = T::decode(&data[off..])?;
            off += c;
            set.insert(item);
        }
        Ok((set, off))
    }
}

// ============================================================================
// Tuples — concatenation
// ============================================================================

impl<A: Encode, B: Encode> Encode for (A, B) {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        self.0.encode_to(buf);
        self.1.encode_to(buf);
    }
}

impl<A: Decode, B: Decode> Decode for (A, B) {
    fn decode(data: &[u8]) -> Result<(Self, usize), DecodeError> {
        let (a, c1) = A::decode(data)?;
        let (b, c2) = B::decode(&data[c1..])?;
        Ok(((a, b), c1 + c2))
    }
}

// ============================================================================
// BTreeMap<K, V> — u32 count + sorted key-value pairs
// ============================================================================

impl<K: Encode + Ord, V: Encode> Encode for std::collections::BTreeMap<K, V> {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        (self.len() as u32).encode_to(buf);
        for (k, v) in self {
            k.encode_to(buf);
            v.encode_to(buf);
        }
    }
}

impl<K: Decode + Ord, V: Decode> Decode for std::collections::BTreeMap<K, V> {
    fn decode(data: &[u8]) -> Result<(Self, usize), DecodeError> {
        let (count, mut off) = u32::decode(data)?;
        let count = count as usize;
        if count > data.len() {
            return Err(DecodeError::SequenceTooLong {
                count: count as u32,
                remaining: data.len() as u32,
            });
        }
        let mut map = std::collections::BTreeMap::new();
        for _ in 0..count {
            let (k, c) = K::decode(&data[off..])?;
            off += c;
            let (v, c) = V::decode(&data[off..])?;
            off += c;
            map.insert(k, v);
        }
        Ok((map, off))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u32_roundtrip() {
        let val: u32 = 0xDEADBEEF;
        let encoded = val.encode();
        assert_eq!(encoded, [0xEF, 0xBE, 0xAD, 0xDE]);
        let (decoded, consumed) = u32::decode(&encoded).unwrap();
        assert_eq!(decoded, val);
        assert_eq!(consumed, 4);
    }

    #[test]
    fn test_bool_roundtrip() {
        assert_eq!(true.encode(), [1]);
        assert_eq!(false.encode(), [0]);
        assert_eq!(bool::decode(&[1]).unwrap(), (true, 1));
        assert_eq!(bool::decode(&[0]).unwrap(), (false, 1));
        assert!(bool::decode(&[2]).is_err());
    }

    #[test]
    fn test_vec_u16_roundtrip() {
        let val: Vec<u16> = vec![1, 2, 3];
        let encoded = val.encode();
        // u32 count (3) + 3 × u16
        assert_eq!(encoded, [3, 0, 0, 0, 1, 0, 2, 0, 3, 0]);
        let (decoded, consumed) = Vec::<u16>::decode(&encoded).unwrap();
        assert_eq!(decoded, val);
        assert_eq!(consumed, 10);
    }

    #[test]
    fn test_option_roundtrip() {
        let none: Option<u32> = None;
        assert_eq!(none.encode(), [0]);
        let (decoded, _) = Option::<u32>::decode(&[0]).unwrap();
        assert_eq!(decoded, None);

        let some: Option<u32> = Some(42);
        let encoded = some.encode();
        assert_eq!(encoded, [1, 42, 0, 0, 0]);
        let (decoded, _) = Option::<u32>::decode(&encoded).unwrap();
        assert_eq!(decoded, Some(42));
    }

    #[test]
    fn test_fixed_array_roundtrip() {
        let val: [u8; 4] = [1, 2, 3, 4];
        let encoded = val.encode();
        assert_eq!(encoded, [1, 2, 3, 4]); // no length prefix
        let (decoded, consumed) = <[u8; 4]>::decode(&encoded).unwrap();
        assert_eq!(decoded, val);
        assert_eq!(consumed, 4);
    }

    #[test]
    fn test_u24_roundtrip() {
        let val = U24::new(0x123456);
        let encoded = val.encode();
        assert_eq!(encoded, [0x56, 0x34, 0x12]); // 3 bytes LE
        let (decoded, consumed) = U24::decode(&encoded).unwrap();
        assert_eq!(decoded, val);
        assert_eq!(consumed, 3);
    }

    #[test]
    fn test_u24_zero() {
        let val = U24(0);
        let encoded = val.encode();
        assert_eq!(encoded, [0, 0, 0]);
        let (decoded, _) = U24::decode(&encoded).unwrap();
        assert_eq!(decoded.as_u32(), 0);
    }

    #[test]
    fn test_tuple_roundtrip() {
        let val: (u16, u32) = (1, 2);
        let encoded = val.encode();
        assert_eq!(encoded, [1, 0, 2, 0, 0, 0]);
        let (decoded, consumed) = <(u16, u32)>::decode(&encoded).unwrap();
        assert_eq!(decoded, val);
        assert_eq!(consumed, 6);
    }

    #[test]
    fn test_btreemap_roundtrip() {
        use std::collections::BTreeMap;
        let mut map = BTreeMap::new();
        map.insert(1u16, 10u32);
        map.insert(2u16, 20u32);
        let encoded = map.encode();
        // u32 count (2) + (u16, u32) × 2
        assert_eq!(encoded, [2, 0, 0, 0, 1, 0, 10, 0, 0, 0, 2, 0, 20, 0, 0, 0]);
        let (decoded, consumed) = BTreeMap::<u16, u32>::decode(&encoded).unwrap();
        assert_eq!(decoded, map);
        assert_eq!(consumed, 16);
    }

    #[test]
    fn test_empty_vec() {
        let val: Vec<u8> = vec![];
        let encoded = val.encode();
        assert_eq!(encoded, [0, 0, 0, 0]); // u32 count = 0
        let (decoded, consumed) = Vec::<u8>::decode(&encoded).unwrap();
        assert_eq!(decoded, val);
        assert_eq!(consumed, 4);
    }

    #[test]
    fn test_decode_eof() {
        assert!(u32::decode(&[1, 2]).is_err());
        assert!(u64::decode(&[]).is_err());
        assert!(bool::decode(&[]).is_err());
    }
}
