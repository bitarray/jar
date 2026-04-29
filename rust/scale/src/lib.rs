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

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

use alloc::vec::Vec;

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

impl<T: Encode> Encode for [T] {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        (self.len() as u32).encode_to(buf);
        for item in self {
            item.encode_to(buf);
        }
    }
}

impl<T: Encode> Encode for Vec<T> {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        self.as_slice().encode_to(buf);
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

impl<T: Encode + Ord> Encode for alloc::collections::BTreeSet<T> {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        (self.len() as u32).encode_to(buf);
        for item in self {
            item.encode_to(buf);
        }
    }
}

impl<T: Decode + Ord> Decode for alloc::collections::BTreeSet<T> {
    fn decode(data: &[u8]) -> Result<(Self, usize), DecodeError> {
        let (count, mut off) = u32::decode(data)?;
        let count = count as usize;
        if count > data.len() {
            return Err(DecodeError::SequenceTooLong {
                count: count as u32,
                remaining: data.len() as u32,
            });
        }
        let mut set = alloc::collections::BTreeSet::new();
        for _ in 0..count {
            let (item, c) = T::decode(&data[off..])?;
            off += c;
            // Enforce strictly ascending order (Encode always produces sorted)
            if let Some(last) = set.iter().next_back()
                && &item <= last
            {
                return Err(DecodeError::NotSorted);
            }
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

impl<K: Encode + Ord, V: Encode> Encode for alloc::collections::BTreeMap<K, V> {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        (self.len() as u32).encode_to(buf);
        for (k, v) in self {
            k.encode_to(buf);
            v.encode_to(buf);
        }
    }
}

impl<K: Decode + Ord, V: Decode> Decode for alloc::collections::BTreeMap<K, V> {
    fn decode(data: &[u8]) -> Result<(Self, usize), DecodeError> {
        let (count, mut off) = u32::decode(data)?;
        let count = count as usize;
        if count > data.len() {
            return Err(DecodeError::SequenceTooLong {
                count: count as u32,
                remaining: data.len() as u32,
            });
        }
        let mut map = alloc::collections::BTreeMap::new();
        for _ in 0..count {
            let (k, c) = K::decode(&data[off..])?;
            off += c;
            // Enforce strictly ascending key order (Encode always produces sorted)
            if let Some(last_key) = map.keys().next_back()
                && &k <= last_key
            {
                return Err(DecodeError::NotSorted);
            }
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
        use alloc::collections::BTreeMap;
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

    #[test]
    fn test_bool_invalid_discriminator() {
        assert!(matches!(
            bool::decode(&[2]),
            Err(DecodeError::InvalidDiscriminator(2))
        ));
        assert!(matches!(
            bool::decode(&[0xFF]),
            Err(DecodeError::InvalidDiscriminator(0xFF))
        ));
    }

    #[test]
    fn test_option_invalid_discriminator() {
        assert!(matches!(
            Option::<u32>::decode(&[2]),
            Err(DecodeError::InvalidDiscriminator(2))
        ));
        assert!(matches!(
            Option::<u8>::decode(&[0xFF]),
            Err(DecodeError::InvalidDiscriminator(0xFF))
        ));
    }

    #[test]
    fn test_option_some_truncated_payload() {
        // discriminator = 1 (Some) but no payload bytes for u32
        assert!(Option::<u32>::decode(&[1]).is_err());
        assert!(Option::<u32>::decode(&[1, 0, 0]).is_err());
    }

    #[test]
    fn test_vec_count_exceeds_data() {
        // count = 1000 but only 4 bytes for count prefix, no element data
        let mut data = Vec::new();
        1000u32.encode_to(&mut data);
        assert!(matches!(
            Vec::<u32>::decode(&data),
            Err(DecodeError::SequenceTooLong { count: 1000, .. })
        ));
    }

    #[test]
    fn test_vec_count_ok_but_elements_truncated() {
        // count = 2 but only 1 u32 element follows
        let mut data = Vec::new();
        2u32.encode_to(&mut data);
        42u32.encode_to(&mut data);
        // Only 1 element of 2 present — should fail during decode of second element
        assert!(Vec::<u32>::decode(&data).is_err());
    }

    #[test]
    fn test_btreemap_duplicate_keys_rejected() {
        // Manually encode with duplicate keys — decoder enforces strict ordering
        let mut data = Vec::new();
        2u32.encode_to(&mut data); // count = 2
        1u16.encode_to(&mut data); // key = 1
        10u32.encode_to(&mut data); // value = 10
        1u16.encode_to(&mut data); // key = 1 (duplicate)
        20u32.encode_to(&mut data); // value = 20
        assert!(matches!(
            alloc::collections::BTreeMap::<u16, u32>::decode(&data),
            Err(DecodeError::NotSorted)
        ));
    }

    #[test]
    fn test_btreemap_out_of_order_rejected() {
        // Keys not in ascending order
        let mut data = Vec::new();
        2u32.encode_to(&mut data); // count = 2
        5u16.encode_to(&mut data); // key = 5
        10u32.encode_to(&mut data);
        3u16.encode_to(&mut data); // key = 3 (less than 5)
        20u32.encode_to(&mut data);
        assert!(matches!(
            alloc::collections::BTreeMap::<u16, u32>::decode(&data),
            Err(DecodeError::NotSorted)
        ));
    }

    #[test]
    fn test_fixed_array_too_short() {
        assert!(<[u8; 32]>::decode(&[0; 31]).is_err());
        assert!(<[u8; 4]>::decode(&[1, 2, 3]).is_err());
        assert!(<[u8; 1]>::decode(&[]).is_err());
    }

    #[test]
    fn test_decode_consumes_exact_bytes() {
        // Verify decode stops at the right position with trailing data
        let mut data = Vec::new();
        42u32.encode_to(&mut data);
        data.push(0xFF); // trailing garbage
        let (val, consumed) = u32::decode(&data).unwrap();
        assert_eq!(val, 42);
        assert_eq!(consumed, 4);
    }

    #[test]
    fn test_nested_vec_option_truncated() {
        // Vec<Option<u32>> with count=1, discriminator=1 (Some), but truncated u32
        let data = [1, 0, 0, 0, 1, 0, 0]; // count=1, Some, then only 2 bytes of u32
        assert!(Vec::<Option<u32>>::decode(&data).is_err());
    }

    #[test]
    fn test_u16_exact_boundary() {
        let (val, consumed) = u16::decode(&[0xFF, 0xFF]).unwrap();
        assert_eq!(val, u16::MAX);
        assert_eq!(consumed, 2);

        let (val, _) = u16::decode(&[0, 0]).unwrap();
        assert_eq!(val, 0);
    }

    #[test]
    fn test_u64_max_roundtrip() {
        let val = u64::MAX;
        let encoded = val.encode();
        assert_eq!(encoded, [0xFF; 8]);
        let (decoded, _) = u64::decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }
}

#[cfg(test)]
mod proptest_roundtrips {
    use super::*;
    use alloc::collections::BTreeMap;
    use proptest::prelude::*;

    /// Helper: encode then decode, verify roundtrip.
    fn roundtrip<T: Encode + Decode + PartialEq + core::fmt::Debug>(val: &T) {
        let encoded = val.encode();
        let (decoded, consumed) = T::decode(&encoded).expect("decode should succeed");
        assert_eq!(&decoded, val, "roundtrip mismatch");
        assert_eq!(consumed, encoded.len(), "should consume all bytes");
    }

    proptest! {
        #[test]
        fn u8_roundtrip(v: u8) { roundtrip(&v); }

        #[test]
        fn u16_roundtrip(v: u16) { roundtrip(&v); }

        #[test]
        fn u32_roundtrip(v: u32) { roundtrip(&v); }

        #[test]
        fn u64_roundtrip(v: u64) { roundtrip(&v); }

        #[test]
        fn bool_roundtrip(v: bool) { roundtrip(&v); }

        #[test]
        fn vec_u8_roundtrip(v: Vec<u8>) { roundtrip(&v); }

        #[test]
        fn vec_u32_roundtrip(v: Vec<u32>) { roundtrip(&v); }

        #[test]
        fn option_u64_roundtrip(v: Option<u64>) { roundtrip(&v); }

        #[test]
        fn tuple_u16_u32_roundtrip(a: u16, b: u32) { roundtrip(&(a, b)); }

        #[test]
        fn fixed_array_32_roundtrip(v: [u8; 32]) { roundtrip(&v); }

        #[test]
        fn btreemap_u16_u32_roundtrip(
            entries in proptest::collection::vec((any::<u16>(), any::<u32>()), 0..20)
        ) {
            let map: BTreeMap<u16, u32> = entries.into_iter().collect();
            roundtrip(&map);
        }

        #[test]
        fn nested_vec_option_roundtrip(v: Vec<Option<u32>>) { roundtrip(&v); }

        #[test]
        fn btreeset_u32_roundtrip(
            entries in proptest::collection::vec(any::<u32>(), 0..20)
        ) {
            let set: alloc::collections::BTreeSet<u32> = entries.into_iter().collect();
            roundtrip(&set);
        }

        #[test]
        fn nested_vec_vec_u8_roundtrip(
            vecs in proptest::collection::vec(
                proptest::collection::vec(any::<u8>(), 0..32),
                0..10,
            )
        ) {
            roundtrip(&vecs);
        }

        #[test]
        fn option_vec_u8_roundtrip(v: Option<Vec<u8>>) { roundtrip(&v); }

        #[test]
        fn fixed_array_64_roundtrip(v: [u8; 64]) { roundtrip(&v); }

        #[test]
        fn fixed_array_96_roundtrip(v in proptest::collection::vec(any::<u8>(), 96..=96)) {
            let mut arr = [0u8; 96];
            arr.copy_from_slice(&v);
            roundtrip(&arr);
        }

        #[test]
        fn fixed_array_144_roundtrip(v in proptest::collection::vec(any::<u8>(), 144..=144)) {
            let mut arr = [0u8; 144];
            arr.copy_from_slice(&v);
            roundtrip(&arr);
        }

        #[test]
        fn encode_deterministic_u32(v: u32) {
            assert_eq!(v.encode(), v.encode(), "encoding should be deterministic");
        }

        #[test]
        fn encode_deterministic_vec_u8(v: Vec<u8>) {
            assert_eq!(v.encode(), v.encode(), "encoding should be deterministic");
        }

        #[test]
        fn decode_no_panic_u32(bytes in proptest::collection::vec(any::<u8>(), 0..16)) {
            let _ = u32::decode(&bytes);
        }

        #[test]
        fn decode_no_panic_vec_u8(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = Vec::<u8>::decode(&bytes);
        }

        #[test]
        fn decode_no_panic_option_u64(bytes in proptest::collection::vec(any::<u8>(), 0..16)) {
            let _ = Option::<u64>::decode(&bytes);
        }
    }
}
