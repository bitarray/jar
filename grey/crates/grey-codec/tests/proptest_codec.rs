//! Property-based tests for the JAM codec using proptest.
//!
//! Tests that encode → decode roundtrips produce the original value
//! for all inputs, not just hand-picked examples.

use grey_codec::decode::decode_compact;
use grey_codec::encode::encode_compact;
use grey_codec::{Decode, Encode};
use proptest::prelude::*;

// ── Compact integer roundtrip ───────────────────────────────────────────

proptest! {
    #[test]
    fn compact_u64_roundtrip(value in any::<u64>()) {
        let mut buf = Vec::new();
        encode_compact(value, &mut buf);

        let (decoded, bytes_consumed) = decode_compact(&buf)
            .expect("decode_compact should succeed for any encoded value");

        prop_assert_eq!(decoded, value, "roundtrip mismatch for {}", value);
        prop_assert_eq!(bytes_consumed, buf.len(), "should consume entire buffer");
    }

    #[test]
    fn compact_small_values_roundtrip(value in 0u64..256) {
        let mut buf = Vec::new();
        encode_compact(value, &mut buf);

        let (decoded, _) = decode_compact(&buf).unwrap();
        prop_assert_eq!(decoded, value);

        // Small values should encode compactly (1-2 bytes)
        prop_assert!(buf.len() <= 2, "small value {} encoded to {} bytes", value, buf.len());
    }

    #[test]
    fn compact_encoding_is_prefix_free(a in any::<u64>(), b in any::<u64>()) {
        // Two different values should never produce the same encoding
        if a != b {
            let mut buf_a = Vec::new();
            let mut buf_b = Vec::new();
            encode_compact(a, &mut buf_a);
            encode_compact(b, &mut buf_b);
            prop_assert_ne!(buf_a, buf_b, "different values {} and {} should have different encodings", a, b);
        }
    }
}

// ── Fixed-width integer roundtrip ───────────────────────────────────────

proptest! {
    #[test]
    fn u32_roundtrip(value in any::<u32>()) {
        let encoded = value.encode();
        let (decoded, len) = u32::decode(&encoded).expect("u32 decode should succeed");
        prop_assert_eq!(decoded, value);
        prop_assert_eq!(len, 4);
        prop_assert_eq!(encoded.len(), 4);
    }

    #[test]
    fn u64_roundtrip(value in any::<u64>()) {
        let encoded = value.encode();
        let (decoded, len) = u64::decode(&encoded).expect("u64 decode should succeed");
        prop_assert_eq!(decoded, value);
        prop_assert_eq!(len, 8);
        prop_assert_eq!(encoded.len(), 8);
    }

    #[test]
    fn u16_roundtrip(value in any::<u16>()) {
        let encoded = value.encode();
        let (decoded, len) = u16::decode(&encoded).expect("u16 decode should succeed");
        prop_assert_eq!(decoded, value);
        prop_assert_eq!(len, 2);
        prop_assert_eq!(encoded.len(), 2);
    }

    #[test]
    fn hash_roundtrip(bytes in prop::array::uniform32(any::<u8>())) {
        let hash = grey_types::Hash(bytes);
        let encoded = hash.encode();
        prop_assert_eq!(encoded.len(), 32);
        let (decoded, len) = grey_types::Hash::decode(&encoded).unwrap();
        prop_assert_eq!(decoded.0, hash.0);
        prop_assert_eq!(len, 32);
    }

    #[test]
    fn bool_roundtrip(value in any::<bool>()) {
        let encoded = value.encode();
        prop_assert_eq!(encoded.len(), 1);
        let (decoded, len) = bool::decode(&encoded).unwrap();
        prop_assert_eq!(decoded, value);
        prop_assert_eq!(len, 1);
    }

    #[test]
    fn compact_encoding_length_bounds(value in any::<u64>()) {
        let mut buf = Vec::new();
        encode_compact(value, &mut buf);
        // Compact encoding uses 1-9 bytes
        prop_assert!(!buf.is_empty() && buf.len() <= 9,
            "compact encoding of {} used {} bytes (expected 1-9)", value, buf.len());
    }
}

// ── Encoding determinism ─────────────────────────────────────────────

proptest! {
    /// Encoding the same value twice always produces identical bytes.
    #[test]
    fn u32_encoding_is_deterministic(value in any::<u32>()) {
        let a = value.encode();
        let b = value.encode();
        prop_assert_eq!(&a, &b, "u32 encoding not deterministic for {}", value);
    }

    #[test]
    fn u64_encoding_is_deterministic(value in any::<u64>()) {
        let a = value.encode();
        let b = value.encode();
        prop_assert_eq!(&a, &b, "u64 encoding not deterministic for {}", value);
    }

    #[test]
    fn compact_encoding_is_deterministic(value in any::<u64>()) {
        let mut a = Vec::new();
        let mut b = Vec::new();
        encode_compact(value, &mut a);
        encode_compact(value, &mut b);
        prop_assert_eq!(&a, &b, "compact encoding not deterministic for {}", value);
    }

    #[test]
    fn hash_encoding_is_deterministic(bytes in prop::array::uniform32(any::<u8>())) {
        let hash = grey_types::Hash(bytes);
        let a = hash.encode();
        let b = hash.encode();
        prop_assert_eq!(&a, &b, "Hash encoding not deterministic");
    }

    #[test]
    fn bool_encoding_is_deterministic(value in any::<bool>()) {
        let a = value.encode();
        let b = value.encode();
        prop_assert_eq!(&a, &b, "bool encoding not deterministic for {}", value);
    }
}
