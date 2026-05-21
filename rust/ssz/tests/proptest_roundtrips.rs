//! Property-based round-trip tests for SSZ primitives and composites.

use proptest::collection::vec as pvec;
use proptest::prelude::*;
use ssz::{Bitlist, Bitvector, Decode, Encode, FixedVector, List};

fn roundtrip<T: Encode + Decode + PartialEq + core::fmt::Debug>(val: &T) {
    let bytes = val.as_ssz_bytes();
    let decoded = T::from_ssz_bytes(&bytes).expect("decode");
    assert_eq!(&decoded, val, "round-trip mismatch");
    // ssz_bytes_len matches the encoded length.
    assert_eq!(val.ssz_bytes_len(), bytes.len(), "ssz_bytes_len mismatch");
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
    fn u128_roundtrip(v: u128) { roundtrip(&v); }

    #[test]
    fn bool_roundtrip(v: bool) { roundtrip(&v); }

    #[test]
    fn array_32_roundtrip(v: [u8; 32]) { roundtrip(&v); }

    #[test]
    fn option_u64_roundtrip(v: Option<u64>) { roundtrip(&v); }

    #[test]
    fn list_u32_roundtrip(items in pvec(any::<u32>(), 0..64)) {
        let l: List<u32, 64> = List::from_slice(&items).unwrap();
        roundtrip(&l);
    }

    #[test]
    fn list_u32_hash_deterministic(items in pvec(any::<u32>(), 0..64)) {
        let l1: List<u32, 64> = List::from_slice(&items).unwrap();
        let l2: List<u32, 64> = List::from_slice(&items).unwrap();
        let h1 = ssz::hash_tree_root(&l1);
        let h2 = ssz::hash_tree_root(&l2);
        prop_assert_eq!(h1, h2);
    }

    #[test]
    fn fixed_vector_u32_roundtrip(items in pvec(any::<u32>(), 8..=8)) {
        let fv: FixedVector<u32, 8> = FixedVector::from_slice(&items).unwrap();
        roundtrip(&fv);
    }

    #[test]
    fn bitvector_32_roundtrip(bits in pvec(any::<bool>(), 32..=32)) {
        let mut bv: Bitvector<32> = Bitvector::default();
        for (i, b) in bits.iter().enumerate() {
            bv.set(i, *b);
        }
        roundtrip(&bv);
    }

    #[test]
    fn bitlist_256_roundtrip(bits in pvec(any::<bool>(), 0..256)) {
        let bl: Bitlist<256> = Bitlist::from_bits(&bits).unwrap();
        roundtrip(&bl);
    }
}

// --- Derived container tests ---

#[derive(Debug, Clone, PartialEq, Eq, ssz::Encode, ssz::Decode, ssz::HashTreeRoot)]
struct Inner {
    a: u32,
    b: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, ssz::Encode, ssz::Decode, ssz::HashTreeRoot)]
struct Outer {
    head: u16,
    inner: Inner,
    tail: List<u32, 32>,
}

proptest! {
    #[test]
    fn derived_inner_roundtrip(a: u32, b: u64) {
        let v = Inner { a, b };
        roundtrip(&v);
    }

    #[test]
    fn derived_outer_roundtrip(
        head: u16,
        a: u32,
        b: u64,
        tail in pvec(any::<u32>(), 0..32),
    ) {
        let v = Outer {
            head,
            inner: Inner { a, b },
            tail: List::from_slice(&tail).unwrap(),
        };
        roundtrip(&v);
    }

    #[test]
    fn derived_outer_hash_deterministic(
        head: u16,
        a: u32,
        b: u64,
        tail in pvec(any::<u32>(), 0..32),
    ) {
        let v = Outer {
            head,
            inner: Inner { a, b },
            tail: List::from_slice(&tail).unwrap(),
        };
        let h1 = ssz::hash_tree_root(&v);
        let h2 = ssz::hash_tree_root(&v);
        prop_assert_eq!(h1, h2);
    }
}

// --- Newtype transparent ---

#[derive(Debug, Clone, PartialEq, Eq, ssz::Encode, ssz::Decode, ssz::HashTreeRoot)]
struct SlotIdx(#[ssz(transparent)] u32);

#[test]
fn slot_idx_is_transparent_on_wire() {
    let sl = SlotIdx(0xDEAD_BEEF);
    let b1 = sl.as_ssz_bytes();
    let b2 = 0xDEAD_BEEFu32.as_ssz_bytes();
    assert_eq!(b1, b2);
    let h1 = ssz::hash_tree_root(&sl);
    let h2 = ssz::hash_tree_root(&0xDEAD_BEEFu32);
    assert_eq!(h1, h2);
}

// --- Union (derived enum) ---

#[derive(Debug, Clone, PartialEq, Eq, ssz::Encode, ssz::Decode, ssz::HashTreeRoot)]
enum Color {
    #[ssz(selector = 0)]
    Red(u32),
    #[ssz(selector = 1)]
    Blue(u64),
}

proptest! {
    #[test]
    fn color_red_roundtrip(v: u32) {
        roundtrip(&Color::Red(v));
    }

    #[test]
    fn color_blue_roundtrip(v: u64) {
        roundtrip(&Color::Blue(v));
    }
}
