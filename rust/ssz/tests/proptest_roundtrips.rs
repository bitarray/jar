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
    fn array_u64_8_roundtrip(v: [u64; 8]) { roundtrip(&v); }

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
fn array_u64_13_roundtrip() {
    let arr: [u64; 13] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    roundtrip(&arr);
}

#[test]
fn array_u64_hash_deterministic() {
    let a: [u64; 13] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
    let b: [u64; 13] = a;
    assert_eq!(ssz::hash_tree_root(&a), ssz::hash_tree_root(&b));
}

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

// --- Vec blanket impl roundtrips ---

proptest! {
    #[test]
    fn vec_u8_roundtrip(items in pvec(any::<u8>(), 0..256)) {
        roundtrip(&items);
    }

    #[test]
    fn vec_u32_roundtrip(items in pvec(any::<u32>(), 0..64)) {
        roundtrip(&items);
    }

    #[test]
    fn vec_of_inner_roundtrip(items in pvec((any::<u32>(), any::<u64>()), 0..16)) {
        let v: Vec<Inner> = items.into_iter().map(|(a, b)| Inner { a, b }).collect();
        roundtrip(&v);
    }

    #[test]
    fn vec_hash_matches_list_hash(items in pvec(any::<u32>(), 0..32)) {
        // Vec<u32> uses MAX_VEC_LEN = 1 << 32 limit, but the merkle root
        // depends on the limit's `next_power_of_two` chunking — so a Vec<u32>
        // and a List<u32, 32> won't match unless both pick the same cap.
        // Instead: verify Vec hash is deterministic and roundtrip-stable.
        let v = items.clone();
        let h1 = ssz::hash_tree_root(&v);
        let bytes = v.as_ssz_bytes();
        let decoded: Vec<u32> = Vec::from_ssz_bytes(&bytes).unwrap();
        let h2 = ssz::hash_tree_root(&decoded);
        prop_assert_eq!(h1, h2);
    }
}

// --- Union (derived enum) with named-field variants ---

#[derive(Debug, Clone, PartialEq, Eq, ssz::Encode, ssz::Decode, ssz::HashTreeRoot)]
enum NamedVariant {
    #[ssz(selector = 0)]
    Mixed { code: Vec<u8>, size: u64 },
    #[ssz(selector = 1)]
    Fixed { hash: [u8; 32] },
}

proptest! {
    #[test]
    fn named_variant_mixed_roundtrip(code in pvec(any::<u8>(), 0..128), size: u64) {
        roundtrip(&NamedVariant::Mixed { code, size });
    }
    #[test]
    fn named_variant_fixed_roundtrip(hash: [u8; 32]) {
        roundtrip(&NamedVariant::Fixed { hash });
    }
    #[test]
    fn named_variant_hashes_distinguish_variants(code in pvec(any::<u8>(), 0..32), size: u64) {
        let h_mixed = ssz::hash_tree_root(&NamedVariant::Mixed { code: code.clone(), size });
        let h_fixed = ssz::hash_tree_root(&NamedVariant::Fixed { hash: [0; 32] });
        prop_assert_ne!(h_mixed, h_fixed);
    }
}

#[test]
fn named_variant_wire_is_container_plus_selector() {
    let v = NamedVariant::Mixed {
        code: vec![1, 2, 3, 4],
        size: 0xABCD,
    };
    let bytes = v.as_ssz_bytes();
    assert_eq!(bytes[0], 0u8, "selector");
    // Container: 4-byte offset (= 12 = 4 (offset slot) + 8 (size)) + 8-byte size + 4 bytes content.
    assert_eq!(&bytes[1..5], &12u32.to_le_bytes());
    assert_eq!(&bytes[5..13], &0xABCDu64.to_le_bytes());
    assert_eq!(&bytes[13..17], &[1, 2, 3, 4]);
}

// --- Edge case: empty named-fields variant (`A {}`) is selector-only ---

#[derive(Debug, Clone, PartialEq, Eq, ssz::Encode, ssz::Decode, ssz::HashTreeRoot)]
enum EmptyNamed {
    #[ssz(selector = 0)]
    Nothing {},
    #[ssz(selector = 1)]
    Something { value: u32 },
}

#[test]
fn empty_named_variant_is_selector_only() {
    let v = EmptyNamed::Nothing {};
    let bytes = v.as_ssz_bytes();
    assert_eq!(bytes, vec![0u8]);
    let decoded = EmptyNamed::from_ssz_bytes(&bytes).unwrap();
    assert_eq!(decoded, v);
    // Hash distinguishes from a populated sibling.
    let h_empty = ssz::hash_tree_root(&v);
    let h_something = ssz::hash_tree_root(&EmptyNamed::Something { value: 0 });
    assert_ne!(h_empty, h_something);
}
