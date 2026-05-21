//! Cross-check our `hash_tree_root` against the upstream `tree_hash`
//! crate for spec-canonical types.
//!
//! Gated behind the `ethereum-conformance` Cargo feature so we don't pull
//! the upstream test deps into normal builds.
//!
//! Note: we deliberately do *not* cross-check against `ethereum_ssz`'s
//! byte-level `as_ssz_bytes` here because that crate's `lib.name = "ssz"`
//! collides with this crate's name, which breaks Cargo's `--extern ssz=…`
//! resolution. The intent — verifying our wire format matches the spec —
//! is covered by hash equivalence (the hash includes the encoded bytes
//! transitively) plus our own round-trip tests in
//! `proptest_roundtrips.rs`. A future commit may split the byte-level
//! cross-check into its own crate to dodge the name collision.

#![cfg(feature = "ethereum-conformance")]

use proptest::prelude::*;

fn assert_hash_equal<T1, T2>(a: &T1, b: &T2)
where
    T1: ssz::HashTreeRoot,
    T2: tree_hash::TreeHash,
{
    let ours = ssz::hash_tree_root(a);
    let theirs = b.tree_hash_root();
    assert_eq!(ours, theirs.0, "tree hash root diverges");
}

proptest! {
    #[test]
    fn u8_matches(v: u8) { assert_hash_equal(&v, &v); }

    #[test]
    fn u16_matches(v: u16) { assert_hash_equal(&v, &v); }

    #[test]
    fn u32_matches(v: u32) { assert_hash_equal(&v, &v); }

    #[test]
    fn u64_matches(v: u64) { assert_hash_equal(&v, &v); }

    #[test]
    fn bool_matches(v: bool) { assert_hash_equal(&v, &v); }
}

// A simple container: our derive vs upstream `TreeHash` derive. We use
// `tree_hash::Hash256` (an ethereum_types::H256 newtype) instead of a raw
// `[u8; N]` because `tree_hash 0.6` only impls `TreeHash` for hand-picked
// fixed-array sizes through their type alias.
#[derive(Debug, Clone, PartialEq, Eq, ssz::Encode, ssz::Decode, ssz::HashTreeRoot)]
struct OurContainer {
    a: u64,
    b: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, tree_hash_derive::TreeHash)]
struct TheirContainer {
    a: u64,
    b: u32,
}

proptest! {
    #[test]
    fn container_matches(a: u64, b: u32) {
        let ours = OurContainer { a, b };
        let theirs = TheirContainer { a, b };
        let our_root = ssz::hash_tree_root(&ours);
        let their_root = tree_hash::TreeHash::tree_hash_root(&theirs);
        prop_assert_eq!(our_root, their_root.0);
    }
}
