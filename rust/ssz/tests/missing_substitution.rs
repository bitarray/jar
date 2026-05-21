//! Substitution invariant: `MissingOr` placeholder must produce the same
//! hash tree root whether materialized or replaced by the precomputed
//! subtree root.

use proptest::prelude::*;
use ssz::MissingOr;

#[derive(Debug, Clone, PartialEq, Eq, ssz::Encode, ssz::Decode, ssz::HashTreeRoot)]
struct InnerContainer {
    a: u64,
    b: u32,
    c: [u8; 16],
}

#[derive(Debug, Clone, ssz::Encode, ssz::Decode, ssz::HashTreeRoot)]
struct Container {
    head: u32,
    field: MissingOr<InnerContainer>,
}

proptest! {
    #[test]
    fn missing_or_substitution(a: u64, b: u32, c: [u8; 16]) {
        let inner = InnerContainer { a, b, c };
        let h_inner = ssz::hash_tree_root(&inner);

        let materialized = Container {
            head: 0x1234_5678,
            field: MissingOr::Materialized(inner.clone()),
        };
        let missing = Container {
            head: 0x1234_5678,
            field: MissingOr::Missing(h_inner),
        };

        let h_m = ssz::hash_tree_root(&materialized);
        let h_g = ssz::hash_tree_root(&missing);
        prop_assert_eq!(h_m, h_g);
    }

    #[test]
    fn missing_or_substitution_root_only(a: u64, b: u32, c: [u8; 16]) {
        // The MissingOr field itself, in isolation, must satisfy
        // hash_tree_root(Materialized(t)) == hash_tree_root(Missing(t.hash_tree_root()))
        // with NO mix_in_selector.
        let inner = InnerContainer { a, b, c };
        let h_inner = ssz::hash_tree_root(&inner);
        let mat = MissingOr::Materialized(inner.clone());
        let mis: MissingOr<InnerContainer> = MissingOr::Missing(h_inner);
        prop_assert_eq!(ssz::hash_tree_root(&mat), ssz::hash_tree_root(&mis));
        prop_assert_eq!(ssz::hash_tree_root(&mis), h_inner);
    }
}
