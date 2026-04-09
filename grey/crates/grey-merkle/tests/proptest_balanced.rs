//! Property-based tests for balanced and constant-depth Merkle roots.

use grey_merkle::{balanced_merkle_root, constant_depth_merkle_root};
use grey_types::Hash;
use proptest::prelude::*;

/// Generate a random leaf (1-64 bytes).
fn arb_leaf() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..=64)
}

/// Generate a list of leaves (0-16 items).
fn arb_leaves(max_len: usize) -> impl Strategy<Value = Vec<Vec<u8>>> {
    prop::collection::vec(arb_leaf(), 0..=max_len)
}

proptest! {
    #[test]
    fn balanced_deterministic(leaves in arb_leaves(8)) {
        let refs: Vec<&[u8]> = leaves.iter().map(|l| l.as_slice()).collect();
        let root1 = balanced_merkle_root(&refs, grey_crypto::blake2b_256);
        let root2 = balanced_merkle_root(&refs, grey_crypto::blake2b_256);
        prop_assert_eq!(root1, root2);
    }

    #[test]
    fn balanced_empty_is_zero(dummy in 0u8..1) {
        let _ = dummy;
        let root = balanced_merkle_root(&[], grey_crypto::blake2b_256);
        prop_assert_eq!(root, Hash::ZERO);
    }

    #[test]
    fn balanced_single_is_hash(leaf in arb_leaf()) {
        let root = balanced_merkle_root(&[&leaf], grey_crypto::blake2b_256);
        let expected = grey_crypto::blake2b_256(&leaf);
        prop_assert_eq!(root, expected);
    }

    #[test]
    fn balanced_adding_leaf_changes_root(leaves in arb_leaves(4)) {
        prop_assume!(!leaves.is_empty());
        let refs: Vec<&[u8]> = leaves.iter().map(|l| l.as_slice()).collect();
        let full_root = balanced_merkle_root(&refs, grey_crypto::blake2b_256);
        let partial_root = balanced_merkle_root(&refs[..refs.len() - 1], grey_crypto::blake2b_256);
        prop_assert_ne!(full_root, partial_root);
    }

    #[test]
    fn balanced_different_hash_fn_different_root(leaves in arb_leaves(4)) {
        prop_assume!(!leaves.is_empty());
        let refs: Vec<&[u8]> = leaves.iter().map(|l| l.as_slice()).collect();
        let blake_root = balanced_merkle_root(&refs, grey_crypto::blake2b_256);
        let keccak_root = balanced_merkle_root(&refs, grey_crypto::keccak_256);
        prop_assert_ne!(blake_root, keccak_root);
    }

    #[test]
    fn constant_depth_deterministic(leaves in arb_leaves(8)) {
        let refs: Vec<&[u8]> = leaves.iter().map(|l| l.as_slice()).collect();
        let root1 = constant_depth_merkle_root(&refs, grey_crypto::blake2b_256);
        let root2 = constant_depth_merkle_root(&refs, grey_crypto::blake2b_256);
        prop_assert_eq!(root1, root2);
    }

    #[test]
    fn constant_depth_empty_is_zero(dummy in 0u8..1) {
        let _ = dummy;
        let root = constant_depth_merkle_root(&[], grey_crypto::blake2b_256);
        prop_assert_eq!(root, Hash::ZERO);
    }

    #[test]
    fn constant_depth_adding_leaf_changes_root(leaves in arb_leaves(4)) {
        prop_assume!(!leaves.is_empty());
        let refs: Vec<&[u8]> = leaves.iter().map(|l| l.as_slice()).collect();
        let full_root = constant_depth_merkle_root(&refs, grey_crypto::blake2b_256);
        let partial_root = constant_depth_merkle_root(&refs[..refs.len() - 1], grey_crypto::blake2b_256);
        prop_assert_ne!(full_root, partial_root);
    }

    #[test]
    fn constant_depth_different_values_different_roots(
        a in arb_leaf(),
        b in arb_leaf(),
    ) {
        prop_assume!(a != b);
        let root_a = constant_depth_merkle_root(&[&a], grey_crypto::blake2b_256);
        let root_b = constant_depth_merkle_root(&[&b], grey_crypto::blake2b_256);
        prop_assert_ne!(root_a, root_b);
    }
}
