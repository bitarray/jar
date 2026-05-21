//! Equivalence between `List<T, N>` and `SparseList<T, N>` for the same
//! effective contents, plus the sparse-fill invariant.
//!
//! `SparseList<T, N>` treats each element T as a composite (one 32-byte
//! chunk per leaf, via `T::hash_tree_root`). To exercise equivalence we
//! use a small composite container — basic types would chunk-pack
//! differently in the corresponding `List<T, N>` form.

use proptest::collection::vec as pvec;
use proptest::prelude::*;
use ssz::{List, MissingOr, SparseList};

const CAP: u64 = 1024;

#[derive(Debug, Clone, PartialEq, Eq, ssz::Encode, ssz::Decode, ssz::HashTreeRoot)]
struct Leaf {
    a: u32,
    b: u32,
}

proptest! {
    #[test]
    fn fully_materialized_sparse_matches_list(
        items in pvec((any::<u32>(), any::<u32>()), 0..256usize)
    ) {
        let leaves: Vec<Leaf> = items.iter().map(|(a, b)| Leaf { a: *a, b: *b }).collect();
        let l: List<Leaf, CAP> = List::from_slice(&leaves).unwrap();
        let mut sp: SparseList<Leaf, CAP> = SparseList::new();
        for (i, v) in leaves.iter().enumerate() {
            sp.insert(i as u64, MissingOr::Materialized(v.clone())).unwrap();
        }
        sp.set_len(leaves.len() as u64).unwrap();
        let h_list = ssz::hash_tree_root(&l);
        let h_sp = ssz::hash_tree_root(&sp);
        prop_assert_eq!(h_list, h_sp);
    }

    #[test]
    fn sparse_fill_with_missing_subtree_preserves_root(
        items in pvec((any::<u32>(), any::<u32>()), 1..256usize),
        nulls in proptest::collection::vec(any::<bool>(), 1..256usize),
    ) {
        let leaves: Vec<Leaf> = items.iter().map(|(a, b)| Leaf { a: *a, b: *b }).collect();
        let mut sp: SparseList<Leaf, CAP> = SparseList::new();
        for (i, v) in leaves.iter().enumerate() {
            sp.insert(i as u64, MissingOr::Materialized(v.clone())).unwrap();
        }
        sp.set_len(leaves.len() as u64).unwrap();
        let h0 = ssz::hash_tree_root(&sp);

        // Replace selected entries with Missing(precomputed_leaf_root).
        for (i, item) in leaves.iter().enumerate() {
            let should_null = *nulls.get(i).unwrap_or(&false);
            if should_null {
                let h = <Leaf as ssz::HashTreeRoot>::hash_tree_root::<sha2::Sha256>(item);
                sp.insert(i as u64, MissingOr::Missing(h)).unwrap();
            }
        }
        let h1 = ssz::hash_tree_root(&sp);
        prop_assert_eq!(h0, h1);
    }
}
