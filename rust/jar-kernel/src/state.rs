//! σ — the v3 chain state.
//!
//! σ is a `Cache<Global>` plus the validator set. Data blobs, image
//! blobs, cnode blobs, and chain Instance blobs all live in the cache
//! as `Cap` values, addressed by content hash.
//!
//! The state root is the SSZ `hash_tree_root` of the cache's blobs,
//! each represented as a `(blob_hash, cap_hash)` leaf container.

use javm_cap::{Cache, CapHash, cap_hash};
use ssz::{Encode, HashTreeRoot};

/// PoA validator key (placeholder — 32-byte public key).
pub type ValidatorKey = [u8; 32];

/// One state-root leaf: a `(blob_hash, cap_hash)` pair.
///
/// Encoded as the SSZ container `{ blob_hash: [u8;32], cap_hash: [u8;32] }`.
/// The leaf's `hash_tree_root` is `merkleize([blob_hash, cap_hash], 2) =
/// hash(blob_hash || cap_hash)` — equivalent to the legacy BMT leaf
/// protocol but with SHA-256 instead of Blake2b.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, HashTreeRoot)]
pub struct StateLeaf {
    pub blob_hash: CapHash,
    pub cap_hash: CapHash,
}

/// The chain's σ-resident state.
///
/// All cap content lives in `caps` (a `Cache<Global>`). The validator
/// set is kept alongside as a Vec for now; future revisions may move
/// it into a dedicated registry cap.
pub struct State {
    pub caps: Cache,
    pub validators: Vec<ValidatorKey>,
}

impl State {
    pub fn new() -> Self {
        Self {
            caps: Cache::new(),
            validators: Vec::new(),
        }
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

/// State-root: SSZ `hash_tree_root` of the cache's blobs.
///
/// Each leaf is a `StateLeaf { blob_hash, cap_hash }` container. The
/// full state root is `hash_tree_root` of the `Vec<StateLeaf>`, which
/// merkleizes the per-leaf roots, pads to the next power of two, and
/// mixes in the length per SSZ `List` semantics.
///
/// Leaves are produced in sorted `CapHash` order (BTreeMap iteration
/// is sort-stable), so the result is independent of insertion order.
/// Empty caches reduce to the SSZ canonical empty-list root.
pub fn state_root(state: &State) -> CapHash {
    let leaves: Vec<StateLeaf> = state
        .caps
        .iter_blobs()
        .map(|(hash, cap)| StateLeaf {
            blob_hash: *hash,
            cap_hash: cap_hash(cap),
        })
        .collect();
    ssz::hash_tree_root(&leaves)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_state_root_is_deterministic() {
        let s1 = State::new();
        let s2 = State::new();
        assert_eq!(state_root(&s1), state_root(&s2));
    }

    #[test]
    fn state_root_changes_with_published_data() {
        let mut s = State::new();
        let r0 = state_root(&s);
        s.caps
            .put_cap(&javm_cap::Cap::data_inline(b"hello"))
            .unwrap();
        let r1 = state_root(&s);
        assert_ne!(r0, r1);
    }
}
