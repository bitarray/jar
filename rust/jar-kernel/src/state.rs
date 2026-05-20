//! σ — the v3 chain state.
//!
//! Stage C.2 (this commit) lands a cache-driven state shape: σ is a
//! `Cache<Global>` plus the validator set. Data blobs, image blobs,
//! cnode blobs, and chain Instance blobs all live in the cache as
//! `Cap` values, addressed by content hash.
//!
//! The previous Stage C.2 design carried separate registries
//! (`data_blobs`, `data_payloads`, `code_blobs`, `vaults`, etc.) and a
//! SCALE-derived state root. Commit 3 of the cap-type consolidation
//! moves all of those into the cache; their consumers now look up
//! `state.caps.get(CapHashOrRef::Hash(h))` directly.

use javm_cap::bmt::Bmt;
use javm_cap::{Blake2b256, Cache, CapHash, Hash, cap_hash};

/// PoA validator key (placeholder — 32-byte public key).
pub type ValidatorKey = [u8; 32];

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

/// State-root: BMT over the cache's blobs.
///
/// Each leaf is `blake2b256(blob_hash || cap_hash(cap))` so divergence
/// in either the storage key or the cap content surfaces in the root.
/// Leaves are produced in sorted `CapHash` order (BTreeMap iteration
/// order is sort-stable) so the result is independent of insertion
/// order.
///
/// Empty caches reduce to `Blake2b256::hash(&[])` via the BMT's
/// canonical empty-marker convention.
pub fn state_root(state: &State) -> CapHash {
    let leaves: Vec<[u8; 32]> = state
        .caps
        .iter_blobs()
        .map(|(hash, cap)| {
            let c = cap_hash(cap);
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(hash);
            buf[32..].copy_from_slice(&c);
            Blake2b256::hash(&buf)
        })
        .collect();
    Bmt::root::<Blake2b256>(&leaves)
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
        s.caps.publish_data_inline(b"hello").unwrap();
        let r1 = state_root(&s);
        assert_ne!(r0, r1);
    }
}
