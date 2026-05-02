//! Per-cycle pool state owned by `NodeOffchain`.
//!
//! In the event-redesign:
//!
//! - `setScore(identifier, score)` (verify-only host call) buffers the
//!   verifying event into a max-register keyed by `identifier`. Highest
//!   score wins. Two events that share an `identifier` but disagree on
//!   the blob are a collision: the colliding entries defer to the next
//!   cycle's pool. Collision-defer is the engine that makes
//!   self-emitted DA / off-chain storage chunks survive temporary
//!   contention without being lost.
//!
//! - The proposer drains the per-(endpoint, cycle) winners at cycle end
//!   to assemble Body events for the next block.
//!
//! - For dispatch-context emit_event: as events arrive at a dispatch
//!   endpoint, the kernel records the originating signer key in the
//!   per-(dispatch_endpoint, cycle) `AuthoritySeenSet`. The
//!   `AttestationAuthority` cap passed to dispatch verify is scope-
//!   restricted to that seen-set, so the chain-author can only mint
//!   attestations for signers it has actually observed in the cycle.
//!
//! Cycle boundaries align with block boundaries (one cycle == one block
//! window). At the end of a cycle, `roll_cycle` collects the winners
//! (handed to the proposer), lifts the deferred entries into the next
//! cycle's fresh pool, and resets authorities to empty.
//!
//! This module is self-contained and host-call-agnostic — Stage D wires
//! the host calls (`setScore`, `mint_attest_cap`, `emit_event`) to
//! actually populate it.

use std::collections::{BTreeMap, BTreeSet};

use crate::cap::AttestationEntry;
use crate::types::{CapId, KeyId};

/// One identifier-scoped entry in a per-endpoint pool. Carries the
/// score the verify VM assigned, the blob it verified, and any
/// attestation traces produced for the event (so the proposer can
/// re-attach them when assembling next block's body).
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct PoolEntry {
    pub identifier: Vec<u8>,
    pub score: u64,
    pub blob: Vec<u8>,
    pub attestation_traces: Vec<AttestationEntry>,
}

/// Per-(endpoint, cycle) max-register pool.
///
/// Same identifier + same blob: keep the higher-scoring witness.
/// Same identifier + different blob: collision — defer to next cycle.
#[derive(Default, Clone, Debug)]
pub struct EndpointPool {
    pub winners: BTreeMap<Vec<u8>, PoolEntry>,
    pub deferred: BTreeMap<Vec<u8>, Vec<PoolEntry>>,
}

impl EndpointPool {
    /// Insert (or merge) an entry per the max-register / collision-defer
    /// rules.
    pub fn insert(&mut self, entry: PoolEntry) {
        match self.winners.get(&entry.identifier) {
            None => {
                self.winners.insert(entry.identifier.clone(), entry);
            }
            Some(existing) if existing.blob == entry.blob => {
                if entry.score > existing.score {
                    self.winners.insert(entry.identifier.clone(), entry);
                }
            }
            Some(_) => {
                // Collision on the value: defer.
                self.deferred
                    .entry(entry.identifier.clone())
                    .or_default()
                    .push(entry);
            }
        }
    }

    /// Drain the cycle's winners. Empties the winner map.
    pub fn drain_winners(&mut self) -> Vec<PoolEntry> {
        std::mem::take(&mut self.winners).into_values().collect()
    }

    /// Drain all deferred entries (used by `roll_cycle` to lift them into
    /// the next cycle's fresh pool).
    pub fn drain_deferred(&mut self) -> Vec<PoolEntry> {
        let mut out = Vec::new();
        for (_, mut v) in std::mem::take(&mut self.deferred) {
            out.append(&mut v);
        }
        out
    }

    pub fn is_empty(&self) -> bool {
        self.winners.is_empty() && self.deferred.is_empty()
    }
}

/// Per-(dispatch endpoint, cycle) AttestationAuthority seen-key tracker.
/// Mint attempts inside dispatch verify are scope-restricted to keys
/// recorded here.
#[derive(Default, Clone, Debug)]
pub struct AuthoritySeenSet {
    pub keys: BTreeSet<KeyId>,
}

impl AuthoritySeenSet {
    pub fn record(&mut self, key: KeyId) {
        self.keys.insert(key);
    }

    pub fn allows(&self, key: &KeyId) -> bool {
        self.keys.contains(key)
    }
}

/// Aggregated per-cycle pool state. Indexed by endpoint `CapId`.
#[derive(Default, Clone, Debug)]
pub struct CyclePool {
    pub endpoints: BTreeMap<CapId, EndpointPool>,
    pub authorities: BTreeMap<CapId, AuthoritySeenSet>,
}

impl CyclePool {
    pub fn entry(&mut self, endpoint: CapId) -> &mut EndpointPool {
        self.endpoints.entry(endpoint).or_default()
    }

    pub fn authority(&mut self, dispatch_endpoint: CapId) -> &mut AuthoritySeenSet {
        self.authorities.entry(dispatch_endpoint).or_default()
    }

    /// End of cycle. Returns the per-endpoint winners (drained from the
    /// finished cycle) and lifts deferred entries into a fresh pool that
    /// becomes the next cycle's starting state. Authorities reset to
    /// empty.
    pub fn roll_cycle(&mut self) -> CycleRoll {
        let mut winners: BTreeMap<CapId, Vec<PoolEntry>> = BTreeMap::new();
        let mut next = CyclePool::default();
        for (endpoint, mut pool) in std::mem::take(&mut self.endpoints) {
            let w = pool.drain_winners();
            if !w.is_empty() {
                winners.insert(endpoint, w);
            }
            let mut next_pool = EndpointPool::default();
            for deferred in pool.drain_deferred() {
                next_pool.insert(deferred);
            }
            if !next_pool.is_empty() {
                next.endpoints.insert(endpoint, next_pool);
            }
        }
        *self = next;
        CycleRoll { winners }
    }
}

/// Output of `roll_cycle`: per-endpoint winners ready for the proposer
/// to assemble into the next block's body.
#[derive(Default, Clone, Debug)]
pub struct CycleRoll {
    pub winners: BTreeMap<CapId, Vec<PoolEntry>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &[u8], score: u64, blob: &[u8]) -> PoolEntry {
        PoolEntry {
            identifier: id.to_vec(),
            score,
            blob: blob.to_vec(),
            attestation_traces: Vec::new(),
        }
    }

    #[test]
    fn max_register_keeps_higher_score_for_same_blob() {
        let mut p = EndpointPool::default();
        p.insert(entry(b"id", 10, b"v"));
        p.insert(entry(b"id", 5, b"v"));
        p.insert(entry(b"id", 20, b"v"));
        let winners = p.drain_winners();
        assert_eq!(winners.len(), 1);
        assert_eq!(winners[0].score, 20);
        assert!(p.deferred.is_empty());
    }

    #[test]
    fn collision_defers() {
        let mut p = EndpointPool::default();
        p.insert(entry(b"id", 10, b"v1"));
        p.insert(entry(b"id", 50, b"v2"));
        let winners = p.drain_winners();
        assert_eq!(winners.len(), 1);
        assert_eq!(winners[0].blob, b"v1");
        let deferred = p.drain_deferred();
        assert_eq!(deferred.len(), 1);
        assert_eq!(deferred[0].blob, b"v2");
    }

    #[test]
    fn roll_cycle_lifts_deferred_into_next() {
        let mut pool = CyclePool::default();
        let cap = CapId(7);
        pool.entry(cap).insert(entry(b"id", 10, b"v1"));
        pool.entry(cap).insert(entry(b"id", 20, b"v2"));

        let roll = pool.roll_cycle();
        assert_eq!(roll.winners.get(&cap).map(|v| v.len()), Some(1));
        // Deferred entry should now be in next cycle's pool as a winner.
        let next_winners = pool.entry(cap).drain_winners();
        assert_eq!(next_winners.len(), 1);
        assert_eq!(next_winners[0].blob, b"v2");
    }

    #[test]
    fn authority_seen_set_records_and_checks() {
        let mut a = AuthoritySeenSet::default();
        let k1 = KeyId(b"key1".to_vec());
        let k2 = KeyId(b"key2".to_vec());
        a.record(k1.clone());
        assert!(a.allows(&k1));
        assert!(!a.allows(&k2));
    }
}
