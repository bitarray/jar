//! Block / Body shapes.
//!
//! There is no Header struct: chain authors carry "header" semantics
//! (slot, author, seal) inside event[0] of body.events, and "finalization"
//! semantics (state-root commitment) inside event[-1]. Block at the kernel
//! level is just `{ parent, body }`.
//!
//! Manual trait impls so bounds land on `C::Hash` etc., not `C`.

use crate::{
    AttestationEntry, BlockHash, Crypto, Event, MerkleProof, ReachEntry, ResultEntry, VaultId,
};

/// Block body. Carries on-chain events grouped per Transact entrypoint plus
/// all sidecar traces.
pub struct Body<C: Crypto> {
    /// Per-Transact-target event lists. Each entry is
    /// `(target_vault_id, Vec<Event>)`. The kernel walks
    /// `σ.transact_space_cnode` in slot order; for each `Transact` slot, it
    /// consumes the matching entry here. Body well-formedness:
    /// - VaultIds appear in the same relative order as the Transact slots
    ///   in `σ.transact_space_cnode`.
    /// - No entry's VaultId may correspond to a Schedule slot (those run
    ///   kernel-fired with no body input).
    /// - No trailing unmatched entries.
    pub events: Vec<(VaultId, Vec<Event<C>>)>,
    pub attestation_trace: Vec<AttestationEntry<C>>,
    pub result_trace: Vec<ResultEntry>,
    pub reach_trace: Vec<ReachEntry>,
    pub merkle_traces: Vec<MerkleProof<C>>,
}

impl<C: Crypto> Clone for Body<C> {
    fn clone(&self) -> Self {
        Self {
            events: self.events.clone(),
            attestation_trace: self.attestation_trace.clone(),
            result_trace: self.result_trace.clone(),
            reach_trace: self.reach_trace.clone(),
            merkle_traces: self.merkle_traces.clone(),
        }
    }
}

impl<C: Crypto> PartialEq for Body<C> {
    fn eq(&self, other: &Self) -> bool {
        self.events == other.events
            && self.attestation_trace == other.attestation_trace
            && self.result_trace == other.result_trace
            && self.reach_trace == other.reach_trace
            && self.merkle_traces == other.merkle_traces
    }
}

impl<C: Crypto> Eq for Body<C> {}

impl<C: Crypto> core::fmt::Debug for Body<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Body")
            .field("events", &self.events)
            .field("attestation_trace", &self.attestation_trace)
            .field("result_trace", &self.result_trace)
            .field("reach_trace", &self.reach_trace)
            .field("merkle_traces", &self.merkle_traces)
            .finish()
    }
}

impl<C: Crypto> Default for Body<C> {
    fn default() -> Self {
        Self {
            events: Vec::new(),
            attestation_trace: Vec::new(),
            result_trace: Vec::new(),
            reach_trace: Vec::new(),
            merkle_traces: Vec::new(),
        }
    }
}

pub struct Block<C: Crypto> {
    pub parent: BlockHash<C>,
    pub body: Body<C>,
}

impl<C: Crypto> Clone for Block<C> {
    fn clone(&self) -> Self {
        Self {
            parent: self.parent,
            body: self.body.clone(),
        }
    }
}

impl<C: Crypto> PartialEq for Block<C> {
    fn eq(&self, other: &Self) -> bool {
        self.parent == other.parent && self.body == other.body
    }
}

impl<C: Crypto> Eq for Block<C> {}

impl<C: Crypto> core::fmt::Debug for Block<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Block")
            .field("parent", &self.parent)
            .field("body", &self.body)
            .finish()
    }
}

impl<C: Crypto> Default for Block<C> {
    fn default() -> Self {
        Self {
            parent: BlockHash::<C>::default(),
            body: Body::<C>::default(),
        }
    }
}
