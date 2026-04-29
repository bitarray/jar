//! Block / Body shapes.
//!
//! There is no Header struct: chain authors carry "header" semantics
//! (slot, author, seal) inside event[0] of body.events, and "finalization"
//! semantics (state-root commitment) inside event[-1]. Block at the kernel
//! level is just `{ parent, body }`.

use crate::{AttestationEntry, BlockHash, Event, MerkleProof, ReachEntry, ResultEntry, VaultId};

/// Block body. Carries on-chain events plus all sidecar traces.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct Body {
    /// Flat ordered list of (target_vault_id, event). The proposer chooses
    /// the order; conventionally `events[0]` is the chain's header-equivalent
    /// gating Vault and `events[len-1]` is the finalization-equivalent
    /// gating Vault, but the kernel doesn't single these out.
    pub events: Vec<(VaultId, Event)>,
    pub attestation_trace: Vec<AttestationEntry>,
    pub result_trace: Vec<ResultEntry>,
    pub reach_trace: Vec<ReachEntry>,
    pub merkle_traces: Vec<MerkleProof>,
}

#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct Block {
    pub parent: BlockHash,
    pub body: Body,
}
