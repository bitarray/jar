//! Block / Body shapes.
//!
//! There is no Header struct: chain authors carry "header" semantics
//! (slot, author, seal) inside event[0] of body.events, and "finalization"
//! semantics (state-root commitment) inside event[-1]. Block at the kernel
//! level is just `{ parent, body }`.

use crate::{AttestationEntry, BlockHash, Event, MerkleProof, ReachEntry, ResultEntry, VaultId};

/// Block body. Carries on-chain events grouped per Transact entrypoint plus
/// all sidecar traces.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct Body {
    /// Per-Transact-target event lists. Each entry is
    /// `(target_vault_id, Vec<Event>)`. The kernel walks
    /// `σ.transact_space_cnode` in slot order; for each `Transact` slot, it
    /// consumes the matching entry here. Body well-formedness:
    /// - VaultIds appear in the same relative order as the Transact slots
    ///   in `σ.transact_space_cnode`.
    /// - No entry's VaultId may correspond to a Schedule slot (those run
    ///   kernel-fired with no body input).
    /// - No trailing unmatched entries.
    pub events: Vec<(VaultId, Vec<Event>)>,
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
