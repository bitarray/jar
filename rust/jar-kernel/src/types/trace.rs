//! Sidecar trace types: result_trace, reach_trace, merkle_traces.
//!
//! AttestationEntry has moved to `cap/capability.rs` since it's tied to
//! the AttestationCap-as-proof model. This file holds the remaining
//! kernel-managed sidecar shapes.

use super::VaultId;

/// One canonical computation output. Preserved during the event-
/// redesign migration; future cleanup may collapse into the
/// AttestationEntry shape via IDENTITY_KEY.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct ResultEntry {
    pub blob: Vec<u8>,
}

/// Reach: which Vaults were initialized during one top-level invocation.
/// Strict-equality checked in verifier mode.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct ReachEntry {
    pub entrypoint: VaultId,
    pub event_idx: u32,
    pub vaults: Vec<VaultId>,
}

/// One merkle inclusion proof, opaque to the kernel.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct MerkleProof {
    pub vault: VaultId,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    /// Opaque proof bytes — hardware-defined.
    pub proof: Vec<u8>,
}
