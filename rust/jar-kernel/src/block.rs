//! Block / Body shapes plus block-level sidecar trace types.
//!
//! Per the event-redesign: `body.events` is `Vec<(target_path, blob,
//! attestation_traces)>` (not per-VaultId-grouped). `target_path`
//! resolves to an `EventEndpointCap` in `σ.transact_endpoints`.
//! Schedule slots have no `body.events` entries; their attestations
//! live in `body.schedule_attestation_traces`.
//!
//! Sidecar shapes (`ResultEntry`, `ReachEntry`, `MerkleProof`) live
//! here too — they're all body-level traces consumed alongside
//! `attestation_trace` during apply.

use crate::cap::AttestationEntry;
use crate::types::{BlockHash, VaultId};

// =============================================================================
// Block / Body
// =============================================================================

/// One body event entry. Carries:
/// - `target_path`: path-encoded reference resolving to an
///   `EventEndpointCap` in `σ.transact_endpoints`.
/// - `blob`: opaque bytes; the target's verify parses them.
/// - `attestation_traces`: per-event slice consumed by verify.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct BodyEvent {
    pub target_path: Vec<u8>,
    pub blob: Vec<u8>,
    pub attestation_traces: Vec<AttestationEntry>,
}

/// Per-Schedule-slot trace slice. Each Schedule slot has a designated
/// dynamic-size `Vec<AttestationEntry>` (NOT a static slice). The kernel
/// passes `traces` to the Schedule's verify; verify consumes via
/// `mint_attest_cap`.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct ScheduleAttestationTraces {
    /// Index into `σ.transact_endpoints` of this Schedule slot.
    pub slot_index: u32,
    pub traces: Vec<AttestationEntry>,
}

/// Block body. Carries on-chain events (proposer-ordered) plus all
/// sidecar traces.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct Body {
    /// Proposer-ordered list of body events targeting transact endpoints
    /// in `σ.transact_endpoints`.
    pub events: Vec<BodyEvent>,
    /// Block-level cumulative attestation trace consumed across all
    /// event-receiving slot verifies in slot order.
    pub attestation_trace: Vec<AttestationEntry>,
    /// Per-Schedule-slot trace slices. Each slot may consume zero, one,
    /// or many entries.
    pub schedule_attestation_traces: Vec<ScheduleAttestationTraces>,
    /// Block-level result trace (preserved; collapsed-ResultCap with
    /// IDENTITY_KEY now lives in attestation traces).
    pub result_trace: Vec<ResultEntry>,
    /// Reach trace: which Vaults each invocation initialized. Strict
    /// equality.
    pub reach_trace: Vec<ReachEntry>,
    /// Merkle proofs for σ reads done by Schedule slots.
    pub merkle_traces: Vec<MerkleProof>,
}

#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct Block {
    pub parent: BlockHash,
    pub body: Body,
}

// =============================================================================
// Sidecar trace types
// =============================================================================

/// One canonical computation output. Preserved during the event-
/// redesign migration; future cleanup may collapse into the
/// `AttestationEntry` shape via IDENTITY_KEY.
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
