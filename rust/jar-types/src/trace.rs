//! Sidecar trace types: attestation_trace, result_trace, reach_trace,
//! merkle_traces.
//!
//! These are produced by the proposer during apply_block and consumed
//! position-by-position by verifiers. The kernel enforces strict-equality
//! and exhaustion at apply_block end.

use crate::{Hash, KeyId, Signature, VaultId};

/// One signature recorded by an `attest()` call.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct AttestationEntry {
    pub key: KeyId,
    pub blob_hash: Hash,
    pub signature: Signature,
}

impl AttestationEntry {
    /// Returns true if this slot has not yet been filled (Sealing reserved).
    pub fn is_reserved(&self) -> bool {
        self.signature.is_reserved()
    }
}

/// One canonical computation output recorded by a `result_equal()` call.
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
///
/// The proof shape depends on which merkle tree the hardware uses
/// (Patricia, Verkle, …). The kernel stores it in `body.merkle_traces`,
/// hands it back to hardware for verification, and otherwise treats the
/// bytes as opaque. Phase 1 has no real proofs — the type just stops
/// claiming to know the shape.
///
/// `vault` and `key` are kept on the entry so the kernel can pair the
/// proof with what was being read (matched against the corresponding
/// `storage_read` host call). `value` is what was read; verifier-mode
/// hardware checks `(prior_root, vault, key, value, proof) → bool`.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct MerkleProof {
    pub vault: VaultId,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    /// Opaque proof bytes — hardware-defined.
    pub proof: Vec<u8>,
}
