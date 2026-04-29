//! Sidecar trace types: attestation_trace, result_trace, reach_trace,
//! merkle_traces.
//!
//! These are produced by the proposer during apply_block and consumed
//! position-by-position by verifiers. The kernel enforces strict-equality
//! and exhaustion at apply_block end.
//!
//! Manual `Clone` / `Eq` / `PartialEq` / `Debug` / `Default` impls (rather
//! than `#[derive]`) so the bounds are on `C::Hash` / `C::KeyId` /
//! `C::Signature` rather than on `C` itself — `C` is a marker type with
//! no Clone/Eq/etc. requirements of its own.

use crate::{Crypto, VaultId};

/// One signature recorded by an `attest()` call.
pub struct AttestationEntry<C: Crypto> {
    pub key: C::KeyId,
    pub blob_hash: C::Hash,
    pub signature: C::Signature,
}

impl<C: Crypto> Clone for AttestationEntry<C> {
    fn clone(&self) -> Self {
        Self {
            key: self.key,
            blob_hash: self.blob_hash,
            signature: self.signature.clone(),
        }
    }
}

impl<C: Crypto> PartialEq for AttestationEntry<C> {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
            && self.blob_hash == other.blob_hash
            && self.signature == other.signature
    }
}

impl<C: Crypto> Eq for AttestationEntry<C> {}

impl<C: Crypto> core::fmt::Debug for AttestationEntry<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AttestationEntry")
            .field("key", &self.key)
            .field("blob_hash", &self.blob_hash)
            .field("signature", &self.signature)
            .finish()
    }
}

impl<C: Crypto> Default for AttestationEntry<C> {
    fn default() -> Self {
        Self {
            key: C::KeyId::default(),
            blob_hash: C::Hash::default(),
            signature: C::Signature::default(),
        }
    }
}

impl<C: Crypto> AttestationEntry<C> {
    /// Returns true if this slot has not yet been filled (Sealing reserved).
    pub fn is_reserved(&self) -> bool {
        self.signature == C::Signature::default()
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

/// One storage_read proof. Used by light-clients to verify
/// `block_validation_cap` and `block_finalization_cap` runs against
/// `prior_block.header.state_root`.
pub struct MerkleProof<C: Crypto> {
    pub vault: VaultId,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    /// Stub for now; populated by the future Merkle-trie implementation.
    pub proof_path: Vec<C::Hash>,
}

impl<C: Crypto> Clone for MerkleProof<C> {
    fn clone(&self) -> Self {
        Self {
            vault: self.vault,
            key: self.key.clone(),
            value: self.value.clone(),
            proof_path: self.proof_path.clone(),
        }
    }
}

impl<C: Crypto> PartialEq for MerkleProof<C> {
    fn eq(&self, other: &Self) -> bool {
        self.vault == other.vault
            && self.key == other.key
            && self.value == other.value
            && self.proof_path == other.proof_path
    }
}

impl<C: Crypto> Eq for MerkleProof<C> {}

impl<C: Crypto> core::fmt::Debug for MerkleProof<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MerkleProof")
            .field("vault", &self.vault)
            .field("key", &self.key)
            .field("value", &self.value)
            .field("proof_path", &self.proof_path)
            .finish()
    }
}

impl<C: Crypto> Default for MerkleProof<C> {
    fn default() -> Self {
        Self {
            vault: VaultId::default(),
            key: Vec::new(),
            value: Vec::new(),
            proof_path: Vec::new(),
        }
    }
}
