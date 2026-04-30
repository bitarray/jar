//! Code-blob content store + smoke fixtures.
//!
//! After the unified-persistence refactor, code blobs live as
//! `Capability::Code(CodeCap)` entries inside Vault CNodes — one
//! Vault holds its own code as a CodeCap in a designated slot. The
//! per-Vault `code_hash` field and the kernel-internal `state.code_vault`
//! are gone.
//!
//! `CodeCap` carries an `Arc<Vec<u8>>`, so multiple Vault slots holding
//! the same blob share the same allocation in memory transparently.
//! Content-addressed dedup at the σ level (so that re-inserting the
//! same bytes coalesces to one allocation) is a node-side optimization
//! and is not done here.
//!
//! Resolution of a Vault's entry CodeCap is via [`resolve_init_blob`],
//! which reads `vault.slots[CODE_CAP_SLOT]` and looks up the CapRecord.

use std::sync::Arc;

use crate::cap::Capability;
use crate::state::CODE_CAP_SLOT;
use crate::state::cap_registry;
use crate::types::{KResult, KernelError, State, VaultId};

/// Resolve the init CodeCap blob for a Vault. Reads `slots[CODE_CAP_SLOT]`,
/// looks up the CapRecord, and returns a clone of the `Arc<Vec<u8>>`
/// blob. Cheap (just an Arc bump). Errors if the slot is empty or holds
/// a non-Code cap.
pub fn resolve_init_blob(state: &State, vault_id: VaultId) -> KResult<Arc<Vec<u8>>> {
    let vault = state.vault(vault_id)?;
    let cap_id = vault.slots.get(CODE_CAP_SLOT).ok_or_else(|| {
        KernelError::Internal(format!(
            "vault {:?} has no CodeCap at slot {}",
            vault_id, CODE_CAP_SLOT
        ))
    })?;
    let record = cap_registry::lookup(state, cap_id)?;
    match &record.cap {
        Capability::Code(c) => Ok(Arc::clone(&c.blob)),
        other => Err(KernelError::Internal(format!(
            "vault {:?} slot {} holds {:?}, expected Code",
            vault_id,
            CODE_CAP_SLOT,
            std::mem::discriminant(other)
        ))),
    }
}

/// Default smoke fixture: a PVM blob that ecallis IPC-slot (REPLY) → halts
/// immediately. Compiled at build time from `rust/jar-test-services/halt`.
pub fn halt_blob() -> &'static [u8] {
    include_bytes!(env!("JAR_HALT_BLOB_PATH"))
}

/// Default dispatch smoke fixture: a PVM blob that ecallis Protocol cap id=19
/// (`HostCall::SlotClear`), then REPLY-halts. Compiled at build time from
/// `rust/jar-test-services/slot_clear`.
pub fn slot_clear_blob() -> &'static [u8] {
    include_bytes!(env!("JAR_SLOT_CLEAR_BLOB_PATH"))
}
