//! Code-blob resolution.
//!
//! Vault code lives in σ as content-addressed values inside the kernel-internal
//! `code_vault`'s storage. Each vault's `Vault.code_hash` is the key. Genesis
//! populates the code vault; the kernel reads it whenever it needs to
//! instantiate a `javm::kernel::InvocationKernel`.

use jar_types::{Hash, KResult, KernelError, State};

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

/// Resolve a `code_hash` to its blob bytes via `state.code_vault`'s storage.
/// Errors if the code vault has no entry under `code_hash` — that's a genesis
/// bug or a vault was created with a hash whose blob was never registered.
pub fn resolve_code_blob<'s>(state: &'s State, code_hash: &Hash) -> KResult<&'s [u8]> {
    let code_vault = state.vault(state.code_vault)?;
    code_vault
        .storage
        .get(code_hash.as_ref())
        .map(|v| v.as_slice())
        .ok_or_else(|| KernelError::Internal(format!("no blob for {:?}", code_hash)))
}

/// Insert `blob` into `state.code_vault`'s storage under `crypto::hash(blob)`,
/// returning that hash. Idempotent: re-inserting the same bytes is a no-op.
/// Used by genesis and tests; no quota check.
pub fn register_blob(state: &mut State, blob: Vec<u8>) -> KResult<Hash> {
    use std::sync::Arc;
    let hash = crate::crypto::hash(&blob);
    let code_vault_id = state.code_vault;
    let vault_arc = state
        .vaults
        .get(&code_vault_id)
        .ok_or(KernelError::VaultNotFound(code_vault_id))?
        .clone();
    let mut vault: jar_types::Vault = (*vault_arc).clone();
    vault.storage.insert(hash.as_ref().to_vec(), blob);
    vault.recompute_footprint();
    state.vaults.insert(code_vault_id, Arc::new(vault));
    Ok(hash)
}
