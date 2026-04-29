//! Storage host-call helpers + quota enforcement.
//!
//! Storage authority is encoded in the cap variant:
//! - `Capability::Storage` — overlay (this-block mutable), rights say if
//!   writes are permitted.
//! - `Capability::SnapshotStorage` — committed prior-block view, read-only by
//!   construction; bound to a specific state-root.
//!
//! There is no `StorageMode` flag: the caller's authority is whatever cap
//! their Frame contains. Phase 1 stubs the snapshot read against the same
//! in-memory state (the off-chain dispatch pipeline already runs against a
//! kernel-side clone); Phase 2 wires real merkle proofs through hardware.

use std::sync::Arc;

use crate::types::{Capability, KResult, KernelError, State, StorageRights, VaultId};

use crate::cap_registry;

/// Resolve a storage-class cap and check rights + key coverage. Returns the
/// underlying `vault_id` if the cap is well-formed for `need`.
fn resolve_storage(
    state: &State,
    storage_cap: crate::types::CapId,
    key: &[u8],
    need: StorageRights,
) -> KResult<VaultId> {
    let record = cap_registry::lookup(state, storage_cap)?;
    match &record.cap {
        Capability::Storage {
            vault_id,
            key_range,
            rights,
        } => {
            if need.read && !rights.read {
                return Err(KernelError::Internal("Storage cap lacks Read".into()));
            }
            if need.write && !rights.write {
                return Err(KernelError::Internal("Storage cap lacks Write".into()));
            }
            if !key_range.covers(key) {
                return Err(KernelError::Internal(format!(
                    "key {:?} outside Storage cap range",
                    key
                )));
            }
            Ok(*vault_id)
        }
        Capability::SnapshotStorage {
            vault_id,
            key_range,
            ..
        } => {
            if need.write {
                return Err(KernelError::ReadOnly("storage_write on SnapshotStorage"));
            }
            if !key_range.covers(key) {
                return Err(KernelError::Internal(format!(
                    "key {:?} outside SnapshotStorage cap range",
                    key
                )));
            }
            Ok(*vault_id)
        }
        _ => Err(KernelError::Internal(
            "expected Storage or SnapshotStorage cap for storage_*".into(),
        )),
    }
}

/// `storage_read(storage_cap, key) -> Option<Vec<u8>>`.
pub fn storage_read(
    state: &State,
    storage_cap: crate::types::CapId,
    key: &[u8],
) -> KResult<Option<Vec<u8>>> {
    let vault_id = resolve_storage(state, storage_cap, key, StorageRights::RO)?;
    let vault = state.vault(vault_id)?;
    Ok(vault.storage.get(key).cloned())
}

/// `storage_write(storage_cap, key, value)` — quota-checked. Requires a
/// `Storage` cap with write rights; rejects `SnapshotStorage`.
pub fn storage_write(
    state: &mut State,
    storage_cap: crate::types::CapId,
    key: &[u8],
    value: &[u8],
) -> KResult<()> {
    let vault_id = resolve_storage(state, storage_cap, key, StorageRights::RW)?;
    let vault_arc = state
        .vaults
        .get(&vault_id)
        .ok_or(KernelError::VaultNotFound(vault_id))?
        .clone();
    let mut vault: crate::types::Vault = (*vault_arc).clone();

    let prev_len = vault
        .storage
        .get(key)
        .map(|v| (key.len() + v.len()) as i64)
        .unwrap_or(0);
    let new_len = (key.len() + value.len()) as i64;
    let delta = new_len - prev_len;
    let new_footprint = vault.total_footprint as i64 + delta;
    if new_footprint < 0 {
        return Err(KernelError::Internal("negative footprint".into()));
    }
    let new_footprint = new_footprint as u64;

    let new_item_count = if vault.storage.contains_key(key) {
        vault.storage.len() as u64
    } else {
        vault.storage.len() as u64 + 1
    };

    if new_footprint > vault.quota_bytes {
        return Err(KernelError::QuotaExceeded {
            what: "quota_bytes",
        });
    }
    if new_item_count > vault.quota_items {
        return Err(KernelError::QuotaExceeded {
            what: "quota_items",
        });
    }

    vault.storage.insert(key.to_vec(), value.to_vec());
    vault.total_footprint = new_footprint;
    state.vaults.insert(vault_id, Arc::new(vault));
    Ok(())
}

/// `storage_delete(storage_cap, key)` — refunds quota.
pub fn storage_delete(
    state: &mut State,
    storage_cap: crate::types::CapId,
    key: &[u8],
) -> KResult<()> {
    let vault_id = resolve_storage(state, storage_cap, key, StorageRights::RW)?;
    let vault_arc = state
        .vaults
        .get(&vault_id)
        .ok_or(KernelError::VaultNotFound(vault_id))?
        .clone();
    let mut vault: crate::types::Vault = (*vault_arc).clone();
    if let Some(prev) = vault.storage.remove(key) {
        let delta = (key.len() + prev.len()) as u64;
        vault.total_footprint = vault.total_footprint.saturating_sub(delta);
        state.vaults.insert(vault_id, Arc::new(vault));
    }
    Ok(())
}
