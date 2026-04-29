//! Storage host-call helpers + quota enforcement.

use std::sync::Arc;

use jar_types::{
    Capability, Crypto, KResult, KernelError, State, StorageMode, StorageRights, VaultId,
};

use crate::cap_registry;

/// Check that `state` is in a writable context. Errors with `ReadOnly` if not.
pub fn require_writable(mode: StorageMode, host_call: &'static str) -> KResult<()> {
    if mode.is_writable() {
        Ok(())
    } else {
        Err(KernelError::ReadOnly(host_call))
    }
}

/// Resolve a Storage cap and check rights + key coverage.
fn resolve_storage<C: Crypto>(
    state: &State<C>,
    storage_cap: jar_types::CapId,
    key: &[u8],
    need: StorageRights,
) -> KResult<(VaultId, ())> {
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
            Ok((*vault_id, ()))
        }
        _ => Err(KernelError::Internal(
            "expected Storage cap for storage_*".into(),
        )),
    }
}

/// `storage_read(storage_cap, key) -> Option<Vec<u8>>`.
pub fn storage_read<C: Crypto>(
    state: &State<C>,
    storage_cap: jar_types::CapId,
    key: &[u8],
) -> KResult<Option<Vec<u8>>> {
    let (vault_id, _) = resolve_storage(state, storage_cap, key, StorageRights::RO)?;
    let vault = state.vault(vault_id)?;
    Ok(vault.storage.get(key).cloned())
}

/// `storage_write(storage_cap, key, value)` — quota-checked.
pub fn storage_write<C: Crypto>(
    state: &mut State<C>,
    mode: StorageMode,
    storage_cap: jar_types::CapId,
    key: &[u8],
    value: &[u8],
) -> KResult<()> {
    require_writable(mode, "storage_write")?;
    let (vault_id, _) = resolve_storage(state, storage_cap, key, StorageRights::RW)?;
    let vault_arc = state
        .vaults
        .get(&vault_id)
        .ok_or(KernelError::VaultNotFound(vault_id))?
        .clone();
    let mut vault: jar_types::Vault<C> = (*vault_arc).clone();

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
pub fn storage_delete<C: Crypto>(
    state: &mut State<C>,
    mode: StorageMode,
    storage_cap: jar_types::CapId,
    key: &[u8],
) -> KResult<()> {
    require_writable(mode, "storage_delete")?;
    let (vault_id, _) = resolve_storage(state, storage_cap, key, StorageRights::RW)?;
    let vault_arc = state
        .vaults
        .get(&vault_id)
        .ok_or(KernelError::VaultNotFound(vault_id))?
        .clone();
    let mut vault: jar_types::Vault<C> = (*vault_arc).clone();
    if let Some(prev) = vault.storage.remove(key) {
        let delta = (key.len() + prev.len()) as u64;
        vault.total_footprint = vault.total_footprint.saturating_sub(delta);
        state.vaults.insert(vault_id, Arc::new(vault));
    }
    Ok(())
}
