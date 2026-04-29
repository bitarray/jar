//! The 16 kernel host calls (plus a few derived helpers — see `HostCall`).
//!
//! All handlers return `(r0, r1)` — the values written into φ[7] and φ[8] for
//! the resume. Most handlers use `r0` as their primary return; `r1` is used
//! for length-of-output / secondary-flag where applicable.
//!
//! Argument convention: φ[7..12] carry up to 6 inputs. Pointer/length pairs
//! address guest memory windows.
//!
//! There is no `StorageMode` flag. The authority for each operation comes
//! from the caps in `ctx.frame`:
//! - `storage_*` accept `Storage` (overlay) or `SnapshotStorage` (committed
//!   prior view); the latter rejects writes/deletes.
//! - `cnode_*`, `cap_derive`, `create_vault`, `quota_set` need specific cap
//!   shapes in the frame to authorize the operation. Frames assembled for
//!   read-only contexts (e.g., Dispatch step-2/step-3) simply don't include
//!   those caps; the ops bounce on `RC_BAD_CAP`.

use jar_types::{
    AttestationScope, CNodeId, Caller, CapId, CapRecord, Capability, Command, KResult, KernelError,
    KernelRole, ResourceKind, ResultEntry, SlotContent,
};

use crate::attest;
use crate::cap_registry;
use crate::cnode_ops;
use crate::host_abi::*;
use crate::invocation::{InvocationCtx, VmExec};
use crate::pinning;
use crate::runtime::Hardware;
use crate::storage;

/// Top-level host-call dispatcher. Returns (r0, r1) to write into resume.
pub fn dispatch_host_call<V: VmExec, H: Hardware>(
    call: HostCall,
    vm: &mut V,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<(u64, u64)> {
    match call {
        HostCall::Gas => Ok((vm.gas(), 0)),
        HostCall::SelfId => Ok((ctx.current_vault.0, 0)),
        HostCall::Caller => Ok(encode_caller(&ctx.caller)),
        HostCall::StorageRead => host_storage_read(vm, ctx),
        HostCall::StorageWrite => host_storage_write(vm, ctx),
        HostCall::StorageDelete => host_storage_delete(vm, ctx),
        HostCall::CnodeGrant => host_cnode_grant(vm, ctx),
        HostCall::CnodeRevoke => host_cnode_revoke(vm, ctx),
        HostCall::CnodeMove => host_cnode_move(vm, ctx),
        HostCall::CapDerive => host_cap_derive(vm, ctx),
        HostCall::CapCall => host_cap_call(vm, ctx),
        HostCall::VaultInitialize => host_vault_initialize(vm, ctx),
        HostCall::CreateVault => host_create_vault(vm, ctx),
        HostCall::QuotaSet => host_quota_set(vm, ctx),
        HostCall::Attest => host_attest(vm, ctx),
        HostCall::AttestationKey => host_attestation_key(vm, ctx),
        HostCall::AttestationAggregate => Ok((0, 0)),
        HostCall::ResultEqual => host_result_equal(vm, ctx),
        HostCall::SlotClear => host_slot_clear(vm, ctx),
        HostCall::SlotEmit => Ok((RC_UNIMPLEMENTED, 0)),
    }
}

/// Encode the typed Caller into two u64s. r0: tag (0=Vault, 1=Kernel),
/// r1: payload (vault_id for Vault, KernelRole as u32 for Kernel).
fn encode_caller(c: &Caller) -> (u64, u64) {
    match c {
        Caller::Vault(vid) => (0, vid.0),
        Caller::Kernel(role) => (
            1,
            match role {
                KernelRole::TransactEntry => 0,
                KernelRole::AggregateStandalone => 1,
                KernelRole::AggregateMerge => 2,
            },
        ),
    }
}

// -----------------------------------------------------------------------------
// Storage
// -----------------------------------------------------------------------------

fn host_storage_read<V: VmExec, H: Hardware>(
    vm: &mut V,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<(u64, u64)> {
    // φ[7] = frame_slot for Storage / SnapshotStorage cap
    // φ[8] = key_ptr, φ[9] = key_len, φ[10] = out_ptr, φ[11] = out_max
    let frame_slot = vm.reg(7) as u8;
    let key_ptr = vm.reg(8) as u32;
    let key_len = vm.reg(9) as u32;
    let out_ptr = vm.reg(10) as u32;
    let out_max = vm.reg(11) as u32;

    let cap_id = match ctx.frame.get(frame_slot) {
        Some(c) => c,
        None => return Ok((RC_BAD_CAP, 0)),
    };
    let key = vm
        .read_mem(key_ptr, key_len)
        .ok_or_else(|| KernelError::Internal("storage_read: bad key window".into()))?;
    match storage::storage_read(ctx.state, cap_id, &key)? {
        Some(value) => {
            let to_write = value.len().min(out_max as usize);
            if to_write > 0 {
                vm.write_mem(out_ptr, &value[..to_write]);
            }
            Ok((value.len() as u64, 0))
        }
        None => Ok((RC_NONE, 0)),
    }
}

fn host_storage_write<V: VmExec, H: Hardware>(
    vm: &mut V,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<(u64, u64)> {
    let frame_slot = vm.reg(7) as u8;
    let key_ptr = vm.reg(8) as u32;
    let key_len = vm.reg(9) as u32;
    let val_ptr = vm.reg(10) as u32;
    let val_len = vm.reg(11) as u32;

    let cap_id = match ctx.frame.get(frame_slot) {
        Some(c) => c,
        None => return Ok((RC_BAD_CAP, 0)),
    };
    let key = vm
        .read_mem(key_ptr, key_len)
        .ok_or_else(|| KernelError::Internal("storage_write: bad key window".into()))?;
    let val = vm
        .read_mem(val_ptr, val_len)
        .ok_or_else(|| KernelError::Internal("storage_write: bad val window".into()))?;

    match storage::storage_write(ctx.state, cap_id, &key, &val) {
        Ok(()) => Ok((RC_OK, 0)),
        Err(KernelError::ReadOnly(_)) => Ok((RC_READONLY, 0)),
        Err(KernelError::QuotaExceeded { .. }) => Ok((RC_QUOTA, 0)),
        Err(e) => Err(e),
    }
}

fn host_storage_delete<V: VmExec, H: Hardware>(
    vm: &mut V,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<(u64, u64)> {
    let frame_slot = vm.reg(7) as u8;
    let key_ptr = vm.reg(8) as u32;
    let key_len = vm.reg(9) as u32;

    let cap_id = match ctx.frame.get(frame_slot) {
        Some(c) => c,
        None => return Ok((RC_BAD_CAP, 0)),
    };
    let key = vm
        .read_mem(key_ptr, key_len)
        .ok_or_else(|| KernelError::Internal("storage_delete: bad key window".into()))?;

    match storage::storage_delete(ctx.state, cap_id, &key) {
        Ok(()) => Ok((RC_OK, 0)),
        Err(KernelError::ReadOnly(_)) => Ok((RC_READONLY, 0)),
        Err(e) => Err(e),
    }
}

// -----------------------------------------------------------------------------
// CNode operations
// -----------------------------------------------------------------------------

fn host_cnode_grant<V: VmExec, H: Hardware>(
    vm: &mut V,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<(u64, u64)> {
    // φ[7]=src_frame_slot, φ[8]=dest_cnode_frame_slot, φ[9]=dest_cnode_slot
    let src_slot = vm.reg(7) as u8;
    let dest_cnode_slot = vm.reg(8) as u8;
    let dest_slot = vm.reg(9) as u8;
    let src_cap = match ctx.frame.get(src_slot) {
        Some(c) => c,
        None => return Ok((RC_BAD_CAP, 0)),
    };
    let dest_cnode_cap = match ctx.frame.get(dest_cnode_slot) {
        Some(c) => c,
        None => return Ok((RC_BAD_CAP, 0)),
    };
    let dest_cnode_id = match &cap_registry::lookup(ctx.state, dest_cnode_cap)?.cap {
        Capability::CNode { cnode_id } => *cnode_id,
        _ => return Ok((RC_BAD_CAP, 0)),
    };
    match cnode_ops::cnode_grant(ctx.state, src_cap, dest_cnode_id, dest_slot) {
        Ok(_) => Ok((RC_OK, 0)),
        Err(KernelError::Pinning(_)) => Ok((RC_PINNING, 0)),
        Err(e) => Err(e),
    }
}

fn host_cnode_revoke<V: VmExec, H: Hardware>(
    vm: &mut V,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<(u64, u64)> {
    let cnode_frame_slot = vm.reg(7) as u8;
    let cnode_slot = vm.reg(8) as u8;
    let cnode_cap = match ctx.frame.get(cnode_frame_slot) {
        Some(c) => c,
        None => return Ok((RC_BAD_CAP, 0)),
    };
    let cnode_id = match &cap_registry::lookup(ctx.state, cnode_cap)?.cap {
        Capability::CNode { cnode_id } => *cnode_id,
        _ => return Ok((RC_BAD_CAP, 0)),
    };
    cnode_ops::cnode_revoke(ctx.state, cnode_id, cnode_slot)?;
    Ok((RC_OK, 0))
}

fn host_cnode_move<V: VmExec, H: Hardware>(
    vm: &mut V,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<(u64, u64)> {
    // φ[7]=src_cnode_frame_slot, φ[8]=src_slot, φ[9]=dest_cnode_frame_slot, φ[10]=dest_slot
    let src_cn_fs = vm.reg(7) as u8;
    let src_slot = vm.reg(8) as u8;
    let dst_cn_fs = vm.reg(9) as u8;
    let dst_slot = vm.reg(10) as u8;
    let resolve = |fs: u8| -> KResult<CNodeId> {
        let cap = ctx
            .frame
            .get(fs)
            .ok_or_else(|| KernelError::Internal(format!("frame slot {} empty", fs)))?;
        match &cap_registry::lookup(ctx.state, cap)?.cap {
            Capability::CNode { cnode_id } => Ok(*cnode_id),
            _ => Err(KernelError::Internal("expected CNode cap".into())),
        }
    };
    let src_cn = resolve(src_cn_fs)?;
    let dst_cn = resolve(dst_cn_fs)?;
    match cnode_ops::cnode_move(ctx.state, src_cn, src_slot, dst_cn, dst_slot) {
        Ok(_) => Ok((RC_OK, 0)),
        Err(KernelError::Pinning(_)) => Ok((RC_PINNING, 0)),
        Err(e) => Err(e),
    }
}

fn host_cap_derive<V: VmExec, H: Hardware>(
    vm: &mut V,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<(u64, u64)> {
    // φ[7]=src_frame_slot, φ[8]=dest_frame_slot, φ[9]=narrowing_ptr, φ[10]=narrowing_len,
    // φ[11]=mode (0=Frame, 1=persistent into a CNode-cap-frame-slot), φ[12]=dest_cnode_frame_slot
    let src_slot = vm.reg(7) as u8;
    let dst_slot = vm.reg(8) as u8;
    let narr_ptr = vm.reg(9) as u32;
    let narr_len = vm.reg(10) as u32;
    let mode = vm.reg(11);
    let dest_cnode_fs = vm.reg(12) as u8;

    let src_cap = match ctx.frame.get(src_slot) {
        Some(c) => c,
        None => return Ok((RC_BAD_CAP, 0)),
    };
    let narrowing = if narr_len > 0 {
        vm.read_mem(narr_ptr, narr_len)
            .ok_or_else(|| KernelError::Internal("cap_derive: bad narrowing window".into()))?
    } else {
        Vec::new()
    };
    let src_record = cap_registry::lookup(ctx.state, src_cap)?.clone();
    // Compute the new capability shape (kernel chooses based on src + mode).
    let (new_cap, dest_persistent) = match (&src_record.cap, mode) {
        (Capability::Dispatch { vault_id, .. }, 0) => (
            Capability::DispatchRef {
                vault_id: *vault_id,
            },
            false,
        ),
        (Capability::Dispatch { vault_id, .. }, 1) => {
            let dest_cnode_cap = match ctx.frame.get(dest_cnode_fs) {
                Some(c) => c,
                None => return Ok((RC_BAD_CAP, 0)),
            };
            let dest_cnode_id = match &cap_registry::lookup(ctx.state, dest_cnode_cap)?.cap {
                Capability::CNode { cnode_id } => *cnode_id,
                _ => return Ok((RC_BAD_CAP, 0)),
            };
            (
                Capability::Dispatch {
                    vault_id: *vault_id,
                    born_in: dest_cnode_id,
                },
                true,
            )
        }
        (Capability::Transact { vault_id, .. }, 0) => (
            Capability::TransactRef {
                vault_id: *vault_id,
            },
            false,
        ),
        (Capability::Transact { vault_id, .. }, 1) => {
            let dest_cnode_cap = match ctx.frame.get(dest_cnode_fs) {
                Some(c) => c,
                None => return Ok((RC_BAD_CAP, 0)),
            };
            let dest_cnode_id = match &cap_registry::lookup(ctx.state, dest_cnode_cap)?.cap {
                Capability::CNode { cnode_id } => *cnode_id,
                _ => return Ok((RC_BAD_CAP, 0)),
            };
            (
                Capability::Transact {
                    vault_id: *vault_id,
                    born_in: dest_cnode_id,
                },
                true,
            )
        }
        (Capability::DispatchRef { vault_id }, 0) => (
            Capability::DispatchRef {
                vault_id: *vault_id,
            },
            false,
        ),
        (Capability::TransactRef { vault_id }, 0) => (
            Capability::TransactRef {
                vault_id: *vault_id,
            },
            false,
        ),
        (Capability::VaultRef { vault_id, rights }, _) => (
            Capability::VaultRef {
                vault_id: *vault_id,
                rights: *rights,
            },
            mode == 1,
        ),
        _ => return Ok((RC_BAD_CAP, 0)),
    };
    match cap_registry::derive(ctx.state, src_cap, new_cap, narrowing, dest_persistent) {
        Ok(new_id) => {
            ctx.frame.set(dst_slot, new_id);
            Ok((new_id.0, 0))
        }
        Err(KernelError::Pinning(_)) => Ok((RC_PINNING, 0)),
        Err(e) => Err(e),
    }
}

// -----------------------------------------------------------------------------
// cap_call — the universal callable-cap exercise
// -----------------------------------------------------------------------------

fn host_cap_call<V: VmExec, H: Hardware>(
    vm: &mut V,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<(u64, u64)> {
    let cap_fs = vm.reg(7) as u8;
    let args_ptr = vm.reg(8) as u32;
    let args_len = vm.reg(9) as u32;
    let caps_ptr = vm.reg(10) as u32;
    let caps_len = vm.reg(11) as u32;

    let cap_id = match ctx.frame.get(cap_fs) {
        Some(c) => c,
        None => return Ok((RC_BAD_CAP, 0)),
    };
    let cap = cap_registry::lookup(ctx.state, cap_id)?.cap.clone();
    let args = if args_len > 0 {
        vm.read_mem(args_ptr, args_len)
            .ok_or_else(|| KernelError::Internal("cap_call: bad args window".into()))?
    } else {
        Vec::new()
    };
    let caps_bytes = if caps_len > 0 {
        vm.read_mem(caps_ptr, caps_len)
            .ok_or_else(|| KernelError::Internal("cap_call: bad caps window".into()))?
    } else {
        Vec::new()
    };
    let mut arg_caps: Vec<CapId> = Vec::with_capacity(caps_bytes.len());
    for fs in caps_bytes {
        let cid = ctx
            .frame
            .get(fs)
            .ok_or_else(|| KernelError::Internal(format!("cap_call: arg slot {} empty", fs)))?;
        arg_caps.push(cid);
    }

    match cap {
        Capability::VaultRef { rights, .. } if rights.initialize => {
            // Sub-CALL stub. No arg-scan for sub-CALLs.
            Ok((RC_UNIMPLEMENTED, 0))
        }
        Capability::Dispatch { vault_id, .. } | Capability::DispatchRef { vault_id } => {
            pinning::arg_scan(ctx.state, &arg_caps)?;
            if matches!(ctx.role, KernelRole::AggregateMerge) && vault_id == ctx.current_vault {
                if ctx.slot_emission.is_some() {
                    return Err(KernelError::Internal(
                        "step-3 emitted more than one slot replacement".into(),
                    ));
                }
                *ctx.slot_emission = Some(SlotContent::AggregatedDispatch {
                    payload: args,
                    caps: caps_bytes_to_vec(&arg_caps),
                    attestation_trace: ctx.attestation_trace.clone(),
                    result_trace: ctx.result_trace.clone(),
                });
                return Ok((RC_OK, 0));
            }
            ctx.commands.push(Command::Dispatch {
                entrypoint: vault_id,
                payload: args,
                caps: caps_bytes_to_vec(&arg_caps),
            });
            Ok((RC_OK, 0))
        }
        Capability::Transact { vault_id, .. } | Capability::TransactRef { vault_id } => {
            pinning::arg_scan(ctx.state, &arg_caps)?;
            if matches!(ctx.role, KernelRole::AggregateMerge) {
                if ctx.slot_emission.is_some() {
                    return Err(KernelError::Internal(
                        "step-3 emitted more than one slot replacement".into(),
                    ));
                }
                *ctx.slot_emission = Some(SlotContent::AggregatedTransact {
                    target: vault_id,
                    payload: args,
                    caps: caps_bytes_to_vec(&arg_caps),
                    attestation_trace: ctx.attestation_trace.clone(),
                    result_trace: ctx.result_trace.clone(),
                });
                return Ok((RC_OK, 0));
            }
            ctx.commands.push(Command::Dispatch {
                entrypoint: vault_id,
                payload: args,
                caps: caps_bytes_to_vec(&arg_caps),
            });
            Ok((RC_OK, 0))
        }
        Capability::Schedule { .. } => Ok((RC_BAD_CAP, 0)),
        _ => Ok((RC_BAD_CAP, 0)),
    }
}

fn caps_bytes_to_vec(caps: &[CapId]) -> Vec<u8> {
    let mut out = Vec::with_capacity(caps.len() * 8);
    for c in caps {
        out.extend_from_slice(&c.0.to_le_bytes());
    }
    out
}

// -----------------------------------------------------------------------------
// vault_initialize — placeholder; real sub-VM scheduling deferred.
// -----------------------------------------------------------------------------

fn host_vault_initialize<V: VmExec, H: Hardware>(
    _vm: &mut V,
    _ctx: &mut InvocationCtx<'_, H>,
) -> KResult<(u64, u64)> {
    Ok((RC_UNIMPLEMENTED, 0))
}

// -----------------------------------------------------------------------------
// create_vault, quota_set
// -----------------------------------------------------------------------------

fn host_create_vault<V: VmExec, H: Hardware>(
    vm: &mut V,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<(u64, u64)> {
    let res_fs = vm.reg(7) as u8;
    let code_hash_ptr = vm.reg(8) as u32;
    let dest_fs = vm.reg(9) as u8;

    let res_cap_id = match ctx.frame.get(res_fs) {
        Some(c) => c,
        None => return Ok((RC_BAD_CAP, 0)),
    };
    let (quota_items, quota_bytes) = match &cap_registry::lookup(ctx.state, res_cap_id)?.cap {
        Capability::Resource(ResourceKind::CreateVault {
            quota_items,
            quota_bytes,
        }) => (*quota_items, *quota_bytes),
        _ => return Ok((RC_BAD_CAP, 0)),
    };
    let code_hash_bytes = vm
        .read_mem(code_hash_ptr, 32)
        .ok_or_else(|| KernelError::Internal("create_vault: bad code_hash window".into()))?;
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&code_hash_bytes);
    let code_hash = jar_types::Hash(buf);

    let new_vault_id = ctx.state.next_vault_id();
    let mut vault = jar_types::Vault::new(code_hash);
    vault.quota_items = quota_items;
    vault.quota_bytes = quota_bytes;
    ctx.state
        .vaults
        .insert(new_vault_id, std::sync::Arc::new(vault));

    let cap_id = cap_registry::alloc(
        ctx.state,
        CapRecord {
            cap: Capability::VaultRef {
                vault_id: new_vault_id,
                rights: jar_types::VaultRights::ALL,
            },
            issuer: Some(res_cap_id),
            narrowing: Vec::new(),
        },
    );
    ctx.frame.set(dest_fs, cap_id);
    Ok((cap_id.0, new_vault_id.0))
}

fn host_quota_set<V: VmExec, H: Hardware>(
    vm: &mut V,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<(u64, u64)> {
    let res_fs = vm.reg(7) as u8;
    let new_items = vm.reg(8);
    let new_bytes = vm.reg(9);
    let res_cap_id = match ctx.frame.get(res_fs) {
        Some(c) => c,
        None => return Ok((RC_BAD_CAP, 0)),
    };
    let target = match &cap_registry::lookup(ctx.state, res_cap_id)?.cap {
        Capability::Resource(ResourceKind::SetQuota { target }) => *target,
        _ => return Ok((RC_BAD_CAP, 0)),
    };
    let arc = ctx
        .state
        .vaults
        .get(&target)
        .ok_or(KernelError::VaultNotFound(target))?
        .clone();
    let mut vault: jar_types::Vault = (*arc).clone();
    vault.quota_items = new_items;
    vault.quota_bytes = new_bytes;
    ctx.state.vaults.insert(target, std::sync::Arc::new(vault));
    Ok((RC_OK, 0))
}

// -----------------------------------------------------------------------------
// AttestationCap / ResultCap
// -----------------------------------------------------------------------------

fn host_attest<V: VmExec, H: Hardware>(
    vm: &mut V,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<(u64, u64)> {
    let cap_fs = vm.reg(7) as u8;
    let blob_ptr = vm.reg(8) as u32;
    let blob_len = vm.reg(9) as u32;
    let cap_id = match ctx.frame.get(cap_fs) {
        Some(c) => c,
        None => return Ok((RC_BAD_CAP, 0)),
    };
    let cap = cap_registry::lookup(ctx.state, cap_id)?.cap.clone();
    let blob_owned = if blob_len > 0 {
        Some(
            vm.read_mem(blob_ptr, blob_len)
                .ok_or_else(|| KernelError::Internal("attest: bad blob window".into()))?,
        )
    } else {
        None
    };
    let scope = match &cap {
        Capability::AttestationCap { scope, .. } => *scope,
        _ => return Ok((RC_BAD_CAP, 0)),
    };
    let outcome = match (scope, blob_owned.as_deref()) {
        (AttestationScope::Direct, Some(blob)) => attest::attest(
            &cap,
            Some(blob),
            ctx.attest_cursor,
            ctx.attestation_trace,
            ctx.hw,
        )?,
        (AttestationScope::Direct, None) => {
            return Err(KernelError::Internal(
                "Direct attest requires a non-empty blob".into(),
            ));
        }
        (AttestationScope::Sealing, _) => {
            attest::attest(&cap, None, ctx.attest_cursor, ctx.attestation_trace, ctx.hw)?
        }
    };
    Ok((if outcome.as_bool() { 1 } else { 0 }, 0))
}

fn host_attestation_key<V: VmExec, H: Hardware>(
    vm: &mut V,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<(u64, u64)> {
    let cap_fs = vm.reg(7) as u8;
    let out_ptr = vm.reg(8) as u32;
    let cap_id = match ctx.frame.get(cap_fs) {
        Some(c) => c,
        None => return Ok((RC_BAD_CAP, 0)),
    };
    let cap = cap_registry::lookup(ctx.state, cap_id)?.cap.clone();
    let key = attest::key_of(&cap)?;
    vm.write_mem(out_ptr, key.as_ref());
    Ok((key.0.len() as u64, 0))
}

fn host_result_equal<V: VmExec, H: Hardware>(
    vm: &mut V,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<(u64, u64)> {
    let blob_ptr = vm.reg(7) as u32;
    let blob_len = vm.reg(8) as u32;
    let blob = if blob_len > 0 {
        vm.read_mem(blob_ptr, blob_len)
            .ok_or_else(|| KernelError::Internal("result_equal: bad blob window".into()))?
    } else {
        Vec::new()
    };
    if ctx.attest_cursor.result_pos < ctx.result_trace.len() {
        let recorded = &ctx.result_trace[ctx.attest_cursor.result_pos];
        let eq = recorded.blob == blob;
        ctx.attest_cursor.result_pos += 1;
        return Ok((if eq { 1 } else { 0 }, 0));
    }
    ctx.result_trace.push(ResultEntry { blob });
    ctx.attest_cursor.result_pos += 1;
    Ok((1, 0))
}

// -----------------------------------------------------------------------------
// slot_clear — only valid at step-3.
// -----------------------------------------------------------------------------

fn host_slot_clear<V: VmExec, H: Hardware>(
    _vm: &mut V,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<(u64, u64)> {
    if !matches!(ctx.role, KernelRole::AggregateMerge) {
        return Err(KernelError::Internal(
            "slot_clear is only valid in step-3".into(),
        ));
    }
    if ctx.slot_emission.is_some() {
        return Err(KernelError::Internal(
            "step-3 emitted more than one slot replacement".into(),
        ));
    }
    *ctx.slot_emission = Some(SlotContent::Empty);
    Ok((RC_OK, 0))
}
