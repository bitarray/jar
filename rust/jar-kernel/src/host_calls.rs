//! The kernel host calls (see `HostCall`).
//!
//! Every handler takes `&mut javm::kernel::InvocationKernel` directly — no
//! VM-abstraction trait. Args flow in via `vm.active_reg(N)`; return values
//! flow back in `(r0, r1)` via `HostCallOutcome::Resume`. Memory windows
//! address guest DATA caps via `read_data_cap_window` /
//! `write_data_cap_window`; bad windows are guest-driven faults, not
//! kernel errors.
//!
//! Authority for each operation comes from caps in `ctx.frame`:
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
use javm::kernel::InvocationKernel;

use crate::attest;
use crate::cap_registry;
use crate::cnode_ops;
use crate::host_abi::*;
use crate::invocation::{HostCallOutcome, InvocationCtx};
use crate::pinning;
use crate::runtime::Hardware;
use crate::storage;

/// Top-level host-call dispatcher. Returns the action the driver should
/// take next: resume the VM with `(r0, r1)` or fault the invocation.
pub fn dispatch_host_call<H: Hardware>(
    call: HostCall,
    vm: &mut InvocationKernel,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<HostCallOutcome> {
    match call {
        HostCall::Gas => Ok(HostCallOutcome::Resume(vm.active_gas(), 0)),
        HostCall::SelfId => Ok(HostCallOutcome::Resume(ctx.current_vault.0, 0)),
        HostCall::Caller => {
            let (r0, r1) = encode_caller(&ctx.caller);
            Ok(HostCallOutcome::Resume(r0, r1))
        }
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
        HostCall::AttestationAggregate => Ok(HostCallOutcome::Resume(0, 0)),
        HostCall::ResultEqual => host_result_equal(vm, ctx),
        HostCall::SlotClear => host_slot_clear(vm, ctx),
        HostCall::SlotEmit => Ok(HostCallOutcome::Resume(RC_UNIMPLEMENTED, 0)),
        HostCall::SlotRead => host_slot_read(vm, ctx),
    }
}

/// Convenience: read a guest memory window or return a guest fault outcome.
fn read_window(vm: &InvocationKernel, addr: u32, len: u32, what: &str) -> Result<Vec<u8>, String> {
    if len == 0 {
        return Ok(Vec::new());
    }
    vm.read_data_cap_window(addr, len)
        .ok_or_else(|| format!("{}: bad read window @ {:#x}+{}", what, addr, len))
}

/// Convenience: write a guest memory window or return a guest fault outcome.
fn write_window(
    vm: &mut InvocationKernel,
    addr: u32,
    data: &[u8],
    what: &str,
) -> Result<(), String> {
    if data.is_empty() {
        return Ok(());
    }
    if vm.write_data_cap_window(addr, data) {
        Ok(())
    } else {
        Err(format!(
            "{}: bad write window @ {:#x}+{}",
            what,
            addr,
            data.len()
        ))
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

fn host_storage_read<H: Hardware>(
    vm: &mut InvocationKernel,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<HostCallOutcome> {
    // φ[7] = frame_slot for Storage / SnapshotStorage cap
    // φ[8] = key_ptr, φ[9] = key_len, φ[10] = out_ptr, φ[11] = out_max
    let frame_slot = vm.active_reg(7) as u8;
    let key_ptr = vm.active_reg(8) as u32;
    let key_len = vm.active_reg(9) as u32;
    let out_ptr = vm.active_reg(10) as u32;
    let out_max = vm.active_reg(11) as u32;

    let cap_id = match ctx.frame.get(frame_slot) {
        Some(c) => c,
        None => return Ok(HostCallOutcome::Resume(RC_BAD_CAP, 0)),
    };
    let key = match read_window(vm, key_ptr, key_len, "storage_read key") {
        Ok(b) => b,
        Err(reason) => return Ok(HostCallOutcome::Fault(reason)),
    };
    match storage::storage_read(ctx.state, cap_id, &key)? {
        Some(value) => {
            let to_write = value.len().min(out_max as usize);
            if to_write > 0
                && let Err(reason) =
                    write_window(vm, out_ptr, &value[..to_write], "storage_read out")
            {
                return Ok(HostCallOutcome::Fault(reason));
            }
            Ok(HostCallOutcome::Resume(value.len() as u64, 0))
        }
        None => Ok(HostCallOutcome::Resume(RC_NONE, 0)),
    }
}

fn host_storage_write<H: Hardware>(
    vm: &mut InvocationKernel,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<HostCallOutcome> {
    let frame_slot = vm.active_reg(7) as u8;
    let key_ptr = vm.active_reg(8) as u32;
    let key_len = vm.active_reg(9) as u32;
    let val_ptr = vm.active_reg(10) as u32;
    let val_len = vm.active_reg(11) as u32;

    let cap_id = match ctx.frame.get(frame_slot) {
        Some(c) => c,
        None => return Ok(HostCallOutcome::Resume(RC_BAD_CAP, 0)),
    };
    let key = match read_window(vm, key_ptr, key_len, "storage_write key") {
        Ok(b) => b,
        Err(reason) => return Ok(HostCallOutcome::Fault(reason)),
    };
    let val = match read_window(vm, val_ptr, val_len, "storage_write val") {
        Ok(b) => b,
        Err(reason) => return Ok(HostCallOutcome::Fault(reason)),
    };

    match storage::storage_write(ctx.state, cap_id, &key, &val) {
        Ok(()) => Ok(HostCallOutcome::Resume(RC_OK, 0)),
        Err(KernelError::ReadOnly(_)) => Ok(HostCallOutcome::Resume(RC_READONLY, 0)),
        Err(KernelError::QuotaExceeded { .. }) => Ok(HostCallOutcome::Resume(RC_QUOTA, 0)),
        Err(e) => Err(e),
    }
}

fn host_storage_delete<H: Hardware>(
    vm: &mut InvocationKernel,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<HostCallOutcome> {
    let frame_slot = vm.active_reg(7) as u8;
    let key_ptr = vm.active_reg(8) as u32;
    let key_len = vm.active_reg(9) as u32;

    let cap_id = match ctx.frame.get(frame_slot) {
        Some(c) => c,
        None => return Ok(HostCallOutcome::Resume(RC_BAD_CAP, 0)),
    };
    let key = match read_window(vm, key_ptr, key_len, "storage_delete key") {
        Ok(b) => b,
        Err(reason) => return Ok(HostCallOutcome::Fault(reason)),
    };

    match storage::storage_delete(ctx.state, cap_id, &key) {
        Ok(()) => Ok(HostCallOutcome::Resume(RC_OK, 0)),
        Err(KernelError::ReadOnly(_)) => Ok(HostCallOutcome::Resume(RC_READONLY, 0)),
        Err(e) => Err(e),
    }
}

// -----------------------------------------------------------------------------
// CNode operations
// -----------------------------------------------------------------------------

fn host_cnode_grant<H: Hardware>(
    vm: &mut InvocationKernel,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<HostCallOutcome> {
    // φ[7]=src_frame_slot, φ[8]=dest_cnode_frame_slot, φ[9]=dest_cnode_slot
    let src_slot = vm.active_reg(7) as u8;
    let dest_cnode_slot = vm.active_reg(8) as u8;
    let dest_slot = vm.active_reg(9) as u8;
    let src_cap = match ctx.frame.get(src_slot) {
        Some(c) => c,
        None => return Ok(HostCallOutcome::Resume(RC_BAD_CAP, 0)),
    };
    let dest_cnode_cap = match ctx.frame.get(dest_cnode_slot) {
        Some(c) => c,
        None => return Ok(HostCallOutcome::Resume(RC_BAD_CAP, 0)),
    };
    let dest_cnode_id = match &cap_registry::lookup(ctx.state, dest_cnode_cap)?.cap {
        Capability::CNode { cnode_id } => *cnode_id,
        _ => return Ok(HostCallOutcome::Resume(RC_BAD_CAP, 0)),
    };
    match cnode_ops::cnode_grant(ctx.state, src_cap, dest_cnode_id, dest_slot) {
        Ok(_) => Ok(HostCallOutcome::Resume(RC_OK, 0)),
        Err(KernelError::Pinning(_)) => Ok(HostCallOutcome::Resume(RC_PINNING, 0)),
        Err(e) => Err(e),
    }
}

fn host_cnode_revoke<H: Hardware>(
    vm: &mut InvocationKernel,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<HostCallOutcome> {
    let cnode_frame_slot = vm.active_reg(7) as u8;
    let cnode_slot = vm.active_reg(8) as u8;
    let cnode_cap = match ctx.frame.get(cnode_frame_slot) {
        Some(c) => c,
        None => return Ok(HostCallOutcome::Resume(RC_BAD_CAP, 0)),
    };
    let cnode_id = match &cap_registry::lookup(ctx.state, cnode_cap)?.cap {
        Capability::CNode { cnode_id } => *cnode_id,
        _ => return Ok(HostCallOutcome::Resume(RC_BAD_CAP, 0)),
    };
    cnode_ops::cnode_revoke(ctx.state, cnode_id, cnode_slot)?;
    Ok(HostCallOutcome::Resume(RC_OK, 0))
}

fn host_cnode_move<H: Hardware>(
    vm: &mut InvocationKernel,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<HostCallOutcome> {
    // φ[7]=src_cnode_frame_slot, φ[8]=src_slot, φ[9]=dest_cnode_frame_slot, φ[10]=dest_slot
    let src_cn_fs = vm.active_reg(7) as u8;
    let src_slot = vm.active_reg(8) as u8;
    let dst_cn_fs = vm.active_reg(9) as u8;
    let dst_slot = vm.active_reg(10) as u8;
    let resolve = |state: &jar_types::State, fs: u8| -> KResult<CNodeId> {
        let cap = ctx
            .frame
            .get(fs)
            .ok_or_else(|| KernelError::Internal(format!("frame slot {} empty", fs)))?;
        match &cap_registry::lookup(state, cap)?.cap {
            Capability::CNode { cnode_id } => Ok(*cnode_id),
            _ => Err(KernelError::Internal("expected CNode cap".into())),
        }
    };
    let src_cn = resolve(ctx.state, src_cn_fs)?;
    let dst_cn = resolve(ctx.state, dst_cn_fs)?;
    match cnode_ops::cnode_move(ctx.state, src_cn, src_slot, dst_cn, dst_slot) {
        Ok(_) => Ok(HostCallOutcome::Resume(RC_OK, 0)),
        Err(KernelError::Pinning(_)) => Ok(HostCallOutcome::Resume(RC_PINNING, 0)),
        Err(e) => Err(e),
    }
}

fn host_cap_derive<H: Hardware>(
    vm: &mut InvocationKernel,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<HostCallOutcome> {
    // φ[7]=src_frame_slot, φ[8]=dest_frame_slot, φ[9]=narrowing_ptr, φ[10]=narrowing_len,
    // φ[11]=mode (0=Frame, 1=persistent into a CNode-cap-frame-slot), φ[12]=dest_cnode_frame_slot
    let src_slot = vm.active_reg(7) as u8;
    let dst_slot = vm.active_reg(8) as u8;
    let narr_ptr = vm.active_reg(9) as u32;
    let narr_len = vm.active_reg(10) as u32;
    let mode = vm.active_reg(11);
    let dest_cnode_fs = vm.active_reg(12) as u8;

    let src_cap = match ctx.frame.get(src_slot) {
        Some(c) => c,
        None => return Ok(HostCallOutcome::Resume(RC_BAD_CAP, 0)),
    };
    let narrowing = match read_window(vm, narr_ptr, narr_len, "cap_derive narrowing") {
        Ok(b) => b,
        Err(reason) => return Ok(HostCallOutcome::Fault(reason)),
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
                None => return Ok(HostCallOutcome::Resume(RC_BAD_CAP, 0)),
            };
            let dest_cnode_id = match &cap_registry::lookup(ctx.state, dest_cnode_cap)?.cap {
                Capability::CNode { cnode_id } => *cnode_id,
                _ => return Ok(HostCallOutcome::Resume(RC_BAD_CAP, 0)),
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
                None => return Ok(HostCallOutcome::Resume(RC_BAD_CAP, 0)),
            };
            let dest_cnode_id = match &cap_registry::lookup(ctx.state, dest_cnode_cap)?.cap {
                Capability::CNode { cnode_id } => *cnode_id,
                _ => return Ok(HostCallOutcome::Resume(RC_BAD_CAP, 0)),
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
        _ => return Ok(HostCallOutcome::Resume(RC_BAD_CAP, 0)),
    };
    match cap_registry::derive(ctx.state, src_cap, new_cap, narrowing, dest_persistent) {
        Ok(new_id) => {
            ctx.frame.set(dst_slot, new_id);
            Ok(HostCallOutcome::Resume(new_id.0, 0))
        }
        Err(KernelError::Pinning(_)) => Ok(HostCallOutcome::Resume(RC_PINNING, 0)),
        Err(e) => Err(e),
    }
}

// -----------------------------------------------------------------------------
// cap_call — the universal callable-cap exercise
// -----------------------------------------------------------------------------

fn host_cap_call<H: Hardware>(
    vm: &mut InvocationKernel,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<HostCallOutcome> {
    let cap_fs = vm.active_reg(7) as u8;
    let args_ptr = vm.active_reg(8) as u32;
    let args_len = vm.active_reg(9) as u32;
    let caps_ptr = vm.active_reg(10) as u32;
    let caps_len = vm.active_reg(11) as u32;

    let cap_id = match ctx.frame.get(cap_fs) {
        Some(c) => c,
        None => return Ok(HostCallOutcome::Resume(RC_BAD_CAP, 0)),
    };
    let cap = cap_registry::lookup(ctx.state, cap_id)?.cap.clone();
    let args = match read_window(vm, args_ptr, args_len, "cap_call args") {
        Ok(b) => b,
        Err(reason) => return Ok(HostCallOutcome::Fault(reason)),
    };
    let caps_bytes = match read_window(vm, caps_ptr, caps_len, "cap_call caps") {
        Ok(b) => b,
        Err(reason) => return Ok(HostCallOutcome::Fault(reason)),
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
            Ok(HostCallOutcome::Resume(RC_UNIMPLEMENTED, 0))
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
                return Ok(HostCallOutcome::Resume(RC_OK, 0));
            }
            ctx.commands.push(Command::Dispatch {
                entrypoint: vault_id,
                payload: args,
                caps: caps_bytes_to_vec(&arg_caps),
            });
            Ok(HostCallOutcome::Resume(RC_OK, 0))
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
                return Ok(HostCallOutcome::Resume(RC_OK, 0));
            }
            ctx.commands.push(Command::Dispatch {
                entrypoint: vault_id,
                payload: args,
                caps: caps_bytes_to_vec(&arg_caps),
            });
            Ok(HostCallOutcome::Resume(RC_OK, 0))
        }
        Capability::Schedule { .. } => Ok(HostCallOutcome::Resume(RC_BAD_CAP, 0)),
        _ => Ok(HostCallOutcome::Resume(RC_BAD_CAP, 0)),
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

fn host_vault_initialize<H: Hardware>(
    _vm: &mut InvocationKernel,
    _ctx: &mut InvocationCtx<'_, H>,
) -> KResult<HostCallOutcome> {
    Ok(HostCallOutcome::Resume(RC_UNIMPLEMENTED, 0))
}

// -----------------------------------------------------------------------------
// create_vault, quota_set
// -----------------------------------------------------------------------------

fn host_create_vault<H: Hardware>(
    vm: &mut InvocationKernel,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<HostCallOutcome> {
    let res_fs = vm.active_reg(7) as u8;
    let code_hash_ptr = vm.active_reg(8) as u32;
    let dest_fs = vm.active_reg(9) as u8;

    let res_cap_id = match ctx.frame.get(res_fs) {
        Some(c) => c,
        None => return Ok(HostCallOutcome::Resume(RC_BAD_CAP, 0)),
    };
    let (quota_items, quota_bytes) = match &cap_registry::lookup(ctx.state, res_cap_id)?.cap {
        Capability::Resource(ResourceKind::CreateVault {
            quota_items,
            quota_bytes,
        }) => (*quota_items, *quota_bytes),
        _ => return Ok(HostCallOutcome::Resume(RC_BAD_CAP, 0)),
    };
    let code_hash_bytes = match read_window(vm, code_hash_ptr, 32, "create_vault code_hash") {
        Ok(b) => b,
        Err(reason) => return Ok(HostCallOutcome::Fault(reason)),
    };
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
    Ok(HostCallOutcome::Resume(cap_id.0, new_vault_id.0))
}

fn host_quota_set<H: Hardware>(
    vm: &mut InvocationKernel,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<HostCallOutcome> {
    let res_fs = vm.active_reg(7) as u8;
    let new_items = vm.active_reg(8);
    let new_bytes = vm.active_reg(9);
    let res_cap_id = match ctx.frame.get(res_fs) {
        Some(c) => c,
        None => return Ok(HostCallOutcome::Resume(RC_BAD_CAP, 0)),
    };
    let target = match &cap_registry::lookup(ctx.state, res_cap_id)?.cap {
        Capability::Resource(ResourceKind::SetQuota { target }) => *target,
        _ => return Ok(HostCallOutcome::Resume(RC_BAD_CAP, 0)),
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
    Ok(HostCallOutcome::Resume(RC_OK, 0))
}

// -----------------------------------------------------------------------------
// AttestationCap / ResultCap
// -----------------------------------------------------------------------------

fn host_attest<H: Hardware>(
    vm: &mut InvocationKernel,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<HostCallOutcome> {
    let cap_fs = vm.active_reg(7) as u8;
    let blob_ptr = vm.active_reg(8) as u32;
    let blob_len = vm.active_reg(9) as u32;
    let cap_id = match ctx.frame.get(cap_fs) {
        Some(c) => c,
        None => return Ok(HostCallOutcome::Resume(RC_BAD_CAP, 0)),
    };
    let cap = cap_registry::lookup(ctx.state, cap_id)?.cap.clone();
    let blob_owned = if blob_len > 0 {
        match read_window(vm, blob_ptr, blob_len, "attest blob") {
            Ok(b) => Some(b),
            Err(reason) => return Ok(HostCallOutcome::Fault(reason)),
        }
    } else {
        None
    };
    let scope = match &cap {
        Capability::AttestationCap { scope, .. } => *scope,
        _ => return Ok(HostCallOutcome::Resume(RC_BAD_CAP, 0)),
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
    Ok(HostCallOutcome::Resume(
        if outcome.as_bool() { 1 } else { 0 },
        0,
    ))
}

fn host_attestation_key<H: Hardware>(
    vm: &mut InvocationKernel,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<HostCallOutcome> {
    let cap_fs = vm.active_reg(7) as u8;
    let out_ptr = vm.active_reg(8) as u32;
    let cap_id = match ctx.frame.get(cap_fs) {
        Some(c) => c,
        None => return Ok(HostCallOutcome::Resume(RC_BAD_CAP, 0)),
    };
    let cap = cap_registry::lookup(ctx.state, cap_id)?.cap.clone();
    let key = attest::key_of(&cap)?;
    let key_bytes = key.as_ref().to_vec();
    let key_len = key_bytes.len() as u64;
    if let Err(reason) = write_window(vm, out_ptr, &key_bytes, "attestation_key out") {
        return Ok(HostCallOutcome::Fault(reason));
    }
    Ok(HostCallOutcome::Resume(key_len, 0))
}

fn host_result_equal<H: Hardware>(
    vm: &mut InvocationKernel,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<HostCallOutcome> {
    let blob_ptr = vm.active_reg(7) as u32;
    let blob_len = vm.active_reg(8) as u32;
    let blob = match read_window(vm, blob_ptr, blob_len, "result_equal blob") {
        Ok(b) => b,
        Err(reason) => return Ok(HostCallOutcome::Fault(reason)),
    };
    if ctx.attest_cursor.result_pos < ctx.result_trace.len() {
        let recorded = &ctx.result_trace[ctx.attest_cursor.result_pos];
        let eq = recorded.blob == blob;
        ctx.attest_cursor.result_pos += 1;
        return Ok(HostCallOutcome::Resume(if eq { 1 } else { 0 }, 0));
    }
    ctx.result_trace.push(ResultEntry { blob });
    ctx.attest_cursor.result_pos += 1;
    Ok(HostCallOutcome::Resume(1, 0))
}

// -----------------------------------------------------------------------------
// slot_clear — only valid at step-3.
// -----------------------------------------------------------------------------

fn host_slot_clear<H: Hardware>(
    _vm: &mut InvocationKernel,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<HostCallOutcome> {
    if !matches!(ctx.role, KernelRole::AggregateMerge) {
        return Ok(HostCallOutcome::Fault(
            "slot_clear is only valid in step-3".into(),
        ));
    }
    if ctx.slot_emission.is_some() {
        return Err(KernelError::Internal(
            "step-3 emitted more than one slot replacement".into(),
        ));
    }
    *ctx.slot_emission = Some(SlotContent::Empty);
    Ok(HostCallOutcome::Resume(RC_OK, 0))
}

// -----------------------------------------------------------------------------
// slot_read — only valid at step-3. Surfaces prev_slot SCALE bytes.
// -----------------------------------------------------------------------------

fn host_slot_read<H: Hardware>(
    vm: &mut InvocationKernel,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<HostCallOutcome> {
    let out_ptr = vm.active_reg(7) as u32;
    let out_max = vm.active_reg(8) as u32;
    let prev = match ctx.prev_slot {
        Some(p) => p,
        None => {
            return Ok(HostCallOutcome::Fault("slot_read outside step-3".into()));
        }
    };
    let bytes = encode_slot(prev);
    let to_write = bytes.len().min(out_max as usize);
    if to_write > 0
        && let Err(reason) = write_window(vm, out_ptr, &bytes[..to_write], "slot_read out")
    {
        return Ok(HostCallOutcome::Fault(reason));
    }
    Ok(HostCallOutcome::Resume(bytes.len() as u64, 0))
}

/// Canonical encoding of `SlotContent` for `host_slot_read`. Mirrors the
/// shape used in state-root encoding — flat, length-prefixed, kernel-static.
fn encode_slot(slot: &SlotContent) -> Vec<u8> {
    let mut buf = Vec::new();
    match slot {
        SlotContent::Empty => {
            buf.push(0);
        }
        SlotContent::AggregatedDispatch {
            payload,
            caps,
            attestation_trace,
            result_trace,
        } => {
            buf.push(1);
            push_bytes(&mut buf, payload);
            push_bytes(&mut buf, caps);
            push_u64(&mut buf, attestation_trace.len() as u64);
            for a in attestation_trace {
                push_bytes(&mut buf, &a.key.0);
                buf.extend_from_slice(a.blob_hash.as_ref());
                push_bytes(&mut buf, &a.signature.0);
            }
            push_u64(&mut buf, result_trace.len() as u64);
            for r in result_trace {
                push_bytes(&mut buf, &r.blob);
            }
        }
        SlotContent::AggregatedTransact {
            target,
            payload,
            caps,
            attestation_trace,
            result_trace,
        } => {
            buf.push(2);
            push_u64(&mut buf, target.0);
            push_bytes(&mut buf, payload);
            push_bytes(&mut buf, caps);
            push_u64(&mut buf, attestation_trace.len() as u64);
            for a in attestation_trace {
                push_bytes(&mut buf, &a.key.0);
                buf.extend_from_slice(a.blob_hash.as_ref());
                push_bytes(&mut buf, &a.signature.0);
            }
            push_u64(&mut buf, result_trace.len() as u64);
            for r in result_trace {
                push_bytes(&mut buf, &r.blob);
            }
        }
    }
    buf
}

fn push_u64(buf: &mut Vec<u8>, x: u64) {
    buf.extend_from_slice(&x.to_le_bytes());
}

fn push_bytes(buf: &mut Vec<u8>, b: &[u8]) {
    push_u64(buf, b.len() as u64);
    buf.extend_from_slice(b);
}
