//! The kernel host calls (see `HostCall`).
//!
//! Each handler takes `&mut javm::kernel::InvocationKernel` directly — no
//! VM-abstraction trait. Args flow in via `vm.active_reg(N)`; return values
//! flow back in `(r0, r1)` via `HostCallOutcome::Resume`. Memory windows
//! address guest DATA caps via `read_data_cap_window` /
//! `write_data_cap_window`; bad windows are guest-driven faults, not
//! kernel errors.
//!
//! This module is the dispatcher; the per-concern handlers live in
//! sibling files (`storage`, `cap`, `attest`, `slot`).

pub mod attest;
pub mod cap;
pub mod slot;
pub mod storage;

use crate::cap::KernelCap;
use crate::runtime::Hardware;
use crate::types::{Caller, Capability, KResult, KernelRole};
use crate::vm::host_abi::*;
use crate::vm::{HostCallOutcome, InvocationCtx, Vm};

/// Fetch the kernel `Capability` value held at `slot` in the running
/// VM's cap-table, if any. Returns `None` for empty slots, host-call
/// selector slots (`KernelCap::HostCall`), or non-Protocol caps.
pub(crate) fn fetch_kernel_cap(vm: &Vm, slot: u8) -> Option<&Capability> {
    match vm.cap_table_get(slot) {
        Some(javm::cap::Cap::Protocol(KernelCap::Cap(c))) => Some(c),
        _ => None,
    }
}

/// Top-level host-call dispatcher. Returns the action the driver should
/// take next: resume the VM with `(r0, r1)` or fault the invocation.
pub fn dispatch_host_call<H: Hardware>(
    call: HostCall,
    vm: &mut Vm,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<HostCallOutcome> {
    match call {
        HostCall::Gas => Ok(HostCallOutcome::Resume(vm.active_gas(), 0)),
        HostCall::SelfId => Ok(HostCallOutcome::Resume(ctx.current_vault.0, 0)),
        HostCall::Caller => {
            let (r0, r1) = encode_caller(&ctx.caller);
            Ok(HostCallOutcome::Resume(r0, r1))
        }
        HostCall::StorageRead => storage::host_storage_read(vm, ctx),
        HostCall::StorageWrite => storage::host_storage_write(vm, ctx),
        HostCall::StorageDelete => storage::host_storage_delete(vm, ctx),
        HostCall::CapDerive => cap::host_cap_derive(vm, ctx),
        HostCall::VaultInitialize => cap::host_vault_initialize(vm, ctx),
        HostCall::CreateVault => cap::host_create_vault(vm, ctx),
        HostCall::QuotaSet => cap::host_quota_set(vm, ctx),
        HostCall::Attest => attest::host_attest(vm, ctx),
        HostCall::AttestationKey => attest::host_attestation_key(vm, ctx),
        HostCall::AttestationAggregate => Ok(HostCallOutcome::Resume(0, 0)),
        HostCall::ResultEqual => attest::host_result_equal(vm, ctx),
        HostCall::SlotClear => slot::host_slot_clear(vm, ctx),
        HostCall::SlotEmit => Ok(HostCallOutcome::Resume(RC_UNIMPLEMENTED, 0)),
        HostCall::SlotRead => slot::host_slot_read(vm, ctx),
    }
}

/// Read a guest memory window or return a guest fault outcome.
pub(crate) fn read_window(vm: &Vm, addr: u32, len: u32, what: &str) -> Result<Vec<u8>, String> {
    if len == 0 {
        return Ok(Vec::new());
    }
    vm.read_data_cap_window(addr, len)
        .ok_or_else(|| format!("{}: bad read window @ {:#x}+{}", what, addr, len))
}

/// Write to a guest memory window or return a guest fault outcome.
pub(crate) fn write_window(vm: &mut Vm, addr: u32, data: &[u8], what: &str) -> Result<(), String> {
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
