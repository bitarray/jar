//! Kernel host calls (see `HostCall`).
//!
//! Each handler takes `&mut javm::kernel::InvocationKernel` directly —
//! no VM-abstraction trait. Args flow in via `vm.active_reg(N)`; return
//! values flow back in `(r0, r1)` via `HostCallOutcome::Resume`. Memory
//! windows address guest DATA caps via `read_data_cap_window` /
//! `write_data_cap_window`; bad windows are guest-driven faults, not
//! kernel errors.
//!
//! This module is the dispatcher; the per-call handlers live in sibling
//! files (`emit`, `attest`, `score`). The handlers are stubbed during
//! the migration — concrete implementations land in Stage D.

pub mod attest;
pub mod emit;
pub mod score;

use crate::cap::KernelCap;
use crate::runtime::Hardware;
use crate::types::KResult;
use crate::vm::host_abi::*;
use crate::vm::{HostCallOutcome, InvocationCtx, Vm};

/// Fetch the kernel cap held at `slot` in the running VM's cap-table,
/// if any. Returns `None` for empty slots and non-Protocol cells.
#[allow(dead_code)] // stubbed during event-redesign migration; rewired in Stage D
pub(crate) fn fetch_kernel_cap(vm: &Vm, slot: u8) -> Option<&KernelCap> {
    match vm.cap_table_get(slot) {
        Some(javm::cap::Cap::Protocol(kc)) => Some(kc),
        _ => None,
    }
}

/// Top-level host-call dispatcher.
pub fn dispatch_host_call<H: Hardware>(
    call: HostCall,
    vm: &mut Vm,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<HostCallOutcome> {
    match call {
        HostCall::EmitEvent => emit::host_emit_event(vm, ctx),
        HostCall::MintAttestCap => attest::host_mint_attest_cap(vm, ctx),
        HostCall::SetScore => score::host_set_score(vm, ctx),
    }
}

/// Read a guest memory window or return a guest fault outcome.
#[allow(dead_code)] // stubbed during event-redesign migration; rewired in Stage D
pub(crate) fn read_window(vm: &Vm, addr: u32, len: u32, what: &str) -> Result<Vec<u8>, String> {
    if len == 0 {
        return Ok(Vec::new());
    }
    vm.read_data_cap_window(addr, len)
        .ok_or_else(|| format!("{what}: bad read window @ {addr:#x}+{len}"))
}

/// Write to a guest memory window or return a guest fault outcome.
#[allow(dead_code)] // stubbed during event-redesign migration; rewired in Stage D
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
