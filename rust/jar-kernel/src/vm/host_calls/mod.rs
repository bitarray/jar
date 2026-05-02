//! Kernel host-call handlers + the dispatcher that routes a
//! `KernelResult::ProtocolCall { slot }` to the appropriate handler.
//!
//! Each handler takes `&mut javm::kernel::InvocationKernel` directly —
//! no VM-abstraction trait. Args flow in via `vm.active_reg(N)`; return
//! values flow back in `(r0, r1)` via `HostCallOutcome::Resume`. Memory
//! windows address guest DATA caps via `read_data_cap_window` /
//! `write_data_cap_window`; bad windows are guest-driven faults, not
//! kernel errors.
//!
//! Dispatch flow: `drive_invocation` reads the cap at the firing
//! `slot` and matches on the `ProtocolCap` variant — there is no slot
//! number → host call mapping table; the cap value at the slot is the
//! selector.

pub mod attest;
pub mod emit;
pub mod score;

use crate::cap::ProtocolCap;
use crate::runtime::Hardware;
use crate::types::KResult;
use crate::vm::{HostCallOutcome, InvocationCtx, Vm};

/// Fetch the protocol-cap payload held at `slot` in the running VM's
/// cap-table, if any. Returns `None` for empty slots and non-Protocol
/// cells.
pub(crate) fn fetch_protocol_cap(vm: &Vm, slot: u8) -> Option<ProtocolCap> {
    match vm.cap_table_get(slot) {
        Some(javm::cap::Cap::Protocol(kc)) => Some(kc.clone()),
        _ => None,
    }
}

/// Dispatch a `ProtocolCall` to the matching host handler based on the
/// cap variant at `slot`. An empty slot or a slot holding a non-host-
/// call cap is a guest fault.
pub fn dispatch_protocol_call<H: Hardware>(
    slot: u8,
    vm: &mut Vm,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<HostCallOutcome> {
    let cap = match fetch_protocol_cap(vm, slot) {
        Some(c) => c,
        None => {
            return Ok(HostCallOutcome::Fault(format!(
                "ProtocolCall: slot {slot} holds no protocol cap"
            )));
        }
    };
    match cap {
        ProtocolCap::EmitEvent => emit::host_emit_event(vm, ctx),
        ProtocolCap::MintAttestCap => attest::host_mint_attest_cap(vm, ctx),
        ProtocolCap::SetScore => score::host_set_score(vm, ctx),
        other => Ok(HostCallOutcome::Fault(format!(
            "ProtocolCall: slot {slot} cap is not a host-call cap: {other:?}"
        ))),
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
