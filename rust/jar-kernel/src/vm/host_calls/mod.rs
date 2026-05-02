//! Kernel host-call handlers.
//!
//! Each handler takes `&mut javm::kernel::InvocationKernel` directly —
//! no VM-abstraction trait. Args flow in via `vm.active_reg(N)`; return
//! values flow back in `(r0, r1)` via `HostCallOutcome::Resume`. Memory
//! windows address guest DATA caps via `read_data_cap_window` /
//! `write_data_cap_window`; bad windows are guest-driven faults, not
//! kernel errors.
//!
//! Dispatch is `ProtocolCap::call`-driven: `drive_invocation` reads
//! the cap at the firing slot and calls `cap.call(vm, ctx)`. The cap
//! variant is the selector. See `cap::protocol::ProtocolCap::call`.

pub mod attest;
pub mod emit;
pub mod score;

use crate::vm::Vm;

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
