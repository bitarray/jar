//! Invocation driver for `javm::kernel::InvocationKernel`.
//!
//! `drive_invocation` runs a real PVM VM until terminal (Halt / Panic /
//! PageFault / OutOfGas), routing every `ProtocolCall(slot)` through
//! `host_calls::dispatch_host_call`. Each handler returns a
//! `HostCallOutcome` — either `Resume(r0, r1)` (the loop calls
//! `vm.resume_protocol_call` and continues) or `Fault(reason)` (the
//! invocation rolls back gracefully).
//!
//! Memory windows in the kernel are not flat: the guest reads/writes its
//! own DATA caps. The kernel routes through `read_data_cap_window` /
//! `write_data_cap_window`; failures are guest-driven faults, not kernel
//! errors.

use jar_types::{
    AttestationEntry, Caller, Command, KResult, KernelError, KernelRole, ResultEntry, SlotContent,
    State, VaultId,
};

use crate::attest::AttestCursor;
use crate::frame::Frame;
use crate::host_abi::HostCall;
use crate::reach::ReachSet;
use crate::runtime::Hardware;

/// Default per-invocation gas budget. javm charges per instruction and per
/// memory cycle; this matches the magnitude javm's own tests use.
///
// TODO(spec): per-event gas budget should come from Event/cap.
pub const INVOCATION_GAS_BUDGET: u64 = 100_000_000;

/// Per-invocation kernel-side context. Carried by reference into every
/// host-call handler.
///
/// Storage authority is encoded in the `Frame`'s caps. Transact / Schedule
/// frames carry `Storage` (overlay) caps; Dispatch step-2/3 frames carry
/// `SnapshotStorage` caps.
pub struct InvocationCtx<'a, H: Hardware> {
    pub state: &'a mut State,
    pub role: KernelRole,
    pub current_vault: VaultId,
    pub frame: Frame,
    pub caller: Caller,
    pub commands: &'a mut Vec<Command>,
    pub reach: &'a mut ReachSet,
    pub attest_cursor: &'a mut AttestCursor,
    pub attestation_trace: &'a mut Vec<AttestationEntry>,
    pub result_trace: &'a mut Vec<ResultEntry>,
    /// Step-3-only: the slot emission, populated by `cap_call` or
    /// `slot_clear`. The kernel rejects if set twice.
    pub slot_emission: &'a mut Option<SlotContent>,
    /// Step-3-only: prior-slot bytes for the entrypoint, surfaced to the
    /// guest via `HostCall::SlotRead`. `None` outside step-3.
    pub prev_slot: Option<&'a SlotContent>,
    pub hw: &'a H,
}

/// The result of running one top-level invocation.
#[derive(Debug)]
pub struct InvocationResult {
    pub halt_value: Option<u64>,
    pub fault: Option<String>,
}

impl InvocationResult {
    pub fn ok(rv: u64) -> Self {
        Self {
            halt_value: Some(rv),
            fault: None,
        }
    }
    pub fn fault(reason: impl Into<String>) -> Self {
        Self {
            halt_value: None,
            fault: Some(reason.into()),
        }
    }
    pub fn is_ok(&self) -> bool {
        self.fault.is_none()
    }
}

/// What a host-call handler tells the driver to do next.
#[derive(Debug)]
pub enum HostCallOutcome {
    /// Resume the VM with these `(φ[7], φ[8])` values.
    Resume(u64, u64),
    /// Treat as a graceful invocation fault (rolls back σ at the caller).
    Fault(String),
}

/// Drive a real javm VM to a terminal state, routing each ProtocolCall to
/// the kernel's host-call dispatcher.
pub fn drive_invocation<H: Hardware>(
    vm: &mut javm::kernel::InvocationKernel,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<InvocationResult> {
    loop {
        match vm.run() {
            javm::kernel::KernelResult::Halt(rv) => return Ok(InvocationResult::ok(rv)),
            javm::kernel::KernelResult::Panic => return Ok(InvocationResult::fault("guest panic")),
            javm::kernel::KernelResult::OutOfGas => return Err(KernelError::OutOfGas),
            javm::kernel::KernelResult::PageFault(addr) => {
                return Ok(InvocationResult::fault(format!(
                    "page fault at {:#x}",
                    addr
                )));
            }
            javm::kernel::KernelResult::ProtocolCall { slot } => {
                let call = HostCall::from_slot(slot)?;
                match crate::host_calls::dispatch_host_call(call, vm, ctx)? {
                    HostCallOutcome::Resume(r0, r1) => vm.resume_protocol_call(r0, r1),
                    HostCallOutcome::Fault(reason) => return Ok(InvocationResult::fault(reason)),
                }
            }
        }
    }
}
