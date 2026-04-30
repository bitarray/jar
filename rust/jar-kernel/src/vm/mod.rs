//! Invocation driver for `javm::kernel::InvocationKernel<KernelCap>`.
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
//!
//! Per-invocation kernel caps (Storage, SnapshotStorage) live in the
//! running VM's javm cap-table at `KERNEL_CAP_SLOT`. Host calls fetch
//! them via `vm.cap_table_get(slot)`. There is no separate kernel-side
//! `Frame` struct any more.

use crate::types::{
    AttestationEntry, Caller, Command, KResult, KernelError, KernelRole, ResultEntry, SlotContent,
    State, VaultId,
};

pub mod foreign_cnode;
pub mod host_abi;
pub mod host_calls;

use crate::cap::KernelCap;
use crate::cap::attest::AttestCursor;
use crate::reach::ReachSet;
use crate::runtime::Hardware;
use crate::vm::host_abi::HostCall;

/// Default per-invocation gas budget. javm charges per instruction and per
/// memory cycle; this matches the magnitude javm's own tests use.
///
// TODO(spec): per-event gas budget should come from Event/cap.
pub const INVOCATION_GAS_BUDGET: u64 = 100_000_000;

/// Convenience alias: the `InvocationKernel` parameterized over the
/// kernel's protocol-cap payload.
pub type Vm = javm::kernel::InvocationKernel<KernelCap>;

/// Per-invocation kernel-side context. Carried by reference into every
/// host-call handler.
///
/// Storage authority is encoded in the running VM's cap-table:
/// Transact / Schedule invocations place `Storage` (overlay) caps;
/// Dispatch step-2/3 invocations place `SnapshotStorage` caps.
pub struct InvocationCtx<'a, H: Hardware> {
    pub state: &'a mut State,
    pub role: KernelRole,
    pub current_vault: VaultId,
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
///
/// On every iteration of the run loop, we construct a fresh
/// [`foreign_cnode::VaultCnodeView`] borrowing `ctx.state`. javm
/// consults this adapter for slot operations on `FrameId::Foreign`
/// frames produced by its resolve walk (i.e. when the guest does
/// `MGMT_MOVE` / `MGMT_COPY` / `MGMT_DROP` against a cap-ref that
/// crosses through a `VaultRef`). The adapter is rebuilt each
/// iteration because borrowing `&mut State` consumes the borrow until
/// the view drops.
pub fn drive_invocation<H: Hardware>(
    vm: &mut Vm,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<InvocationResult> {
    loop {
        let outcome = {
            let mut view = foreign_cnode::VaultCnodeView::new(&mut *ctx.state);
            vm.run_with_host(&mut view)
        };
        match outcome {
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
                match crate::vm::host_calls::dispatch_host_call(call, vm, ctx)? {
                    HostCallOutcome::Resume(r0, r1) => vm.resume_protocol_call(r0, r1),
                    HostCallOutcome::Fault(reason) => return Ok(InvocationResult::fault(reason)),
                }
            }
        }
    }
}
