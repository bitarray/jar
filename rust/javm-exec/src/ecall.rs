//! `EcallHandler` trait: how the execution engine dispatches ecalls
//! to the integration layer.
//!
//! Per architecture: the engine knows there are ecalls and that each
//! carries a kind (PVM `ecall` opcode 3 with no immediate, vs PVM
//! `ecalli` opcode 10 with a u32 immediate). It doesn't know what the
//! kind *means*. The caller supplies an `EcallHandler` that
//! interprets ecalls as MGMT operations, host-call selectors, CALL /
//! HALT / yield transfers, etc.
//!
//! The handler may either:
//!
//! - Return `Continue` — engine continues at the current PC
//!   (already advanced past the ecall instruction before the handler
//!   runs). Used for purely-stateful ecalls (MGMT_COPY, MGMT_MOVE,
//!   etc.) that just mutate `regs` / `mem` and resume.
//!
//! - Return `Exit(reason)` — engine returns this `ExitReason` from
//!   `execute()`. Used for control-flow ecalls (HALT, yield, CALL
//!   into another Instance) that require the integration layer.

use crate::exit::ExitReason;
use crate::mem::Memory;
use crate::regs::Regs;

/// Which PVM ecall opcode triggered this invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcallKind {
    /// PVM `ecall` (opcode 3). No immediate; the handler reads
    /// `regs[11]` (mgmt op) and `regs[12]` (subject|object) per the
    /// v3 ABI convention.
    Ecall,
    /// PVM `ecalli` (opcode 10). Carries a u32 immediate payload.
    Ecalli(u32),
}

/// Result of handling one ecall.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EcallResult {
    /// Engine continues at the current PC (advanced past the ecall).
    Continue,
    /// Engine exits with the given reason.
    Exit(ExitReason),
}

/// Trait the integration layer implements to interpret ecalls.
///
/// PC has been advanced past the instruction by the engine; the
/// handler operates on the post-advance register/memory state.
pub trait EcallHandler {
    fn handle(&mut self, kind: EcallKind, regs: &mut Regs, mem: &mut dyn Memory) -> EcallResult;
}

/// A no-op handler: every ecall exits with `Panic`. Useful as a
/// default for tests where the engine isn't supposed to encounter
/// ecalls.
#[derive(Debug, Default)]
pub struct PanickingHandler;

impl EcallHandler for PanickingHandler {
    fn handle(&mut self, _kind: EcallKind, _regs: &mut Regs, _mem: &mut dyn Memory) -> EcallResult {
        EcallResult::Exit(ExitReason::Panic)
    }
}
