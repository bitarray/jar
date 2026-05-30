//! `EcallHandler` trait: how the execution engine dispatches ecalls
//! to the integration layer.
//!
//! Per architecture: the engine knows there are ecalls and that each
//! carries a kind (custom-0 `ecall.jar`, funct3=001, no immediate, vs
//! custom-0 `ecalli`, funct3=010, with a sign-extended imm12 carried
//! as a u32). It doesn't know what the kind *means*. The caller
//! supplies an `EcallHandler` that interprets ecalls as MGMT
//! operations, host-call selectors, CALL / HALT / yield transfers, etc.
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

/// Which custom-0 ecall encoding triggered this invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcallKind {
    /// `ecall.jar` (custom-0 funct3=001). No immediate; the handler
    /// reads the operand registers per the ABI convention it defines.
    Ecall,
    /// `ecalli imm` (custom-0 funct3=010). Carries the sign-extended
    /// imm12 as a u32 payload.
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
