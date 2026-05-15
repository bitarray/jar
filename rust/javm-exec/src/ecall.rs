//! `EcallHandler` trait: how the execution engine dispatches ecalls
//! to the integration layer.
//!
//! Per architecture: the engine knows there are ecalls (one PVM
//! opcode) and that each ecall carries a u32 opcode payload. It
//! doesn't know what that opcode *means*. The caller supplies an
//! `EcallHandler` implementation that interprets ecall opcodes as
//! MGMT operations, host-call selectors, CALL / HALT / yield
//! transfers, etc.
//!
//! The handler may either:
//!
//! - Finish synchronously and return `Continue` — the engine
//!   advances PC past the ecall instruction (already done before
//!   the handler runs) and keeps executing. Used for purely-stateful
//!   ecalls (MGMT_COPY, MGMT_MOVE, etc.) that just mutate `regs` /
//!   `mem` and resume.
//!
//! - Return `Exit(reason)` — the engine returns this `ExitReason`
//!   from its `execute()` call. Used for control-flow ecalls (HALT,
//!   yield, CALL into another Instance) that require the
//!   integration layer to take over.

use crate::exit::ExitReason;
use crate::mem::Mem;
use crate::regs::Regs;

/// Result of handling one ecall.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EcallResult {
    /// Engine continues at the current PC (advanced past the ecall).
    Continue,
    /// Engine exits with the given reason.
    Exit(ExitReason),
}

/// Trait the integration layer implements to interpret ecall opcodes.
///
/// `op` is the raw 32-bit ecall payload (per the PVM `ecalli`
/// instruction). The engine has already validated the ecall encoding
/// and advanced PC past the instruction; the handler operates on
/// the post-advance register/memory state.
pub trait EcallHandler {
    fn handle(&mut self, op: u32, regs: &mut Regs, mem: &mut Mem) -> EcallResult;
}

/// A no-op handler: every ecall exits with `Panic`. Useful as a
/// default for tests where the engine isn't supposed to encounter
/// ecalls.
#[derive(Debug, Default)]
pub struct PanickingHandler;

impl EcallHandler for PanickingHandler {
    fn handle(&mut self, _op: u32, _regs: &mut Regs, _mem: &mut Mem) -> EcallResult {
        EcallResult::Exit(ExitReason::Panic)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panicking_handler_always_exits_panic() {
        let mut h = PanickingHandler;
        let mut regs = Regs::new();
        let mut mem = Mem::new();
        assert_eq!(
            h.handle(0, &mut regs, &mut mem),
            EcallResult::Exit(ExitReason::Panic)
        );
        assert_eq!(
            h.handle(42, &mut regs, &mut mem),
            EcallResult::Exit(ExitReason::Panic)
        );
    }

    /// A handler that increments φ₀ on every ecall and continues.
    /// Useful for exercising the loop-around-handler pattern.
    struct CountingHandler {
        count: u32,
    }
    impl EcallHandler for CountingHandler {
        fn handle(&mut self, _op: u32, regs: &mut Regs, _mem: &mut Mem) -> EcallResult {
            self.count += 1;
            regs.write(0, regs.read(0).wrapping_add(1));
            EcallResult::Continue
        }
    }

    #[test]
    fn counting_handler_mutates_regs_and_continues() {
        let mut h = CountingHandler { count: 0 };
        let mut regs = Regs::new();
        let mut mem = Mem::new();
        assert_eq!(h.handle(1, &mut regs, &mut mem), EcallResult::Continue);
        assert_eq!(regs.read(0), 1);
        assert_eq!(h.handle(2, &mut regs, &mut mem), EcallResult::Continue);
        assert_eq!(regs.read(0), 2);
        assert_eq!(h.count, 2);
    }
}
