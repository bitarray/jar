//! Interpreter: simple step-by-step PVM execution.
//!
//! **v0 scope is minimal.** v3 doesn't change the PVM instruction
//! set, so the long-term goal is full coverage of the JAM Gray
//! Paper Appendix A.5 opcode list (see v2 `javm/src/instruction.rs`
//! for the canonical list). For now, the interpreter handles
//! enough instructions to validate the architecture end-to-end:
//! load-immediate, arithmetic, ecall, halt, trap.
//!
//! The instruction representation is also minimal — instructions
//! are stored as a `Vec<Instruction>` rather than the byte-level
//! PVM encoding. When the cap layer + integration crate are ready,
//! we'll wire up the real PVM byte-encoded program loader and the
//! instruction-set coverage grows incrementally.
//!
//! What we *do* validate at this layer:
//! - The execute-step-by-step loop structure.
//! - Gas charging per instruction (placeholder constant cost).
//! - `EcallHandler` plumbing (`Continue` vs `Exit`).
//! - `ExitReason` produced at each natural termination point.

use crate::ecall::{EcallHandler, EcallResult};
use crate::exit::ExitReason;
use crate::gas::GasCounter;
use crate::mem::Mem;
use crate::regs::Regs;

/// Minimal v0 instruction set.
///
/// All instructions take 1 unit of gas (placeholder; the real
/// per-instruction cost table lands when we cherry-pick `gas_cost`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Instruction {
    /// Halt with `ExitReason::Halt`.
    Halt,
    /// Deliberate trap (opcode 0 in PVM). Returns `ExitReason::Trap`.
    Trap,
    /// No-op. Advances PC by one. Useful for tests.
    Nop,
    /// `regs[dst] = imm`.
    LoadImm { dst: u8, imm: u64 },
    /// `regs[dst] = regs[a] + regs[b]` (wrapping).
    Add { dst: u8, a: u8, b: u8 },
    /// `regs[dst] = regs[a] - regs[b]` (wrapping).
    Sub { dst: u8, a: u8, b: u8 },
    /// Ecall with the given u32 opcode. Dispatched to the
    /// `EcallHandler`. If the handler returns `Continue`, PC is
    /// advanced normally; if `Exit(reason)`, the interpreter returns
    /// with that reason.
    Ecalli(u32),
}

/// Placeholder per-instruction gas cost. The real cost table is
/// cherry-picked later.
pub const GAS_COST_PER_INSN: u64 = 1;

/// The interpreter is a stateless namespace; `execute` is a free
/// function on an immutable program plus mutable regs/mem/gas.
pub struct Interpreter;

impl Interpreter {
    /// Execute instructions starting at `regs.pc`. Returns the
    /// terminal `ExitReason`. After return, `regs.pc` reflects the
    /// last advanced PC (so a `HostCall` caller can inspect /
    /// resume).
    pub fn execute(
        program: &[Instruction],
        regs: &mut Regs,
        mem: &mut Mem,
        gas: &mut GasCounter,
        handler: &mut dyn EcallHandler,
    ) -> ExitReason {
        loop {
            // Out-of-program: treat as Panic (caller should never run
            // past the end).
            let pc = regs.pc as usize;
            if pc >= program.len() {
                return ExitReason::Panic;
            }

            // Charge gas before executing.
            if gas.charge(GAS_COST_PER_INSN).is_err() {
                return ExitReason::OutOfGas;
            }

            let insn = program[pc];

            // Advance PC *before* executing (so handlers see the
            // post-advance PC).
            regs.pc = regs.pc.wrapping_add(1);

            match insn {
                Instruction::Halt => return ExitReason::Halt,
                Instruction::Trap => return ExitReason::Trap,
                Instruction::Nop => {}
                Instruction::LoadImm { dst, imm } => {
                    regs.write(dst as usize, imm);
                }
                Instruction::Add { dst, a, b } => {
                    let va = regs.read(a as usize);
                    let vb = regs.read(b as usize);
                    regs.write(dst as usize, va.wrapping_add(vb));
                }
                Instruction::Sub { dst, a, b } => {
                    let va = regs.read(a as usize);
                    let vb = regs.read(b as usize);
                    regs.write(dst as usize, va.wrapping_sub(vb));
                }
                Instruction::Ecalli(op) => {
                    match handler.handle(crate::EcallKind::Ecalli(op), regs, mem) {
                        EcallResult::Continue => {}
                        EcallResult::Exit(reason) => return reason,
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecall::PanickingHandler;

    /// Helper: run program from PC=0 with a fresh state.
    fn run(program: &[Instruction], gas: u64) -> (ExitReason, Regs, u64) {
        let mut regs = Regs::new();
        let mut mem = Mem::new();
        let mut g = GasCounter::new(gas);
        let mut h = PanickingHandler;
        let reason = Interpreter::execute(program, &mut regs, &mut mem, &mut g, &mut h);
        (reason, regs, g.remaining())
    }

    #[test]
    fn halt_immediately_returns_halt() {
        let prog = [Instruction::Halt];
        let (r, _, remaining) = run(&prog, 100);
        assert_eq!(r, ExitReason::Halt);
        assert_eq!(remaining, 99); // 1 instruction × 1 gas
    }

    #[test]
    fn trap_returns_trap() {
        let prog = [Instruction::Trap];
        let (r, _, _) = run(&prog, 100);
        assert_eq!(r, ExitReason::Trap);
    }

    #[test]
    fn add_two_numbers_then_halt() {
        // r1 = 5; r2 = 7; r0 = r1 + r2; halt.
        let prog = [
            Instruction::LoadImm { dst: 1, imm: 5 },
            Instruction::LoadImm { dst: 2, imm: 7 },
            Instruction::Add { dst: 0, a: 1, b: 2 },
            Instruction::Halt,
        ];
        let (r, regs, _) = run(&prog, 100);
        assert_eq!(r, ExitReason::Halt);
        assert_eq!(regs.read(0), 12);
        assert_eq!(regs.read(1), 5);
        assert_eq!(regs.read(2), 7);
    }

    #[test]
    fn sub_works() {
        let prog = [
            Instruction::LoadImm { dst: 1, imm: 10 },
            Instruction::LoadImm { dst: 2, imm: 3 },
            Instruction::Sub { dst: 0, a: 1, b: 2 },
            Instruction::Halt,
        ];
        let (_, regs, _) = run(&prog, 100);
        assert_eq!(regs.read(0), 7);
    }

    #[test]
    fn out_of_gas_terminates_with_outofgas() {
        let prog = [
            Instruction::LoadImm { dst: 0, imm: 1 },
            Instruction::LoadImm { dst: 0, imm: 2 },
            Instruction::LoadImm { dst: 0, imm: 3 },
            Instruction::Halt,
        ];
        let (r, _, _) = run(&prog, 2);
        // 2 charges succeed; 3rd charge fails.
        assert_eq!(r, ExitReason::OutOfGas);
    }

    #[test]
    fn pc_past_end_panics() {
        let prog: [Instruction; 0] = [];
        let (r, _, _) = run(&prog, 100);
        assert_eq!(r, ExitReason::Panic);
    }

    #[test]
    fn nop_advances_pc() {
        let prog = [Instruction::Nop, Instruction::Halt];
        let (r, regs, _) = run(&prog, 100);
        assert_eq!(r, ExitReason::Halt);
        assert_eq!(regs.pc, 2);
    }

    /// Custom handler: every ecall increments φ₀ and continues.
    struct IncrementingHandler;
    impl EcallHandler for IncrementingHandler {
        fn handle(
            &mut self,
            _kind: crate::EcallKind,
            regs: &mut Regs,
            _mem: &mut Mem,
        ) -> EcallResult {
            regs.write(0, regs.read(0).wrapping_add(1));
            EcallResult::Continue
        }
    }

    #[test]
    fn ecalli_continue_passes_state_to_handler_and_resumes() {
        let prog = [
            Instruction::Ecalli(7),
            Instruction::Ecalli(7),
            Instruction::Ecalli(7),
            Instruction::Halt,
        ];
        let mut regs = Regs::new();
        let mut mem = Mem::new();
        let mut gas = GasCounter::new(100);
        let mut h = IncrementingHandler;
        let r = Interpreter::execute(&prog, &mut regs, &mut mem, &mut gas, &mut h);
        assert_eq!(r, ExitReason::Halt);
        assert_eq!(regs.read(0), 3); // 3 ecalls, each += 1
    }

    /// Custom handler: exit on opcode 42; otherwise continue.
    struct ExitOnOpHandler;
    impl EcallHandler for ExitOnOpHandler {
        fn handle(
            &mut self,
            kind: crate::EcallKind,
            _regs: &mut Regs,
            _mem: &mut Mem,
        ) -> EcallResult {
            if matches!(kind, crate::EcallKind::Ecalli(42)) {
                EcallResult::Exit(ExitReason::HostCall(42))
            } else {
                EcallResult::Continue
            }
        }
    }

    #[test]
    fn ecalli_exit_returns_to_caller() {
        let prog = [
            Instruction::Nop,
            Instruction::Ecalli(42),
            Instruction::Halt, // shouldn't reach
        ];
        let mut regs = Regs::new();
        let mut mem = Mem::new();
        let mut gas = GasCounter::new(100);
        let mut h = ExitOnOpHandler;
        let r = Interpreter::execute(&prog, &mut regs, &mut mem, &mut gas, &mut h);
        assert_eq!(r, ExitReason::HostCall(42));
        // PC was advanced past the ecalli before the handler ran.
        assert_eq!(regs.pc, 2);
    }
}
