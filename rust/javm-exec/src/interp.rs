//! Byte-PVM interpreter.
//!
//! Predecodes a [`PvmProgram`] via [`crate::decode::predecode`] and
//! dispatches over the resulting [`DecodedInst`] array.
//!
//! **Coverage in this commit is intentionally narrow** — the
//! cherry-pick of v2's full 3000-line opcode dispatch is mechanical
//! follow-up work. This MVP covers:
//!
//! - No-args: `Trap`, `Fallthrough`, `Unlikely`
//! - PVM ecalls: `Ecall`, `Ecalli` (both route through
//!   [`EcallHandler`])
//! - One-reg ext imm: `LoadImm64`
//! - Two registers: `MoveReg`
//! - Three registers: `Add64`, `Sub64`, `And`, `Or`, `Xor`
//!
//! Any other opcode causes the interpreter to return
//! `ExitReason::Panic` and records a `TODO` in
//! `regs.gpr[7]` (the high register, conventionally unused by the
//! ABI) — diagnostic aid, not part of the spec.
//!
//! This validates the byte-encoding pipeline end-to-end. Filling
//! out the remaining ~80 opcodes follows the same dispatch shape
//! and is a mechanical port from v2 `interpreter/mod.rs`.

use crate::decode::{DecodedInst, predecode};
use crate::ecall::{EcallHandler, EcallKind, EcallResult};
use crate::exit::ExitReason;
use crate::gas::GasCounter;
use crate::instruction::Opcode;
use crate::mem::Mem;
use crate::program::PvmProgram;
use crate::regs::Regs;

/// Namespace for byte-PVM execution.
pub struct Interpreter;

impl Interpreter {
    /// Execute `program` starting at `regs.pc`. Returns the terminal
    /// `ExitReason`. `regs.pc` after return reflects the last
    /// advanced PC (so callers can inspect / resume after a
    /// `HostCall` or `PageFault`).
    pub fn run(
        program: &PvmProgram,
        regs: &mut Regs,
        mem: &mut Mem,
        gas: &mut GasCounter,
        handler: &mut dyn EcallHandler,
    ) -> ExitReason {
        let predecoded = predecode(program);
        let insts = &predecoded.decoded_insts;
        let pc_to_idx = &predecoded.pc_to_idx;

        // Resolve starting PC.
        let mut idx = if (regs.pc as usize) < pc_to_idx.len() {
            pc_to_idx[regs.pc as usize]
        } else {
            u32::MAX
        };
        if idx == u32::MAX {
            return ExitReason::Panic;
        }

        loop {
            let inst: DecodedInst = insts[idx as usize];

            // Per-gas-block charge (JAR v0.8.0).
            if inst.bb_gas_cost > 0 && gas.charge(inst.bb_gas_cost as u64).is_err() {
                regs.pc = inst.pc as u64;
                return ExitReason::OutOfGas;
            }

            let ra = inst.ra as usize;
            let rb = inst.rb as usize;
            let rd = inst.rd as usize;

            let branch_idx = u32::MAX; // sentinel; branches/jumps will update once added
            let mut exit: Option<ExitReason> = None;

            match inst.opcode {
                Opcode::Trap => {
                    exit = Some(ExitReason::Trap);
                }
                Opcode::Fallthrough | Opcode::Unlikely => {
                    // No-op; sequential advance.
                }
                Opcode::Ecall => {
                    regs.pc = inst.next_pc as u64;
                    match handler.handle(EcallKind::Ecall, regs, mem) {
                        EcallResult::Continue => {}
                        EcallResult::Exit(reason) => return reason,
                    }
                    idx = inst.next_idx;
                    continue;
                }
                Opcode::Ecalli => {
                    regs.pc = inst.next_pc as u64;
                    match handler.handle(EcallKind::Ecalli(inst.imm1 as u32), regs, mem) {
                        EcallResult::Continue => {}
                        EcallResult::Exit(reason) => return reason,
                    }
                    idx = inst.next_idx;
                    continue;
                }
                Opcode::LoadImm64 => {
                    regs.gpr[ra] = inst.imm1;
                }
                Opcode::MoveReg => {
                    regs.gpr[rd] = regs.gpr[ra];
                }
                Opcode::Add64 => {
                    regs.gpr[rd] = regs.gpr[ra].wrapping_add(regs.gpr[rb]);
                }
                Opcode::Sub64 => {
                    regs.gpr[rd] = regs.gpr[ra].wrapping_sub(regs.gpr[rb]);
                }
                Opcode::And => {
                    regs.gpr[rd] = regs.gpr[ra] & regs.gpr[rb];
                }
                Opcode::Or => {
                    regs.gpr[rd] = regs.gpr[ra] | regs.gpr[rb];
                }
                Opcode::Xor => {
                    regs.gpr[rd] = regs.gpr[ra] ^ regs.gpr[rb];
                }
                _ => {
                    // TODO: cherry-pick remaining opcode arms from
                    // v2 `interpreter/mod.rs::run`. Mark which opcode
                    // wasn't handled in regs.gpr[7] as a diagnostic
                    // (this is not part of the PVM spec; it's a
                    // debugging convenience during the port).
                    regs.gpr[7] = inst.opcode as u64;
                    exit = Some(ExitReason::Panic);
                }
            }

            if let Some(reason) = exit {
                regs.pc = inst.pc as u64;
                return reason;
            }

            idx = if branch_idx != u32::MAX {
                branch_idx
            } else {
                inst.next_idx
            };
            regs.pc = insts[idx as usize].pc as u64;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecall::PanickingHandler;

    /// Helper: encode an opcode + raw operand bytes into a PvmProgram
    /// with trivial bitmask (every byte = instruction start). For
    /// tests that don't need full multi-byte instructions.
    fn single_byte_prog(opcode_byte: u8) -> PvmProgram {
        PvmProgram::new(vec![opcode_byte], vec![1u8], vec![], 25).unwrap()
    }

    fn run_with_panic_handler(prog: &PvmProgram, gas: u64) -> (ExitReason, Regs) {
        let mut regs = Regs::new();
        let mut mem = Mem::new();
        let mut g = GasCounter::new(gas);
        let mut h = PanickingHandler;
        let r = Interpreter::run(prog, &mut regs, &mut mem, &mut g, &mut h);
        (r, regs)
    }

    #[test]
    fn trap_returns_trap() {
        let (r, _) = run_with_panic_handler(&single_byte_prog(0), 1000);
        assert_eq!(r, ExitReason::Trap);
    }

    #[test]
    fn fallthrough_falls_into_sentinel_trap() {
        // 1-byte Fallthrough — after executing, the predecoder's
        // sentinel trap takes over and we exit with Trap.
        let (r, _) = run_with_panic_handler(&single_byte_prog(1), 1000);
        assert_eq!(r, ExitReason::Trap);
    }

    #[test]
    fn unlikely_falls_into_sentinel_trap() {
        let (r, _) = run_with_panic_handler(&single_byte_prog(2), 1000);
        assert_eq!(r, ExitReason::Trap);
    }

    /// Ecalli with `imm = 42` routes through the EcallHandler.
    /// The handler exits with HostCall(42).
    #[test]
    fn ecalli_routes_through_handler() {
        // Ecalli encoding (OneImm, opcode 10):
        //   bytes:   [opcode, imm0, imm1, ..., imm_{lx-1}]
        // `lx` is `skip_distance.min(4)`, where skip_distance is the
        // number of bytes from the opcode to the next instruction start
        // in the bitmask. So for `imm=42` packing into 1 byte:
        //   bytes:   [10, 42, <next-insn-opcode>]
        //   bitmask: [1, 0, 1]  -- insn at PC=0, immediate byte at PC=1,
        //                          next insn (trap) at PC=2.
        let prog = PvmProgram::new(vec![10u8, 42, 0], vec![1, 0, 1], vec![], 25).unwrap();

        struct Capture {
            seen: Option<EcallKind>,
        }
        impl EcallHandler for Capture {
            fn handle(&mut self, kind: EcallKind, _regs: &mut Regs, _mem: &mut Mem) -> EcallResult {
                self.seen = Some(kind);
                EcallResult::Exit(ExitReason::HostCall(match kind {
                    EcallKind::Ecalli(op) => op,
                    EcallKind::Ecall => 0,
                }))
            }
        }

        let mut regs = Regs::new();
        let mut mem = Mem::new();
        let mut gas = GasCounter::new(1000);
        let mut h = Capture { seen: None };
        let r = Interpreter::run(&prog, &mut regs, &mut mem, &mut gas, &mut h);
        assert_eq!(r, ExitReason::HostCall(42));
        assert_eq!(h.seen, Some(EcallKind::Ecalli(42)));
    }

    #[test]
    fn unsupported_opcode_panics_and_records_in_r7() {
        // Opcode 100 = MoveReg, which IS supported. Use opcode 101
        // (Sbrk) which isn't covered in this MVP — should Panic and
        // record 101 in regs.gpr[7].
        // Sbrk is TwoReg category: opcode + 1-byte regs.
        // Bytes: [101, 0x00], bitmask: [1, 0].
        let prog = PvmProgram::new(vec![101u8, 0x00], vec![1, 0], vec![], 25).unwrap();
        let (r, regs) = run_with_panic_handler(&prog, 1000);
        assert_eq!(r, ExitReason::Panic);
        assert_eq!(regs.gpr[7], Opcode::Sbrk as u64);
    }
}
