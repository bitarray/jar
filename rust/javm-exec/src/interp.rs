//! Byte-PVM interpreter.
//!
//! Predecodes a [`PvmProgram`] via [`crate::decode::predecode`] and
//! dispatches over the resulting [`DecodedInst`] array.
//!
//! Cherry-picked from v2 `javm/src/interpreter/mod.rs::run` (~787
//! LOC). The opcode-dispatch arms are verbatim modulo two adaptations:
//!
//! 1. **State as parameters.** v2's `Interpreter` owns gas/regs/mem/
//!    code/etc. v3's `Interpreter::run` is a free function that takes
//!    `&PvmProgram + &mut Regs + &mut Mem + &mut GasCounter +
//!    &mut dyn EcallHandler`. The predecoded state is computed on
//!    entry (matching v2's `Interpreter::new` flow, but inline rather
//!    than stored).
//!
//! 2. **Ecall routing.** v2 returns `ExitReason::Ecall` / `HostCall`
//!    directly to the kernel. v3 routes both through the
//!    `EcallHandler` trait: on `Continue` the loop resumes at
//!    `inst.next_idx`; on `Exit(reason)` the run returns. The
//!    diagnostic `regs.gpr[7]` "unsupported opcode" recording from
//!    the MVP is dropped (full coverage means it can't fire).
//!
//! Preserved optimizations (vs v2):
//! - Predecoded `DecodedInst` flat layout (40 bytes; no `Args` enum
//!   matching in the hot loop).
//! - `pc_to_idx` hot-loop indexing for dynamic jumps.
//! - Gas-block charging via `inst.bb_gas_cost` (JAR v0.8.0).
//! - `do_load!` / `do_store!` macros (zero overhead).
//! - Fast-path `mem.read_*` / `write_*` helpers (single MOV on x86).

use crate::decode::predecode;
use crate::ecall::{EcallHandler, EcallKind, EcallResult};
use crate::exit::ExitReason;
use crate::gas::GasCounter;
use crate::instruction::Opcode;
use crate::mem::Memory;
use crate::program::PvmProgram;
use crate::regs::Regs;

/// Namespace for byte-PVM execution.
pub struct Interpreter;

impl Interpreter {
    /// Execute `program` starting at `regs.pc`. Returns the terminal
    /// [`ExitReason`]. On return, `regs.pc` reflects the PC at exit
    /// (already advanced past an ecall instruction if exit came from
    /// the handler; otherwise the PC of the offending instruction).
    pub fn run<M: Memory>(
        program: &PvmProgram,
        regs: &mut Regs,
        mem: &mut M,
        gas: &mut GasCounter,
        handler: &mut dyn EcallHandler,
    ) -> ExitReason {
        // Macros for repetitive load/store dispatch arms. Each macro
        // expands to the same code as the hand-written variants, so
        // there is zero runtime overhead.
        macro_rules! do_store {
            ($mem:expr, $exit:ident, $addr:expr, $write_fn:ident, $val:expr) => {{
                let a = $addr;
                if !$mem.$write_fn(a, $val) {
                    $exit = Some(ExitReason::PageFault(a & !0xFFF));
                }
            }};
        }
        macro_rules! do_load {
            ($mem:expr, $regs:expr, $exit:ident, $dst:expr, $addr:expr, $read_fn:ident, |$v:ident| $conv:expr) => {{
                let a = $addr;
                match $mem.$read_fn(a) {
                    Some($v) => {
                        $regs.gpr[$dst] = $conv;
                    }
                    None => {
                        $exit = Some(ExitReason::PageFault(a & !0xFFF));
                    }
                }
            }};
        }

        let predecoded = predecode(program);
        let insts = &predecoded.decoded_insts;
        let pc_to_idx = &predecoded.pc_to_idx;
        let basic_block_starts = &predecoded.basic_block_starts;
        let jump_table = &program.jump_table;

        // Resolve starting PC to instruction index.
        let mut idx = if (regs.pc as usize) < pc_to_idx.len() {
            pc_to_idx[regs.pc as usize]
        } else {
            u32::MAX
        };
        if idx == u32::MAX {
            return ExitReason::Panic;
        }

        loop {
            // SAFETY: idx is maintained within 0..insts.len() by the
            // predecoder and incremented only via validated next_idx /
            // target_idx values.
            let inst = *unsafe { insts.get_unchecked(idx as usize) };

            // Per-gas-block charging (JAR v0.8.0): only at PC=0 and
            // post-terminator starts.
            if inst.bb_gas_cost > 0 && gas.charge(inst.bb_gas_cost as u64).is_err() {
                regs.pc = inst.pc as u64;
                return ExitReason::OutOfGas;
            }

            let ra = inst.ra as usize;
            let rb = inst.rb as usize;
            let rd = inst.rd as usize;
            let imm1 = inst.imm1;

            // Most instructions advance sequentially. Branches/jumps
            // set branch_idx to the pre-resolved instruction index.
            let mut branch_idx: u32 = u32::MAX;
            let mut exit: Option<ExitReason> = None;

            match inst.opcode {
                // === No arguments ===
                Opcode::Trap => {
                    exit = Some(ExitReason::Trap);
                }
                Opcode::Fallthrough | Opcode::Unlikely => {}
                Opcode::Ecall => {
                    regs.pc = inst.next_pc as u64;
                    match handler.handle(EcallKind::Ecall, regs, mem) {
                        EcallResult::Continue => {
                            idx = inst.next_idx;
                            continue;
                        }
                        EcallResult::Exit(reason) => return reason,
                    }
                }

                // === One immediate ===
                Opcode::Ecalli => {
                    regs.pc = inst.next_pc as u64;
                    match handler.handle(EcallKind::Ecalli(imm1 as u32), regs, mem) {
                        EcallResult::Continue => {
                            idx = inst.next_idx;
                            continue;
                        }
                        EcallResult::Exit(reason) => return reason,
                    }
                }

                // === One register + extended immediate ===
                Opcode::LoadImm64 => {
                    regs.gpr[ra] = imm1;
                }

                // === One offset (jump) ===
                Opcode::Jump => {
                    if inst.target_idx != u32::MAX {
                        branch_idx = inst.target_idx;
                    } else {
                        exit = Some(ExitReason::Panic);
                    }
                }

                // === One register + one immediate ===
                Opcode::JumpInd => {
                    let addr = regs.gpr[ra].wrapping_add(imm1) % (1u64 << 32);
                    match djump(addr, jump_table, basic_block_starts) {
                        Ok(target_pc) => {
                            let t = target_pc as usize;
                            if t < pc_to_idx.len() {
                                let tidx = pc_to_idx[t];
                                if tidx != u32::MAX {
                                    branch_idx = tidx;
                                } else {
                                    exit = Some(ExitReason::Panic);
                                }
                            } else {
                                exit = Some(ExitReason::Panic);
                            }
                        }
                        Err(reason) => exit = Some(reason),
                    }
                }
                Opcode::LoadImm => {
                    regs.gpr[ra] = imm1;
                }

                // === Two registers ===
                Opcode::MoveReg => {
                    regs.gpr[rd] = regs.gpr[ra];
                }
                Opcode::Sbrk => {
                    // JAR v0.8.0: sbrk removed.
                    exit = Some(ExitReason::Panic);
                }
                Opcode::CountSetBits64 => {
                    regs.gpr[rd] = regs.gpr[ra].count_ones() as u64;
                }
                Opcode::CountSetBits32 => {
                    regs.gpr[rd] = (regs.gpr[ra] as u32).count_ones() as u64;
                }
                Opcode::LeadingZeroBits64 => {
                    regs.gpr[rd] = regs.gpr[ra].leading_zeros() as u64;
                }
                Opcode::LeadingZeroBits32 => {
                    regs.gpr[rd] = (regs.gpr[ra] as u32).leading_zeros() as u64;
                }
                Opcode::TrailingZeroBits64 => {
                    regs.gpr[rd] = regs.gpr[ra].trailing_zeros() as u64;
                }
                Opcode::TrailingZeroBits32 => {
                    regs.gpr[rd] = (regs.gpr[ra] as u32).trailing_zeros() as u64;
                }
                Opcode::SignExtend8 => {
                    regs.gpr[rd] = regs.gpr[ra] as u8 as i8 as i64 as u64;
                }
                Opcode::SignExtend16 => {
                    regs.gpr[rd] = regs.gpr[ra] as u16 as i16 as i64 as u64;
                }
                Opcode::ZeroExtend16 => {
                    regs.gpr[rd] = regs.gpr[ra] as u16 as u64;
                }
                Opcode::ReverseBytes => {
                    regs.gpr[rd] = regs.gpr[ra].swap_bytes();
                }

                // === Two registers + one immediate ===
                Opcode::AddImm32 => {
                    regs.gpr[ra] = crate::args::sign_extend_32(regs.gpr[rb].wrapping_add(imm1));
                }
                Opcode::AddImm64 => {
                    regs.gpr[ra] = regs.gpr[rb].wrapping_add(imm1);
                }
                Opcode::MulImm32 => {
                    regs.gpr[ra] = crate::args::sign_extend_32(
                        (regs.gpr[rb] as u32).wrapping_mul(imm1 as u32) as u64,
                    );
                }
                Opcode::MulImm64 => {
                    regs.gpr[ra] = regs.gpr[rb].wrapping_mul(imm1);
                }
                Opcode::AndImm => {
                    regs.gpr[ra] = regs.gpr[rb] & imm1;
                }
                Opcode::XorImm => {
                    regs.gpr[ra] = regs.gpr[rb] ^ imm1;
                }
                Opcode::OrImm => {
                    regs.gpr[ra] = regs.gpr[rb] | imm1;
                }
                Opcode::SetLtUImm => {
                    regs.gpr[ra] = if regs.gpr[rb] < imm1 { 1 } else { 0 };
                }
                Opcode::SetLtSImm => {
                    regs.gpr[ra] = if (regs.gpr[rb] as i64) < (imm1 as i64) {
                        1
                    } else {
                        0
                    };
                }
                Opcode::SetGtUImm => {
                    regs.gpr[ra] = if regs.gpr[rb] > imm1 { 1 } else { 0 };
                }
                Opcode::SetGtSImm => {
                    regs.gpr[ra] = if (regs.gpr[rb] as i64) > (imm1 as i64) {
                        1
                    } else {
                        0
                    };
                }
                Opcode::ShloLImm32 => {
                    regs.gpr[ra] = crate::args::sign_extend_32(
                        (regs.gpr[rb] as u32).wrapping_shl((imm1 % 32) as u32) as u64,
                    );
                }
                Opcode::ShloRImm32 => {
                    regs.gpr[ra] = crate::args::sign_extend_32(
                        (regs.gpr[rb] as u32).wrapping_shr((imm1 % 32) as u32) as u64,
                    );
                }
                Opcode::SharRImm32 => {
                    regs.gpr[ra] =
                        (regs.gpr[rb] as u32 as i32).wrapping_shr((imm1 % 32) as u32) as i64 as u64;
                }
                Opcode::ShloLImm64 => {
                    regs.gpr[ra] = regs.gpr[rb].wrapping_shl((imm1 % 64) as u32);
                }
                Opcode::ShloRImm64 => {
                    regs.gpr[ra] = regs.gpr[rb].wrapping_shr((imm1 % 64) as u32);
                }
                Opcode::SharRImm64 => {
                    regs.gpr[ra] = (regs.gpr[rb] as i64).wrapping_shr((imm1 % 64) as u32) as u64;
                }
                Opcode::NegAddImm32 => {
                    regs.gpr[ra] =
                        crate::args::sign_extend_32(imm1.wrapping_sub(regs.gpr[rb]) as u32 as u64);
                }
                Opcode::NegAddImm64 => {
                    regs.gpr[ra] = imm1.wrapping_sub(regs.gpr[rb]);
                }
                Opcode::CmovIzImm => {
                    if regs.gpr[rb] == 0 {
                        regs.gpr[ra] = imm1;
                    }
                }
                Opcode::CmovNzImm => {
                    if regs.gpr[rb] != 0 {
                        regs.gpr[ra] = imm1;
                    }
                }
                Opcode::RotR64Imm => {
                    regs.gpr[ra] = regs.gpr[rb].rotate_right((imm1 % 64) as u32);
                }
                Opcode::RotR32Imm => {
                    regs.gpr[ra] = crate::args::sign_extend_32(
                        (regs.gpr[rb] as u32).rotate_right((imm1 % 32) as u32) as u64,
                    );
                }

                // ImmAlt variants: op ra, imm, rb (imm is the "left" operand).
                Opcode::ShloLImmAlt32 => {
                    regs.gpr[ra] = crate::args::sign_extend_32(
                        (imm1 as u32).wrapping_shl((regs.gpr[rb] % 32) as u32) as u64,
                    );
                }
                Opcode::ShloRImmAlt32 => {
                    regs.gpr[ra] = crate::args::sign_extend_32(
                        (imm1 as u32).wrapping_shr((regs.gpr[rb] % 32) as u32) as u64,
                    );
                }
                Opcode::SharRImmAlt32 => {
                    regs.gpr[ra] = ((imm1 as u32) as i32).wrapping_shr((regs.gpr[rb] % 32) as u32)
                        as i64 as u64;
                }
                Opcode::ShloLImmAlt64 => {
                    regs.gpr[ra] = imm1.wrapping_shl((regs.gpr[rb] % 64) as u32);
                }
                Opcode::ShloRImmAlt64 => {
                    regs.gpr[ra] = imm1.wrapping_shr((regs.gpr[rb] % 64) as u32);
                }
                Opcode::SharRImmAlt64 => {
                    regs.gpr[ra] = (imm1 as i64).wrapping_shr((regs.gpr[rb] % 64) as u32) as u64;
                }
                Opcode::RotR64ImmAlt => {
                    regs.gpr[ra] = imm1.rotate_right((regs.gpr[rb] % 64) as u32);
                }
                Opcode::RotR32ImmAlt => {
                    regs.gpr[ra] = crate::args::sign_extend_32(
                        (imm1 as u32).rotate_right((regs.gpr[rb] % 32) as u32) as u64,
                    );
                }

                // === Two registers + one offset (branches) ===
                Opcode::BranchEq
                | Opcode::BranchNe
                | Opcode::BranchLtU
                | Opcode::BranchGeU
                | Opcode::BranchLtS
                | Opcode::BranchGeS => {
                    let (a, b) = (regs.gpr[ra], regs.gpr[rb]);
                    let cond = match inst.opcode {
                        Opcode::BranchEq => a == b,
                        Opcode::BranchNe => a != b,
                        Opcode::BranchLtU => a < b,
                        Opcode::BranchGeU => a >= b,
                        Opcode::BranchLtS => (a as i64) < (b as i64),
                        Opcode::BranchGeS => (a as i64) >= (b as i64),
                        _ => unreachable!(),
                    };
                    if cond {
                        if inst.target_idx != u32::MAX {
                            branch_idx = inst.target_idx;
                        } else {
                            exit = Some(ExitReason::Panic);
                        }
                    }
                }

                // === Three register ALU ===
                Opcode::Add32 => {
                    regs.gpr[rd] =
                        crate::args::sign_extend_32(regs.gpr[ra].wrapping_add(regs.gpr[rb]));
                }
                Opcode::Sub32 => {
                    regs.gpr[rd] =
                        crate::args::sign_extend_32(regs.gpr[ra].wrapping_sub(regs.gpr[rb]));
                }
                Opcode::Add64 => {
                    regs.gpr[rd] = regs.gpr[ra].wrapping_add(regs.gpr[rb]);
                }
                Opcode::Sub64 => {
                    regs.gpr[rd] = regs.gpr[ra].wrapping_sub(regs.gpr[rb]);
                }
                Opcode::Mul32 => {
                    regs.gpr[rd] = crate::args::sign_extend_32(
                        (regs.gpr[ra] as u32).wrapping_mul(regs.gpr[rb] as u32) as u64,
                    );
                }
                Opcode::Mul64 => {
                    regs.gpr[rd] = regs.gpr[ra].wrapping_mul(regs.gpr[rb]);
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
                Opcode::SetLtU => {
                    regs.gpr[rd] = if regs.gpr[ra] < regs.gpr[rb] { 1 } else { 0 };
                }
                Opcode::SetLtS => {
                    regs.gpr[rd] = if (regs.gpr[ra] as i64) < (regs.gpr[rb] as i64) {
                        1
                    } else {
                        0
                    };
                }
                Opcode::CmovIz => {
                    if regs.gpr[rb] == 0 {
                        regs.gpr[rd] = regs.gpr[ra];
                    }
                }
                Opcode::CmovNz => {
                    if regs.gpr[rb] != 0 {
                        regs.gpr[rd] = regs.gpr[ra];
                    }
                }
                Opcode::ShloL32 => {
                    regs.gpr[rd] = crate::args::sign_extend_32(
                        (regs.gpr[ra] as u32).wrapping_shl((regs.gpr[rb] % 32) as u32) as u64,
                    );
                }
                Opcode::ShloR32 => {
                    regs.gpr[rd] = crate::args::sign_extend_32(
                        (regs.gpr[ra] as u32).wrapping_shr((regs.gpr[rb] % 32) as u32) as u64,
                    );
                }
                Opcode::SharR32 => {
                    regs.gpr[rd] = (regs.gpr[ra] as u32 as i32)
                        .wrapping_shr((regs.gpr[rb] % 32) as u32)
                        as i64 as u64;
                }
                Opcode::ShloL64 => {
                    regs.gpr[rd] = regs.gpr[ra].wrapping_shl((regs.gpr[rb] % 64) as u32);
                }
                Opcode::ShloR64 => {
                    regs.gpr[rd] = regs.gpr[ra].wrapping_shr((regs.gpr[rb] % 64) as u32);
                }
                Opcode::SharR64 => {
                    regs.gpr[rd] =
                        (regs.gpr[ra] as i64).wrapping_shr((regs.gpr[rb] % 64) as u32) as u64;
                }
                Opcode::RotL64 => {
                    regs.gpr[rd] = regs.gpr[ra].rotate_left((regs.gpr[rb] % 64) as u32);
                }
                Opcode::RotR64 => {
                    regs.gpr[rd] = regs.gpr[ra].rotate_right((regs.gpr[rb] % 64) as u32);
                }
                Opcode::RotL32 => {
                    regs.gpr[rd] = crate::args::sign_extend_32(
                        (regs.gpr[ra] as u32).rotate_left((regs.gpr[rb] % 32) as u32) as u64,
                    );
                }
                Opcode::RotR32 => {
                    regs.gpr[rd] = crate::args::sign_extend_32(
                        (regs.gpr[ra] as u32).rotate_right((regs.gpr[rb] % 32) as u32) as u64,
                    );
                }
                Opcode::AndInv => {
                    regs.gpr[rd] = regs.gpr[ra] & !regs.gpr[rb];
                }
                Opcode::OrInv => {
                    regs.gpr[rd] = regs.gpr[ra] | !regs.gpr[rb];
                }
                Opcode::Xnor => {
                    regs.gpr[rd] = !(regs.gpr[ra] ^ regs.gpr[rb]);
                }
                Opcode::Max => {
                    regs.gpr[rd] = core::cmp::max(regs.gpr[ra] as i64, regs.gpr[rb] as i64) as u64;
                }
                Opcode::MaxU => {
                    regs.gpr[rd] = core::cmp::max(regs.gpr[ra], regs.gpr[rb]);
                }
                Opcode::Min => {
                    regs.gpr[rd] = core::cmp::min(regs.gpr[ra] as i64, regs.gpr[rb] as i64) as u64;
                }
                Opcode::MinU => {
                    regs.gpr[rd] = core::cmp::min(regs.gpr[ra], regs.gpr[rb]);
                }

                // === Indirect loads (two reg + imm) ===
                Opcode::LoadIndU8 => do_load!(
                    mem,
                    regs,
                    exit,
                    ra,
                    regs.gpr[rb].wrapping_add(imm1) as u32,
                    read_u8,
                    |v| v as u64
                ),
                Opcode::LoadIndI8 => do_load!(
                    mem,
                    regs,
                    exit,
                    ra,
                    regs.gpr[rb].wrapping_add(imm1) as u32,
                    read_u8,
                    |v| v as i8 as i64 as u64
                ),
                Opcode::LoadIndU16 => do_load!(
                    mem,
                    regs,
                    exit,
                    ra,
                    regs.gpr[rb].wrapping_add(imm1) as u32,
                    read_u16_le,
                    |v| v as u64
                ),
                Opcode::LoadIndI16 => do_load!(
                    mem,
                    regs,
                    exit,
                    ra,
                    regs.gpr[rb].wrapping_add(imm1) as u32,
                    read_u16_le,
                    |v| v as i16 as i64 as u64
                ),
                Opcode::LoadIndU32 => do_load!(
                    mem,
                    regs,
                    exit,
                    ra,
                    regs.gpr[rb].wrapping_add(imm1) as u32,
                    read_u32_le,
                    |v| v as u64
                ),
                Opcode::LoadIndI32 => do_load!(
                    mem,
                    regs,
                    exit,
                    ra,
                    regs.gpr[rb].wrapping_add(imm1) as u32,
                    read_u32_le,
                    |v| v as i32 as i64 as u64
                ),
                Opcode::LoadIndU64 => do_load!(
                    mem,
                    regs,
                    exit,
                    ra,
                    regs.gpr[rb].wrapping_add(imm1) as u32,
                    read_u64_le,
                    |v| v
                ),

                // === Indirect stores (two reg + imm) ===
                Opcode::StoreIndU8 => do_store!(
                    mem,
                    exit,
                    regs.gpr[rb].wrapping_add(imm1) as u32,
                    write_u8,
                    regs.gpr[ra] as u8
                ),
                Opcode::StoreIndU16 => do_store!(
                    mem,
                    exit,
                    regs.gpr[rb].wrapping_add(imm1) as u32,
                    write_u16_le,
                    regs.gpr[ra] as u16
                ),
                Opcode::StoreIndU32 => do_store!(
                    mem,
                    exit,
                    regs.gpr[rb].wrapping_add(imm1) as u32,
                    write_u32_le,
                    regs.gpr[ra] as u32
                ),
                Opcode::StoreIndU64 => do_store!(
                    mem,
                    exit,
                    regs.gpr[rb].wrapping_add(imm1) as u32,
                    write_u64_le,
                    regs.gpr[ra]
                ),

                // === Div/Rem (three reg, common in crypto) ===
                Opcode::DivU32 => {
                    let b = regs.gpr[rb] as u32;
                    regs.gpr[rd] = (regs.gpr[ra] as u32)
                        .checked_div(b)
                        .map(|q| crate::args::sign_extend_32(q as u64))
                        .unwrap_or(u64::MAX);
                }
                Opcode::DivU64 => {
                    let b = regs.gpr[rb];
                    regs.gpr[rd] = regs.gpr[ra].checked_div(b).unwrap_or(u64::MAX);
                }
                Opcode::DivS32 => {
                    let a = regs.gpr[ra] as i32;
                    let b = regs.gpr[rb] as i32;
                    regs.gpr[rd] = if b == 0 {
                        u64::MAX
                    } else if a == i32::MIN && b == -1 {
                        a as u64
                    } else {
                        crate::args::sign_extend_32((a / b) as i64 as u64)
                    };
                }
                Opcode::DivS64 => {
                    let a = regs.gpr[ra] as i64;
                    let b = regs.gpr[rb] as i64;
                    regs.gpr[rd] = if b == 0 {
                        u64::MAX
                    } else if a == i64::MIN && b == -1 {
                        a as u64
                    } else {
                        (a / b) as u64
                    };
                }
                Opcode::RemU32 => {
                    let b = regs.gpr[rb] as u32;
                    regs.gpr[rd] = if b == 0 {
                        crate::args::sign_extend_32(regs.gpr[ra] as u32 as u64)
                    } else {
                        crate::args::sign_extend_32((regs.gpr[ra] as u32 % b) as u64)
                    };
                }
                Opcode::RemU64 => {
                    let b = regs.gpr[rb];
                    regs.gpr[rd] = if b == 0 {
                        regs.gpr[ra]
                    } else {
                        regs.gpr[ra] % b
                    };
                }
                Opcode::RemS32 => {
                    let a = regs.gpr[ra] as i32;
                    let b = regs.gpr[rb] as i32;
                    regs.gpr[rd] = if b == 0 {
                        a as u64
                    } else if a == i32::MIN && b == -1 {
                        0
                    } else {
                        crate::args::sign_extend_32((a % b) as i64 as u64)
                    };
                }
                Opcode::RemS64 => {
                    let a = regs.gpr[ra] as i64;
                    let b = regs.gpr[rb] as i64;
                    regs.gpr[rd] = if b == 0 {
                        a as u64
                    } else if a == i64::MIN && b == -1 {
                        0
                    } else {
                        (a % b) as u64
                    };
                }
                Opcode::MulUpperSS => {
                    regs.gpr[rd] = ((regs.gpr[ra] as i64 as i128)
                        .wrapping_mul(regs.gpr[rb] as i64 as i128)
                        >> 64) as u64;
                }
                Opcode::MulUpperUU => {
                    regs.gpr[rd] =
                        ((regs.gpr[ra] as u128).wrapping_mul(regs.gpr[rb] as u128) >> 64) as u64;
                }
                Opcode::MulUpperSU => {
                    regs.gpr[rd] = ((regs.gpr[ra] as i64 as i128)
                        .wrapping_mul(regs.gpr[rb] as u128 as i128)
                        >> 64) as u64;
                }

                // === Two immediates (store_imm: addr = imm1, value = imm2) ===
                Opcode::StoreImmU8 => {
                    do_store!(mem, exit, imm1 as u32, write_u8, inst.imm2 as u8)
                }
                Opcode::StoreImmU16 => {
                    do_store!(mem, exit, imm1 as u32, write_u16_le, inst.imm2 as u16)
                }
                Opcode::StoreImmU32 => {
                    do_store!(mem, exit, imm1 as u32, write_u32_le, inst.imm2 as u32)
                }
                Opcode::StoreImmU64 => {
                    do_store!(mem, exit, imm1 as u32, write_u64_le, inst.imm2)
                }

                // === Absolute address loads (addr = imm1) ===
                Opcode::LoadU8 => {
                    do_load!(mem, regs, exit, ra, imm1 as u32, read_u8, |v| v as u64)
                }
                Opcode::LoadI8 => {
                    do_load!(
                        mem,
                        regs,
                        exit,
                        ra,
                        imm1 as u32,
                        read_u8,
                        |v| v as i8 as i64 as u64
                    )
                }
                Opcode::LoadU16 => {
                    do_load!(mem, regs, exit, ra, imm1 as u32, read_u16_le, |v| v as u64)
                }
                Opcode::LoadI16 => do_load!(mem, regs, exit, ra, imm1 as u32, read_u16_le, |v| v
                    as i16
                    as i64
                    as u64),
                Opcode::LoadU32 => {
                    do_load!(mem, regs, exit, ra, imm1 as u32, read_u32_le, |v| v as u64)
                }
                Opcode::LoadI32 => do_load!(mem, regs, exit, ra, imm1 as u32, read_u32_le, |v| v
                    as i32
                    as i64
                    as u64),
                Opcode::LoadU64 => {
                    do_load!(mem, regs, exit, ra, imm1 as u32, read_u64_le, |v| v)
                }

                // === Absolute address stores (addr = imm1, value = reg[ra]) ===
                Opcode::StoreU8 => {
                    do_store!(mem, exit, imm1 as u32, write_u8, regs.gpr[ra] as u8)
                }
                Opcode::StoreU16 => {
                    do_store!(mem, exit, imm1 as u32, write_u16_le, regs.gpr[ra] as u16)
                }
                Opcode::StoreU32 => {
                    do_store!(mem, exit, imm1 as u32, write_u32_le, regs.gpr[ra] as u32)
                }
                Opcode::StoreU64 => {
                    do_store!(mem, exit, imm1 as u32, write_u64_le, regs.gpr[ra])
                }

                // === Store imm indirect (addr = reg[ra] + imm1, value = imm2) ===
                Opcode::StoreImmIndU8 => do_store!(
                    mem,
                    exit,
                    regs.gpr[ra].wrapping_add(imm1) as u32,
                    write_u8,
                    inst.imm2 as u8
                ),
                Opcode::StoreImmIndU16 => do_store!(
                    mem,
                    exit,
                    regs.gpr[ra].wrapping_add(imm1) as u32,
                    write_u16_le,
                    inst.imm2 as u16
                ),
                Opcode::StoreImmIndU32 => do_store!(
                    mem,
                    exit,
                    regs.gpr[ra].wrapping_add(imm1) as u32,
                    write_u32_le,
                    inst.imm2 as u32
                ),
                Opcode::StoreImmIndU64 => do_store!(
                    mem,
                    exit,
                    regs.gpr[ra].wrapping_add(imm1) as u32,
                    write_u64_le,
                    inst.imm2
                ),

                // === LoadImmJump (reg[ra] = imm1, branch to target) ===
                Opcode::LoadImmJump => {
                    regs.gpr[ra] = imm1;
                    if inst.target_idx != u32::MAX {
                        branch_idx = inst.target_idx;
                    } else {
                        exit = Some(ExitReason::Panic);
                    }
                }

                // === BranchImm variants (cond on reg[ra] vs imm1) ===
                Opcode::BranchEqImm
                | Opcode::BranchNeImm
                | Opcode::BranchLtUImm
                | Opcode::BranchLeUImm
                | Opcode::BranchGeUImm
                | Opcode::BranchGtUImm
                | Opcode::BranchLtSImm
                | Opcode::BranchLeSImm
                | Opcode::BranchGeSImm
                | Opcode::BranchGtSImm => {
                    let (a, b) = (regs.gpr[ra], imm1);
                    let cond = match inst.opcode {
                        Opcode::BranchEqImm => a == b,
                        Opcode::BranchNeImm => a != b,
                        Opcode::BranchLtUImm => a < b,
                        Opcode::BranchLeUImm => a <= b,
                        Opcode::BranchGeUImm => a >= b,
                        Opcode::BranchGtUImm => a > b,
                        Opcode::BranchLtSImm => (a as i64) < (b as i64),
                        Opcode::BranchLeSImm => (a as i64) <= (b as i64),
                        Opcode::BranchGeSImm => (a as i64) >= (b as i64),
                        Opcode::BranchGtSImm => (a as i64) > (b as i64),
                        _ => unreachable!(),
                    };
                    if cond {
                        if inst.target_idx != u32::MAX {
                            branch_idx = inst.target_idx;
                        } else {
                            exit = Some(ExitReason::Panic);
                        }
                    }
                }

                // === Two registers + two immediates ===
                Opcode::LoadImmJumpInd => {
                    regs.gpr[ra] = imm1;
                    let addr = regs.gpr[rb].wrapping_add(inst.imm2) % (1u64 << 32);
                    match djump(addr, jump_table, basic_block_starts) {
                        Ok(target_pc) => {
                            let t = target_pc as usize;
                            if t < pc_to_idx.len() {
                                let tidx = pc_to_idx[t];
                                if tidx != u32::MAX {
                                    branch_idx = tidx;
                                } else {
                                    exit = Some(ExitReason::Panic);
                                }
                            } else {
                                exit = Some(ExitReason::Panic);
                            }
                        }
                        Err(reason) => exit = Some(reason),
                    }
                }
            }

            if let Some(reason) = exit {
                regs.pc = inst.pc as u64;
                return reason;
            }

            idx = if branch_idx == u32::MAX {
                inst.next_idx
            } else {
                branch_idx
            };
        }
    }
}

/// Dynamic-jump address resolution (eq A.18).
///
/// `a` is the post-imm-add jump value (mod 2^32, but passed as u64
/// here). The jump table is indexed by `a / 2`, minus 1. Targets
/// must land on basic-block starts.
fn djump(a: u64, jump_table: &[u32], basic_block_starts: &[bool]) -> Result<u32, ExitReason> {
    const ZA: u64 = 2;
    if a == 0 || a > (jump_table.len() as u64) * ZA || !a.is_multiple_of(ZA) {
        return Err(ExitReason::Panic);
    }
    let idx = (a / ZA) as usize - 1;
    let target = jump_table[idx];
    let t = target as usize;
    if t >= basic_block_starts.len() || !basic_block_starts[t] {
        return Err(ExitReason::Panic);
    }
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecall::PanickingHandler;
    use crate::mem::Mem;
    use crate::regs::REG_COUNT;

    /// Helper: build a PvmProgram from a single trap byte.
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
        let (r, _) = run_with_panic_handler(&single_byte_prog(1), 1000);
        assert_eq!(r, ExitReason::Trap);
    }

    #[test]
    fn unlikely_falls_into_sentinel_trap() {
        let (r, _) = run_with_panic_handler(&single_byte_prog(2), 1000);
        assert_eq!(r, ExitReason::Trap);
    }

    /// Ecalli with `imm = 42` routes through the EcallHandler.
    #[test]
    fn ecalli_routes_through_handler() {
        // Ecalli (opcode 10, OneImm category): [10, 42, <next-trap>].
        let prog = PvmProgram::new(vec![10u8, 42, 0], vec![1, 0, 1], vec![], 25).unwrap();

        struct Capture {
            seen: Option<EcallKind>,
        }
        impl EcallHandler for Capture {
            fn handle(
                &mut self,
                kind: EcallKind,
                _r: &mut Regs,
                _m: &mut dyn Memory,
            ) -> EcallResult {
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

    // ====================================================================
    // Conformance tests: cherry-picked from v2
    // `javm/src/interpreter/mod.rs::tests`. Each test ports a v2 single-
    // step test by extending its program with a trailing trap so the v3
    // `run()` exit reason is `Trap` and final register state can be
    // observed afterward.
    // ====================================================================

    /// Run `program` with starting registers; panic handler. Returns
    /// `(exit_reason, regs, gas_used)`.
    fn run_with_regs(
        code: Vec<u8>,
        bitmask: Vec<u8>,
        initial_regs: [u64; REG_COUNT],
        gas_budget: u64,
    ) -> (ExitReason, Regs, u64) {
        let prog = PvmProgram::new(code, bitmask, vec![], 25).unwrap();
        let mut regs = Regs::new();
        regs.gpr = initial_regs;
        let mut mem = Mem::new();
        let mut g = GasCounter::new(gas_budget);
        let mut h = PanickingHandler;
        let r = Interpreter::run(&prog, &mut regs, &mut mem, &mut g, &mut h);
        (r, regs, gas_budget - g.remaining())
    }

    #[test]
    fn out_of_gas_in_long_fallthrough() {
        // 100 fallthroughs, only 5 gas — should OOG.
        let (r, _, _) = run_with_regs(vec![1u8; 100], vec![1u8; 100], [0; REG_COUNT], 5);
        assert_eq!(r, ExitReason::OutOfGas);
    }

    #[test]
    fn empty_program_panics() {
        // Zero-length code: starting PC is OOB → Panic.
        let prog = PvmProgram::new(vec![], vec![], vec![], 25).unwrap();
        let mut regs = Regs::new();
        let mut mem = Mem::new();
        let mut g = GasCounter::new(100);
        let mut h = PanickingHandler;
        assert_eq!(
            Interpreter::run(&prog, &mut regs, &mut mem, &mut g, &mut h),
            ExitReason::Panic
        );
    }

    #[test]
    fn load_imm_sets_register() {
        // LoadImm (opcode 51, OneRegOneImm), reg 0, imm = 42 (4 bytes LE).
        // bytes: [51, 0x00, 42, 0, 0, 0, 0 (trap)]
        // bitmask: [1, 0, 0, 0, 0, 0, 1] — instruction is 6 bytes, then trap.
        let code = vec![51, 0x00, 42, 0, 0, 0, 0];
        let bitmask = vec![1, 0, 0, 0, 0, 0, 1];
        let (r, regs, _) = run_with_regs(code, bitmask, [0; REG_COUNT], 100);
        assert_eq!(r, ExitReason::Trap);
        assert_eq!(regs.gpr[0], 42);
    }

    #[test]
    fn add_imm_64_two_reg_one_imm() {
        // AddImm64 (opcode 149, TwoRegOneImm), reg byte 0x10 (rA=0, rB=1), imm=10.
        // reg[1] = 32 + imm 10 → reg[0] = 42.
        let code = vec![149, 0x10, 10, 0, 0, 0, 0];
        let bitmask = vec![1, 0, 0, 0, 0, 0, 1];
        let mut regs = [0u64; REG_COUNT];
        regs[1] = 32;
        let (r, regs_out, _) = run_with_regs(code, bitmask, regs, 100);
        assert_eq!(r, ExitReason::Trap);
        assert_eq!(regs_out.gpr[0], 42);
    }

    #[test]
    fn add64_three_reg() {
        // Add64 (opcode 200, ThreeReg), reg byte 0x10 (rA=0, rB=1), rD=2.
        // reg[0]=100 + reg[1]=200 → reg[2]=300.
        let code = vec![200, 0x10, 2, 0];
        let bitmask = vec![1, 0, 0, 1];
        let mut regs = [0u64; REG_COUNT];
        regs[0] = 100;
        regs[1] = 200;
        let (r, regs_out, _) = run_with_regs(code, bitmask, regs, 100);
        assert_eq!(r, ExitReason::Trap);
        assert_eq!(regs_out.gpr[2], 300);
    }

    #[test]
    fn sub64_three_reg() {
        // Sub64 (opcode 201). 300 - 100 = 200.
        let code = vec![201, 0x10, 2, 0];
        let bitmask = vec![1, 0, 0, 1];
        let mut regs = [0u64; REG_COUNT];
        regs[0] = 300;
        regs[1] = 100;
        let (r, regs_out, _) = run_with_regs(code, bitmask, regs, 100);
        assert_eq!(r, ExitReason::Trap);
        assert_eq!(regs_out.gpr[2], 200);
    }

    #[test]
    fn and_three_reg() {
        // And (opcode 210). 0xFF00 & 0x0FF0 = 0x0F00.
        let code = vec![210, 0x10, 2, 0];
        let bitmask = vec![1, 0, 0, 1];
        let mut regs = [0u64; REG_COUNT];
        regs[0] = 0xFF00;
        regs[1] = 0x0FF0;
        let (r, regs_out, _) = run_with_regs(code, bitmask, regs, 100);
        assert_eq!(r, ExitReason::Trap);
        assert_eq!(regs_out.gpr[2], 0x0F00);
    }

    #[test]
    fn set_lt_u_three_reg() {
        // SetLtU (opcode 216). 5 < 10 → 1.
        let code = vec![216, 0x10, 2, 0];
        let bitmask = vec![1, 0, 0, 1];
        let mut regs = [0u64; REG_COUNT];
        regs[0] = 5;
        regs[1] = 10;
        let (r, regs_out, _) = run_with_regs(code, bitmask, regs, 100);
        assert_eq!(r, ExitReason::Trap);
        assert_eq!(regs_out.gpr[2], 1);
    }

    #[test]
    fn move_reg_two_reg() {
        // MoveReg (opcode 100, TwoReg). reg byte 0x10 = rD=0, rA=1.
        let code = vec![100, 0x10, 0];
        let bitmask = vec![1, 0, 1];
        let mut regs = [0u64; REG_COUNT];
        regs[1] = 42;
        let (r, regs_out, _) = run_with_regs(code, bitmask, regs, 100);
        assert_eq!(r, ExitReason::Trap);
        assert_eq!(regs_out.gpr[0], 42);
    }

    #[test]
    fn count_set_bits_64() {
        // CountSetBits64 (opcode 102). 0xFF has 8 set bits.
        let code = vec![102, 0x10, 0];
        let bitmask = vec![1, 0, 1];
        let mut regs = [0u64; REG_COUNT];
        regs[1] = 0xFF;
        let (r, regs_out, _) = run_with_regs(code, bitmask, regs, 100);
        assert_eq!(r, ExitReason::Trap);
        assert_eq!(regs_out.gpr[0], 8);
    }

    #[test]
    fn div_u64_by_zero_returns_max() {
        // DivU64 (opcode 203). 100 / 0 → u64::MAX (per spec; not a fault).
        let code = vec![203, 0x10, 2, 0];
        let bitmask = vec![1, 0, 0, 1];
        let mut regs = [0u64; REG_COUNT];
        regs[0] = 100;
        regs[1] = 0;
        let (r, regs_out, _) = run_with_regs(code, bitmask, regs, 100);
        assert_eq!(r, ExitReason::Trap);
        assert_eq!(regs_out.gpr[2], u64::MAX);
    }

    #[test]
    fn sign_extend_8() {
        // SignExtend8 (opcode 108). 0x80 → sign-extended -128.
        let code = vec![108, 0x10, 0];
        let bitmask = vec![1, 0, 1];
        let mut regs = [0u64; REG_COUNT];
        regs[1] = 0x80;
        let (r, regs_out, _) = run_with_regs(code, bitmask, regs, 100);
        assert_eq!(r, ExitReason::Trap);
        assert_eq!(regs_out.gpr[0] as i64, -128);
    }

    #[test]
    fn reverse_bytes_u64() {
        // ReverseBytes (opcode 111).
        let code = vec![111, 0x10, 0];
        let bitmask = vec![1, 0, 1];
        let mut regs = [0u64; REG_COUNT];
        regs[1] = 0x0123456789ABCDEF;
        let (r, regs_out, _) = run_with_regs(code, bitmask, regs, 100);
        assert_eq!(r, ExitReason::Trap);
        assert_eq!(regs_out.gpr[0], 0xEFCDAB8967452301);
    }

    #[test]
    fn sbrk_panics() {
        // Sbrk (opcode 101) was removed in JAR v0.8.0; the interpreter
        // returns Panic.
        let code = vec![101, 0x00];
        let bitmask = vec![1, 0];
        let (r, _, _) = run_with_regs(code, bitmask, [0; REG_COUNT], 100);
        assert_eq!(r, ExitReason::Panic);
    }

    #[test]
    fn page_fault_on_unmapped_load() {
        // LoadU8 (opcode 52). Mem is empty → page fault.
        // LoadU8 layout: [opcode, reg_byte, addr_LE...] (OneRegOneImm).
        // Here the immediate is 0x1000 (4 bytes LE).
        let code = vec![52, 0x00, 0x00, 0x10, 0x00, 0x00, 0];
        let bitmask = vec![1, 0, 0, 0, 0, 0, 1];
        let (r, _, _) = run_with_regs(code, bitmask, [0; REG_COUNT], 100);
        assert_eq!(r, ExitReason::PageFault(0x1000));
    }

    /// Branch-target / gas-block boundary: v2 issue #155 regression.
    /// Verifies that branch targets are valid basic-block landing
    /// sites but do NOT introduce new gas-block starts.
    #[test]
    fn gas_blocks_exclude_branch_targets() {
        use crate::decode::{
            compute_basic_block_starts, compute_block_gas_costs, compute_gas_block_starts,
        };

        // Layout (verbatim from v2 test):
        //   PC 0: Fallthrough (1)  — terminator
        //   PC 1: MoveReg 0,1      — not terminator (skip=1)
        //   PC 3: MoveReg 0,1      — not terminator (skip=1)
        //   PC 5: Jump, offset = -2 LE → target = PC 3
        //   PC 10: Trap            — catches fallthrough
        let code = vec![1, 100, 0x10, 100, 0x10, 40, 0xFE, 0xFF, 0xFF, 0xFF, 0];
        let bitmask = vec![1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1];

        let bb = compute_basic_block_starts(&code, &bitmask);
        let gas = compute_gas_block_starts(&code, &bitmask);
        let costs = compute_block_gas_costs(&code, &bitmask, &gas, 25);

        // PC 3 is a branch target → in bb_starts, NOT in gas_starts.
        assert!(bb[3], "PC 3 is a branch target");
        assert!(!gas[3], "PC 3 is NOT a gas block start");
        assert_eq!(costs[3], 0, "PC 3 carries no gas cost");
        // PC 1, 10 are post-terminator → gas block starts.
        assert!(gas[1] && gas[10]);
        assert!(costs[1] > 0 && costs[10] > 0);
    }
}
