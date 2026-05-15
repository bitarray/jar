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
use crate::mem::Mem;
use crate::program::PvmProgram;
use crate::regs::Regs;

/// Namespace for byte-PVM execution.
pub struct Interpreter;

impl Interpreter {
    /// Execute `program` starting at `regs.pc`. Returns the terminal
    /// [`ExitReason`]. On return, `regs.pc` reflects the PC at exit
    /// (already advanced past an ecall instruction if exit came from
    /// the handler; otherwise the PC of the offending instruction).
    pub fn run(
        program: &PvmProgram,
        regs: &mut Regs,
        mem: &mut Mem,
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
            fn handle(&mut self, kind: EcallKind, _r: &mut Regs, _m: &mut Mem) -> EcallResult {
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
}
