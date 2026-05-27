//! PVM2 (RV+C+Zbb+Zba+Zbs+Zicond+custom-0) interpreter.
//!
//! Mirrors the recompiler's semantics — same per-block gas charging at
//! `RvPredecode::block_costs`, same RV-spec ALU/branch behaviour, same
//! `Ecalli`/`BrTable` runtime contracts. Cross-checked against the
//! recompiler in `pvm2_smoke`: bit-identical `gas_used` and side-effects
//! on every workload.
//!
//! Dispatch is a `match` over `RvInst` variants. Instructions come from
//! [`RvPredecode::insts`] (one entry per static instruction); static
//! branch / jal targets are resolved to instruction indices via binary
//! search on the (sorted) `insts` array. Reused infrastructure: `Regs`,
//! `Memory` trait, `GasCounter`, `EcallHandler` — identical to the PVM
//! interpreter's contract.

use crate::ecall::{EcallHandler, EcallKind, EcallResult};
use crate::exit::ExitReason;
use crate::gas::GasCounter;
use crate::mem::Memory;
use crate::regs::Regs;
use crate::rv_instruction::RvInst;
use crate::rv_predecode::{RvPreDecodedInst, RvPredecode};

/// PVM2 interpreter namespace.
pub struct RvInterpreter;

impl RvInterpreter {
    /// Execute the predecoded PVM2 program starting at `regs.pc`.
    /// `jump_table` and `jump_table_offsets` come from the Image
    /// (see [`javm_cap::image::Image`]).
    pub fn run<M: Memory>(
        predecode: &RvPredecode,
        jump_table: &[u32],
        jump_table_offsets: &[u32],
        regs: &mut Regs,
        mem: &mut M,
        gas: &mut GasCounter,
        handler: &mut dyn EcallHandler,
    ) -> ExitReason {
        // `decode_error_at` records a Reserved encoding seen during the
        // predecode walk but doesn't preclude execution: programs may
        // contain unreachable padding (e.g. `0x0000` bytes between
        // functions) that the recompiler also tolerates. We panic only
        // if execution actually *reaches* a `RvInst::Reserved` arm.
        let insts: &[RvPreDecodedInst] = &predecode.insts;
        if insts.is_empty() {
            return ExitReason::Panic;
        }

        // Resolve starting PC → instruction index.
        let mut idx = match find_idx_for_pc(insts, regs.pc as u32) {
            Some(i) => i,
            None => return ExitReason::Panic,
        };

        loop {
            let inst = unsafe { insts.get_unchecked(idx) };

            // Per-block gas charging.
            if inst.is_gas_block_start {
                let cost = predecode.block_costs[idx] as u64;
                if cost > 0 && gas.charge(cost).is_err() {
                    regs.pc = inst.pc as u64;
                    return ExitReason::OutOfGas;
                }
            }

            let pc = inst.pc;
            let next_pc = inst.next_pc;

            // Terminator arms below set `next_idx_override` to the target
            // instruction index (computed from PC) and `break` out of
            // the match so the loop loops with that idx.
            let mut next_idx_override: Option<usize> = None;

            match inst.inst {
                // ---- Loads ---------------------------------------------------
                RvInst::Lb { rd, rs1, imm } => {
                    let addr = compute_addr(regs, rs1, imm);
                    match mem.read_u8(addr) {
                        Some(v) => reg_write(regs, rd, v as i8 as i64 as u64),
                        None => return page_fault(regs, pc, addr),
                    }
                }
                RvInst::Lh { rd, rs1, imm } => {
                    let addr = compute_addr(regs, rs1, imm);
                    match mem.read_u16_le(addr) {
                        Some(v) => reg_write(regs, rd, v as i16 as i64 as u64),
                        None => return page_fault(regs, pc, addr),
                    }
                }
                RvInst::Lw { rd, rs1, imm } => {
                    let addr = compute_addr(regs, rs1, imm);
                    match mem.read_u32_le(addr) {
                        Some(v) => reg_write(regs, rd, v as i32 as i64 as u64),
                        None => return page_fault(regs, pc, addr),
                    }
                }
                RvInst::Ld { rd, rs1, imm } => {
                    let addr = compute_addr(regs, rs1, imm);
                    match mem.read_u64_le(addr) {
                        Some(v) => reg_write(regs, rd, v),
                        None => return page_fault(regs, pc, addr),
                    }
                }
                RvInst::Lbu { rd, rs1, imm } => {
                    let addr = compute_addr(regs, rs1, imm);
                    match mem.read_u8(addr) {
                        Some(v) => reg_write(regs, rd, v as u64),
                        None => return page_fault(regs, pc, addr),
                    }
                }
                RvInst::Lhu { rd, rs1, imm } => {
                    let addr = compute_addr(regs, rs1, imm);
                    match mem.read_u16_le(addr) {
                        Some(v) => reg_write(regs, rd, v as u64),
                        None => return page_fault(regs, pc, addr),
                    }
                }
                RvInst::Lwu { rd, rs1, imm } => {
                    let addr = compute_addr(regs, rs1, imm);
                    match mem.read_u32_le(addr) {
                        Some(v) => reg_write(regs, rd, v as u64),
                        None => return page_fault(regs, pc, addr),
                    }
                }

                // ---- Stores --------------------------------------------------
                RvInst::Sb { rs1, rs2, imm } => {
                    let addr = compute_addr(regs, rs1, imm);
                    if !mem.write_u8(addr, reg_read(regs, rs2) as u8) {
                        return page_fault(regs, pc, addr);
                    }
                }
                RvInst::Sh { rs1, rs2, imm } => {
                    let addr = compute_addr(regs, rs1, imm);
                    if !mem.write_u16_le(addr, reg_read(regs, rs2) as u16) {
                        return page_fault(regs, pc, addr);
                    }
                }
                RvInst::Sw { rs1, rs2, imm } => {
                    let addr = compute_addr(regs, rs1, imm);
                    if !mem.write_u32_le(addr, reg_read(regs, rs2) as u32) {
                        return page_fault(regs, pc, addr);
                    }
                }
                RvInst::Sd { rs1, rs2, imm } => {
                    let addr = compute_addr(regs, rs1, imm);
                    if !mem.write_u64_le(addr, reg_read(regs, rs2)) {
                        return page_fault(regs, pc, addr);
                    }
                }

                // ---- ALU immediate (64-bit) ----------------------------------
                RvInst::Addi { rd, rs1, imm } => {
                    let v = reg_read(regs, rs1).wrapping_add(imm as i64 as u64);
                    reg_write(regs, rd, v);
                }
                RvInst::Slti { rd, rs1, imm } => {
                    let v = ((reg_read(regs, rs1) as i64) < (imm as i64)) as u64;
                    reg_write(regs, rd, v);
                }
                RvInst::Sltiu { rd, rs1, imm } => {
                    let v = (reg_read(regs, rs1) < (imm as i64 as u64)) as u64;
                    reg_write(regs, rd, v);
                }
                RvInst::Andi { rd, rs1, imm } => {
                    let v = reg_read(regs, rs1) & (imm as i64 as u64);
                    reg_write(regs, rd, v);
                }
                RvInst::Ori { rd, rs1, imm } => {
                    let v = reg_read(regs, rs1) | (imm as i64 as u64);
                    reg_write(regs, rd, v);
                }
                RvInst::Xori { rd, rs1, imm } => {
                    let v = reg_read(regs, rs1) ^ (imm as i64 as u64);
                    reg_write(regs, rd, v);
                }
                RvInst::Slli { rd, rs1, shamt } => {
                    reg_write(
                        regs,
                        rd,
                        reg_read(regs, rs1).wrapping_shl(shamt as u32 & 63),
                    );
                }
                RvInst::Srli { rd, rs1, shamt } => {
                    reg_write(
                        regs,
                        rd,
                        reg_read(regs, rs1).wrapping_shr(shamt as u32 & 63),
                    );
                }
                RvInst::Srai { rd, rs1, shamt } => {
                    let v = (reg_read(regs, rs1) as i64).wrapping_shr(shamt as u32 & 63);
                    reg_write(regs, rd, v as u64);
                }

                // ---- ALU immediate (32-bit, sign-extend to 64) ---------------
                RvInst::Addiw { rd, rs1, imm } => {
                    let v = (reg_read(regs, rs1) as i32).wrapping_add(imm);
                    reg_write(regs, rd, v as i64 as u64);
                }
                RvInst::Slliw { rd, rs1, shamt } => {
                    let v = (reg_read(regs, rs1) as u32).wrapping_shl(shamt as u32 & 31);
                    reg_write(regs, rd, v as i32 as i64 as u64);
                }
                RvInst::Srliw { rd, rs1, shamt } => {
                    let v = (reg_read(regs, rs1) as u32).wrapping_shr(shamt as u32 & 31);
                    reg_write(regs, rd, v as i32 as i64 as u64);
                }
                RvInst::Sraiw { rd, rs1, shamt } => {
                    let v = (reg_read(regs, rs1) as i32).wrapping_shr(shamt as u32 & 31);
                    reg_write(regs, rd, v as i64 as u64);
                }

                // ---- ALU register-register (64-bit) --------------------------
                RvInst::Add { rd, rs1, rs2 } => {
                    let v = reg_read(regs, rs1).wrapping_add(reg_read(regs, rs2));
                    reg_write(regs, rd, v);
                }
                RvInst::Sub { rd, rs1, rs2 } => {
                    let v = reg_read(regs, rs1).wrapping_sub(reg_read(regs, rs2));
                    reg_write(regs, rd, v);
                }
                RvInst::Sll { rd, rs1, rs2 } => {
                    let s = reg_read(regs, rs2) as u32 & 63;
                    reg_write(regs, rd, reg_read(regs, rs1).wrapping_shl(s));
                }
                RvInst::Srl { rd, rs1, rs2 } => {
                    let s = reg_read(regs, rs2) as u32 & 63;
                    reg_write(regs, rd, reg_read(regs, rs1).wrapping_shr(s));
                }
                RvInst::Sra { rd, rs1, rs2 } => {
                    let s = reg_read(regs, rs2) as u32 & 63;
                    reg_write(
                        regs,
                        rd,
                        (reg_read(regs, rs1) as i64).wrapping_shr(s) as u64,
                    );
                }
                RvInst::Slt { rd, rs1, rs2 } => {
                    let v = ((reg_read(regs, rs1) as i64) < (reg_read(regs, rs2) as i64)) as u64;
                    reg_write(regs, rd, v);
                }
                RvInst::Sltu { rd, rs1, rs2 } => {
                    let v = (reg_read(regs, rs1) < reg_read(regs, rs2)) as u64;
                    reg_write(regs, rd, v);
                }
                RvInst::Xor { rd, rs1, rs2 } => {
                    reg_write(regs, rd, reg_read(regs, rs1) ^ reg_read(regs, rs2));
                }
                RvInst::Or { rd, rs1, rs2 } => {
                    reg_write(regs, rd, reg_read(regs, rs1) | reg_read(regs, rs2));
                }
                RvInst::And { rd, rs1, rs2 } => {
                    reg_write(regs, rd, reg_read(regs, rs1) & reg_read(regs, rs2));
                }

                // ---- ALU register-register (32-bit, sign-extend to 64) ------
                RvInst::Addw { rd, rs1, rs2 } => {
                    let v = (reg_read(regs, rs1) as i32).wrapping_add(reg_read(regs, rs2) as i32);
                    reg_write(regs, rd, v as i64 as u64);
                }
                RvInst::Subw { rd, rs1, rs2 } => {
                    let v = (reg_read(regs, rs1) as i32).wrapping_sub(reg_read(regs, rs2) as i32);
                    reg_write(regs, rd, v as i64 as u64);
                }
                RvInst::Sllw { rd, rs1, rs2 } => {
                    let s = reg_read(regs, rs2) as u32 & 31;
                    let v = (reg_read(regs, rs1) as u32).wrapping_shl(s);
                    reg_write(regs, rd, v as i32 as i64 as u64);
                }
                RvInst::Srlw { rd, rs1, rs2 } => {
                    let s = reg_read(regs, rs2) as u32 & 31;
                    let v = (reg_read(regs, rs1) as u32).wrapping_shr(s);
                    reg_write(regs, rd, v as i32 as i64 as u64);
                }
                RvInst::Sraw { rd, rs1, rs2 } => {
                    let s = reg_read(regs, rs2) as u32 & 31;
                    let v = (reg_read(regs, rs1) as i32).wrapping_shr(s);
                    reg_write(regs, rd, v as i64 as u64);
                }

                // ---- M extension --------------------------------------------
                RvInst::Mul { rd, rs1, rs2 } => {
                    let v = reg_read(regs, rs1).wrapping_mul(reg_read(regs, rs2));
                    reg_write(regs, rd, v);
                }
                RvInst::Mulh { rd, rs1, rs2 } => {
                    let a = reg_read(regs, rs1) as i64 as i128;
                    let b = reg_read(regs, rs2) as i64 as i128;
                    reg_write(regs, rd, ((a * b) >> 64) as u64);
                }
                RvInst::Mulhsu { rd, rs1, rs2 } => {
                    let a = reg_read(regs, rs1) as i64 as i128;
                    let b = reg_read(regs, rs2) as u128 as i128;
                    reg_write(regs, rd, ((a * b) >> 64) as u64);
                }
                RvInst::Mulhu { rd, rs1, rs2 } => {
                    let a = reg_read(regs, rs1) as u128;
                    let b = reg_read(regs, rs2) as u128;
                    reg_write(regs, rd, ((a * b) >> 64) as u64);
                }
                RvInst::Div { rd, rs1, rs2 } => {
                    let a = reg_read(regs, rs1) as i64;
                    let b = reg_read(regs, rs2) as i64;
                    let v = if b == 0 {
                        u64::MAX
                    } else if a == i64::MIN && b == -1 {
                        a as u64
                    } else {
                        (a / b) as u64
                    };
                    reg_write(regs, rd, v);
                }
                RvInst::Divu { rd, rs1, rs2 } => {
                    let a = reg_read(regs, rs1);
                    let b = reg_read(regs, rs2);
                    let v = a.checked_div(b).unwrap_or(u64::MAX);
                    reg_write(regs, rd, v);
                }
                RvInst::Rem { rd, rs1, rs2 } => {
                    let a = reg_read(regs, rs1) as i64;
                    let b = reg_read(regs, rs2) as i64;
                    let v = if b == 0 {
                        a as u64
                    } else if a == i64::MIN && b == -1 {
                        0
                    } else {
                        (a % b) as u64
                    };
                    reg_write(regs, rd, v);
                }
                RvInst::Remu { rd, rs1, rs2 } => {
                    let a = reg_read(regs, rs1);
                    let b = reg_read(regs, rs2);
                    let v = if b == 0 { a } else { a % b };
                    reg_write(regs, rd, v);
                }
                RvInst::Mulw { rd, rs1, rs2 } => {
                    let v = (reg_read(regs, rs1) as i32).wrapping_mul(reg_read(regs, rs2) as i32);
                    reg_write(regs, rd, v as i64 as u64);
                }
                RvInst::Divw { rd, rs1, rs2 } => {
                    let a = reg_read(regs, rs1) as i32;
                    let b = reg_read(regs, rs2) as i32;
                    let v = if b == 0 {
                        u32::MAX as i32
                    } else if a == i32::MIN && b == -1 {
                        a
                    } else {
                        a / b
                    };
                    reg_write(regs, rd, v as i64 as u64);
                }
                RvInst::Divuw { rd, rs1, rs2 } => {
                    let a = reg_read(regs, rs1) as u32;
                    let b = reg_read(regs, rs2) as u32;
                    let v = a.checked_div(b).unwrap_or(u32::MAX);
                    reg_write(regs, rd, v as i32 as i64 as u64);
                }
                RvInst::Remw { rd, rs1, rs2 } => {
                    let a = reg_read(regs, rs1) as i32;
                    let b = reg_read(regs, rs2) as i32;
                    let v = if b == 0 {
                        a
                    } else if a == i32::MIN && b == -1 {
                        0
                    } else {
                        a % b
                    };
                    reg_write(regs, rd, v as i64 as u64);
                }
                RvInst::Remuw { rd, rs1, rs2 } => {
                    let a = reg_read(regs, rs1) as u32;
                    let b = reg_read(regs, rs2) as u32;
                    let v = if b == 0 { a } else { a % b };
                    reg_write(regs, rd, v as i32 as i64 as u64);
                }

                // ---- Zbb -----------------------------------------------------
                RvInst::Clz { rd, rs1 } => {
                    reg_write(regs, rd, reg_read(regs, rs1).leading_zeros() as u64);
                }
                RvInst::Clzw { rd, rs1 } => {
                    reg_write(
                        regs,
                        rd,
                        (reg_read(regs, rs1) as u32).leading_zeros() as u64,
                    );
                }
                RvInst::Ctz { rd, rs1 } => {
                    let v = reg_read(regs, rs1);
                    let n = if v == 0 { 64 } else { v.trailing_zeros() };
                    reg_write(regs, rd, n as u64);
                }
                RvInst::Ctzw { rd, rs1 } => {
                    let v = reg_read(regs, rs1) as u32;
                    let n = if v == 0 { 32 } else { v.trailing_zeros() };
                    reg_write(regs, rd, n as u64);
                }
                RvInst::Cpop { rd, rs1 } => {
                    reg_write(regs, rd, reg_read(regs, rs1).count_ones() as u64);
                }
                RvInst::Cpopw { rd, rs1 } => {
                    reg_write(regs, rd, (reg_read(regs, rs1) as u32).count_ones() as u64);
                }
                RvInst::SextB { rd, rs1 } => {
                    reg_write(regs, rd, reg_read(regs, rs1) as i8 as i64 as u64);
                }
                RvInst::SextH { rd, rs1 } => {
                    reg_write(regs, rd, reg_read(regs, rs1) as i16 as i64 as u64);
                }
                RvInst::ZextH { rd, rs1 } => {
                    reg_write(regs, rd, reg_read(regs, rs1) & 0xFFFF);
                }
                RvInst::Rev8 { rd, rs1 } => {
                    reg_write(regs, rd, reg_read(regs, rs1).swap_bytes());
                }
                RvInst::OrcB { rd, rs1 } => {
                    let v = reg_read(regs, rs1);
                    // Per-byte: replace each byte by 0xFF if non-zero, else 0.
                    let mut out: u64 = 0;
                    for i in 0..8 {
                        let b = (v >> (i * 8)) & 0xFF;
                        if b != 0 {
                            out |= 0xFFu64 << (i * 8);
                        }
                    }
                    reg_write(regs, rd, out);
                }
                RvInst::Min { rd, rs1, rs2 } => {
                    let a = reg_read(regs, rs1) as i64;
                    let b = reg_read(regs, rs2) as i64;
                    reg_write(regs, rd, a.min(b) as u64);
                }
                RvInst::Minu { rd, rs1, rs2 } => {
                    let a = reg_read(regs, rs1);
                    let b = reg_read(regs, rs2);
                    reg_write(regs, rd, a.min(b));
                }
                RvInst::Max { rd, rs1, rs2 } => {
                    let a = reg_read(regs, rs1) as i64;
                    let b = reg_read(regs, rs2) as i64;
                    reg_write(regs, rd, a.max(b) as u64);
                }
                RvInst::Maxu { rd, rs1, rs2 } => {
                    let a = reg_read(regs, rs1);
                    let b = reg_read(regs, rs2);
                    reg_write(regs, rd, a.max(b));
                }
                RvInst::Andn { rd, rs1, rs2 } => {
                    reg_write(regs, rd, reg_read(regs, rs1) & !reg_read(regs, rs2));
                }
                RvInst::Orn { rd, rs1, rs2 } => {
                    reg_write(regs, rd, reg_read(regs, rs1) | !reg_read(regs, rs2));
                }
                RvInst::Xnor { rd, rs1, rs2 } => {
                    reg_write(regs, rd, !(reg_read(regs, rs1) ^ reg_read(regs, rs2)));
                }
                RvInst::Rol { rd, rs1, rs2 } => {
                    let s = reg_read(regs, rs2) as u32 & 63;
                    reg_write(regs, rd, reg_read(regs, rs1).rotate_left(s));
                }
                RvInst::Ror { rd, rs1, rs2 } => {
                    let s = reg_read(regs, rs2) as u32 & 63;
                    reg_write(regs, rd, reg_read(regs, rs1).rotate_right(s));
                }
                RvInst::Rolw { rd, rs1, rs2 } => {
                    let s = reg_read(regs, rs2) as u32 & 31;
                    let v = (reg_read(regs, rs1) as u32).rotate_left(s);
                    reg_write(regs, rd, v as i32 as i64 as u64);
                }
                RvInst::Rorw { rd, rs1, rs2 } => {
                    let s = reg_read(regs, rs2) as u32 & 31;
                    let v = (reg_read(regs, rs1) as u32).rotate_right(s);
                    reg_write(regs, rd, v as i32 as i64 as u64);
                }
                RvInst::Rori { rd, rs1, shamt } => {
                    reg_write(
                        regs,
                        rd,
                        reg_read(regs, rs1).rotate_right(shamt as u32 & 63),
                    );
                }
                RvInst::Roriw { rd, rs1, shamt } => {
                    let v = (reg_read(regs, rs1) as u32).rotate_right(shamt as u32 & 31);
                    reg_write(regs, rd, v as i32 as i64 as u64);
                }

                // ---- Zba -----------------------------------------------------
                RvInst::Sh1add { rd, rs1, rs2 } => {
                    let v = reg_read(regs, rs1)
                        .wrapping_shl(1)
                        .wrapping_add(reg_read(regs, rs2));
                    reg_write(regs, rd, v);
                }
                RvInst::Sh2add { rd, rs1, rs2 } => {
                    let v = reg_read(regs, rs1)
                        .wrapping_shl(2)
                        .wrapping_add(reg_read(regs, rs2));
                    reg_write(regs, rd, v);
                }
                RvInst::Sh3add { rd, rs1, rs2 } => {
                    let v = reg_read(regs, rs1)
                        .wrapping_shl(3)
                        .wrapping_add(reg_read(regs, rs2));
                    reg_write(regs, rd, v);
                }
                RvInst::Sh1adduw { rd, rs1, rs2 } => {
                    let a = (reg_read(regs, rs1) as u32 as u64).wrapping_shl(1);
                    reg_write(regs, rd, a.wrapping_add(reg_read(regs, rs2)));
                }
                RvInst::Sh2adduw { rd, rs1, rs2 } => {
                    let a = (reg_read(regs, rs1) as u32 as u64).wrapping_shl(2);
                    reg_write(regs, rd, a.wrapping_add(reg_read(regs, rs2)));
                }
                RvInst::Sh3adduw { rd, rs1, rs2 } => {
                    let a = (reg_read(regs, rs1) as u32 as u64).wrapping_shl(3);
                    reg_write(regs, rd, a.wrapping_add(reg_read(regs, rs2)));
                }
                RvInst::Adduw { rd, rs1, rs2 } => {
                    let a = reg_read(regs, rs1) as u32 as u64;
                    reg_write(regs, rd, a.wrapping_add(reg_read(regs, rs2)));
                }
                RvInst::Slliuw { rd, rs1, shamt } => {
                    let a = reg_read(regs, rs1) as u32 as u64;
                    reg_write(regs, rd, a.wrapping_shl(shamt as u32 & 63));
                }

                // ---- Zbs (single-bit) ----------------------------------------
                RvInst::Bclr { rd, rs1, rs2 } => {
                    let bit = reg_read(regs, rs2) & 63;
                    reg_write(regs, rd, reg_read(regs, rs1) & !(1u64 << bit));
                }
                RvInst::Bset { rd, rs1, rs2 } => {
                    let bit = reg_read(regs, rs2) & 63;
                    reg_write(regs, rd, reg_read(regs, rs1) | (1u64 << bit));
                }
                RvInst::Binv { rd, rs1, rs2 } => {
                    let bit = reg_read(regs, rs2) & 63;
                    reg_write(regs, rd, reg_read(regs, rs1) ^ (1u64 << bit));
                }
                RvInst::Bext { rd, rs1, rs2 } => {
                    let bit = reg_read(regs, rs2) & 63;
                    reg_write(regs, rd, (reg_read(regs, rs1) >> bit) & 1);
                }
                RvInst::Bclri { rd, rs1, shamt } => {
                    reg_write(regs, rd, reg_read(regs, rs1) & !(1u64 << (shamt & 63)));
                }
                RvInst::Bseti { rd, rs1, shamt } => {
                    reg_write(regs, rd, reg_read(regs, rs1) | (1u64 << (shamt & 63)));
                }
                RvInst::Binvi { rd, rs1, shamt } => {
                    reg_write(regs, rd, reg_read(regs, rs1) ^ (1u64 << (shamt & 63)));
                }
                RvInst::Bexti { rd, rs1, shamt } => {
                    reg_write(regs, rd, (reg_read(regs, rs1) >> (shamt & 63)) & 1);
                }

                // ---- Zicond --------------------------------------------------
                RvInst::CzeroEqz { rd, rs1, rs2 } => {
                    // (rs2 == 0) ? 0 : rs1
                    let v = if reg_read(regs, rs2) == 0 {
                        0
                    } else {
                        reg_read(regs, rs1)
                    };
                    reg_write(regs, rd, v);
                }
                RvInst::CzeroNez { rd, rs1, rs2 } => {
                    // (rs2 != 0) ? 0 : rs1
                    let v = if reg_read(regs, rs2) != 0 {
                        0
                    } else {
                        reg_read(regs, rs1)
                    };
                    reg_write(regs, rd, v);
                }

                // ---- Upper immediate ----------------------------------------
                RvInst::Lui { rd, imm } => {
                    reg_write(regs, rd, imm as i64 as u64);
                }

                // ---- Control flow -------------------------------------------
                RvInst::Jal { rd, imm } => {
                    if rd != 0 {
                        reg_write(regs, rd, next_pc as u64);
                    }
                    let target = (pc as i64).wrapping_add(imm as i64) as u32;
                    next_idx_override = Some(match find_idx_for_pc(insts, target) {
                        Some(i) => i,
                        None => {
                            regs.pc = pc as u64;
                            return ExitReason::Panic;
                        }
                    });
                }
                RvInst::Beq { rs1, rs2, imm } => {
                    if reg_read(regs, rs1) == reg_read(regs, rs2) {
                        let target = (pc as i64).wrapping_add(imm as i64) as u32;
                        match find_idx_for_pc(insts, target) {
                            Some(i) => next_idx_override = Some(i),
                            None => {
                                regs.pc = pc as u64;
                                return ExitReason::Panic;
                            }
                        }
                    }
                }
                RvInst::Bne { rs1, rs2, imm } => {
                    if reg_read(regs, rs1) != reg_read(regs, rs2) {
                        let target = (pc as i64).wrapping_add(imm as i64) as u32;
                        match find_idx_for_pc(insts, target) {
                            Some(i) => next_idx_override = Some(i),
                            None => {
                                regs.pc = pc as u64;
                                return ExitReason::Panic;
                            }
                        }
                    }
                }
                RvInst::Blt { rs1, rs2, imm } => {
                    if (reg_read(regs, rs1) as i64) < (reg_read(regs, rs2) as i64) {
                        let target = (pc as i64).wrapping_add(imm as i64) as u32;
                        match find_idx_for_pc(insts, target) {
                            Some(i) => next_idx_override = Some(i),
                            None => {
                                regs.pc = pc as u64;
                                return ExitReason::Panic;
                            }
                        }
                    }
                }
                RvInst::Bge { rs1, rs2, imm } => {
                    if (reg_read(regs, rs1) as i64) >= (reg_read(regs, rs2) as i64) {
                        let target = (pc as i64).wrapping_add(imm as i64) as u32;
                        match find_idx_for_pc(insts, target) {
                            Some(i) => next_idx_override = Some(i),
                            None => {
                                regs.pc = pc as u64;
                                return ExitReason::Panic;
                            }
                        }
                    }
                }
                RvInst::Bltu { rs1, rs2, imm } => {
                    if reg_read(regs, rs1) < reg_read(regs, rs2) {
                        let target = (pc as i64).wrapping_add(imm as i64) as u32;
                        match find_idx_for_pc(insts, target) {
                            Some(i) => next_idx_override = Some(i),
                            None => {
                                regs.pc = pc as u64;
                                return ExitReason::Panic;
                            }
                        }
                    }
                }
                RvInst::Bgeu { rs1, rs2, imm } => {
                    if reg_read(regs, rs1) >= reg_read(regs, rs2) {
                        let target = (pc as i64).wrapping_add(imm as i64) as u32;
                        match find_idx_for_pc(insts, target) {
                            Some(i) => next_idx_override = Some(i),
                            None => {
                                regs.pc = pc as u64;
                                return ExitReason::Panic;
                            }
                        }
                    }
                }

                // ---- System (no-op for our single-threaded VM) --------------
                RvInst::Fence | RvInst::FenceI => {}

                // ---- Custom-0 -----------------------------------------------
                RvInst::Trap => {
                    regs.pc = pc as u64;
                    return ExitReason::Trap;
                }
                RvInst::EcallJar => {
                    regs.pc = next_pc as u64;
                    match handler.handle(EcallKind::Ecall, regs, mem) {
                        EcallResult::Continue => match find_idx_for_pc(insts, next_pc) {
                            Some(i) => next_idx_override = Some(i),
                            None => return ExitReason::Panic,
                        },
                        EcallResult::Exit(r) => return r,
                    }
                }
                RvInst::Ecalli { imm } => {
                    regs.pc = next_pc as u64;
                    match handler.handle(EcallKind::Ecalli(imm as u32), regs, mem) {
                        EcallResult::Continue => match find_idx_for_pc(insts, next_pc) {
                            Some(i) => next_idx_override = Some(i),
                            None => return ExitReason::Panic,
                        },
                        EcallResult::Exit(r) => return r,
                    }
                }
                RvInst::BrTable { table_id, rs1 } => {
                    // Spec: idx = (rs1 - 1) >> 1; if rs1 == 0 or idx OOB,
                    // recompiler routes to PANIC (not fallthrough — see
                    // `rv_br_table` comment). Match exactly.
                    let rs1_v = reg_read(regs, rs1);
                    if rs1_v == 0 {
                        regs.pc = pc as u64;
                        return ExitReason::Panic;
                    }
                    let entry_idx = ((rs1_v - 1) >> 1) as usize;
                    let nt = jump_table_offsets.len().saturating_sub(1);
                    if (table_id as usize) >= nt {
                        regs.pc = pc as u64;
                        return ExitReason::Panic;
                    }
                    let start = jump_table_offsets[table_id as usize] as usize;
                    let end = jump_table_offsets[(table_id as usize) + 1] as usize;
                    if entry_idx >= end - start {
                        regs.pc = pc as u64;
                        return ExitReason::Panic;
                    }
                    let target = jump_table[start + entry_idx];
                    match find_idx_for_pc(insts, target) {
                        Some(i) => next_idx_override = Some(i),
                        None => {
                            regs.pc = pc as u64;
                            return ExitReason::Panic;
                        }
                    }
                }
                RvInst::Fallthrough => {
                    // Terminator no-op: just advance. The next instruction is
                    // already marked as a block start so its cost gets
                    // charged on the next iteration.
                }

                RvInst::Reserved { .. } => {
                    regs.pc = pc as u64;
                    return ExitReason::Panic;
                }
            }

            // Advance to the next instruction. Branches / Jal / BrTable /
            // post-handler Ecalli set `next_idx_override`; everything else
            // falls through to the sequential next.
            match next_idx_override {
                Some(new_idx) => idx = new_idx,
                None => {
                    idx += 1;
                    if idx >= insts.len() {
                        // Ran off the end. PVM2 expects every reachable
                        // program path to end in a terminator.
                        regs.pc = next_pc as u64;
                        return ExitReason::Panic;
                    }
                }
            }
        }
    }
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

/// Read PVM2 register `x`. `x0` reads as zero; `x3`/`x4` are reserved
/// (defence-in-depth zero); `x1..x2, x5..x15` map to slots `0..12`.
#[inline]
fn reg_read(regs: &Regs, x: u8) -> u64 {
    match x {
        0 => 0,
        1 => regs.gpr[0],
        2 => regs.gpr[1],
        5..=15 => regs.gpr[(x as usize) - 3],
        _ => 0,
    }
}

/// Write PVM2 register `x`. Writes to `x0`, `x3`, `x4`, or out-of-range
/// are no-ops.
#[inline]
fn reg_write(regs: &mut Regs, x: u8, v: u64) {
    match x {
        0 => {}
        1 => regs.gpr[0] = v,
        2 => regs.gpr[1] = v,
        5..=15 => regs.gpr[(x as usize) - 3] = v,
        _ => {}
    }
}

/// `(rs1 + imm) & 0xFFFFFFFF` — PVM2 effective address (sandbox is
/// 32-bit). Matches `rv_addr_to_scratch` in the recompiler.
#[inline]
fn compute_addr(regs: &Regs, rs1: u8, imm: i32) -> u32 {
    (reg_read(regs, rs1) as u32).wrapping_add(imm as u32)
}

/// Build a `PageFault` exit and record the failing PC.
#[inline]
fn page_fault(regs: &mut Regs, pc: u32, addr: u32) -> ExitReason {
    regs.pc = pc as u64;
    ExitReason::PageFault(addr & !0xFFF)
}

/// Binary-search `insts` (sorted by `pc`) for an entry whose `pc` matches.
#[inline]
fn find_idx_for_pc(insts: &[RvPreDecodedInst], pc: u32) -> Option<usize> {
    insts.binary_search_by_key(&pc, |i| i.pc).ok()
}

#[cfg(test)]
#[allow(clippy::identity_op)] // Encoding constants are clearer with explicit zero shifts.
mod tests {
    use super::*;
    use crate::ecall::PanickingHandler;
    use crate::mem::CopyingMemory;
    use crate::rv_predecode::predecode_rv;
    use alloc::vec::Vec;

    fn enc4(words: &[u32]) -> Vec<u8> {
        let mut v = Vec::with_capacity(words.len() * 4);
        for w in words {
            v.extend_from_slice(&w.to_le_bytes());
        }
        v
    }

    fn run_simple(code: &[u8], initial_gas: u64) -> (Regs, ExitReason, u64) {
        let pre = predecode_rv(code);
        let mut regs = Regs::new();
        let mut mem = CopyingMemory::new();
        let mut gas = GasCounter::new(initial_gas);
        let mut h = PanickingHandler;
        let reason = RvInterpreter::run(&pre, &[], &[], &mut regs, &mut mem, &mut gas, &mut h);
        let used = initial_gas.saturating_sub(gas.remaining());
        (regs, reason, used)
    }

    #[test]
    fn trap_immediately() {
        // trap: custom-0 funct3=000 = opcode 0x0B = (0b00010 << 2) | 0b11
        // word = (0b000 << 12) | 0x0B = 0x0000_000B
        let code = enc4(&[0x0000_000B]);
        let (regs, reason, _) = run_simple(&code, 1_000_000);
        assert_eq!(reason, ExitReason::Trap);
        assert_eq!(regs.pc, 0);
    }

    #[test]
    fn addi_then_trap() {
        // addi x10, x0, 42 ; trap
        // addi I-type: imm[11:0]=42, rs1=0, funct3=000, rd=10, opcode=0010011
        // = (42 << 20) | (0 << 15) | (0 << 12) | (10 << 7) | 0x13
        // = 0x02A00513
        let addi = (42u32 << 20) | (10 << 7) | 0x13;
        let trap = 0x0000_000Bu32;
        let code = enc4(&[addi, trap]);
        let (regs, reason, _) = run_simple(&code, 1_000_000);
        assert_eq!(reason, ExitReason::Trap);
        // x10 → slot 7 (x10 - 3 = 7)
        assert_eq!(regs.gpr[7], 42);
    }

    #[test]
    fn div_by_zero_returns_neg_one() {
        // addi x5, x0, 7 ; addi x6, x0, 0 ; div x7, x5, x6 ; trap
        let addi_x5_7 = (7u32 << 20) | (5 << 7) | 0x13;
        let addi_x6_0 = (0u32 << 20) | (6 << 7) | 0x13;
        // div = funct7=0000001, rs2, rs1, funct3=100, rd, opcode=0110011
        let div = (1u32 << 25) | (6 << 20) | (5 << 15) | (0b100 << 12) | (7 << 7) | 0x33;
        let trap = 0x0000_000Bu32;
        let code = enc4(&[addi_x5_7, addi_x6_0, div, trap]);
        let (regs, _reason, _) = run_simple(&code, 1_000_000);
        // x7 → slot 4 (x7 - 3 = 4)
        assert_eq!(regs.gpr[4], u64::MAX);
    }

    #[test]
    fn out_of_gas_at_block_start() {
        // addi x10, x0, 1 ; trap — needs more gas than supplied.
        let addi = (1u32 << 20) | (10 << 7) | 0x13;
        let trap = 0x0000_000Bu32;
        let code = enc4(&[addi, trap]);
        let (regs, reason, _) = run_simple(&code, 0);
        assert_eq!(reason, ExitReason::OutOfGas);
        assert_eq!(regs.pc, 0);
    }

    #[test]
    fn sign_extend_addiw() {
        // addiw x10, x0, -1 → x10 = 0xFFFFFFFF_FFFFFFFF (sign-extended)
        let addiw = ((-1i32) as u32) << 20 | (0 << 15) | (0 << 12) | (10 << 7) | 0x1B;
        let trap = 0x0000_000Bu32;
        let code = enc4(&[addiw, trap]);
        let (regs, _reason, _) = run_simple(&code, 1_000_000);
        assert_eq!(regs.gpr[7], u64::MAX);
    }

    #[test]
    fn czero_eqz_zeroes_when_rs2_is_zero() {
        // addi x5, x0, 42 ; addi x6, x0, 0 ; czero.eqz x7, x5, x6 ; trap
        // czero.eqz: funct7=0000111, rs2, rs1, funct3=101, rd, OP=0110011
        let addi_x5 = (42u32 << 20) | (5 << 7) | 0x13;
        let addi_x6 = (0u32 << 20) | (6 << 7) | 0x13;
        let czero = (0b0000111u32 << 25) | (6 << 20) | (5 << 15) | (0b101 << 12) | (7 << 7) | 0x33;
        let trap = 0x0000_000Bu32;
        let code = enc4(&[addi_x5, addi_x6, czero, trap]);
        let (regs, _reason, _) = run_simple(&code, 1_000_000);
        assert_eq!(regs.gpr[4], 0); // x7 = 0 because rs2 (x6) == 0
    }

    #[test]
    fn czero_eqz_passes_when_rs2_nonzero() {
        let addi_x5 = (42u32 << 20) | (5 << 7) | 0x13;
        let addi_x6 = (3u32 << 20) | (6 << 7) | 0x13;
        let czero = (0b0000111u32 << 25) | (6 << 20) | (5 << 15) | (0b101 << 12) | (7 << 7) | 0x33;
        let trap = 0x0000_000Bu32;
        let code = enc4(&[addi_x5, addi_x6, czero, trap]);
        let (regs, _reason, _) = run_simple(&code, 1_000_000);
        assert_eq!(regs.gpr[4], 42); // rs2 != 0 → rd = rs1
    }

    #[test]
    fn br_table_zero_rs1_panics() {
        // br_table table_id=0, rs1=5 (x5 = 0 by default)
        // custom-0 I-type: funct3=011, rd=0
        let br_table = (0u32 << 20) | (5 << 15) | (0b011 << 12) | (0 << 7) | (0b00010 << 2) | 0b11;
        let code = enc4(&[br_table]);
        // Provide a jump_table_offsets with one table to pass the
        // table_id bounds check; rs1=0 should panic regardless.
        let pre = predecode_rv(&code);
        let mut regs = Regs::new();
        let mut mem = CopyingMemory::new();
        let mut gas = GasCounter::new(1_000_000);
        let mut h = PanickingHandler;
        let reason = RvInterpreter::run(&pre, &[], &[0, 0], &mut regs, &mut mem, &mut gas, &mut h);
        assert_eq!(reason, ExitReason::Panic);
    }
}
