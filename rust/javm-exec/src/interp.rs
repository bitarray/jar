//! PVM2 (RV+C+Zbb+Zba+Zbs+Zicond+custom-0) interpreter.
//!
//! [`Program`] bundles the constituents an interpreter run needs
//! (code bytes, predecode output, code base) so the integration layer
//! can cache the predecode alongside the bytecode and pass a single Arc
//! to the executor.
//!
//! Mirrors the recompiler's semantics — same per-block gas charging at
//! `Predecode::block_costs`, same RV-spec ALU/branch behaviour, same
//! `Ecalli`/`Jalr` runtime contracts (jalr targets validated to be
//! basic-block starts via the per-instruction block-start flag).
//! Cross-checked against the recompiler in
//! the `smoke` example: bit-identical `gas_used` and side-effects on
//! every workload.
//!
//! Dispatch is a `match` over `Inst` variants. Instructions come from
//! [`Predecode::insts`] (one entry per static instruction); static
//! branch / jal targets are resolved to instruction indices via binary
//! search on the (sorted) `insts` array. Reused infrastructure: `Regs`,
//! `Memory` trait, `GasCounter`, `EcallHandler` — identical to the PVM
//! interpreter's contract.

use alloc::vec::Vec;

use crate::ecall::{EcallHandler, EcallKind, EcallResult};
use crate::exit::ExitReason;
use crate::gas::GasCounter;
use crate::instruction::Inst;
use crate::mem::{Memory, perm};
use crate::predecode::{Predecode, RvPreDecodedInst, predecode};
use crate::regs::Regs;

/// Predecoded PVM2 program: bytecode plus the per-instruction analysis
/// the interpreter consumes. Cache-friendly — the integration layer
/// builds one of these per Image and shares it across invocations.
#[derive(Debug)]
pub struct Program {
    pub code: Vec<u8>,
    pub predecode: Predecode,
    /// Guest VA at which this code region is mapped, so that
    /// `PC = code_base + byte_offset`. `regs.pc` and
    /// `predecode.insts[].pc` are offsets; register-held code addresses
    /// (return addresses, auipc results) are VAs (`code_base + offset`).
    pub code_base: u32,
}

impl Program {
    /// Predecode `code`. The predecode pass is O(code.len()); cache
    /// the result. `code_base` is the guest VA the region is mapped at.
    pub fn new(code: Vec<u8>, code_base: u32) -> Self {
        let predecode = predecode(&code);
        Self {
            code,
            predecode,
            code_base,
        }
    }
}

/// PVM2 interpreter namespace.
pub struct Interpreter;

impl Interpreter {
    /// Convenience wrapper for [`Interpreter::run`] that accepts a
    /// cached [`Program`].
    #[inline]
    pub fn run_program<M: Memory>(
        program: &Program,
        regs: &mut Regs,
        mem: &mut M,
        gas: &mut GasCounter,
        handler: &mut dyn EcallHandler,
    ) -> ExitReason {
        Self::run(
            &program.predecode,
            &program.code,
            program.code_base,
            regs,
            mem,
            gas,
            handler,
        )
    }

    /// Execute the predecoded PVM2 program starting at `regs.pc` (a
    /// byte-offset into the code region). `code_base` is the guest VA
    /// the region is mapped at: jal/jalr/auipc produce and consume
    /// code addresses as `code_base + offset`.
    pub fn run<M: Memory>(
        predecode: &Predecode,
        code: &[u8],
        code_base: u32,
        regs: &mut Regs,
        mem: &mut M,
        gas: &mut GasCounter,
        handler: &mut dyn EcallHandler,
    ) -> ExitReason {
        // `decode_error_at` records a Reserved encoding seen during the
        // predecode walk but doesn't preclude execution: programs may
        // contain unreachable padding (e.g. `0x0000` bytes between
        // functions) that the recompiler also tolerates. We panic only
        // if execution actually *reaches* a `Inst::Reserved` arm.
        let insts: &[RvPreDecodedInst] = &predecode.insts;
        if insts.is_empty() {
            return ExitReason::Panic;
        }

        // Resolve starting PC → instruction index. The entry must be a
        // basic-block start: a fresh invocation enters at an endpoint's
        // `entry_pc` (untrusted Image metadata) and every resume lands on
        // a post-terminator `bb_start` (the pause invariant). A
        // non-block-start entry would run a partial block having charged
        // zero gas — so we Panic, exactly as the recompiler's prologue
        // does (its dense dispatch table holds the panic stub at every
        // non-block-start offset). Lazy: this fires at invocation, never
        // at Image admission.
        let mut idx = match find_idx_for_pc(insts, regs.pc as u32) {
            Some(i) if insts[i].is_gas_block_start => i,
            _ => return ExitReason::Panic,
        };

        loop {
            let inst = unsafe { insts.get_unchecked(idx) };

            // Per-block gas gate: **check before charge** (pre-reserve),
            // so gas never goes negative and OOG never charges the
            // un-entered block (see ~/docs/spec-staging/gas-cost.md §1).
            // A block enters only if gas covers its instruction cost
            // *plus* its worst-case #3 reserve; only the instruction cost
            // is debited (the reserve is a gate). `cost == 0` marks an
            // ecall/ecalli block — no static gate; charged dynamically.
            if inst.is_gas_block_start {
                let cost = predecode.block_costs[idx] as u64;
                if cost != 0 {
                    let reserve = predecode.block_reserves[idx] as u64;
                    if gas.remaining() < cost + reserve {
                        regs.pc = inst.pc as u64;
                        return ExitReason::OutOfGas;
                    }
                    gas.charge(cost).expect("gas pre-reserved at block entry");
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
                Inst::Lb { rd, rs1, imm } => {
                    let addr = compute_addr(regs, rs1, imm);
                    match load_u8(mem, code, code_base, addr) {
                        Some(v) => reg_write(regs, rd, v as i8 as i64 as u64),
                        None => return page_fault(regs, pc, addr),
                    }
                }
                Inst::Lh { rd, rs1, imm } => {
                    let addr = compute_addr(regs, rs1, imm);
                    match load_u16(mem, code, code_base, addr) {
                        Some(v) => reg_write(regs, rd, v as i16 as i64 as u64),
                        None => return page_fault(regs, pc, addr),
                    }
                }
                Inst::Lw { rd, rs1, imm } => {
                    let addr = compute_addr(regs, rs1, imm);
                    match load_u32(mem, code, code_base, addr) {
                        Some(v) => reg_write(regs, rd, v as i32 as i64 as u64),
                        None => return page_fault(regs, pc, addr),
                    }
                }
                Inst::Ld { rd, rs1, imm } => {
                    let addr = compute_addr(regs, rs1, imm);
                    match load_u64(mem, code, code_base, addr) {
                        Some(v) => reg_write(regs, rd, v),
                        None => return page_fault(regs, pc, addr),
                    }
                }
                Inst::Lbu { rd, rs1, imm } => {
                    let addr = compute_addr(regs, rs1, imm);
                    match load_u8(mem, code, code_base, addr) {
                        Some(v) => reg_write(regs, rd, v as u64),
                        None => return page_fault(regs, pc, addr),
                    }
                }
                Inst::Lhu { rd, rs1, imm } => {
                    let addr = compute_addr(regs, rs1, imm);
                    match load_u16(mem, code, code_base, addr) {
                        Some(v) => reg_write(regs, rd, v as u64),
                        None => return page_fault(regs, pc, addr),
                    }
                }
                Inst::Lwu { rd, rs1, imm } => {
                    let addr = compute_addr(regs, rs1, imm);
                    match load_u32(mem, code, code_base, addr) {
                        Some(v) => reg_write(regs, rd, v as u64),
                        None => return page_fault(regs, pc, addr),
                    }
                }

                // ---- Stores --------------------------------------------------
                Inst::Sb { rs1, rs2, imm } => {
                    let addr = compute_addr(regs, rs1, imm);
                    if !store_writable(mem, addr, 1)
                        || !mem.write_u8(addr, reg_read(regs, rs2) as u8)
                    {
                        return page_fault(regs, pc, addr);
                    }
                }
                Inst::Sh { rs1, rs2, imm } => {
                    let addr = compute_addr(regs, rs1, imm);
                    if !store_writable(mem, addr, 2)
                        || !mem.write_u16_le(addr, reg_read(regs, rs2) as u16)
                    {
                        return page_fault(regs, pc, addr);
                    }
                }
                Inst::Sw { rs1, rs2, imm } => {
                    let addr = compute_addr(regs, rs1, imm);
                    if !store_writable(mem, addr, 4)
                        || !mem.write_u32_le(addr, reg_read(regs, rs2) as u32)
                    {
                        return page_fault(regs, pc, addr);
                    }
                }
                Inst::Sd { rs1, rs2, imm } => {
                    let addr = compute_addr(regs, rs1, imm);
                    if !store_writable(mem, addr, 8) || !mem.write_u64_le(addr, reg_read(regs, rs2))
                    {
                        return page_fault(regs, pc, addr);
                    }
                }

                // ---- ALU immediate (64-bit) ----------------------------------
                Inst::Addi { rd, rs1, imm } => {
                    let v = reg_read(regs, rs1).wrapping_add(imm as i64 as u64);
                    reg_write(regs, rd, v);
                }
                Inst::Slti { rd, rs1, imm } => {
                    let v = ((reg_read(regs, rs1) as i64) < (imm as i64)) as u64;
                    reg_write(regs, rd, v);
                }
                Inst::Sltiu { rd, rs1, imm } => {
                    let v = (reg_read(regs, rs1) < (imm as i64 as u64)) as u64;
                    reg_write(regs, rd, v);
                }
                Inst::Andi { rd, rs1, imm } => {
                    let v = reg_read(regs, rs1) & (imm as i64 as u64);
                    reg_write(regs, rd, v);
                }
                Inst::Ori { rd, rs1, imm } => {
                    let v = reg_read(regs, rs1) | (imm as i64 as u64);
                    reg_write(regs, rd, v);
                }
                Inst::Xori { rd, rs1, imm } => {
                    let v = reg_read(regs, rs1) ^ (imm as i64 as u64);
                    reg_write(regs, rd, v);
                }
                Inst::Slli { rd, rs1, shamt } => {
                    reg_write(
                        regs,
                        rd,
                        reg_read(regs, rs1).wrapping_shl(shamt as u32 & 63),
                    );
                }
                Inst::Srli { rd, rs1, shamt } => {
                    reg_write(
                        regs,
                        rd,
                        reg_read(regs, rs1).wrapping_shr(shamt as u32 & 63),
                    );
                }
                Inst::Srai { rd, rs1, shamt } => {
                    let v = (reg_read(regs, rs1) as i64).wrapping_shr(shamt as u32 & 63);
                    reg_write(regs, rd, v as u64);
                }

                // ---- ALU immediate (32-bit, sign-extend to 64) ---------------
                Inst::Addiw { rd, rs1, imm } => {
                    let v = (reg_read(regs, rs1) as i32).wrapping_add(imm);
                    reg_write(regs, rd, v as i64 as u64);
                }
                Inst::Slliw { rd, rs1, shamt } => {
                    let v = (reg_read(regs, rs1) as u32).wrapping_shl(shamt as u32 & 31);
                    reg_write(regs, rd, v as i32 as i64 as u64);
                }
                Inst::Srliw { rd, rs1, shamt } => {
                    let v = (reg_read(regs, rs1) as u32).wrapping_shr(shamt as u32 & 31);
                    reg_write(regs, rd, v as i32 as i64 as u64);
                }
                Inst::Sraiw { rd, rs1, shamt } => {
                    let v = (reg_read(regs, rs1) as i32).wrapping_shr(shamt as u32 & 31);
                    reg_write(regs, rd, v as i64 as u64);
                }

                // ---- ALU register-register (64-bit) --------------------------
                Inst::Add { rd, rs1, rs2 } => {
                    let v = reg_read(regs, rs1).wrapping_add(reg_read(regs, rs2));
                    reg_write(regs, rd, v);
                }
                Inst::Sub { rd, rs1, rs2 } => {
                    let v = reg_read(regs, rs1).wrapping_sub(reg_read(regs, rs2));
                    reg_write(regs, rd, v);
                }
                Inst::Sll { rd, rs1, rs2 } => {
                    let s = reg_read(regs, rs2) as u32 & 63;
                    reg_write(regs, rd, reg_read(regs, rs1).wrapping_shl(s));
                }
                Inst::Srl { rd, rs1, rs2 } => {
                    let s = reg_read(regs, rs2) as u32 & 63;
                    reg_write(regs, rd, reg_read(regs, rs1).wrapping_shr(s));
                }
                Inst::Sra { rd, rs1, rs2 } => {
                    let s = reg_read(regs, rs2) as u32 & 63;
                    reg_write(
                        regs,
                        rd,
                        (reg_read(regs, rs1) as i64).wrapping_shr(s) as u64,
                    );
                }
                Inst::Slt { rd, rs1, rs2 } => {
                    let v = ((reg_read(regs, rs1) as i64) < (reg_read(regs, rs2) as i64)) as u64;
                    reg_write(regs, rd, v);
                }
                Inst::Sltu { rd, rs1, rs2 } => {
                    let v = (reg_read(regs, rs1) < reg_read(regs, rs2)) as u64;
                    reg_write(regs, rd, v);
                }
                Inst::Xor { rd, rs1, rs2 } => {
                    reg_write(regs, rd, reg_read(regs, rs1) ^ reg_read(regs, rs2));
                }
                Inst::Or { rd, rs1, rs2 } => {
                    reg_write(regs, rd, reg_read(regs, rs1) | reg_read(regs, rs2));
                }
                Inst::And { rd, rs1, rs2 } => {
                    reg_write(regs, rd, reg_read(regs, rs1) & reg_read(regs, rs2));
                }

                // ---- ALU register-register (32-bit, sign-extend to 64) ------
                Inst::Addw { rd, rs1, rs2 } => {
                    let v = (reg_read(regs, rs1) as i32).wrapping_add(reg_read(regs, rs2) as i32);
                    reg_write(regs, rd, v as i64 as u64);
                }
                Inst::Subw { rd, rs1, rs2 } => {
                    let v = (reg_read(regs, rs1) as i32).wrapping_sub(reg_read(regs, rs2) as i32);
                    reg_write(regs, rd, v as i64 as u64);
                }
                Inst::Sllw { rd, rs1, rs2 } => {
                    let s = reg_read(regs, rs2) as u32 & 31;
                    let v = (reg_read(regs, rs1) as u32).wrapping_shl(s);
                    reg_write(regs, rd, v as i32 as i64 as u64);
                }
                Inst::Srlw { rd, rs1, rs2 } => {
                    let s = reg_read(regs, rs2) as u32 & 31;
                    let v = (reg_read(regs, rs1) as u32).wrapping_shr(s);
                    reg_write(regs, rd, v as i32 as i64 as u64);
                }
                Inst::Sraw { rd, rs1, rs2 } => {
                    let s = reg_read(regs, rs2) as u32 & 31;
                    let v = (reg_read(regs, rs1) as i32).wrapping_shr(s);
                    reg_write(regs, rd, v as i64 as u64);
                }

                // ---- M extension --------------------------------------------
                Inst::Mul { rd, rs1, rs2 } => {
                    let v = reg_read(regs, rs1).wrapping_mul(reg_read(regs, rs2));
                    reg_write(regs, rd, v);
                }
                Inst::Mulh { rd, rs1, rs2 } => {
                    let a = reg_read(regs, rs1) as i64 as i128;
                    let b = reg_read(regs, rs2) as i64 as i128;
                    reg_write(regs, rd, ((a * b) >> 64) as u64);
                }
                Inst::Mulhsu { rd, rs1, rs2 } => {
                    let a = reg_read(regs, rs1) as i64 as i128;
                    let b = reg_read(regs, rs2) as u128 as i128;
                    reg_write(regs, rd, ((a * b) >> 64) as u64);
                }
                Inst::Mulhu { rd, rs1, rs2 } => {
                    let a = reg_read(regs, rs1) as u128;
                    let b = reg_read(regs, rs2) as u128;
                    reg_write(regs, rd, ((a * b) >> 64) as u64);
                }
                Inst::Div { rd, rs1, rs2 } => {
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
                Inst::Divu { rd, rs1, rs2 } => {
                    let a = reg_read(regs, rs1);
                    let b = reg_read(regs, rs2);
                    let v = a.checked_div(b).unwrap_or(u64::MAX);
                    reg_write(regs, rd, v);
                }
                Inst::Rem { rd, rs1, rs2 } => {
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
                Inst::Remu { rd, rs1, rs2 } => {
                    let a = reg_read(regs, rs1);
                    let b = reg_read(regs, rs2);
                    let v = if b == 0 { a } else { a % b };
                    reg_write(regs, rd, v);
                }
                Inst::Mulw { rd, rs1, rs2 } => {
                    let v = (reg_read(regs, rs1) as i32).wrapping_mul(reg_read(regs, rs2) as i32);
                    reg_write(regs, rd, v as i64 as u64);
                }
                Inst::Divw { rd, rs1, rs2 } => {
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
                Inst::Divuw { rd, rs1, rs2 } => {
                    let a = reg_read(regs, rs1) as u32;
                    let b = reg_read(regs, rs2) as u32;
                    let v = a.checked_div(b).unwrap_or(u32::MAX);
                    reg_write(regs, rd, v as i32 as i64 as u64);
                }
                Inst::Remw { rd, rs1, rs2 } => {
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
                Inst::Remuw { rd, rs1, rs2 } => {
                    let a = reg_read(regs, rs1) as u32;
                    let b = reg_read(regs, rs2) as u32;
                    let v = if b == 0 { a } else { a % b };
                    reg_write(regs, rd, v as i32 as i64 as u64);
                }

                // ---- Zbb -----------------------------------------------------
                Inst::Clz { rd, rs1 } => {
                    reg_write(regs, rd, reg_read(regs, rs1).leading_zeros() as u64);
                }
                Inst::Clzw { rd, rs1 } => {
                    reg_write(
                        regs,
                        rd,
                        (reg_read(regs, rs1) as u32).leading_zeros() as u64,
                    );
                }
                Inst::Ctz { rd, rs1 } => {
                    let v = reg_read(regs, rs1);
                    let n = if v == 0 { 64 } else { v.trailing_zeros() };
                    reg_write(regs, rd, n as u64);
                }
                Inst::Ctzw { rd, rs1 } => {
                    let v = reg_read(regs, rs1) as u32;
                    let n = if v == 0 { 32 } else { v.trailing_zeros() };
                    reg_write(regs, rd, n as u64);
                }
                Inst::Cpop { rd, rs1 } => {
                    reg_write(regs, rd, reg_read(regs, rs1).count_ones() as u64);
                }
                Inst::Cpopw { rd, rs1 } => {
                    reg_write(regs, rd, (reg_read(regs, rs1) as u32).count_ones() as u64);
                }
                Inst::SextB { rd, rs1 } => {
                    reg_write(regs, rd, reg_read(regs, rs1) as i8 as i64 as u64);
                }
                Inst::SextH { rd, rs1 } => {
                    reg_write(regs, rd, reg_read(regs, rs1) as i16 as i64 as u64);
                }
                Inst::ZextH { rd, rs1 } => {
                    reg_write(regs, rd, reg_read(regs, rs1) & 0xFFFF);
                }
                Inst::Rev8 { rd, rs1 } => {
                    reg_write(regs, rd, reg_read(regs, rs1).swap_bytes());
                }
                Inst::OrcB { rd, rs1 } => {
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
                Inst::Min { rd, rs1, rs2 } => {
                    let a = reg_read(regs, rs1) as i64;
                    let b = reg_read(regs, rs2) as i64;
                    reg_write(regs, rd, a.min(b) as u64);
                }
                Inst::Minu { rd, rs1, rs2 } => {
                    let a = reg_read(regs, rs1);
                    let b = reg_read(regs, rs2);
                    reg_write(regs, rd, a.min(b));
                }
                Inst::Max { rd, rs1, rs2 } => {
                    let a = reg_read(regs, rs1) as i64;
                    let b = reg_read(regs, rs2) as i64;
                    reg_write(regs, rd, a.max(b) as u64);
                }
                Inst::Maxu { rd, rs1, rs2 } => {
                    let a = reg_read(regs, rs1);
                    let b = reg_read(regs, rs2);
                    reg_write(regs, rd, a.max(b));
                }
                Inst::Andn { rd, rs1, rs2 } => {
                    reg_write(regs, rd, reg_read(regs, rs1) & !reg_read(regs, rs2));
                }
                Inst::Orn { rd, rs1, rs2 } => {
                    reg_write(regs, rd, reg_read(regs, rs1) | !reg_read(regs, rs2));
                }
                Inst::Xnor { rd, rs1, rs2 } => {
                    reg_write(regs, rd, !(reg_read(regs, rs1) ^ reg_read(regs, rs2)));
                }
                Inst::Rol { rd, rs1, rs2 } => {
                    let s = reg_read(regs, rs2) as u32 & 63;
                    reg_write(regs, rd, reg_read(regs, rs1).rotate_left(s));
                }
                Inst::Ror { rd, rs1, rs2 } => {
                    let s = reg_read(regs, rs2) as u32 & 63;
                    reg_write(regs, rd, reg_read(regs, rs1).rotate_right(s));
                }
                Inst::Rolw { rd, rs1, rs2 } => {
                    let s = reg_read(regs, rs2) as u32 & 31;
                    let v = (reg_read(regs, rs1) as u32).rotate_left(s);
                    reg_write(regs, rd, v as i32 as i64 as u64);
                }
                Inst::Rorw { rd, rs1, rs2 } => {
                    let s = reg_read(regs, rs2) as u32 & 31;
                    let v = (reg_read(regs, rs1) as u32).rotate_right(s);
                    reg_write(regs, rd, v as i32 as i64 as u64);
                }
                Inst::Rori { rd, rs1, shamt } => {
                    reg_write(
                        regs,
                        rd,
                        reg_read(regs, rs1).rotate_right(shamt as u32 & 63),
                    );
                }
                Inst::Roriw { rd, rs1, shamt } => {
                    let v = (reg_read(regs, rs1) as u32).rotate_right(shamt as u32 & 31);
                    reg_write(regs, rd, v as i32 as i64 as u64);
                }

                // ---- Zba -----------------------------------------------------
                Inst::Sh1add { rd, rs1, rs2 } => {
                    let v = reg_read(regs, rs1)
                        .wrapping_shl(1)
                        .wrapping_add(reg_read(regs, rs2));
                    reg_write(regs, rd, v);
                }
                Inst::Sh2add { rd, rs1, rs2 } => {
                    let v = reg_read(regs, rs1)
                        .wrapping_shl(2)
                        .wrapping_add(reg_read(regs, rs2));
                    reg_write(regs, rd, v);
                }
                Inst::Sh3add { rd, rs1, rs2 } => {
                    let v = reg_read(regs, rs1)
                        .wrapping_shl(3)
                        .wrapping_add(reg_read(regs, rs2));
                    reg_write(regs, rd, v);
                }
                Inst::Sh1adduw { rd, rs1, rs2 } => {
                    let a = (reg_read(regs, rs1) as u32 as u64).wrapping_shl(1);
                    reg_write(regs, rd, a.wrapping_add(reg_read(regs, rs2)));
                }
                Inst::Sh2adduw { rd, rs1, rs2 } => {
                    let a = (reg_read(regs, rs1) as u32 as u64).wrapping_shl(2);
                    reg_write(regs, rd, a.wrapping_add(reg_read(regs, rs2)));
                }
                Inst::Sh3adduw { rd, rs1, rs2 } => {
                    let a = (reg_read(regs, rs1) as u32 as u64).wrapping_shl(3);
                    reg_write(regs, rd, a.wrapping_add(reg_read(regs, rs2)));
                }
                Inst::Adduw { rd, rs1, rs2 } => {
                    let a = reg_read(regs, rs1) as u32 as u64;
                    reg_write(regs, rd, a.wrapping_add(reg_read(regs, rs2)));
                }
                Inst::Slliuw { rd, rs1, shamt } => {
                    let a = reg_read(regs, rs1) as u32 as u64;
                    reg_write(regs, rd, a.wrapping_shl(shamt as u32 & 63));
                }

                // ---- Zbs (single-bit) ----------------------------------------
                Inst::Bclr { rd, rs1, rs2 } => {
                    let bit = reg_read(regs, rs2) & 63;
                    reg_write(regs, rd, reg_read(regs, rs1) & !(1u64 << bit));
                }
                Inst::Bset { rd, rs1, rs2 } => {
                    let bit = reg_read(regs, rs2) & 63;
                    reg_write(regs, rd, reg_read(regs, rs1) | (1u64 << bit));
                }
                Inst::Binv { rd, rs1, rs2 } => {
                    let bit = reg_read(regs, rs2) & 63;
                    reg_write(regs, rd, reg_read(regs, rs1) ^ (1u64 << bit));
                }
                Inst::Bext { rd, rs1, rs2 } => {
                    let bit = reg_read(regs, rs2) & 63;
                    reg_write(regs, rd, (reg_read(regs, rs1) >> bit) & 1);
                }
                Inst::Bclri { rd, rs1, shamt } => {
                    reg_write(regs, rd, reg_read(regs, rs1) & !(1u64 << (shamt & 63)));
                }
                Inst::Bseti { rd, rs1, shamt } => {
                    reg_write(regs, rd, reg_read(regs, rs1) | (1u64 << (shamt & 63)));
                }
                Inst::Binvi { rd, rs1, shamt } => {
                    reg_write(regs, rd, reg_read(regs, rs1) ^ (1u64 << (shamt & 63)));
                }
                Inst::Bexti { rd, rs1, shamt } => {
                    reg_write(regs, rd, (reg_read(regs, rs1) >> (shamt & 63)) & 1);
                }

                // ---- Zicond --------------------------------------------------
                Inst::CzeroEqz { rd, rs1, rs2 } => {
                    // (rs2 == 0) ? 0 : rs1
                    let v = if reg_read(regs, rs2) == 0 {
                        0
                    } else {
                        reg_read(regs, rs1)
                    };
                    reg_write(regs, rd, v);
                }
                Inst::CzeroNez { rd, rs1, rs2 } => {
                    // (rs2 != 0) ? 0 : rs1
                    let v = if reg_read(regs, rs2) != 0 {
                        0
                    } else {
                        reg_read(regs, rs1)
                    };
                    reg_write(regs, rd, v);
                }

                // ---- Upper immediate ----------------------------------------
                Inst::Lui { rd, imm } => {
                    reg_write(regs, rd, imm as i64 as u64);
                }
                // auipc rd = pc_va + imm, where pc_va = code_base + pc.
                // Folds to a constant the recompiler bakes in identically.
                Inst::Auipc { rd, imm } => {
                    let v = code_base.wrapping_add(pc).wrapping_add(imm as u32);
                    reg_write(regs, rd, v as i32 as i64 as u64);
                }

                // ---- Control flow -------------------------------------------
                Inst::Jal { rd, imm } => {
                    if rd != 0 {
                        // Return address is a guest VA (code_base + offset).
                        reg_write(regs, rd, code_base.wrapping_add(next_pc) as u64);
                    }
                    let target = (pc as i64).wrapping_add(imm as i64) as u32;
                    // The target must be a basic-block start (gas precharge
                    // happens at block entry) — else Panic, matching the
                    // recompiler's `emit_static_branch` panic stub and the
                    // `Jalr` arm below. Accepting a mid-block target would
                    // execute a partial block having charged zero gas.
                    next_idx_override = Some(match find_idx_for_pc(insts, target) {
                        Some(i) if insts[i].is_gas_block_start => i,
                        _ => {
                            regs.pc = pc as u64;
                            return ExitReason::Panic;
                        }
                    });
                }
                // jalr rd, rs1, imm — indirect jump. target_va =
                // (rs1 + imm) & 0xFFFFFFFF; offset = target_va - code_base.
                // The target must be a basic-block start (gas precharge
                // happens at block entry) — else Panic (security-critical:
                // rejects mid-block / mid-instruction targets).
                Inst::Jalr { rd, rs1, imm } => {
                    let target_va = (reg_read(regs, rs1) as u32).wrapping_add(imm as u32);
                    if rd != 0 {
                        reg_write(regs, rd, code_base.wrapping_add(next_pc) as u64);
                    }
                    let target_off = target_va.wrapping_sub(code_base);
                    next_idx_override = Some(match find_idx_for_pc(insts, target_off) {
                        Some(i) if insts[i].is_gas_block_start => i,
                        _ => {
                            regs.pc = pc as u64;
                            return ExitReason::Panic;
                        }
                    });
                }
                Inst::Beq { rs1, rs2, imm } => {
                    if reg_read(regs, rs1) == reg_read(regs, rs2) {
                        let target = (pc as i64).wrapping_add(imm as i64) as u32;
                        match find_idx_for_pc(insts, target) {
                            Some(i) if insts[i].is_gas_block_start => next_idx_override = Some(i),
                            _ => {
                                regs.pc = pc as u64;
                                return ExitReason::Panic;
                            }
                        }
                    }
                }
                Inst::Bne { rs1, rs2, imm } => {
                    if reg_read(regs, rs1) != reg_read(regs, rs2) {
                        let target = (pc as i64).wrapping_add(imm as i64) as u32;
                        match find_idx_for_pc(insts, target) {
                            Some(i) if insts[i].is_gas_block_start => next_idx_override = Some(i),
                            _ => {
                                regs.pc = pc as u64;
                                return ExitReason::Panic;
                            }
                        }
                    }
                }
                Inst::Blt { rs1, rs2, imm } => {
                    if (reg_read(regs, rs1) as i64) < (reg_read(regs, rs2) as i64) {
                        let target = (pc as i64).wrapping_add(imm as i64) as u32;
                        match find_idx_for_pc(insts, target) {
                            Some(i) if insts[i].is_gas_block_start => next_idx_override = Some(i),
                            _ => {
                                regs.pc = pc as u64;
                                return ExitReason::Panic;
                            }
                        }
                    }
                }
                Inst::Bge { rs1, rs2, imm } => {
                    if (reg_read(regs, rs1) as i64) >= (reg_read(regs, rs2) as i64) {
                        let target = (pc as i64).wrapping_add(imm as i64) as u32;
                        match find_idx_for_pc(insts, target) {
                            Some(i) if insts[i].is_gas_block_start => next_idx_override = Some(i),
                            _ => {
                                regs.pc = pc as u64;
                                return ExitReason::Panic;
                            }
                        }
                    }
                }
                Inst::Bltu { rs1, rs2, imm } => {
                    if reg_read(regs, rs1) < reg_read(regs, rs2) {
                        let target = (pc as i64).wrapping_add(imm as i64) as u32;
                        match find_idx_for_pc(insts, target) {
                            Some(i) if insts[i].is_gas_block_start => next_idx_override = Some(i),
                            _ => {
                                regs.pc = pc as u64;
                                return ExitReason::Panic;
                            }
                        }
                    }
                }
                Inst::Bgeu { rs1, rs2, imm } => {
                    if reg_read(regs, rs1) >= reg_read(regs, rs2) {
                        let target = (pc as i64).wrapping_add(imm as i64) as u32;
                        match find_idx_for_pc(insts, target) {
                            Some(i) if insts[i].is_gas_block_start => next_idx_override = Some(i),
                            _ => {
                                regs.pc = pc as u64;
                                return ExitReason::Panic;
                            }
                        }
                    }
                }

                // ---- System (no-op for our single-threaded VM) --------------
                Inst::Fence | Inst::FenceI => {}

                // ---- Custom-0 -----------------------------------------------
                Inst::Trap => {
                    regs.pc = pc as u64;
                    return ExitReason::Trap;
                }
                Inst::EcallJar => {
                    // ecall block: charge its dynamic cost (check-before-
                    // charge). On OOG, gas is unchanged and the resume PC
                    // is the ecall's OWN pc, so a top-up re-attempts the
                    // whole op (gas-cost.md §3 "ecall/ecalli blocks").
                    let cost = crate::gas_const::ecall_dynamic_cost(false);
                    if gas.remaining() < cost {
                        regs.pc = pc as u64;
                        return ExitReason::OutOfGas;
                    }
                    gas.charge(cost).expect("ecall cost checked");
                    regs.pc = next_pc as u64;
                    match handler.handle(EcallKind::Ecall, regs, mem) {
                        EcallResult::Continue => match find_idx_for_pc(insts, next_pc) {
                            Some(i) => next_idx_override = Some(i),
                            None => return ExitReason::Panic,
                        },
                        EcallResult::Exit(r) => return r,
                    }
                }
                Inst::Ecalli { imm } => {
                    let cost = crate::gas_const::ecall_dynamic_cost(true);
                    if gas.remaining() < cost {
                        regs.pc = pc as u64;
                        return ExitReason::OutOfGas;
                    }
                    gas.charge(cost).expect("ecall cost checked");
                    regs.pc = next_pc as u64;
                    match handler.handle(EcallKind::Ecalli(imm as u32), regs, mem) {
                        EcallResult::Continue => match find_idx_for_pc(insts, next_pc) {
                            Some(i) => next_idx_override = Some(i),
                            None => return ExitReason::Panic,
                        },
                        EcallResult::Exit(r) => return r,
                    }
                }
                Inst::Fallthrough => {
                    // Terminator no-op: just advance. The next instruction is
                    // already marked as a block start so its cost gets
                    // charged on the next iteration.
                }

                Inst::Reserved { .. } => {
                    regs.pc = pc as u64;
                    return ExitReason::Panic;
                }
            }

            // Advance to the next instruction. Branches / Jal / Jalr /
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

/// Read PVM2 register `x`, via the shared slot map ([`crate::regs`]).
/// `x0` (and any reserved register `x16..x31`, which never reaches here once
/// decode maps it to `Reserved`) reads as zero; `x1, x2, x5..x15` map to
/// slots `0..12` and `x3`/`x4` to the spilled slots `13`/`14`.
#[inline]
fn reg_read(regs: &Regs, x: u8) -> u64 {
    match crate::regs::REG_SLOT_LUT[(x & 31) as usize] {
        0xFF => 0,
        s => regs.gpr[s as usize],
    }
}

/// Write PVM2 register `x`, via the shared slot map. Writes to `x0` (and
/// any reserved register `x16..x31`) are no-ops; `x3`/`x4` write slots
/// `13`/`14`.
#[inline]
fn reg_write(regs: &mut Regs, x: u8, v: u64) {
    let s = crate::regs::REG_SLOT_LUT[(x & 31) as usize];
    if s != 0xFF {
        regs.gpr[s as usize] = v;
    }
}

/// `(rs1 + imm) & 0xFFFFFFFF` — PVM2 effective address (sandbox is
/// 32-bit). Matches `rv_addr_to_scratch` in the recompiler.
#[inline]
fn compute_addr(regs: &Regs, rs1: u8, imm: i32) -> u32 {
    (reg_read(regs, rs1) as u32).wrapping_add(imm as u32)
}

/// Read a `width`-byte little-endian value (`width ≤ 8`, zero-extended
/// into the `u64`) from the read-only code region if `addr` falls
/// wholly within `[code_base, code_base + code.len())`. Returns `None`
/// otherwise. Serves the PIC idiom (`auipc` + load) the spec blesses
/// and the recompiler allows via its RO code direct-map: the
/// interpreter's data buffer is based at `DATA_BASE`, so a code-region
/// address never hits it and must be served from the code bytes here.
#[inline]
fn read_code(code: &[u8], code_base: u32, addr: u32, width: usize) -> Option<u64> {
    let off = addr.checked_sub(code_base)? as usize;
    let end = off.checked_add(width)?;
    if end > code.len() {
        return None;
    }
    let mut buf = [0u8; 8];
    buf[..width].copy_from_slice(&code[off..end]);
    Some(u64::from_le_bytes(buf))
}

/// Width-typed loads that fall back to the read-only code region when
/// the data buffer misses, so `auipc`+load of the guest's own code
/// succeeds (B2 parity with the recompiler's RO code mapping).
#[inline]
fn load_u8<M: Memory>(mem: &M, code: &[u8], code_base: u32, addr: u32) -> Option<u8> {
    mem.read_u8(addr)
        .or_else(|| read_code(code, code_base, addr, 1).map(|v| v as u8))
}
#[inline]
fn load_u16<M: Memory>(mem: &M, code: &[u8], code_base: u32, addr: u32) -> Option<u16> {
    mem.read_u16_le(addr)
        .or_else(|| read_code(code, code_base, addr, 2).map(|v| v as u16))
}
#[inline]
fn load_u32<M: Memory>(mem: &M, code: &[u8], code_base: u32, addr: u32) -> Option<u32> {
    mem.read_u32_le(addr)
        .or_else(|| read_code(code, code_base, addr, 4).map(|v| v as u32))
}
#[inline]
fn load_u64<M: Memory>(mem: &M, code: &[u8], code_base: u32, addr: u32) -> Option<u64> {
    mem.read_u64_le(addr)
        .or_else(|| read_code(code, code_base, addr, 8))
}

/// True iff every page a `width`-byte guest store at `addr` touches is
/// writable (`perm::RW`). A `width`-byte store (`width ≤ 8`) spans at
/// most two consecutive pages, so checking the first and last byte's
/// page covers it. Enforced only for *guest* stores so the interpreter
/// (the in-process consensus oracle) faults a write to a read-only /
/// pinned page exactly as the recompiler's hardware page tables do —
/// trusted kernel/host-call writes use `mem.write_*` directly and
/// intentionally bypass this.
#[inline]
fn store_writable<M: Memory>(mem: &M, addr: u32, width: u32) -> bool {
    mem.perm_of(addr) == perm::RW && mem.perm_of(addr.wrapping_add(width - 1)) == perm::RW
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
    use crate::predecode::predecode;
    use alloc::vec::Vec;

    fn enc4(words: &[u32]) -> Vec<u8> {
        let mut v = Vec::with_capacity(words.len() * 4);
        for w in words {
            v.extend_from_slice(&w.to_le_bytes());
        }
        v
    }

    fn run_simple(code: &[u8], initial_gas: u64) -> (Regs, ExitReason, u64) {
        let pre = predecode(code);
        let mut regs = Regs::new();
        let mut mem = CopyingMemory::new();
        let mut gas = GasCounter::new(initial_gas);
        let mut h = PanickingHandler;
        let reason = Interpreter::run(&pre, code, 0, &mut regs, &mut mem, &mut gas, &mut h);
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
    fn reserved_custom0_011_panics() {
        // custom-0 funct3=011 is reserved (was br_table); PVM2 uses
        // native jalr. Executing a Reserved encoding panics.
        let word = (0u32 << 20) | (5 << 15) | (0b011 << 12) | (0 << 7) | (0b00010 << 2) | 0b11;
        let code = enc4(&[word]);
        let pre = predecode(&code);
        let mut regs = Regs::new();
        let mut mem = CopyingMemory::new();
        let mut gas = GasCounter::new(1_000_000);
        let mut h = PanickingHandler;
        let reason = Interpreter::run(&pre, &code, 0, &mut regs, &mut mem, &mut gas, &mut h);
        assert_eq!(reason, ExitReason::Panic);
    }

    // ---- B1: static jal/branch to a non-block-start must Panic ----------
    //
    // The block-start set is {0} ∪ {pc after a terminator}. A static
    // branch/jal whose target is a valid instruction boundary that is NOT
    // a block start would, unguarded, run a partial block having charged
    // zero gas. The interpreter must Panic there, matching the
    // recompiler's `emit_static_branch` panic stub. An honest linker never
    // emits such a target (it injects `fallthrough`), so this only bites a
    // crafted blob.

    #[test]
    fn branch_to_non_block_start_panics() {
        // 0:  beq x0,x0,+8   (taken; terminator → PC=4 is a block start)
        // 4:  addi x10,x0,1  (not a terminator → PC=8 is NOT a block start)
        // 8:  addi x11,x0,2  (the branch target — mid-block)
        // 12: trap
        let beq = 0x0000_0463u32; // beq x0,x0,+8
        let addi1 = (1u32 << 20) | (10 << 7) | 0x13;
        let addi2 = (2u32 << 20) | (11 << 7) | 0x13;
        let trap = 0x0000_000Bu32;
        let code = enc4(&[beq, addi1, addi2, trap]);
        let (regs, reason, _) = run_simple(&code, 1_000_000);
        assert_eq!(reason, ExitReason::Panic);
        assert_eq!(regs.pc, 0); // the faulting branch's PC
    }

    #[test]
    fn jal_to_non_block_start_panics() {
        // 0:  jal x0,+8      (terminator → PC=4 is a block start)
        // 4:  addi x10,x0,1  (not a terminator → PC=8 is NOT a block start)
        // 8:  addi x11,x0,2  (the jal target — mid-block)
        // 12: trap
        let jal = 0x0080_006Fu32; // jal x0,+8
        let addi1 = (1u32 << 20) | (10 << 7) | 0x13;
        let addi2 = (2u32 << 20) | (11 << 7) | 0x13;
        let trap = 0x0000_000Bu32;
        let code = enc4(&[jal, addi1, addi2, trap]);
        let (regs, reason, _) = run_simple(&code, 1_000_000);
        assert_eq!(reason, ExitReason::Panic);
        assert_eq!(regs.pc, 0);
    }

    #[test]
    fn branch_to_real_block_start_is_allowed() {
        // Regression guard: a branch to a genuine block start still works.
        // 0:  beq x0,x0,+8   (terminator → PC=4 block start)
        // 4:  trap           (terminator → PC=8 IS a block start; unreached)
        // 8:  addi x10,x0,7  (the branch target — a valid block start)
        // 12: trap
        let beq = 0x0000_0463u32; // beq x0,x0,+8
        let trap = 0x0000_000Bu32;
        let addi = (7u32 << 20) | (10 << 7) | 0x13;
        let code = enc4(&[beq, trap, addi, trap]);
        let (regs, reason, _) = run_simple(&code, 1_000_000);
        assert_eq!(reason, ExitReason::Trap);
        assert_eq!(regs.gpr[7], 7); // x10 → slot 7: the branch was taken
    }

    // ---- B2: a guest can read (but not write) its own code bytes --------

    #[test]
    fn auipc_load_reads_own_code_region() {
        // auipc x10,0 ; lw x11,0(x10) ; trap. With the data buffer based
        // away from the code region, the load address lands in the code
        // region and must be served from the code bytes (the PIC idiom),
        // not page-fault — matching the recompiler's RO code direct-map.
        let auipc = (0u32 << 12) | (10 << 7) | 0x17; // auipc x10,0
        let lw = (0u32 << 20) | (10 << 15) | (0b010 << 12) | (11 << 7) | 0x03; // lw x11,0(x10)
        let trap = 0x0000_000Bu32;
        let code = enc4(&[auipc, lw, trap]);
        let pre = predecode(&code);
        let mut regs = Regs::new();
        let mut mem = CopyingMemory::new();
        mem.base = 0x1000_0000; // data buffer elsewhere; code region unmapped here
        let mut gas = GasCounter::new(1_000_000);
        let mut h = PanickingHandler;
        let code_base = 0x0040_0000u32;
        let reason = Interpreter::run(
            &pre, &code, code_base, &mut regs, &mut mem, &mut gas, &mut h,
        );
        assert_eq!(reason, ExitReason::Trap);
        assert_eq!(regs.gpr[7], code_base as u64); // x10 = code_base + 0
        assert_eq!(regs.gpr[8] as u32, auipc); // x11 = the first code word
    }

    #[test]
    fn store_into_code_region_faults() {
        // auipc x10,0 ; sw x0,0(x10) ; trap. Code is read-only: a store
        // into the code region must PageFault in both engines.
        let auipc = (0u32 << 12) | (10 << 7) | 0x17; // auipc x10,0
        let sw = (0u32 << 25) | (0 << 20) | (10 << 15) | (0b010 << 12) | (0 << 7) | 0x23; // sw x0,0(x10)
        let trap = 0x0000_000Bu32;
        let code = enc4(&[auipc, sw, trap]);
        let pre = predecode(&code);
        let mut regs = Regs::new();
        let mut mem = CopyingMemory::new();
        mem.base = 0x1000_0000;
        let mut gas = GasCounter::new(1_000_000);
        let mut h = PanickingHandler;
        let code_base = 0x0040_0000u32;
        let reason = Interpreter::run(
            &pre, &code, code_base, &mut regs, &mut mem, &mut gas, &mut h,
        );
        assert_eq!(reason, ExitReason::PageFault(code_base));
    }

    // ---- B3: a guest store to a read-only page faults -------------------

    #[test]
    fn store_writable_respects_per_page_perms() {
        // Two RW pages, then mark the second read-only. A store wholly in
        // an RW page passes; one touching the RO page (incl. a straddle)
        // fails.
        let page = crate::mem::PAGE_SIZE;
        let mut mem = CopyingMemory::with_pages(2, perm::RW);
        mem.perms[1] = perm::RO;
        assert!(store_writable(&mem, 0, 4)); // wholly in RW page
        assert!(!store_writable(&mem, page, 4)); // wholly in RO page
        assert!(!store_writable(&mem, page - 2, 4)); // straddles RW→RO
    }

    #[test]
    fn guest_store_to_ro_page_faults() {
        // lui x5,1 (x5 = 0x1000) ; sw x0,0(x5) ; trap. Page 1 is RO, so
        // the store faults; the recompiler's hardware RO mapping faults
        // identically.
        let lui = (1u32 << 12) | (5 << 7) | 0x37; // lui x5,1
        let sw = (0u32 << 25) | (0 << 20) | (5 << 15) | (0b010 << 12) | (0 << 7) | 0x23; // sw x0,0(x5)
        let trap = 0x0000_000Bu32;
        let code = enc4(&[lui, sw, trap]);
        let pre = predecode(&code);
        let mut regs = Regs::new();
        let mut mem = CopyingMemory::with_pages(2, perm::RW);
        mem.perms[1] = perm::RO;
        let mut gas = GasCounter::new(1_000_000);
        let mut h = PanickingHandler;
        let reason = Interpreter::run(&pre, &code, 0, &mut regs, &mut mem, &mut gas, &mut h);
        assert_eq!(reason, ExitReason::PageFault(crate::mem::PAGE_SIZE));
        // The RO page was not mutated.
        assert_eq!(mem.read_u32_le(crate::mem::PAGE_SIZE), Some(0));
    }

    // ---- B6: entry PC must be a basic-block start ----------------------

    #[test]
    fn entry_at_non_block_start_panics() {
        // Enter at PC=4, which is mid-block: the addi at PC=0 is not a
        // terminator, so PC=4 is not a block start. Must Panic at
        // invocation, matching the recompiler's dispatch-table prologue
        // (a non-block-start offset holds the panic stub).
        let addi1 = (1u32 << 20) | (10 << 7) | 0x13;
        let addi2 = (2u32 << 20) | (11 << 7) | 0x13;
        let trap = 0x0000_000Bu32;
        let code = enc4(&[addi1, addi2, trap]);
        let pre = predecode(&code);
        let mut regs = Regs::new();
        regs.pc = 4; // non-block-start entry
        let mut mem = CopyingMemory::new();
        let mut gas = GasCounter::new(1_000_000);
        let mut h = PanickingHandler;
        let reason = Interpreter::run(&pre, &code, 0, &mut regs, &mut mem, &mut gas, &mut h);
        assert_eq!(reason, ExitReason::Panic);
    }

    #[test]
    fn entry_at_real_block_start_is_allowed() {
        // 0: trap (terminator → PC=4 is a block start)
        // 4: addi x10,x0,7 ; 8: trap. Entering at the PC=4 block start runs.
        let trap = 0x0000_000Bu32;
        let addi = (7u32 << 20) | (10 << 7) | 0x13;
        let code = enc4(&[trap, addi, trap]);
        let pre = predecode(&code);
        let mut regs = Regs::new();
        regs.pc = 4; // post-terminator block start
        let mut mem = CopyingMemory::new();
        let mut gas = GasCounter::new(1_000_000);
        let mut h = PanickingHandler;
        let reason = Interpreter::run(&pre, &code, 0, &mut regs, &mut mem, &mut gas, &mut h);
        assert_eq!(reason, ExitReason::Trap);
        assert_eq!(regs.gpr[7], 7); // x10 → slot 7: PC=4 block executed
    }

    // ---- x3/x4 are real (spilled) registers the interpreter executes ----

    #[test]
    fn x3_x4_execute_as_real_registers() {
        // addi x3, x0, 7 ; addi x4, x0, 5 ; add x5, x3, x4 ; trap.
        // x3/x4 are RV64E GPRs (high slots 13/14); the interpreter executes
        // them, so x5 = 7 + 5 = 12.
        let addi_x3_7 = (7u32 << 20) | (3 << 7) | 0x13; // addi x3, x0, 7
        let addi_x4_5 = (5u32 << 20) | (4 << 7) | 0x13; // addi x4, x0, 5
        let add_x5 = (4u32 << 20) | (3 << 15) | (5 << 7) | 0x33; // add x5, x3, x4
        let trap = 0x0000_000Bu32;
        let code = enc4(&[addi_x3_7, addi_x4_5, add_x5, trap]);
        let (regs, reason, _) = run_simple(&code, 1_000_000);
        assert_eq!(reason, ExitReason::Trap);
        // x5 → slot 2 (x5 - 3); x3 → slot 13; x4 → slot 14.
        assert_eq!(regs.gpr[2], 12);
        assert_eq!(regs.gpr[13], 7);
        assert_eq!(regs.gpr[14], 5);
    }

    #[test]
    fn x3_free_arithmetic_still_runs() {
        // add x5, x6, x7 ; trap — no x3/x4, executes normally.
        let add_ok = 0x0073_02B3u32; // add x5, x6, x7
        let trap = 0x0000_000Bu32;
        let code = enc4(&[add_ok, trap]);
        let (_regs, reason, _) = run_simple(&code, 1_000_000);
        assert_eq!(reason, ExitReason::Trap);
    }
}
