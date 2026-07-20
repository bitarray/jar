//! Per-basic-block gas cost model for PVM2 (JAR v0.8.0).
//!
//! Simulates a single-pass CPU pipeline to compute gas cost for a
//! basic block. Cost = `max(simulation_cycles - 3, 1)`.
//!
//! Pipeline model:
//! - Reorder buffer: max 32 entries
//! - 4 decode slots per cycle, 5 dispatch slots per cycle
//! - Execution units: ALU:4, LOAD:4, STORE:4, MUL:1, DIV:1
//!
//! Per-opcode pipeline metadata lives in `RV_GAS_COST_LUT`, indexed by
//! the per-kind constants below (`RV_KIND_*`). The interpreter and
//! recompiler share this LUT via [`rv_feed_gas_kind`] / [`rv_feed_gas_direct`].

#![allow(dead_code)] // some helpers are used only by the recompiler crate

/// `FastCost` is the per-instruction analysis the gas simulator
/// consumes. Cycles, decode slots, exec-unit class, src/dst register
/// masks. `is_terminator` marks gas-block-ending instructions.
#[derive(Clone, Copy, Debug)]
pub struct FastCost {
    pub cycles: u8,
    pub decode_slots: u8,
    /// 0=none, 1=alu, 2=load(+alu), 3=store(+alu), 4=mul(+alu), 5=div(+alu)
    pub exec_unit: u8,
    pub src_mask: u16,
    pub dst_mask: u16,
    pub is_terminator: bool,
    pub is_move_reg: bool,
}

const EU_NONE: u8 = 0;
const EU_ALU: u8 = 1;
const EU_LOAD: u8 = 2;
const EU_STORE: u8 = 3;
const EU_MUL: u8 = 4;
const EU_DIV: u8 = 5;

/// Default load/store latency (L2 cache hit baseline).
pub const DEFAULT_MEM_CYCLES: u8 = 25;

// ============================================================================
// PVM2 fast-path gas accounting (LUT + feed_direct)
// ============================================================================
//
// Mirrors PVM's `feed_gas_direct` / `GAS_COST_LUT` optimization for the
// PVM2 path. The hot per-instruction cost is computed via:
//   1. `rv_op_metadata(&inst)` → `(kind: u8, rs1, rs2, rd)` — one
//      match over `Inst` variants, returning a u32-packed tuple.
//   2. `RV_GAS_COST_LUT[kind]` — static array lookup giving cycles,
//      decode_slots, exec_unit, reg patterns, and overlap flags.
//   3. `GasSimulator::feed_direct(cycles, decode_slots, src1, src2, dst)`
//      — bypasses `FastCost` construction and the bitmask iteration in
//      `feed`.
//
// PVM2 doesn't need a "needs_full" slow path: branches use a flat 20
// (no target-opcode dependency), and overlap-dependent decode_slots
// are computed inline from the LUT entry's `overlap_slots` nibbles.

/// PVM2-side flags for `RvGasCostEntry::flags`.
const RVF_TERM: u8 = 1;
/// `decode_slots` depends on whether `rd` overlaps any source register
/// in `src_pat`. Lo nibble of `overlap_slots` is the value when the
/// overlap holds; hi nibble is the value when it doesn't.
const RVF_OVERLAP_DST_SRC: u8 = 2;
/// `decode_slots` depends on whether `rs1 == rd` (used by shifts and
/// rotates — the existing PVM shift rule). Same overlap-slots layout.
const RVF_OVERLAP_RS1_RD: u8 = 4;

#[derive(Clone, Copy)]
struct RvGasCostEntry {
    /// Execution latency (cycles). For LOAD/STORE rows this is
    /// overridden at lookup time by `mem_cycles`.
    cycles: u8,
    /// Base decode_slots (used when no overlap flag is set).
    decode_slots: u8,
    /// Execution unit class (`EU_*` constants from this file).
    exec_unit: u8,
    /// Source register pattern: 0=none, 1=rs1, 2=rs1+rs2.
    src_pat: u8,
    /// Destination register pattern: 0=none, 1=rd.
    /// (Writes to x0 are silently treated as "no destination" by
    /// `rv_slot_u8`.)
    dst_pat: u8,
    /// `RVF_*` flag bits.
    flags: u8,
    /// When `RVF_OVERLAP_*` is set: lo nibble = decode_slots when
    /// overlap holds, hi nibble = decode_slots when it doesn't.
    overlap_slots: u8,
}

#[allow(clippy::too_many_arguments)]
const fn rgc(
    cycles: u8,
    decode_slots: u8,
    exec_unit: u8,
    src_pat: u8,
    dst_pat: u8,
    flags: u8,
) -> RvGasCostEntry {
    RvGasCostEntry {
        cycles,
        decode_slots,
        exec_unit,
        src_pat,
        dst_pat,
        flags,
        overlap_slots: 0,
    }
}

#[allow(clippy::too_many_arguments)]
const fn rgc_ov(
    cycles: u8,
    overlap_if: u8,
    overlap_no: u8,
    exec_unit: u8,
    src_pat: u8,
    dst_pat: u8,
    flags: u8,
) -> RvGasCostEntry {
    RvGasCostEntry {
        cycles,
        decode_slots: 0,
        exec_unit,
        src_pat,
        dst_pat,
        flags,
        overlap_slots: overlap_if | (overlap_no << 4),
    }
}

// PVM2 opcode kinds. Used as indices into RV_GAS_COST_LUT.
// All variants of `Inst` that share a gas-cost row map to the same
// kind (e.g. `Lb`/`Lh`/.../`Lwu` all → `RV_KIND_LOAD`).
//
// Exposed to the recompiler so each `compile_rv_instruction` arm can
// supply its kind constant directly to the gas-feed call, removing a
// separate match over `Inst` per instruction.
pub const RV_KIND_RESERVED: u8 = 0;
pub const RV_KIND_TRAP: u8 = 1;
pub const RV_KIND_FALLTHROUGH: u8 = 2;
pub const RV_KIND_ECALL_JAR: u8 = 3;
pub const RV_KIND_ECALLI: u8 = 4;
pub const RV_KIND_JALR: u8 = 5; // indirect jump (return / indirect call)
pub const RV_KIND_FENCE: u8 = 6;
pub const RV_KIND_JAL: u8 = 7;
pub const RV_KIND_BRANCH: u8 = 8;
pub const RV_KIND_LOAD: u8 = 9;
pub const RV_KIND_STORE: u8 = 10;
pub const RV_KIND_LUI: u8 = 11;
pub const RV_KIND_ADDI: u8 = 12; // 64-bit I-type ALU (Addi/Andi/Ori/Xori/Sltiu/Slli/Srli/Slti/Srai)
pub const RV_KIND_ADDIW: u8 = 13; // 32-bit I-type ALU (Addiw/Slliw/Srliw/Sraiw)
pub const RV_KIND_ADD: u8 = 14; // 64-bit R-type ALU (Add/Sub/And/Or/Xor)
pub const RV_KIND_SLL: u8 = 15; // 64-bit shifts (Sll/Srl/Sra)
pub const RV_KIND_SLT: u8 = 16; // 64-bit compare (Slt/Sltu)
pub const RV_KIND_ADDW: u8 = 17; // 32-bit R-type ALU (Addw/Subw)
pub const RV_KIND_SLLW: u8 = 18; // 32-bit shifts (Sllw/Srlw/Sraw)
pub const RV_KIND_MUL: u8 = 19;
pub const RV_KIND_MULW: u8 = 20;
pub const RV_KIND_MULH: u8 = 21; // Mulh/Mulhu
pub const RV_KIND_MULHSU: u8 = 22;
pub const RV_KIND_DIV: u8 = 23; // Div/Divu/Rem/Remu + W-variants
pub const RV_KIND_ZBB_U1: u8 = 24; // Clz/Clzw/Cpop/Cpopw/SextB/SextH/ZextH/Rev8/OrcB
pub const RV_KIND_ZBB_CTZ: u8 = 25; // Ctz/Ctzw
pub const RV_KIND_ZBB_MINMAX: u8 = 26; // Min/Minu/Max/Maxu
pub const RV_KIND_ZBB_INV: u8 = 27; // Andn/Orn (no overlap rule)
pub const RV_KIND_ZBB_XNOR: u8 = 28; // Xnor (overlap rule)
pub const RV_KIND_ZBB_ROT: u8 = 29; // Rol/Ror
pub const RV_KIND_ZBB_RORI: u8 = 30; // Rori (single-src I-type)
pub const RV_KIND_ZBB_ROTW: u8 = 31; // Rolw/Rorw
pub const RV_KIND_ZBB_RORIW: u8 = 32; // Roriw
pub const RV_KIND_ZBA: u8 = 33; // Sh1add..Sh3adduw, Adduw
pub const RV_KIND_ZBA_IMM: u8 = 34; // Slliuw
pub const RV_KIND_ZBS: u8 = 35; // Bclr/Bset/Binv/Bext
pub const RV_KIND_ZBS_IMM: u8 = 36; // Bclri/Bseti/Binvi/Bexti
pub const RV_KIND_ZICOND: u8 = 37; // CzeroEqz/CzeroNez

const RV_LUT_LEN: usize = 64;

static RV_GAS_COST_LUT: [RvGasCostEntry; RV_LUT_LEN] = {
    let d = rgc(2, 1, EU_NONE, 0, 0, RVF_TERM); // default — Reserved-shaped
    let mut t = [d; RV_LUT_LEN];
    // Custom-0 / no-reg terminators
    t[RV_KIND_RESERVED as usize] = rgc(2, 1, EU_NONE, 0, 0, RVF_TERM);
    t[RV_KIND_TRAP as usize] = rgc(2, 1, EU_NONE, 0, 0, RVF_TERM);
    t[RV_KIND_FALLTHROUGH as usize] = rgc(2, 1, EU_NONE, 0, 0, RVF_TERM);
    t[RV_KIND_ECALL_JAR as usize] = rgc(100, 4, EU_ALU, 0, 0, RVF_TERM);
    t[RV_KIND_ECALLI as usize] = rgc(100, 4, EU_ALU, 0, 0, RVF_TERM);
    // jalr: src = rs1 (target), no tracked dst (terminator — its rd
    // write has no in-block successor), terminator. 22/1/ALU mirrors
    // the legacy PVM indirect-jump cost.
    t[RV_KIND_JALR as usize] = rgc(22, 1, EU_ALU, 1, 0, RVF_TERM);
    // Fences: no-op
    t[RV_KIND_FENCE as usize] = rgc(1, 1, EU_NONE, 0, 0, 0);
    // JAL: src=none, dst=rd, terminator (mirrors PVM jump = 15/1/ALU)
    t[RV_KIND_JAL as usize] = rgc(15, 1, EU_ALU, 0, 1, RVF_TERM);
    // Branches: src=rs1+rs2, dst=none, terminator. Flat 20-cycle (PVM2
    // doesn't have a trap-fast-path because the linker rewrites trap
    // targets).
    t[RV_KIND_BRANCH as usize] = rgc(20, 1, EU_ALU, 2, 0, RVF_TERM);
    // Loads / stores
    t[RV_KIND_LOAD as usize] = rgc(25, 1, EU_LOAD, 1, 1, 0);
    t[RV_KIND_STORE as usize] = rgc(25, 1, EU_STORE, 2, 0, 0);
    // Lui
    t[RV_KIND_LUI as usize] = rgc(1, 2, EU_NONE, 0, 1, 0);
    // 64-bit I-type ALU
    t[RV_KIND_ADDI as usize] = rgc_ov(1, 1, 2, EU_ALU, 1, 1, RVF_OVERLAP_DST_SRC);
    // 32-bit I-type ALU
    t[RV_KIND_ADDIW as usize] = rgc_ov(2, 2, 3, EU_ALU, 1, 1, RVF_OVERLAP_DST_SRC);
    // 64-bit R-type ALU
    t[RV_KIND_ADD as usize] = rgc_ov(1, 1, 2, EU_ALU, 2, 1, RVF_OVERLAP_DST_SRC);
    // 64-bit shifts (rs1 == rd rule)
    t[RV_KIND_SLL as usize] = rgc_ov(1, 2, 3, EU_ALU, 2, 1, RVF_OVERLAP_RS1_RD);
    // 64-bit comparisons (no overlap)
    t[RV_KIND_SLT as usize] = rgc(3, 3, EU_ALU, 2, 1, 0);
    // 32-bit R-type ALU
    t[RV_KIND_ADDW as usize] = rgc_ov(2, 2, 3, EU_ALU, 2, 1, RVF_OVERLAP_DST_SRC);
    // 32-bit shifts
    t[RV_KIND_SLLW as usize] = rgc_ov(2, 3, 4, EU_ALU, 2, 1, RVF_OVERLAP_RS1_RD);
    // Multiplies
    t[RV_KIND_MUL as usize] = rgc_ov(3, 1, 2, EU_MUL, 2, 1, RVF_OVERLAP_DST_SRC);
    t[RV_KIND_MULW as usize] = rgc_ov(4, 2, 3, EU_MUL, 2, 1, RVF_OVERLAP_DST_SRC);
    t[RV_KIND_MULH as usize] = rgc(4, 4, EU_MUL, 2, 1, 0);
    t[RV_KIND_MULHSU as usize] = rgc(6, 4, EU_MUL, 2, 1, 0);
    // Divides
    t[RV_KIND_DIV as usize] = rgc(60, 4, EU_DIV, 2, 1, 0);
    // Zbb 1-cycle unary
    t[RV_KIND_ZBB_U1 as usize] = rgc(1, 1, EU_ALU, 1, 1, 0);
    // Zbb 2-cycle ctz
    t[RV_KIND_ZBB_CTZ as usize] = rgc(2, 1, EU_ALU, 1, 1, 0);
    // Zbb min/max (overlap rule)
    t[RV_KIND_ZBB_MINMAX as usize] = rgc_ov(3, 2, 3, EU_ALU, 2, 1, RVF_OVERLAP_DST_SRC);
    // Zbb inverted bitwise (no overlap)
    t[RV_KIND_ZBB_INV as usize] = rgc(2, 3, EU_ALU, 2, 1, 0);
    // Zbb xnor (overlap rule)
    t[RV_KIND_ZBB_XNOR as usize] = rgc_ov(2, 2, 3, EU_ALU, 2, 1, RVF_OVERLAP_DST_SRC);
    // Zbb rotates (rs1 == rd rule)
    t[RV_KIND_ZBB_ROT as usize] = rgc_ov(1, 2, 3, EU_ALU, 2, 1, RVF_OVERLAP_RS1_RD);
    t[RV_KIND_ZBB_RORI as usize] = rgc_ov(1, 1, 2, EU_ALU, 1, 1, RVF_OVERLAP_DST_SRC);
    t[RV_KIND_ZBB_ROTW as usize] = rgc_ov(2, 3, 4, EU_ALU, 2, 1, RVF_OVERLAP_RS1_RD);
    t[RV_KIND_ZBB_RORIW as usize] = rgc_ov(2, 2, 3, EU_ALU, 1, 1, RVF_OVERLAP_DST_SRC);
    // Zba shift-add
    t[RV_KIND_ZBA as usize] = rgc_ov(1, 1, 2, EU_ALU, 2, 1, RVF_OVERLAP_DST_SRC);
    t[RV_KIND_ZBA_IMM as usize] = rgc_ov(1, 1, 2, EU_ALU, 1, 1, RVF_OVERLAP_DST_SRC);
    // Zbs single-bit
    t[RV_KIND_ZBS as usize] = rgc_ov(1, 1, 2, EU_ALU, 2, 1, RVF_OVERLAP_DST_SRC);
    t[RV_KIND_ZBS_IMM as usize] = rgc_ov(1, 1, 2, EU_ALU, 1, 1, RVF_OVERLAP_DST_SRC);
    // Zicond
    t[RV_KIND_ZICOND as usize] = rgc(2, 2, EU_ALU, 2, 1, 0);
    t
};

/// PVM2 register → simulator slot (u8). 0xFF means "no register" — the
/// simulator's `feed_direct` interprets that as "skip dep / no write".
/// Single source: [`crate::regs::reg_slot_or_ff`] (the recompiler reads
/// the same classification via `REG_SLOT_LUT`, so gas agrees bit-for-bit).
#[inline(always)]
pub fn rv_slot_u8(r: u8) -> u8 {
    crate::regs::reg_slot_or_ff(r)
}

/// True iff a simulator slot is a *spilled* register (`x3`/`x4` → slots
/// 13/14). Used to charge the memory-spill gas cost. `0xFF` ("no register")
/// is `255`, so it is correctly excluded.
#[inline(always)]
fn is_spilled_slot(slot: u8) -> bool {
    slot == 13 || slot == 14
}

/// Compute the [`crate::predecode::RvGasMeta`] for an `Inst`.
/// Called once per instruction at decode time; the result is cached
/// in [`crate::predecode::RvPreDecodedInst::gas_meta`] so the gas
/// hot path doesn't have to re-match the variant.
#[inline]
pub fn rv_gas_meta(inst: &crate::instruction::Inst) -> crate::predecode::RvGasMeta {
    let (kind, rs1, rs2, rd) = rv_op_metadata(inst);
    let entry = &RV_GAS_COST_LUT[kind as usize];
    // Pre-mask the register fields per the LUT's reg patterns so the
    // hot path doesn't have to consult `src_pat` / `dst_pat`.
    let src1_slot = if entry.src_pat >= 1 {
        rv_slot_u8(rs1)
    } else {
        0xFF
    };
    let src2_slot = if entry.src_pat == 2 {
        rv_slot_u8(rs2)
    } else {
        0xFF
    };
    let dst_slot = if entry.dst_pat == 1 {
        rv_slot_u8(rd)
    } else {
        0xFF
    };
    crate::predecode::RvGasMeta {
        kind,
        src1_slot,
        src2_slot,
        dst_slot,
    }
}

/// Single match over `Inst` returning `(kind, rs1, rs2, rd)`. Each
/// field is u8; the tuple packs into a u32 register so the call site
/// is cheap. Variants that share a gas cost share a kind.
#[inline(always)]
fn rv_op_metadata(inst: &crate::instruction::Inst) -> (u8, u8, u8, u8) {
    use crate::instruction::Inst::*;
    match *inst {
        // No-reg / no-arg
        Trap => (RV_KIND_TRAP, 0, 0, 0),
        Fallthrough => (RV_KIND_FALLTHROUGH, 0, 0, 0),
        EcallJar => (RV_KIND_ECALL_JAR, 0, 0, 0),
        Ecalli { .. } => (RV_KIND_ECALLI, 0, 0, 0),
        Fence | FenceI => (RV_KIND_FENCE, 0, 0, 0),
        Reserved { .. } => (RV_KIND_RESERVED, 0, 0, 0),

        // JAL — terminator with link
        Jal { rd, .. } => (RV_KIND_JAL, 0, 0, rd),

        // JALR — indirect-jump terminator. src = rs1 (target); rd
        // (return addr) isn't tracked (terminator, no in-block successor).
        Jalr { rs1, .. } => (RV_KIND_JALR, rs1, 0, 0),

        // Branches
        Beq { rs1, rs2, .. }
        | Bne { rs1, rs2, .. }
        | Blt { rs1, rs2, .. }
        | Bge { rs1, rs2, .. }
        | Bltu { rs1, rs2, .. }
        | Bgeu { rs1, rs2, .. } => (RV_KIND_BRANCH, rs1, rs2, 0),

        // Loads
        Lb { rd, rs1, .. }
        | Lh { rd, rs1, .. }
        | Lw { rd, rs1, .. }
        | Ld { rd, rs1, .. }
        | Lbu { rd, rs1, .. }
        | Lhu { rd, rs1, .. }
        | Lwu { rd, rs1, .. } => (RV_KIND_LOAD, rs1, 0, rd),

        // Stores
        Sb { rs1, rs2, .. } | Sh { rs1, rs2, .. } | Sw { rs1, rs2, .. } | Sd { rs1, rs2, .. } => {
            (RV_KIND_STORE, rs1, rs2, 0)
        }

        // Upper immediate; auipc folds to a constant materialise (== lui cost).
        Lui { rd, .. } => (RV_KIND_LUI, 0, 0, rd),
        Auipc { rd, .. } => (RV_KIND_LUI, 0, 0, rd),

        // 64-bit I-type ALU
        Addi { rd, rs1, .. }
        | Andi { rd, rs1, .. }
        | Ori { rd, rs1, .. }
        | Xori { rd, rs1, .. }
        | Sltiu { rd, rs1, .. }
        | Slti { rd, rs1, .. }
        | Slli { rd, rs1, .. }
        | Srli { rd, rs1, .. }
        | Srai { rd, rs1, .. } => (RV_KIND_ADDI, rs1, 0, rd),

        // 32-bit I-type ALU
        Addiw { rd, rs1, .. }
        | Slliw { rd, rs1, .. }
        | Srliw { rd, rs1, .. }
        | Sraiw { rd, rs1, .. } => (RV_KIND_ADDIW, rs1, 0, rd),

        // 64-bit R-type ALU
        Add { rd, rs1, rs2 }
        | Sub { rd, rs1, rs2 }
        | And { rd, rs1, rs2 }
        | Or { rd, rs1, rs2 }
        | Xor { rd, rs1, rs2 } => (RV_KIND_ADD, rs1, rs2, rd),
        // 64-bit shifts
        Sll { rd, rs1, rs2 } | Srl { rd, rs1, rs2 } | Sra { rd, rs1, rs2 } => {
            (RV_KIND_SLL, rs1, rs2, rd)
        }
        // 64-bit compare
        Slt { rd, rs1, rs2 } | Sltu { rd, rs1, rs2 } => (RV_KIND_SLT, rs1, rs2, rd),

        // 32-bit R-type ALU
        Addw { rd, rs1, rs2 } | Subw { rd, rs1, rs2 } => (RV_KIND_ADDW, rs1, rs2, rd),
        // 32-bit shifts
        Sllw { rd, rs1, rs2 } | Srlw { rd, rs1, rs2 } | Sraw { rd, rs1, rs2 } => {
            (RV_KIND_SLLW, rs1, rs2, rd)
        }

        // Multiplies
        Mul { rd, rs1, rs2 } => (RV_KIND_MUL, rs1, rs2, rd),
        Mulw { rd, rs1, rs2 } => (RV_KIND_MULW, rs1, rs2, rd),
        Mulh { rd, rs1, rs2 } | Mulhu { rd, rs1, rs2 } => (RV_KIND_MULH, rs1, rs2, rd),
        Mulhsu { rd, rs1, rs2 } => (RV_KIND_MULHSU, rs1, rs2, rd),

        // Divides
        Div { rd, rs1, rs2 }
        | Divu { rd, rs1, rs2 }
        | Rem { rd, rs1, rs2 }
        | Remu { rd, rs1, rs2 }
        | Divw { rd, rs1, rs2 }
        | Divuw { rd, rs1, rs2 }
        | Remw { rd, rs1, rs2 }
        | Remuw { rd, rs1, rs2 } => (RV_KIND_DIV, rs1, rs2, rd),

        // Zbb 1-cycle unary
        Clz { rd, rs1 }
        | Clzw { rd, rs1 }
        | Cpop { rd, rs1 }
        | Cpopw { rd, rs1 }
        | SextB { rd, rs1 }
        | SextH { rd, rs1 }
        | ZextH { rd, rs1 }
        | Rev8 { rd, rs1 }
        | OrcB { rd, rs1 } => (RV_KIND_ZBB_U1, rs1, 0, rd),
        // Zbb 2-cycle
        Ctz { rd, rs1 } | Ctzw { rd, rs1 } => (RV_KIND_ZBB_CTZ, rs1, 0, rd),
        // Zbb min/max
        Min { rd, rs1, rs2 }
        | Minu { rd, rs1, rs2 }
        | Max { rd, rs1, rs2 }
        | Maxu { rd, rs1, rs2 } => (RV_KIND_ZBB_MINMAX, rs1, rs2, rd),
        // Zbb inv-bitwise
        Andn { rd, rs1, rs2 } | Orn { rd, rs1, rs2 } => (RV_KIND_ZBB_INV, rs1, rs2, rd),
        Xnor { rd, rs1, rs2 } => (RV_KIND_ZBB_XNOR, rs1, rs2, rd),
        // Zbb rotates
        Rol { rd, rs1, rs2 } | Ror { rd, rs1, rs2 } => (RV_KIND_ZBB_ROT, rs1, rs2, rd),
        Rori { rd, rs1, .. } => (RV_KIND_ZBB_RORI, rs1, 0, rd),
        Rolw { rd, rs1, rs2 } | Rorw { rd, rs1, rs2 } => (RV_KIND_ZBB_ROTW, rs1, rs2, rd),
        Roriw { rd, rs1, .. } => (RV_KIND_ZBB_RORIW, rs1, 0, rd),

        // Zba
        Sh1add { rd, rs1, rs2 }
        | Sh2add { rd, rs1, rs2 }
        | Sh3add { rd, rs1, rs2 }
        | Sh1adduw { rd, rs1, rs2 }
        | Sh2adduw { rd, rs1, rs2 }
        | Sh3adduw { rd, rs1, rs2 }
        | Adduw { rd, rs1, rs2 } => (RV_KIND_ZBA, rs1, rs2, rd),
        Slliuw { rd, rs1, .. } => (RV_KIND_ZBA_IMM, rs1, 0, rd),

        // Zbs
        Bclr { rd, rs1, rs2 }
        | Bset { rd, rs1, rs2 }
        | Binv { rd, rs1, rs2 }
        | Bext { rd, rs1, rs2 } => (RV_KIND_ZBS, rs1, rs2, rd),
        Bclri { rd, rs1, .. }
        | Bseti { rd, rs1, .. }
        | Binvi { rd, rs1, .. }
        | Bexti { rd, rs1, .. } => (RV_KIND_ZBS_IMM, rs1, 0, rd),

        // Zicond
        CzeroEqz { rd, rs1, rs2 } | CzeroNez { rd, rs1, rs2 } => (RV_KIND_ZICOND, rs1, rs2, rd),
    }
}

/// Kind-driven PVM2 gas feed: look up the cost LUT, compute the
/// overlap-dependent decode_slots and the mem_cycles override, then
/// feed the simulator via `feed_direct`. Takes raw `(kind, src1,
/// src2, dst)` so the recompiler's per-arm dispatch can supply them
/// as compile-time constants + slot lookups without going through
/// an `RvGasMeta` struct.
///
/// Slots are PVM2 register indices (0..14) or `0xFF` for "no
/// register" (x0 / absent operand). Slots 13/14 are `x3`/`x4`, which are
/// host-spilled — see the spill-cost charge below.
///
/// Returns `is_terminator` (RVF_TERM flag from the LUT entry).
#[inline(always)]
pub fn rv_feed_gas_kind(
    kind: u8,
    src1: u8,
    src2: u8,
    dst: u8,
    gas_sim: &mut crate::gas_sim::GasSimulator,
    mem_cycles: u8,
) -> bool {
    let entry = &RV_GAS_COST_LUT[kind as usize];

    // mem_cycles override for LOAD/STORE rows.
    let cycles = if entry.exec_unit == EU_LOAD || entry.exec_unit == EU_STORE {
        mem_cycles
    } else {
        entry.cycles
    };

    // x3/x4 (slots 13/14) are host-spilled: a host with exactly 13 registers
    // materialises them from memory on each access. Charge the memory-spill
    // cost (`mem_cycles`) per spilled operand position, on top of the base
    // cycles — matching the load/op/store the recompiler's spill path emits,
    // and bounding the worst-case conforming host. Conformant code never
    // names x3/x4 (every slot is < 13), so this adds exactly nothing there.
    let spill_ops =
        is_spilled_slot(src1) as u8 + is_spilled_slot(src2) as u8 + is_spilled_slot(dst) as u8;
    let cycles = cycles.saturating_add(mem_cycles.saturating_mul(spill_ops));

    // Overlap-dependent decode_slots.
    let decode_slots = if entry.flags & RVF_OVERLAP_DST_SRC != 0 {
        // Overlap holds when dst (non-empty) matches any active source.
        let overlap = dst != 0xFF && (dst == src1 || dst == src2);
        if overlap {
            entry.overlap_slots & 0x0F
        } else {
            entry.overlap_slots >> 4
        }
    } else if entry.flags & RVF_OVERLAP_RS1_RD != 0 {
        // Shifts: rs1 == rd in RV ⇔ src1_slot == dst_slot post-mapping.
        let overlap = dst != 0xFF && src1 != 0xFF && dst == src1;
        if overlap {
            entry.overlap_slots & 0x0F
        } else {
            entry.overlap_slots >> 4
        }
    } else {
        entry.decode_slots
    };

    gas_sim.feed_direct(cycles, decode_slots, src1, src2, dst);
    entry.flags & RVF_TERM != 0
}

/// Predecode-cached variant: same logic as [`rv_feed_gas_kind`] but
/// takes a pre-resolved [`crate::predecode::RvGasMeta`]. Used by
/// the per-block gas-cost helper that consumes the `Predecode`
/// vector built by `predecode`.
///
/// Returns `is_terminator`.
#[inline(always)]
pub fn rv_feed_gas_direct(
    meta: &crate::predecode::RvGasMeta,
    gas_sim: &mut crate::gas_sim::GasSimulator,
    mem_cycles: u8,
) -> bool {
    rv_feed_gas_kind(
        meta.kind,
        meta.src1_slot,
        meta.src2_slot,
        meta.dst_slot,
        gas_sim,
        mem_cycles,
    )
}

/// Compute per-block gas cost for a PVM2 basic block. The block runs
/// from `insts[block_start]` until the next instruction whose
/// `is_gas_block_start` is true (or the end of `insts`). Uses the
/// single-pass `GasSimulator` (decode-throughput + register-readiness
/// tracking — the model from `spec/Jar/JAVM/GasCostSinglePass.lean`)
/// driven by the LUT fast path (`rv_feed_gas_direct`).
/// Returns `max(max_done − 3, 1)`.
pub fn rv_gas_cost_for_block(
    insts: &[crate::predecode::RvPreDecodedInst],
    block_start: usize,
    mem_cycles: u8,
) -> u32 {
    let mut end = block_start + 1;
    while end < insts.len() && !insts[end].is_gas_block_start {
        end += 1;
    }
    let mut sim = crate::gas_sim::GasSimulator::new();
    for i in &insts[block_start..end] {
        rv_feed_gas_direct(&i.gas_meta, &mut sim, mem_cycles);
    }
    sim.flush_and_get_cost()
}

/// Memory class of a gas `kind` for category-#3 reserve accounting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemClass {
    None,
    Load,
    Store,
}

/// Classify a gas `kind` as a category-#3 memory op. Uses the **same**
/// `exec_unit == EU_LOAD/EU_STORE` predicate `rv_feed_gas_kind` uses for
/// the #2 `mem_cycles` override (gas_cost.rs), so "memory op for #3" and
/// "memory op for #2" provably agree across both engines.
#[inline]
pub fn rv_kind_mem_class(kind: u8) -> MemClass {
    match RV_GAS_COST_LUT[kind as usize].exec_unit {
        EU_LOAD => MemClass::Load,
        EU_STORE => MemClass::Store,
        _ => MemClass::None,
    }
}

/// Per-instruction worst-case category-#3 reserve contribution for a
/// gas `kind`: `store → COW×2` (×2 = `MAX_PAGES_PER_ACCESS`), else 0.
/// **Loads no longer reserve** — read-only page-in is charged eagerly at
/// the CALL (`gas_const::call_frame_cost`), not at a fault, so the only
/// #3 a block can debit mid-flight is a store's copy-on-write. **Both
/// engines** accumulate this at every real gas feed, so the block reserve
/// matches bit-for-bit.
#[inline]
pub fn rv_kind_reserve(kind: u8) -> u32 {
    use crate::gas_const::{COW_COST, MAX_PAGES_PER_ACCESS};
    let r = match rv_kind_mem_class(kind) {
        MemClass::Load => 0,
        MemClass::Store => COW_COST.saturating_mul(MAX_PAGES_PER_ACCESS),
        MemClass::None => 0,
    };
    r.min(u32::MAX as u64) as u32
}

/// Worst-case category-#3 reserve (in gas) for the basic block starting
/// at `block_start`: the maximum materialization cost the block can
/// debit at faults. The block-entry gate reserves this (a gate, not a
/// charge — see `~/docs/spec-staging/gas-cost.md` §1/§3) so #3 can never
/// drive gas negative mid-block.
///
/// Sums [`rv_kind_reserve`] over the block. An `ecall`/`ecalli` block
/// contributes 0 — it has no load/store, and its #3 (the dynamic
/// call-frame / host cost) is charged separately at dispatch. Saturates
/// to `u32::MAX` (blocks are bounded by code size, so this never binds).
pub fn rv_block_reserve_for_block(
    insts: &[crate::predecode::RvPreDecodedInst],
    block_start: usize,
) -> u32 {
    let mut end = block_start + 1;
    while end < insts.len() && !insts[end].is_gas_block_start {
        end += 1;
    }
    let mut reserve: u64 = 0;
    for i in &insts[block_start..end] {
        reserve = reserve.saturating_add(rv_kind_reserve(i.gas_meta.kind) as u64);
    }
    reserve.min(u32::MAX as u64) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::decode;
    use crate::predecode::is_terminator;

    /// Terminator flag as the recompiler sees it: the gas-LUT `RVF_TERM`
    /// bit for the instruction's kind (this is the classifier
    /// `Compiler::feed_gas_rv` consumes to mark gas-block starts).
    fn lut_term(inst: &crate::instruction::Inst) -> bool {
        RV_GAS_COST_LUT[rv_gas_meta(inst).kind as usize].flags & RVF_TERM != 0
    }

    /// B5: "what is a terminator" is hand-coded twice in this crate —
    /// `predecode::is_terminator` (a `match` on `Inst`, which the
    /// interpreter uses to mark gas-block starts) and the gas-LUT
    /// `RVF_TERM` bit (which the recompiler uses for the same purpose).
    /// They are independent and must classify every decodable
    /// instruction identically, or the interpreter and recompiler would
    /// disagree on basic-block boundaries (a consensus fork). Sweep the
    /// whole RVC halfword space and a 4-byte opcode × funct matrix and
    /// assert the two classifiers agree on every encoding that decodes.
    #[test]
    fn predecode_and_gas_lut_terminator_agree() {
        // RVC: every 2-byte halfword whose low bits aren't the 4-byte
        // marker.
        for h in 0u16..=0xFFFF {
            if h & 0b11 == 0b11 {
                continue;
            }
            if let Some((inst, _len)) = decode(&h.to_le_bytes()) {
                assert_eq!(
                    is_terminator(&inst),
                    lut_term(&inst),
                    "RVC halfword {h:#06x} -> {inst:?}"
                );
            }
        }
        // 4-byte: sweep every 7-bit opcode (low bits = 0b11) across
        // funct3 and a representative set of funct7 values, with fixed
        // register fields. This reaches every terminator opcode (jal
        // 0x6F, jalr 0x67, branch 0x63, custom-0 0x0B across all funct3)
        // and every non-terminator class.
        for major in 0u32..0x20 {
            let opcode7 = (major << 2) | 0b11;
            for funct3 in 0u32..8 {
                for &funct7 in &[0u32, 0b000_0001, 0b010_0000, 0b000_0111, 0b011_0000] {
                    let w = (funct7 << 25)
                        | (11 << 20)
                        | (10 << 15)
                        | (funct3 << 12)
                        | (10 << 7)
                        | opcode7;
                    if let Some((inst, _len)) = decode(&w.to_le_bytes()) {
                        assert_eq!(
                            is_terminator(&inst),
                            lut_term(&inst),
                            "word {w:#010x} -> {inst:?}"
                        );
                    }
                }
            }
        }
    }
}
