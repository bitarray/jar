//! RV64E-subset instruction encoders — the single source the generator and the
//! decode round-trip test both drive off.
//!
//! The two existing x3/x4 test files (`javm-recompiler-x86/tests/x3_x4_spill.rs`
//! and `javm-bench/tests/x3_x4_differential.rs`) each hand-rolled a handful of
//! ad-hoc encoders. This centralizes them and extends to the full implemented
//! ISA via the [`OPS`] spec table, validated against `javm_exec::decode` in the
//! tests below (every op must round-trip to a non-`Reserved` instruction).

/// Pack instruction words into a little-endian byte stream.
pub fn enc(words: &[u32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(words.len() * 4);
    for w in words {
        v.extend_from_slice(&w.to_le_bytes());
    }
    v
}

// ---- Format encoders (private; named helpers + OPS table build on these) ----

#[inline]
fn r(opcode: u32, funct7: u32, funct3: u32, rd: u8, rs1: u8, rs2: u8) -> u32 {
    (funct7 << 25)
        | ((rs2 as u32) << 20)
        | ((rs1 as u32) << 15)
        | (funct3 << 12)
        | ((rd as u32) << 7)
        | opcode
}

#[inline]
fn i(opcode: u32, funct3: u32, rd: u8, rs1: u8, imm: i32) -> u32 {
    ((imm as u32 & 0xFFF) << 20)
        | ((rs1 as u32) << 15)
        | (funct3 << 12)
        | ((rd as u32) << 7)
        | opcode
}

#[inline]
fn s(opcode: u32, funct3: u32, rs1: u8, rs2: u8, imm: i32) -> u32 {
    let u = imm as u32;
    (((u >> 5) & 0x7F) << 25)
        | ((rs2 as u32) << 20)
        | ((rs1 as u32) << 15)
        | (funct3 << 12)
        | ((u & 0x1F) << 7)
        | opcode
}

#[inline]
fn b_(opcode: u32, funct3: u32, rs1: u8, rs2: u8, imm: i32) -> u32 {
    let u = imm as u32;
    (((u >> 12) & 1) << 31)
        | (((u >> 5) & 0x3F) << 25)
        | ((rs2 as u32) << 20)
        | ((rs1 as u32) << 15)
        | (funct3 << 12)
        | (((u >> 1) & 0xF) << 8)
        | (((u >> 11) & 1) << 7)
        | opcode
}

#[inline]
fn u_(opcode: u32, rd: u8, imm20: u32) -> u32 {
    ((imm20 & 0xFFFFF) << 12) | ((rd as u32) << 7) | opcode
}

/// 64-bit shift / Zbs-imm: `funct6` occupies imm[11:6], shamt imm[5:0].
#[inline]
fn i_shift64(opcode: u32, funct3: u32, funct6: u32, rd: u8, rs1: u8, shamt: u8) -> u32 {
    let imm = ((funct6 & 0x3F) << 6) | (shamt as u32 & 0x3F);
    i(opcode, funct3, rd, rs1, imm as i32)
}

/// 32-bit (W) shift: `funct7` occupies imm[11:5], shamt imm[4:0].
#[inline]
fn i_shift32(opcode: u32, funct3: u32, funct7: u32, rd: u8, rs1: u8, shamt: u8) -> u32 {
    let imm = ((funct7 & 0x7F) << 5) | (shamt as u32 & 0x1F);
    i(opcode, funct3, rd, rs1, imm as i32)
}

// ---- Major opcodes (7-bit, low two bits always 11 for non-compressed) ----
const OP: u32 = 0x33; // OP        (R-type, 64)
const OP_IMM: u32 = 0x13; // OP-IMM     (I-type, 64)
const OP_IMM_32: u32 = 0x1B; // OP-IMM-32  (I-type, 32)
const OP_32: u32 = 0x3B; // OP-32      (R-type, 32)
const LOAD: u32 = 0x03;
const STORE: u32 = 0x23;
const BRANCH: u32 = 0x63;
const LUI: u32 = 0x37;
const AUIPC: u32 = 0x17;

/// Instruction format — selects how [`encode_op`] places operands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fmt {
    /// `rd, rs1, rs2` (OP / OP-32). `aux` = funct7.
    R,
    /// `rd, rs1, imm12` (OP-IMM / OP-IMM-32 / LOAD).
    I,
    /// `rd, rs1, shamt6` (64-bit shift / Zbs-imm). `aux` = funct6.
    IShift,
    /// `rd, rs1, shamt5` (W shift). `aux` = funct7.
    IShift32,
    /// `rs1(base), rs2(val), imm12` (STORE).
    Store,
    /// `rs1, rs2, imm13` (BRANCH).
    Branch,
    /// `rd, imm20` (LUI / AUIPC).
    U,
    /// `rd, rs1` with a fixed function code (Zbb unary). `aux` = funct12.
    Unary,
}

/// One implemented instruction: enough to encode it from operands.
#[derive(Clone, Copy, Debug)]
pub struct OpSpec {
    pub name: &'static str,
    pub fmt: Fmt,
    pub opcode: u32,
    pub funct3: u32,
    /// funct7 (R / IShift32), funct6 (IShift), or funct12 (Unary).
    pub aux: u32,
}

const fn op(name: &'static str, fmt: Fmt, opcode: u32, funct3: u32, aux: u32) -> OpSpec {
    OpSpec {
        name,
        fmt,
        opcode,
        funct3,
        aux,
    }
}

impl OpSpec {
    /// True for loads, stores, and branches — ops the (v1) register-only
    /// generator skips because they need a backing memory window or
    /// non-straight-line control flow. The rest (R/I/shift/unary/lui/auipc)
    /// are pure register→register and total by construction.
    pub fn touches_memory_or_control(&self) -> bool {
        self.opcode == LOAD || matches!(self.fmt, Fmt::Store | Fmt::Branch)
    }
}

/// Every instruction family the generator can emit. Validated against the
/// decoder in `round_trip_all_ops` (each must decode to a non-`Reserved`
/// instruction). Excludes terminators (`ecalli`/`trap`/`fallthrough`),
/// `fence`, and anything reserved (SYSTEM, x3/x4, x16–31).
#[rustfmt::skip]
pub const OPS: &[OpSpec] = &[
    // -- R-type, 64-bit (OP) --
    op("add",  Fmt::R, OP, 0, 0x00), op("sub", Fmt::R, OP, 0, 0x20),
    op("sll",  Fmt::R, OP, 1, 0x00), op("slt", Fmt::R, OP, 2, 0x00),
    op("sltu", Fmt::R, OP, 3, 0x00), op("xor", Fmt::R, OP, 4, 0x00),
    op("srl",  Fmt::R, OP, 5, 0x00), op("sra", Fmt::R, OP, 5, 0x20),
    op("or",   Fmt::R, OP, 6, 0x00), op("and", Fmt::R, OP, 7, 0x00),
    // M
    op("mul",  Fmt::R, OP, 0, 0x01), op("mulh",   Fmt::R, OP, 1, 0x01),
    op("mulhsu", Fmt::R, OP, 2, 0x01), op("mulhu", Fmt::R, OP, 3, 0x01),
    op("div",  Fmt::R, OP, 4, 0x01), op("divu",   Fmt::R, OP, 5, 0x01),
    op("rem",  Fmt::R, OP, 6, 0x01), op("remu",   Fmt::R, OP, 7, 0x01),
    // Zbb binary
    op("min",  Fmt::R, OP, 4, 0x05), op("minu", Fmt::R, OP, 5, 0x05),
    op("max",  Fmt::R, OP, 6, 0x05), op("maxu", Fmt::R, OP, 7, 0x05),
    op("andn", Fmt::R, OP, 7, 0x20), op("orn",  Fmt::R, OP, 6, 0x20),
    op("xnor", Fmt::R, OP, 4, 0x20), op("rol",  Fmt::R, OP, 1, 0x30),
    op("ror",  Fmt::R, OP, 5, 0x30),
    // Zba
    op("sh1add", Fmt::R, OP, 2, 0x10), op("sh2add", Fmt::R, OP, 4, 0x10),
    op("sh3add", Fmt::R, OP, 6, 0x10),
    // Zbs
    op("bclr", Fmt::R, OP, 1, 0x24), op("bext", Fmt::R, OP, 5, 0x24),
    op("binv", Fmt::R, OP, 1, 0x34), op("bset", Fmt::R, OP, 1, 0x14),
    // Zicond
    op("czero.eqz", Fmt::R, OP, 5, 0x07), op("czero.nez", Fmt::R, OP, 7, 0x07),

    // -- R-type, 32-bit (OP-32) --
    op("addw", Fmt::R, OP_32, 0, 0x00), op("subw", Fmt::R, OP_32, 0, 0x20),
    op("sllw", Fmt::R, OP_32, 1, 0x00), op("srlw", Fmt::R, OP_32, 5, 0x00),
    op("sraw", Fmt::R, OP_32, 5, 0x20),
    op("mulw", Fmt::R, OP_32, 0, 0x01), op("divw", Fmt::R, OP_32, 4, 0x01),
    op("divuw", Fmt::R, OP_32, 5, 0x01), op("remw", Fmt::R, OP_32, 6, 0x01),
    op("remuw", Fmt::R, OP_32, 7, 0x01),
    op("adduw", Fmt::R, OP_32, 0, 0x04),
    op("sh1add.uw", Fmt::R, OP_32, 2, 0x10), op("sh2add.uw", Fmt::R, OP_32, 4, 0x10),
    op("sh3add.uw", Fmt::R, OP_32, 6, 0x10),
    op("rolw", Fmt::R, OP_32, 1, 0x30), op("rorw", Fmt::R, OP_32, 5, 0x30),

    // -- I-type ALU (OP-IMM) --
    op("addi", Fmt::I, OP_IMM, 0, 0), op("slti", Fmt::I, OP_IMM, 2, 0),
    op("sltiu", Fmt::I, OP_IMM, 3, 0), op("xori", Fmt::I, OP_IMM, 4, 0),
    op("ori", Fmt::I, OP_IMM, 6, 0), op("andi", Fmt::I, OP_IMM, 7, 0),
    op("addiw", Fmt::I, OP_IMM_32, 0, 0),

    // -- I-type shift, 64-bit (OP-IMM, funct6) --
    op("slli", Fmt::IShift, OP_IMM, 1, 0x00), op("srli", Fmt::IShift, OP_IMM, 5, 0x00),
    op("srai", Fmt::IShift, OP_IMM, 5, 0x10), op("rori", Fmt::IShift, OP_IMM, 5, 0x18),
    op("bclri", Fmt::IShift, OP_IMM, 1, 0x12), op("bexti", Fmt::IShift, OP_IMM, 5, 0x12),
    op("bseti", Fmt::IShift, OP_IMM, 1, 0x0A), op("binvi", Fmt::IShift, OP_IMM, 1, 0x1A),
    // NB: `slli.uw` is intentionally omitted — its 6-bit shamt overlaps the
    // decoder's 7-bit funct7 check, so shamt ≥ 32 decodes as Reserved. The
    // generator avoids it to keep every emitted instruction a live encoding.

    // -- I-type shift, 32-bit (OP-IMM-32, funct7) --
    op("slliw", Fmt::IShift32, OP_IMM_32, 1, 0x00), op("srliw", Fmt::IShift32, OP_IMM_32, 5, 0x00),
    op("sraiw", Fmt::IShift32, OP_IMM_32, 5, 0x20), op("roriw", Fmt::IShift32, OP_IMM_32, 5, 0x30),

    // -- Zbb unary (fixed funct12) --
    op("clz", Fmt::Unary, OP_IMM, 1, 0x600), op("ctz", Fmt::Unary, OP_IMM, 1, 0x601),
    op("cpop", Fmt::Unary, OP_IMM, 1, 0x602), op("sext.b", Fmt::Unary, OP_IMM, 1, 0x604),
    op("sext.h", Fmt::Unary, OP_IMM, 1, 0x605), op("orc.b", Fmt::Unary, OP_IMM, 5, 0x287),
    op("rev8", Fmt::Unary, OP_IMM, 5, 0x6B8),
    op("clzw", Fmt::Unary, OP_IMM_32, 1, 0x600), op("ctzw", Fmt::Unary, OP_IMM_32, 1, 0x601),
    op("cpopw", Fmt::Unary, OP_IMM_32, 1, 0x602),
    // NB: `zext.h` is intentionally omitted — this decoder recognizes it via the
    // RV32-style OP (0x33) encoding rather than the standard RV64 OP-32, so the
    // generator avoids it to keep the op table on uncontested encodings.

    // -- Loads / Stores --
    op("lb", Fmt::I, LOAD, 0, 0), op("lh", Fmt::I, LOAD, 1, 0),
    op("lw", Fmt::I, LOAD, 2, 0), op("ld", Fmt::I, LOAD, 3, 0),
    op("lbu", Fmt::I, LOAD, 4, 0), op("lhu", Fmt::I, LOAD, 5, 0),
    op("lwu", Fmt::I, LOAD, 6, 0),
    op("sb", Fmt::Store, STORE, 0, 0), op("sh", Fmt::Store, STORE, 1, 0),
    op("sw", Fmt::Store, STORE, 2, 0), op("sd", Fmt::Store, STORE, 3, 0),

    // -- Upper immediate --
    op("lui", Fmt::U, LUI, 0, 0), op("auipc", Fmt::U, AUIPC, 0, 0),

    // -- Branches --
    op("beq", Fmt::Branch, BRANCH, 0, 0), op("bne", Fmt::Branch, BRANCH, 1, 0),
    op("blt", Fmt::Branch, BRANCH, 4, 0), op("bge", Fmt::Branch, BRANCH, 5, 0),
    op("bltu", Fmt::Branch, BRANCH, 6, 0), op("bgeu", Fmt::Branch, BRANCH, 7, 0),
];

/// Encode `op` with the given operands. Operands not used by the format are
/// ignored (e.g. `rs2` for `Fmt::I`, `imm` for `Fmt::Unary`). For shift
/// formats the low bits of `imm` are the shift amount; for `Fmt::U`, `imm` is
/// the 20-bit upper immediate.
pub fn encode_op(spec: &OpSpec, rd: u8, rs1: u8, rs2: u8, imm: i32) -> u32 {
    match spec.fmt {
        Fmt::R => r(spec.opcode, spec.aux, spec.funct3, rd, rs1, rs2),
        Fmt::I => i(spec.opcode, spec.funct3, rd, rs1, imm),
        Fmt::IShift => i_shift64(
            spec.opcode,
            spec.funct3,
            spec.aux,
            rd,
            rs1,
            (imm as u32 & 0x3F) as u8,
        ),
        Fmt::IShift32 => i_shift32(
            spec.opcode,
            spec.funct3,
            spec.aux,
            rd,
            rs1,
            (imm as u32 & 0x1F) as u8,
        ),
        Fmt::Store => s(spec.opcode, spec.funct3, rs1, rs2, imm),
        Fmt::Branch => b_(spec.opcode, spec.funct3, rs1, rs2, imm),
        Fmt::U => u_(spec.opcode, rd, imm as u32),
        Fmt::Unary => i(spec.opcode, spec.funct3, rd, rs1, spec.aux as i32),
    }
}

// ---- Named helpers (the fold, constant materialization, tests) ----

/// `ecalli 0` — HostCall(0), the clean trampoline halt both engines surface as
/// `exit_reason = 4`. Appended by the replay harness, not stored in vectors.
pub const HALT: u32 = 0x0000_200B;

pub fn addi(rd: u8, rs1: u8, imm: i32) -> u32 {
    i(OP_IMM, 0, rd, rs1, imm)
}
pub fn add(rd: u8, rs1: u8, rs2: u8) -> u32 {
    r(OP, 0x00, 0, rd, rs1, rs2)
}
pub fn sub(rd: u8, rs1: u8, rs2: u8) -> u32 {
    r(OP, 0x20, 0, rd, rs1, rs2)
}
pub fn xor(rd: u8, rs1: u8, rs2: u8) -> u32 {
    r(OP, 0x00, 4, rd, rs1, rs2)
}
pub fn div(rd: u8, rs1: u8, rs2: u8) -> u32 {
    r(OP, 0x01, 4, rd, rs1, rs2)
}
pub fn rem(rd: u8, rs1: u8, rs2: u8) -> u32 {
    r(OP, 0x01, 6, rd, rs1, rs2)
}
pub fn mulhsu(rd: u8, rs1: u8, rs2: u8) -> u32 {
    r(OP, 0x01, 2, rd, rs1, rs2)
}
pub fn slli(rd: u8, rs1: u8, shamt: u8) -> u32 {
    i_shift64(OP_IMM, 1, 0x00, rd, rs1, shamt)
}
pub fn rori(rd: u8, rs1: u8, shamt: u8) -> u32 {
    i_shift64(OP_IMM, 5, 0x18, rd, rs1, shamt)
}
pub fn ld(rd: u8, rs1: u8, imm: i32) -> u32 {
    i(LOAD, 3, rd, rs1, imm)
}
pub fn sd(rs1: u8, rs2: u8, imm: i32) -> u32 {
    s(STORE, 3, rs1, rs2, imm)
}
pub fn lui(rd: u8, imm20: u32) -> u32 {
    u_(LUI, rd, imm20)
}
pub fn beq(rs1: u8, rs2: u8, imm: i32) -> u32 {
    b_(BRANCH, 0, rs1, rs2, imm)
}

/// Materialize an arbitrary `value` into `rd` using only `rd` (no scratch
/// register): build MSB-first in 11-bit chunks via `addi`/`slli`. Each `addi`
/// adds an 11-bit (always non-negative) chunk into freshly-zeroed low bits.
pub fn li64(rd: u8, value: u64) -> Vec<u32> {
    let chunk = |sh: u32| ((value >> sh) & 0x7FF) as i32;
    let mut out = vec![addi(rd, 0, ((value >> 55) & 0x1FF) as i32)];
    for sh in [44u32, 33, 22, 11, 0] {
        out.push(slli(rd, rd, 11));
        out.push(addi(rd, rd, chunk(sh)));
    }
    out
}

// ---- Signature epilogue (lossless state readout — see lib docs) ----

/// Number of host-mapped register slots captured by the signature (slots
/// 0..=12 → x1, x2, x5, x6, x7, x8–x15; see [`crate::oracle::slot_to_xreg`]).
pub const SIG_REGS: usize = 13;

/// Byte length of the register signature: one little-endian `u64` per captured
/// slot. Fits in a single page and in `SCRATCHPAD_HEAD_LEN` (128).
pub const SIG_BYTES: usize = SIG_REGS * 8;

/// The x-register stored at signature slot `i` (the inverse of
/// `javm_exec::regs::reg_slot_or_ff`, matching [`crate::oracle::slot_to_xreg`]).
/// Slot 7 = x10 (the former fold `return_value`). The epilogue stores each at
/// byte offset `8*i` of the signature region.
pub const SIG_XREGS: [u8; SIG_REGS] = [1, 2, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

/// Scratch base register for the signature stores. x3 is spilled — it is not in
/// the captured set (slots 0..=12) and is invocation-local (dropped at exit), so
/// clobbering it is invisible to the differential, and both engines agree on
/// x3/x4 spill semantics (the `x3_x4_differential` net). Using it as the store
/// base leaves every captured register untouched, so the stored values are the
/// program's exact post-body register file.
pub const SIG_BASE_REG: u8 = 3;

/// Emit the signature epilogue (no terminator): materialize `sig_base` into the
/// scratch base register, then `sd` each captured register to `sig_base + 8*i`.
/// `sig_base` is the guest VA the scratchpad (slot[0]) DataCap maps at; the
/// guest's stores CoW the region's pages, and the host reads the effective
/// bytes back as the run's lossless register signature (vs the old lossy x10
/// fold).
pub fn signature_epilogue(sig_base: u32) -> Vec<u32> {
    let mut out = li64(SIG_BASE_REG, sig_base as u64);
    for (i, &xr) in SIG_XREGS.iter().enumerate() {
        out.push(sd(SIG_BASE_REG, xr, (i * 8) as i32));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use javm_exec::instruction::{Inst, decode};

    fn decode1(w: u32) -> (Inst, u8) {
        decode(&w.to_le_bytes()).unwrap_or_else(|| panic!("decode failed for {w:#010x}"))
    }

    #[test]
    fn round_trip_all_ops() {
        // Every OPS entry must decode to a recognized (non-Reserved) 4-byte
        // instruction with valid registers. Collect all failures so a bad
        // funct value names itself instead of failing on the first op.
        let mut bad = Vec::new();
        for spec in OPS {
            // rd=x10, rs1=x11, rs2=x12; imm=4 (even, in range for every fmt).
            let w = encode_op(spec, 10, 11, 12, 4);
            match decode(&w.to_le_bytes()) {
                Some((Inst::Reserved { .. }, _)) | None => {
                    bad.push(format!("{} -> Reserved/None ({w:#010x})", spec.name))
                }
                Some((_, 4)) => {}
                Some((_, len)) => bad.push(format!("{} -> len {len} ({w:#010x})", spec.name)),
            }
        }
        assert!(
            bad.is_empty(),
            "encoder/decoder mismatch:\n  {}",
            bad.join("\n  ")
        );
    }

    #[test]
    fn halt_decodes_as_ecalli_zero() {
        assert!(matches!(decode1(HALT), (Inst::Ecalli { imm: 0 }, 4)));
    }

    #[test]
    fn curated_exact_fields() {
        assert!(matches!(
            decode1(add(10, 11, 12)),
            (
                Inst::Add {
                    rd: 10,
                    rs1: 11,
                    rs2: 12
                },
                4
            )
        ));
        assert!(matches!(
            decode1(sub(5, 6, 7)),
            (
                Inst::Sub {
                    rd: 5,
                    rs1: 6,
                    rs2: 7
                },
                4
            )
        ));
        assert!(matches!(
            decode1(div(10, 8, 9)),
            (
                Inst::Div {
                    rd: 10,
                    rs1: 8,
                    rs2: 9
                },
                4
            )
        ));
        assert!(matches!(
            decode1(rem(10, 8, 9)),
            (
                Inst::Rem {
                    rd: 10,
                    rs1: 8,
                    rs2: 9
                },
                4
            )
        ));
        assert!(matches!(
            decode1(mulhsu(10, 8, 9)),
            (
                Inst::Mulhsu {
                    rd: 10,
                    rs1: 8,
                    rs2: 9
                },
                4
            )
        ));
        assert!(matches!(
            decode1(rori(5, 5, 5)),
            (
                Inst::Rori {
                    rd: 5,
                    rs1: 5,
                    shamt: 5
                },
                4
            )
        ));
        assert!(matches!(
            decode1(slli(5, 5, 11)),
            (
                Inst::Slli {
                    rd: 5,
                    rs1: 5,
                    shamt: 11
                },
                4
            )
        ));
        assert!(matches!(
            decode1(ld(7, 6, 8)),
            (
                Inst::Ld {
                    rd: 7,
                    rs1: 6,
                    imm: 8
                },
                4
            )
        ));
        assert!(matches!(
            decode1(sd(6, 7, 0)),
            (
                Inst::Sd {
                    rs1: 6,
                    rs2: 7,
                    imm: 0
                },
                4
            )
        ));
        assert!(matches!(
            decode1(addi(10, 0, -4)),
            (
                Inst::Addi {
                    rd: 10,
                    rs1: 0,
                    imm: -4
                },
                4
            )
        ));
        assert!(matches!(
            decode1(lui(10, 0x12345)),
            (
                Inst::Lui {
                    rd: 10,
                    imm: 0x1234_5000
                },
                4
            )
        ));
        assert!(matches!(
            decode1(beq(8, 9, 12)),
            (
                Inst::Beq {
                    rs1: 8,
                    rs2: 9,
                    imm: 12
                },
                4
            )
        ));
    }

    #[test]
    fn li64_materializes_boundary_values() {
        // The fold's li64 must reproduce arbitrary constants — check each
        // word decodes (not Reserved) for a few boundary values.
        for v in [
            0u64,
            1,
            u64::MAX,
            0x8000_0000_0000_0000,
            0x7FFF_FFFF,
            0xDEAD_BEEF_CAFE_F00D,
        ] {
            for w in li64(7, v) {
                assert!(
                    !matches!(decode1(w), (Inst::Reserved { .. }, _)),
                    "li64({v:#018x}) produced Reserved word {w:#010x}",
                );
            }
        }
    }

    #[test]
    fn signature_epilogue_is_all_valid() {
        let ep = signature_epilogue(0x1000_0000);
        for w in &ep {
            assert!(
                !matches!(decode1(*w), (Inst::Reserved { .. }, _)),
                "signature epilogue produced Reserved word {w:#010x}",
            );
        }
        // li64 (the base address) + one `sd` per captured register.
        assert_eq!(
            ep.len(),
            li64(SIG_BASE_REG, 0).len() + SIG_REGS,
            "epilogue length"
        );
    }
}
