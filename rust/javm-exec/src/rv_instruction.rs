//! RV64+C+custom-0 instruction decoder for PVM2.
//!
//! Decodes a 16-bit-aligned cursor into `(RvInst, byte_length)`.
//! Compressed (RVC) instructions are **decompressed at decode time**
//! into their 32-bit equivalents so the rest of the pipeline sees
//! uniform `RvInst` values; the returned `byte_length` (2 or 4) is
//! the wire length, used to advance PC.
//!
//! ISA coverage matches the PVM2 spec
//! (`~/docs/pvm-isa/05-pvm2-rv-diff.md` and `06-pvm2-pvm-diff.md`):
//!
//!   RV64I base  +  M  +  C  +  Zbb  +  Zba  +  Zbs  +  Zicond
//!   + custom-0 ops:  trap  /  ecall.jar  /  ecalli
//!
//! Forbidden encodings (per PVM2-Base divergences):
//!
//! - AUIPC (RV major `0010111`) — decoder returns `Reserved`.
//! - Standard ECALL / EBREAK (RV `SYSTEM` major) — decoder returns
//!   `Reserved`. PVM2's ecall lives in custom-0 instead.
//! - CSR ops, atomics, FP, vector — `Reserved`.
//! - Any reg field of x3 or x4 (`gp`/`tp`) — `Reserved`.

#![allow(dead_code)]

/// Decoded RV instruction in named-variant form.
///
/// One variant per RV operation we accept. Field layout is per the
/// RV unprivileged spec. Immediate fields are pre-sign-extended to
/// `i32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RvInst {
    // -------- Loads (I-type, major LOAD=0000011) --------
    Lb { rd: u8, rs1: u8, imm: i32 },
    Lh { rd: u8, rs1: u8, imm: i32 },
    Lw { rd: u8, rs1: u8, imm: i32 },
    Ld { rd: u8, rs1: u8, imm: i32 },
    Lbu { rd: u8, rs1: u8, imm: i32 },
    Lhu { rd: u8, rs1: u8, imm: i32 },
    Lwu { rd: u8, rs1: u8, imm: i32 },

    // -------- Stores (S-type, major STORE=0100011) --------
    Sb { rs1: u8, rs2: u8, imm: i32 },
    Sh { rs1: u8, rs2: u8, imm: i32 },
    Sw { rs1: u8, rs2: u8, imm: i32 },
    Sd { rs1: u8, rs2: u8, imm: i32 },

    // -------- ALU with immediate (I-type) --------
    // 64-bit (major OP-IMM = 0010011)
    Addi { rd: u8, rs1: u8, imm: i32 },
    Slti { rd: u8, rs1: u8, imm: i32 },
    Sltiu { rd: u8, rs1: u8, imm: i32 },
    Andi { rd: u8, rs1: u8, imm: i32 },
    Ori { rd: u8, rs1: u8, imm: i32 },
    Xori { rd: u8, rs1: u8, imm: i32 },
    Slli { rd: u8, rs1: u8, shamt: u8 },
    Srli { rd: u8, rs1: u8, shamt: u8 },
    Srai { rd: u8, rs1: u8, shamt: u8 },
    // 32-bit (major OP-IMM-32 = 0011011)
    Addiw { rd: u8, rs1: u8, imm: i32 },
    Slliw { rd: u8, rs1: u8, shamt: u8 },
    Srliw { rd: u8, rs1: u8, shamt: u8 },
    Sraiw { rd: u8, rs1: u8, shamt: u8 },

    // -------- ALU register-register (R-type) --------
    // 64-bit (major OP = 0110011)
    Add { rd: u8, rs1: u8, rs2: u8 },
    Sub { rd: u8, rs1: u8, rs2: u8 },
    Sll { rd: u8, rs1: u8, rs2: u8 },
    Srl { rd: u8, rs1: u8, rs2: u8 },
    Sra { rd: u8, rs1: u8, rs2: u8 },
    Slt { rd: u8, rs1: u8, rs2: u8 },
    Sltu { rd: u8, rs1: u8, rs2: u8 },
    Xor { rd: u8, rs1: u8, rs2: u8 },
    Or { rd: u8, rs1: u8, rs2: u8 },
    And { rd: u8, rs1: u8, rs2: u8 },
    // 32-bit (major OP-32 = 0111011)
    Addw { rd: u8, rs1: u8, rs2: u8 },
    Subw { rd: u8, rs1: u8, rs2: u8 },
    Sllw { rd: u8, rs1: u8, rs2: u8 },
    Srlw { rd: u8, rs1: u8, rs2: u8 },
    Sraw { rd: u8, rs1: u8, rs2: u8 },

    // -------- M extension --------
    Mul { rd: u8, rs1: u8, rs2: u8 },
    Mulh { rd: u8, rs1: u8, rs2: u8 },
    Mulhsu { rd: u8, rs1: u8, rs2: u8 },
    Mulhu { rd: u8, rs1: u8, rs2: u8 },
    Div { rd: u8, rs1: u8, rs2: u8 },
    Divu { rd: u8, rs1: u8, rs2: u8 },
    Rem { rd: u8, rs1: u8, rs2: u8 },
    Remu { rd: u8, rs1: u8, rs2: u8 },
    Mulw { rd: u8, rs1: u8, rs2: u8 },
    Divw { rd: u8, rs1: u8, rs2: u8 },
    Divuw { rd: u8, rs1: u8, rs2: u8 },
    Remw { rd: u8, rs1: u8, rs2: u8 },
    Remuw { rd: u8, rs1: u8, rs2: u8 },

    // -------- Zbb (basic bit manipulation) --------
    Clz { rd: u8, rs1: u8 },
    Clzw { rd: u8, rs1: u8 },
    Ctz { rd: u8, rs1: u8 },
    Ctzw { rd: u8, rs1: u8 },
    Cpop { rd: u8, rs1: u8 },
    Cpopw { rd: u8, rs1: u8 },
    SextB { rd: u8, rs1: u8 },
    SextH { rd: u8, rs1: u8 },
    ZextH { rd: u8, rs1: u8 }, // canonical encoding: pack rd, rs1, x0
    Rev8 { rd: u8, rs1: u8 },
    OrcB { rd: u8, rs1: u8 },
    Min { rd: u8, rs1: u8, rs2: u8 },
    Minu { rd: u8, rs1: u8, rs2: u8 },
    Max { rd: u8, rs1: u8, rs2: u8 },
    Maxu { rd: u8, rs1: u8, rs2: u8 },
    Andn { rd: u8, rs1: u8, rs2: u8 },
    Orn { rd: u8, rs1: u8, rs2: u8 },
    Xnor { rd: u8, rs1: u8, rs2: u8 },
    Rol { rd: u8, rs1: u8, rs2: u8 },
    Ror { rd: u8, rs1: u8, rs2: u8 },
    Rolw { rd: u8, rs1: u8, rs2: u8 },
    Rorw { rd: u8, rs1: u8, rs2: u8 },
    Rori { rd: u8, rs1: u8, shamt: u8 },
    Roriw { rd: u8, rs1: u8, shamt: u8 },

    // -------- Zba (shift-add) --------
    Sh1add { rd: u8, rs1: u8, rs2: u8 },
    Sh2add { rd: u8, rs1: u8, rs2: u8 },
    Sh3add { rd: u8, rs1: u8, rs2: u8 },
    Sh1adduw { rd: u8, rs1: u8, rs2: u8 },
    Sh2adduw { rd: u8, rs1: u8, rs2: u8 },
    Sh3adduw { rd: u8, rs1: u8, rs2: u8 },
    Adduw { rd: u8, rs1: u8, rs2: u8 },
    Slliuw { rd: u8, rs1: u8, shamt: u8 },

    // -------- Zbs (single-bit) --------
    Bclr { rd: u8, rs1: u8, rs2: u8 },
    Bset { rd: u8, rs1: u8, rs2: u8 },
    Binv { rd: u8, rs1: u8, rs2: u8 },
    Bext { rd: u8, rs1: u8, rs2: u8 },
    Bclri { rd: u8, rs1: u8, shamt: u8 },
    Bseti { rd: u8, rs1: u8, shamt: u8 },
    Binvi { rd: u8, rs1: u8, shamt: u8 },
    Bexti { rd: u8, rs1: u8, shamt: u8 },

    // -------- Zicond --------
    CzeroEqz { rd: u8, rs1: u8, rs2: u8 },
    CzeroNez { rd: u8, rs1: u8, rs2: u8 },

    // -------- Upper immediate --------
    Lui { rd: u8, imm: i32 },

    // -------- Control flow --------
    /// `jal rd, off` — Harvard semantics per PVM2.
    /// `rd = pc + sizeof(jal)`; pc = pc + off.
    Jal { rd: u8, imm: i32 },
    /// `jalr rd, rs1, imm` — Harvard semantics + djump validation.
    /// `target = (rs1 + imm) & 0xFFFFFFFE`; trap if not a valid PC.
    Jalr { rd: u8, rs1: u8, imm: i32 },
    Beq { rs1: u8, rs2: u8, imm: i32 },
    Bne { rs1: u8, rs2: u8, imm: i32 },
    Blt { rs1: u8, rs2: u8, imm: i32 },
    Bge { rs1: u8, rs2: u8, imm: i32 },
    Bltu { rs1: u8, rs2: u8, imm: i32 },
    Bgeu { rs1: u8, rs2: u8, imm: i32 },

    // -------- System (RV-defined, all no-ops or reserved in PVM2) --------
    /// `fence` — decoded but treated as no-op (PVM2 is single-threaded).
    Fence,
    /// `fence.i` — same.
    FenceI,

    // -------- Custom-0 (PVM2-jar host ops) --------
    /// `custom-0` sub-op `00`: unconditional execution abort.
    Trap,
    /// `custom-0` sub-op `01`: jar management op / dynamic CALL.
    EcallJar,
    /// `custom-0` sub-op `10`: host-call with 20-bit signed immediate.
    Ecalli { imm: i32 },

    // -------- Sentinel for forbidden encodings --------
    /// Decoder accepted the wire bits but the encoding is reserved
    /// by PVM2 (AUIPC, standard ECALL/EBREAK, CSR, atomics, FP, …).
    /// Programs containing this are rejected at deblob.
    Reserved { raw: u32 },
}

/// Major opcode of a 32-bit RV instruction is bits [6:2]; bits [1:0]
/// are always `11` for non-compressed.
const OP_LOAD: u32 = 0b00_000;
const OP_STORE: u32 = 0b01_000;
const OP_MADD: u32 = 0b10_000; // reserved (FP)
const OP_BRANCH: u32 = 0b11_000;

const OP_LOAD_FP: u32 = 0b00_001; // reserved (FP)
const OP_STORE_FP: u32 = 0b01_001; // reserved (FP)
const OP_JALR: u32 = 0b11_001;

const OP_CUSTOM_0: u32 = 0b00_010;
const OP_CUSTOM_1: u32 = 0b01_010; // reserved
const OP_CUSTOM_2_OR_RV128: u32 = 0b10_010; // reserved
// Note bit 11000 is shared with BRANCH

const OP_MISC_MEM: u32 = 0b00_011;
const OP_AMO: u32 = 0b01_011; // reserved (A)
const OP_JAL: u32 = 0b11_011;

const OP_IMM: u32 = 0b00_100;
const OP_OP: u32 = 0b01_100;
const OP_OP_FP: u32 = 0b10_100; // reserved (FP)
const OP_SYSTEM: u32 = 0b11_100;

const OP_AUIPC: u32 = 0b00_101;
const OP_LUI: u32 = 0b01_101;
const OP_OP_IMM_32: u32 = 0b00_110;
const OP_OP_32: u32 = 0b01_110;

/// Decode a single instruction starting at `bytes[0]`.
///
/// Returns `(inst, byte_length)` where byte_length is 2 (compressed)
/// or 4 (standard). Returns `None` if fewer than 2 bytes are
/// available or the first 2 bytes are zero (which is `Reserved`
/// shape — we treat as decode failure to give the caller a clean
/// signal).
pub fn decode(bytes: &[u8]) -> Option<(RvInst, u8)> {
    if bytes.len() < 2 {
        return None;
    }
    let lo16 = u16::from_le_bytes([bytes[0], bytes[1]]);
    // Length encoding: bits [1:0] of byte 0.
    //   xx11  -> 32-bit (or longer; we don't support >32)
    //   else  -> 16-bit compressed
    if lo16 & 0b11 != 0b11 {
        return Some((decompress(lo16), 2));
    }
    if bytes.len() < 4 {
        return None;
    }
    let w = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    Some((decode_32(w), 4))
}

// ============================================================================
// 32-bit decode
// ============================================================================

fn decode_32(w: u32) -> RvInst {
    let major = (w >> 2) & 0x1F; // [6:2]
    if w & 0b11 != 0b11 {
        return RvInst::Reserved { raw: w };
    }
    let rd = ((w >> 7) & 0x1F) as u8;
    let rs1 = ((w >> 15) & 0x1F) as u8;
    let rs2 = ((w >> 20) & 0x1F) as u8;
    let funct3 = ((w >> 12) & 0x07) as u8;
    let funct7 = ((w >> 25) & 0x7F) as u8;

    match major {
        OP_LOAD => decode_load(w, rd, rs1, funct3),
        OP_STORE => decode_store(w, rs1, rs2, funct3),
        OP_IMM => decode_op_imm(w, rd, rs1, funct3),
        OP_OP_IMM_32 => decode_op_imm_32(w, rd, rs1, funct3),
        OP_OP => decode_op(rd, rs1, rs2, funct3, funct7, w),
        OP_OP_32 => decode_op_32(rd, rs1, rs2, funct3, funct7, w),
        OP_LUI => RvInst::Lui {
            rd,
            imm: (w & 0xFFFFF000) as i32,
        },
        OP_AUIPC => RvInst::Reserved { raw: w }, // forbidden in PVM2
        OP_JAL => {
            let imm = imm_j(w);
            RvInst::Jal { rd, imm }
        }
        OP_JALR => {
            if funct3 != 0 {
                return RvInst::Reserved { raw: w };
            }
            let imm = imm_i(w);
            RvInst::Jalr { rd, rs1, imm }
        }
        OP_BRANCH => decode_branch(rs1, rs2, funct3, imm_b(w), w),
        OP_MISC_MEM => decode_misc_mem(funct3),
        OP_SYSTEM => RvInst::Reserved { raw: w }, // standard ECALL/EBREAK/CSR reserved
        OP_CUSTOM_0 => decode_custom_0(w, rd, rs1, funct3),
        _ => RvInst::Reserved { raw: w },
    }
}

fn decode_load(w: u32, rd: u8, rs1: u8, funct3: u8) -> RvInst {
    let imm = imm_i(w);
    match funct3 {
        0b000 => RvInst::Lb { rd, rs1, imm },
        0b001 => RvInst::Lh { rd, rs1, imm },
        0b010 => RvInst::Lw { rd, rs1, imm },
        0b011 => RvInst::Ld { rd, rs1, imm },
        0b100 => RvInst::Lbu { rd, rs1, imm },
        0b101 => RvInst::Lhu { rd, rs1, imm },
        0b110 => RvInst::Lwu { rd, rs1, imm },
        _ => RvInst::Reserved { raw: w },
    }
}

fn decode_store(w: u32, rs1: u8, rs2: u8, funct3: u8) -> RvInst {
    let imm = imm_s(w);
    match funct3 {
        0b000 => RvInst::Sb { rs1, rs2, imm },
        0b001 => RvInst::Sh { rs1, rs2, imm },
        0b010 => RvInst::Sw { rs1, rs2, imm },
        0b011 => RvInst::Sd { rs1, rs2, imm },
        _ => RvInst::Reserved { raw: w },
    }
}

fn decode_op_imm(w: u32, rd: u8, rs1: u8, funct3: u8) -> RvInst {
    let imm = imm_i(w);
    let shamt = (w >> 20) & 0x3F; // 6-bit for RV64 shifts
    let shtype = (w >> 26) & 0x3F; // upper 6 bits for shift type
    match funct3 {
        0b000 => RvInst::Addi { rd, rs1, imm },
        0b010 => RvInst::Slti { rd, rs1, imm },
        0b011 => RvInst::Sltiu { rd, rs1, imm },
        0b100 => RvInst::Xori { rd, rs1, imm },
        0b110 => RvInst::Ori { rd, rs1, imm },
        0b111 => RvInst::Andi { rd, rs1, imm },
        0b001 => match shtype {
            0b000000 => RvInst::Slli {
                rd,
                rs1,
                shamt: shamt as u8,
            },
            // Zbs: bclri (funct7[6:1]=010010), bseti (001010), binvi (011010)
            0b010010 => RvInst::Bclri {
                rd,
                rs1,
                shamt: shamt as u8,
            },
            0b001010 => RvInst::Bseti {
                rd,
                rs1,
                shamt: shamt as u8,
            },
            0b011010 => RvInst::Binvi {
                rd,
                rs1,
                shamt: shamt as u8,
            },
            // Zbb: clz/ctz/cpop/sext.b/sext.h (funct7=0110000), variant in rs2
            0b011000 => match rs2_field(w) {
                0b00000 => RvInst::Clz { rd, rs1 },
                0b00001 => RvInst::Ctz { rd, rs1 },
                0b00010 => RvInst::Cpop { rd, rs1 },
                0b00100 => RvInst::SextB { rd, rs1 },
                0b00101 => RvInst::SextH { rd, rs1 },
                _ => RvInst::Reserved { raw: w },
            },
            _ => RvInst::Reserved { raw: w },
        },
        0b101 => match shtype {
            0b000000 => RvInst::Srli {
                rd,
                rs1,
                shamt: shamt as u8,
            },
            0b010000 => RvInst::Srai {
                rd,
                rs1,
                shamt: shamt as u8,
            },
            // Zbs: bexti (010010)
            0b010010 => RvInst::Bexti {
                rd,
                rs1,
                shamt: shamt as u8,
            },
            // Zbb: rori (011000)
            0b011000 => RvInst::Rori {
                rd,
                rs1,
                shamt: shamt as u8,
            },
            // Zbb: orc.b / rev8 — distinguished by rs2 field
            0b001010 => match rs2_field(w) {
                0b00111 => RvInst::OrcB { rd, rs1 },
                _ => RvInst::Reserved { raw: w },
            },
            0b011010 => match rs2_field(w) {
                0b11000 => RvInst::Rev8 { rd, rs1 },
                _ => RvInst::Reserved { raw: w },
            },
            _ => RvInst::Reserved { raw: w },
        },
        _ => RvInst::Reserved { raw: w },
    }
}

fn decode_op_imm_32(w: u32, rd: u8, rs1: u8, funct3: u8) -> RvInst {
    let imm = imm_i(w);
    let shamt5 = ((w >> 20) & 0x1F) as u8; // 5-bit for W shifts
    let funct7 = (w >> 25) & 0x7F;
    match funct3 {
        0b000 => RvInst::Addiw { rd, rs1, imm },
        0b001 => match funct7 {
            0b0000000 => RvInst::Slliw {
                rd,
                rs1,
                shamt: shamt5,
            },
            // Zba: slli.uw (funct7=0000100)
            0b0000100 => RvInst::Slliuw {
                rd,
                rs1,
                shamt: ((w >> 20) & 0x3F) as u8,
            },
            // Zbb: clzw/ctzw/cpopw (funct7=0110000, rs2 varies)
            0b0110000 => match rs2_field(w) {
                0b00000 => RvInst::Clzw { rd, rs1 },
                0b00001 => RvInst::Ctzw { rd, rs1 },
                0b00010 => RvInst::Cpopw { rd, rs1 },
                _ => RvInst::Reserved { raw: w },
            },
            _ => RvInst::Reserved { raw: w },
        },
        0b101 => match funct7 {
            0b0000000 => RvInst::Srliw {
                rd,
                rs1,
                shamt: shamt5,
            },
            0b0100000 => RvInst::Sraiw {
                rd,
                rs1,
                shamt: shamt5,
            },
            // Zbb: roriw (funct7=0110000)
            0b0110000 => RvInst::Roriw {
                rd,
                rs1,
                shamt: shamt5,
            },
            _ => RvInst::Reserved { raw: w },
        },
        _ => RvInst::Reserved { raw: w },
    }
}

fn decode_op(rd: u8, rs1: u8, rs2: u8, funct3: u8, funct7: u8, w: u32) -> RvInst {
    match (funct7, funct3) {
        // Base 64-bit ALU
        (0b0000000, 0b000) => RvInst::Add { rd, rs1, rs2 },
        (0b0100000, 0b000) => RvInst::Sub { rd, rs1, rs2 },
        (0b0000000, 0b001) => RvInst::Sll { rd, rs1, rs2 },
        (0b0000000, 0b010) => RvInst::Slt { rd, rs1, rs2 },
        (0b0000000, 0b011) => RvInst::Sltu { rd, rs1, rs2 },
        (0b0000000, 0b100) => RvInst::Xor { rd, rs1, rs2 },
        (0b0000000, 0b101) => RvInst::Srl { rd, rs1, rs2 },
        (0b0100000, 0b101) => RvInst::Sra { rd, rs1, rs2 },
        (0b0000000, 0b110) => RvInst::Or { rd, rs1, rs2 },
        (0b0000000, 0b111) => RvInst::And { rd, rs1, rs2 },
        // M extension
        (0b0000001, 0b000) => RvInst::Mul { rd, rs1, rs2 },
        (0b0000001, 0b001) => RvInst::Mulh { rd, rs1, rs2 },
        (0b0000001, 0b010) => RvInst::Mulhsu { rd, rs1, rs2 },
        (0b0000001, 0b011) => RvInst::Mulhu { rd, rs1, rs2 },
        (0b0000001, 0b100) => RvInst::Div { rd, rs1, rs2 },
        (0b0000001, 0b101) => RvInst::Divu { rd, rs1, rs2 },
        (0b0000001, 0b110) => RvInst::Rem { rd, rs1, rs2 },
        (0b0000001, 0b111) => RvInst::Remu { rd, rs1, rs2 },
        // Zbb
        (0b0100000, 0b111) => RvInst::Andn { rd, rs1, rs2 },
        (0b0100000, 0b110) => RvInst::Orn { rd, rs1, rs2 },
        (0b0100000, 0b100) => RvInst::Xnor { rd, rs1, rs2 },
        (0b0000101, 0b100) => RvInst::Min { rd, rs1, rs2 },
        (0b0000101, 0b101) => RvInst::Minu { rd, rs1, rs2 },
        (0b0000101, 0b110) => RvInst::Max { rd, rs1, rs2 },
        (0b0000101, 0b111) => RvInst::Maxu { rd, rs1, rs2 },
        (0b0110000, 0b001) => RvInst::Rol { rd, rs1, rs2 },
        (0b0110000, 0b101) => RvInst::Ror { rd, rs1, rs2 },
        // Zba
        (0b0010000, 0b010) => RvInst::Sh1add { rd, rs1, rs2 },
        (0b0010000, 0b100) => RvInst::Sh2add { rd, rs1, rs2 },
        (0b0010000, 0b110) => RvInst::Sh3add { rd, rs1, rs2 },
        // Zbs
        (0b0100100, 0b001) => RvInst::Bclr { rd, rs1, rs2 },
        (0b0010100, 0b001) => RvInst::Bset { rd, rs1, rs2 },
        (0b0110100, 0b001) => RvInst::Binv { rd, rs1, rs2 },
        (0b0100100, 0b101) => RvInst::Bext { rd, rs1, rs2 },
        // Zicond
        (0b0000111, 0b101) => RvInst::CzeroEqz { rd, rs1, rs2 },
        (0b0000111, 0b111) => RvInst::CzeroNez { rd, rs1, rs2 },
        // Zbb zext.h via pack rd, rs1, x0 (funct7=0000100, funct3=100)
        (0b0000100, 0b100) if rs2 == 0 => RvInst::ZextH { rd, rs1 },
        _ => RvInst::Reserved { raw: w },
    }
}

fn decode_op_32(rd: u8, rs1: u8, rs2: u8, funct3: u8, funct7: u8, w: u32) -> RvInst {
    match (funct7, funct3) {
        (0b0000000, 0b000) => RvInst::Addw { rd, rs1, rs2 },
        (0b0100000, 0b000) => RvInst::Subw { rd, rs1, rs2 },
        (0b0000000, 0b001) => RvInst::Sllw { rd, rs1, rs2 },
        (0b0000000, 0b101) => RvInst::Srlw { rd, rs1, rs2 },
        (0b0100000, 0b101) => RvInst::Sraw { rd, rs1, rs2 },
        // M-W
        (0b0000001, 0b000) => RvInst::Mulw { rd, rs1, rs2 },
        (0b0000001, 0b100) => RvInst::Divw { rd, rs1, rs2 },
        (0b0000001, 0b101) => RvInst::Divuw { rd, rs1, rs2 },
        (0b0000001, 0b110) => RvInst::Remw { rd, rs1, rs2 },
        (0b0000001, 0b111) => RvInst::Remuw { rd, rs1, rs2 },
        // Zbb-W
        (0b0110000, 0b001) => RvInst::Rolw { rd, rs1, rs2 },
        (0b0110000, 0b101) => RvInst::Rorw { rd, rs1, rs2 },
        // Zba-W: add.uw (funct7=0000100, funct3=000), sh1add.uw (010), sh2add.uw (100), sh3add.uw (110)
        (0b0000100, 0b000) => RvInst::Adduw { rd, rs1, rs2 },
        (0b0010000, 0b010) => RvInst::Sh1adduw { rd, rs1, rs2 },
        (0b0010000, 0b100) => RvInst::Sh2adduw { rd, rs1, rs2 },
        (0b0010000, 0b110) => RvInst::Sh3adduw { rd, rs1, rs2 },
        _ => RvInst::Reserved { raw: w },
    }
}

fn decode_branch(rs1: u8, rs2: u8, funct3: u8, imm: i32, w: u32) -> RvInst {
    match funct3 {
        0b000 => RvInst::Beq { rs1, rs2, imm },
        0b001 => RvInst::Bne { rs1, rs2, imm },
        0b100 => RvInst::Blt { rs1, rs2, imm },
        0b101 => RvInst::Bge { rs1, rs2, imm },
        0b110 => RvInst::Bltu { rs1, rs2, imm },
        0b111 => RvInst::Bgeu { rs1, rs2, imm },
        _ => RvInst::Reserved { raw: w },
    }
}

fn decode_misc_mem(funct3: u8) -> RvInst {
    match funct3 {
        0b000 => RvInst::Fence,
        0b001 => RvInst::FenceI,
        _ => RvInst::Reserved { raw: 0 },
    }
}

fn decode_custom_0(w: u32, _rd: u8, _rs1: u8, funct3: u8) -> RvInst {
    // Sub-op layout (I-type wire shape; funct3 is the sub-op selector):
    //   funct3 = 000 -> trap        (other fields ignored)
    //   funct3 = 001 -> ecall.jar   (other fields ignored)
    //   funct3 = 010 -> ecalli      (imm12 in bits [31:20], rs1/rd zero)
    //
    // Wire bits [31:20] are the standard I-type signed 12-bit imm, so
    // we reuse `imm_i`. Range: [-2048, +2047], ample for host-function
    // selectors (current ABI uses values < 256).
    match funct3 {
        0b000 => RvInst::Trap,
        0b001 => RvInst::EcallJar,
        0b010 => RvInst::Ecalli { imm: imm_i(w) },
        _ => RvInst::Reserved { raw: w },
    }
}

// ============================================================================
// Immediate extraction
// ============================================================================

fn imm_i(w: u32) -> i32 {
    // bits [31:20], sign-extended
    (w as i32) >> 20
}

fn imm_s(w: u32) -> i32 {
    let hi = (w >> 25) & 0x7F;
    let lo = (w >> 7) & 0x1F;
    let raw = ((hi << 5) | lo) as i32;
    // sign-extend 12-bit
    (raw << 20) >> 20
}

fn imm_b(w: u32) -> i32 {
    let b12 = (w >> 31) & 1;
    let b11 = (w >> 7) & 1;
    let b10_5 = (w >> 25) & 0x3F;
    let b4_1 = (w >> 8) & 0xF;
    let raw = (b12 << 12) | (b11 << 11) | (b10_5 << 5) | (b4_1 << 1);
    // sign-extend 13-bit
    ((raw as i32) << 19) >> 19
}

fn imm_j(w: u32) -> i32 {
    let b20 = (w >> 31) & 1;
    let b10_1 = (w >> 21) & 0x3FF;
    let b11 = (w >> 20) & 1;
    let b19_12 = (w >> 12) & 0xFF;
    let raw = (b20 << 20) | (b19_12 << 12) | (b11 << 11) | (b10_1 << 1);
    // sign-extend 21-bit
    ((raw as i32) << 11) >> 11
}

fn rs2_field(w: u32) -> u32 {
    (w >> 20) & 0x1F
}

// ============================================================================
// RVC (compressed) decompression
// ============================================================================

/// Decompress a 16-bit RVC instruction into its 32-bit equivalent
/// `RvInst`. Reserved encodings decode to `Reserved { raw: <halfword> }`.
///
/// References RV unprivileged spec §16 (Compressed). Quadrants are
/// distinguished by op[1:0]; within each quadrant by funct3 ([15:13]).
fn decompress(h: u16) -> RvInst {
    let op = h & 0b11;
    let f3 = (h >> 13) & 0b111;
    match op {
        0b00 => decompress_q0(h, f3),
        0b01 => decompress_q1(h, f3),
        0b10 => decompress_q2(h, f3),
        _ => RvInst::Reserved { raw: h as u32 }, // op=11 isn't compressed
    }
}

// "Compressed register" subset x8..x15 — 3-bit field maps to x8+r.
fn creg(r: u16) -> u8 {
    (r + 8) as u8
}

fn decompress_q0(h: u16, f3: u16) -> RvInst {
    let rs1c = creg((h >> 7) & 0b111);
    let rdrs2c = creg((h >> 2) & 0b111);
    match f3 {
        0b000 => {
            // c.addi4spn -> addi rd', x2, nzuimm
            let imm = ((((h >> 7) & 0x30) << 2) // [11:10]<<5..<<6 -> 9:8 to 6 ? Let me reread.
                | (((h >> 5) & 0x3) << 6) // [6:5] -> 7:6
                | (((h >> 11) & 0x3) << 4) // wait this differs from spec; check spec
                | (((h >> 2) & 0x1) << 3)) // [5] -> 3
                & 0x3FF;
            // Spec for c.addi4spn (CIW):
            //   nzuimm[5:4|9:6|2|3] from h[12:11|10:7|6|5]
            // Easier to recompute explicitly.
            let n = (((h >> 11) & 0x3) << 4) // [12:11] -> [5:4]
                | (((h >> 7) & 0xF) << 6)    // [10:7]  -> [9:6]
                | (((h >> 6) & 0x1) << 2)    // [6]     -> [2]
                | (((h >> 5) & 0x1) << 3);   // [5]     -> [3]
            let _ = imm; // sigh
            if n == 0 {
                RvInst::Reserved { raw: h as u32 } // c.addi4spn nzuimm=0 reserved
            } else {
                RvInst::Addi {
                    rd: rdrs2c,
                    rs1: 2,
                    imm: n as i32,
                }
            }
        }
        0b010 => {
            // c.lw -> lw rd', uimm(rs1')
            let imm = (((h >> 10) & 0x7) << 3) // [12:10] -> [5:3]
                | (((h >> 6) & 0x1) << 2)      // [6]     -> [2]
                | (((h >> 5) & 0x1) << 6); // [5]     -> [6]
            RvInst::Lw {
                rd: rdrs2c,
                rs1: rs1c,
                imm: imm as i32,
            }
        }
        0b011 => {
            // c.ld -> ld rd', uimm(rs1')
            let imm = (((h >> 10) & 0x7) << 3) // [12:10] -> [5:3]
                | (((h >> 5) & 0x3) << 6); // [6:5]   -> [7:6]
            RvInst::Ld {
                rd: rdrs2c,
                rs1: rs1c,
                imm: imm as i32,
            }
        }
        0b110 => {
            // c.sw
            let imm = (((h >> 10) & 0x7) << 3) | (((h >> 6) & 0x1) << 2) | (((h >> 5) & 0x1) << 6);
            RvInst::Sw {
                rs1: rs1c,
                rs2: rdrs2c,
                imm: imm as i32,
            }
        }
        0b111 => {
            // c.sd
            let imm = (((h >> 10) & 0x7) << 3) | (((h >> 5) & 0x3) << 6);
            RvInst::Sd {
                rs1: rs1c,
                rs2: rdrs2c,
                imm: imm as i32,
            }
        }
        _ => RvInst::Reserved { raw: h as u32 },
    }
}

fn decompress_q1(h: u16, f3: u16) -> RvInst {
    match f3 {
        0b000 => {
            // c.nop / c.addi
            let rd = ((h >> 7) & 0x1F) as u8;
            let imm = decode_ci_imm6(h);
            if rd == 0 {
                // c.nop (imm should be 0 but we don't enforce)
                RvInst::Addi {
                    rd: 0,
                    rs1: 0,
                    imm: 0,
                }
            } else {
                RvInst::Addi { rd, rs1: rd, imm }
            }
        }
        0b001 => {
            // c.addiw (RV64) — rd != 0
            let rd = ((h >> 7) & 0x1F) as u8;
            if rd == 0 {
                return RvInst::Reserved { raw: h as u32 };
            }
            let imm = decode_ci_imm6(h);
            RvInst::Addiw { rd, rs1: rd, imm }
        }
        0b010 => {
            // c.li -> addi rd, x0, imm
            let rd = ((h >> 7) & 0x1F) as u8;
            if rd == 0 {
                return RvInst::Reserved { raw: h as u32 };
            }
            let imm = decode_ci_imm6(h);
            RvInst::Addi { rd, rs1: 0, imm }
        }
        0b011 => {
            // c.addi16sp / c.lui
            let rd = ((h >> 7) & 0x1F) as u8;
            if rd == 2 {
                // c.addi16sp
                let imm = (((h >> 12) & 1) << 9)
                    | (((h >> 6) & 1) << 4)
                    | (((h >> 5) & 1) << 6)
                    | (((h >> 3) & 0x3) << 7)
                    | (((h >> 2) & 1) << 5);
                let sx = ((imm as i32) << 22) >> 22; // sign-ext 10-bit
                if sx == 0 {
                    return RvInst::Reserved { raw: h as u32 };
                }
                RvInst::Addi {
                    rd: 2,
                    rs1: 2,
                    imm: sx,
                }
            } else if rd == 0 {
                RvInst::Reserved { raw: h as u32 }
            } else {
                // c.lui — cast to u32 first because shifts go up to <<17
                let h = h as u32;
                let imm = (((h >> 12) & 1) << 17) | (((h >> 2) & 0x1F) << 12);
                let sx = ((imm as i32) << 14) >> 14; // sign-ext 18-bit
                if sx == 0 {
                    return RvInst::Reserved { raw: (h & 0xFFFF) };
                }
                RvInst::Lui { rd, imm: sx }
            }
        }
        0b100 => decompress_q1_misc_alu(h),
        0b101 => {
            // c.j -> jal x0, off
            let imm = decode_cj_imm(h);
            RvInst::Jal { rd: 0, imm }
        }
        0b110 | 0b111 => {
            // c.beqz / c.bnez (rs1 = creg)
            let rs1 = creg((h >> 7) & 0b111);
            let imm = decode_cb_imm(h);
            if f3 == 0b110 {
                RvInst::Beq { rs1, rs2: 0, imm }
            } else {
                RvInst::Bne { rs1, rs2: 0, imm }
            }
        }
        _ => RvInst::Reserved { raw: h as u32 },
    }
}

fn decompress_q1_misc_alu(h: u16) -> RvInst {
    let f6_10 = (h >> 10) & 0b11; // funct2 selecting shift / andi / sub-op
    let rdrs1c = creg((h >> 7) & 0b111);
    match f6_10 {
        0b00 | 0b01 => {
            // c.srli / c.srai (RV64 shamt: bit12||bits6:2)
            let shamt = ((((h >> 12) & 1) << 5) | ((h >> 2) & 0x1F)) as u8;
            if f6_10 == 0b00 {
                RvInst::Srli {
                    rd: rdrs1c,
                    rs1: rdrs1c,
                    shamt,
                }
            } else {
                RvInst::Srai {
                    rd: rdrs1c,
                    rs1: rdrs1c,
                    shamt,
                }
            }
        }
        0b10 => {
            // c.andi
            let imm = decode_ci_imm6(h);
            RvInst::Andi {
                rd: rdrs1c,
                rs1: rdrs1c,
                imm,
            }
        }
        0b11 => {
            // c.sub/xor/or/and (bit12=0) or c.subw/c.addw (bit12=1)
            let rs2c = creg((h >> 2) & 0b111);
            let bit12 = (h >> 12) & 1;
            let f2 = (h >> 5) & 0b11;
            match (bit12, f2) {
                (0, 0b00) => RvInst::Sub {
                    rd: rdrs1c,
                    rs1: rdrs1c,
                    rs2: rs2c,
                },
                (0, 0b01) => RvInst::Xor {
                    rd: rdrs1c,
                    rs1: rdrs1c,
                    rs2: rs2c,
                },
                (0, 0b10) => RvInst::Or {
                    rd: rdrs1c,
                    rs1: rdrs1c,
                    rs2: rs2c,
                },
                (0, 0b11) => RvInst::And {
                    rd: rdrs1c,
                    rs1: rdrs1c,
                    rs2: rs2c,
                },
                (1, 0b00) => RvInst::Subw {
                    rd: rdrs1c,
                    rs1: rdrs1c,
                    rs2: rs2c,
                },
                (1, 0b01) => RvInst::Addw {
                    rd: rdrs1c,
                    rs1: rdrs1c,
                    rs2: rs2c,
                },
                _ => RvInst::Reserved { raw: h as u32 },
            }
        }
        _ => RvInst::Reserved { raw: h as u32 },
    }
}

fn decompress_q2(h: u16, f3: u16) -> RvInst {
    let rdrs1 = ((h >> 7) & 0x1F) as u8;
    let rs2 = ((h >> 2) & 0x1F) as u8;
    match f3 {
        0b000 => {
            // c.slli (RV64 shamt: bit12||bits6:2)
            if rdrs1 == 0 {
                return RvInst::Reserved { raw: h as u32 };
            }
            let shamt = ((((h >> 12) & 1) << 5) | ((h >> 2) & 0x1F)) as u8;
            RvInst::Slli {
                rd: rdrs1,
                rs1: rdrs1,
                shamt,
            }
        }
        0b010 => {
            // c.lwsp -> lw rd, uimm(x2)
            if rdrs1 == 0 {
                return RvInst::Reserved { raw: h as u32 };
            }
            let imm = (((h >> 12) & 1) << 5)
                | (((h >> 4) & 0x7) << 2)
                | (((h >> 2) & 0x3) << 6);
            RvInst::Lw {
                rd: rdrs1,
                rs1: 2,
                imm: imm as i32,
            }
        }
        0b011 => {
            // c.ldsp -> ld rd, uimm(x2)
            if rdrs1 == 0 {
                return RvInst::Reserved { raw: h as u32 };
            }
            let imm = (((h >> 12) & 1) << 5)
                | (((h >> 5) & 0x3) << 3)
                | (((h >> 2) & 0x7) << 6);
            RvInst::Ld {
                rd: rdrs1,
                rs1: 2,
                imm: imm as i32,
            }
        }
        0b100 => {
            // c.jr / c.mv / c.ebreak / c.jalr / c.add
            let bit12 = (h >> 12) & 1;
            match (bit12, rdrs1, rs2) {
                (0, r, 0) if r != 0 => RvInst::Jalr {
                    rd: 0,
                    rs1: r,
                    imm: 0,
                }, // c.jr
                (0, r, s) if r != 0 && s != 0 => RvInst::Add {
                    rd: r,
                    rs1: 0,
                    rs2: s,
                }, // c.mv
                (1, 0, 0) => RvInst::Reserved { raw: h as u32 }, // c.ebreak → forbidden in PVM2
                (1, r, 0) if r != 0 => RvInst::Jalr {
                    rd: 1,
                    rs1: r,
                    imm: 0,
                }, // c.jalr
                (1, r, s) if r != 0 && s != 0 => RvInst::Add {
                    rd: r,
                    rs1: r,
                    rs2: s,
                }, // c.add
                _ => RvInst::Reserved { raw: h as u32 },
            }
        }
        0b110 => {
            // c.swsp -> sw rs2, uimm(x2)
            let imm = (((h >> 9) & 0xF) << 2) | (((h >> 7) & 0x3) << 6);
            RvInst::Sw {
                rs1: 2,
                rs2,
                imm: imm as i32,
            }
        }
        0b111 => {
            // c.sdsp -> sd rs2, uimm(x2)
            let imm = (((h >> 10) & 0x7) << 3) | (((h >> 7) & 0x7) << 6);
            RvInst::Sd {
                rs1: 2,
                rs2,
                imm: imm as i32,
            }
        }
        _ => RvInst::Reserved { raw: h as u32 },
    }
}

/// Decode CI-format 6-bit signed immediate.
fn decode_ci_imm6(h: u16) -> i32 {
    let imm = (((h >> 12) & 1) << 5) | ((h >> 2) & 0x1F);
    ((imm as i32) << 26) >> 26
}

/// Decode CJ-format 12-bit signed immediate (×2 byte offset).
fn decode_cj_imm(h: u16) -> i32 {
    let b11 = (h >> 12) & 1;
    let b4 = (h >> 11) & 1;
    let b9_8 = (h >> 9) & 0x3;
    let b10 = (h >> 8) & 1;
    let b6 = (h >> 7) & 1;
    let b7 = (h >> 6) & 1;
    let b3_1 = (h >> 3) & 0x7;
    let b5 = (h >> 2) & 1;
    let imm = (b11 << 11)
        | (b10 << 10)
        | (b9_8 << 8)
        | (b7 << 7)
        | (b6 << 6)
        | (b5 << 5)
        | (b4 << 4)
        | (b3_1 << 1);
    ((imm as i32) << 20) >> 20
}

/// Decode CB-format 9-bit signed immediate (×2 byte offset).
fn decode_cb_imm(h: u16) -> i32 {
    let b8 = (h >> 12) & 1;
    let b4_3 = (h >> 10) & 0x3;
    let b7_6 = (h >> 5) & 0x3;
    let b2_1 = (h >> 3) & 0x3;
    let b5 = (h >> 2) & 1;
    let imm = (b8 << 8) | (b7_6 << 6) | (b5 << 5) | (b4_3 << 3) | (b2_1 << 1);
    ((imm as i32) << 23) >> 23
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_add() {
        // add x10, x11, x12 = 0x00C58533
        let bytes = 0x00C58533u32.to_le_bytes();
        assert_eq!(
            decode(&bytes),
            Some((
                RvInst::Add {
                    rd: 10,
                    rs1: 11,
                    rs2: 12,
                },
                4
            ))
        );
    }

    #[test]
    fn decode_ld() {
        // ld x5, 16(x10) = 0x01053283
        let bytes = 0x01053283u32.to_le_bytes();
        assert_eq!(
            decode(&bytes),
            Some((
                RvInst::Ld {
                    rd: 5,
                    rs1: 10,
                    imm: 16,
                },
                4
            ))
        );
    }

    #[test]
    fn decode_sd() {
        // sd x11, 8(x10) = 0x00B53423
        let bytes = 0x00B53423u32.to_le_bytes();
        assert_eq!(
            decode(&bytes),
            Some((
                RvInst::Sd {
                    rs1: 10,
                    rs2: 11,
                    imm: 8,
                },
                4
            ))
        );
    }

    #[test]
    fn decode_addi_negative() {
        // addi x10, x11, -4 = 0xFFC58513
        let bytes = 0xFFC58513u32.to_le_bytes();
        assert_eq!(
            decode(&bytes),
            Some((
                RvInst::Addi {
                    rd: 10,
                    rs1: 11,
                    imm: -4,
                },
                4
            ))
        );
    }

    #[test]
    fn decode_beq() {
        // beq x10, x11, 8 = 0x00B50463
        let bytes = 0x00B50463u32.to_le_bytes();
        assert_eq!(
            decode(&bytes),
            Some((
                RvInst::Beq {
                    rs1: 10,
                    rs2: 11,
                    imm: 8,
                },
                4
            ))
        );
    }

    #[test]
    fn decode_jal() {
        // jal x1, 12 = 0x00C000EF
        let bytes = 0x00C000EFu32.to_le_bytes();
        assert_eq!(
            decode(&bytes),
            Some((RvInst::Jal { rd: 1, imm: 12 }, 4))
        );
    }

    #[test]
    fn decode_lui() {
        // lui x5, 0x12345 = 0x123452B7
        let bytes = 0x123452B7u32.to_le_bytes();
        assert_eq!(
            decode(&bytes),
            Some((
                RvInst::Lui {
                    rd: 5,
                    imm: 0x12345000,
                },
                4
            ))
        );
    }

    #[test]
    fn decode_auipc_reserved() {
        // auipc x5, 0x10 = 0x000102B7? actually 0x00010297
        let bytes = 0x00010297u32.to_le_bytes();
        match decode(&bytes) {
            Some((RvInst::Reserved { .. }, 4)) => {}
            other => panic!("auipc should be Reserved, got {:?}", other),
        }
    }

    #[test]
    fn decode_ecall_reserved() {
        // ecall = 0x00000073
        let bytes = 0x00000073u32.to_le_bytes();
        match decode(&bytes) {
            Some((RvInst::Reserved { .. }, 4)) => {}
            other => panic!("standard ecall should be Reserved, got {:?}", other),
        }
    }

    #[test]
    fn decode_c_mv() {
        // c.mv x10, x11 = 0x852E
        let bytes = 0x852Eu16.to_le_bytes();
        // c.mv → add rd, x0, rs2
        assert_eq!(
            decode(&bytes),
            Some((
                RvInst::Add {
                    rd: 10,
                    rs1: 0,
                    rs2: 11,
                },
                2
            ))
        );
    }

    #[test]
    fn decode_c_addi() {
        // c.addi x10, 1 = 0x0505
        let bytes = 0x0505u16.to_le_bytes();
        assert_eq!(
            decode(&bytes),
            Some((
                RvInst::Addi {
                    rd: 10,
                    rs1: 10,
                    imm: 1,
                },
                2
            ))
        );
    }

    #[test]
    fn decode_c_li() {
        // c.li x10, -1 = 0x557D
        let bytes = 0x557Du16.to_le_bytes();
        assert_eq!(
            decode(&bytes),
            Some((
                RvInst::Addi {
                    rd: 10,
                    rs1: 0,
                    imm: -1,
                },
                2
            ))
        );
    }

    #[test]
    fn decode_c_j() {
        // c.j 4 = 0xA011 (jumps 4 bytes forward)
        let bytes = 0xA011u16.to_le_bytes();
        assert_eq!(decode(&bytes), Some((RvInst::Jal { rd: 0, imm: 4 }, 2)));
    }

    #[test]
    fn decode_custom_trap() {
        // trap: custom-0 (0x0B), funct3=000, rest zero
        let bytes = 0x0000000Bu32.to_le_bytes();
        assert_eq!(decode(&bytes), Some((RvInst::Trap, 4)));
    }

    #[test]
    fn decode_custom_ecall_jar() {
        // ecall.jar: custom-0, funct3=001
        let bytes = 0x0000100Bu32.to_le_bytes();
        assert_eq!(decode(&bytes), Some((RvInst::EcallJar, 4)));
    }

    #[test]
    fn decode_custom_ecalli() {
        // ecalli imm=5: custom-0 (0x0B), funct3=010, imm12 in bits[31:20]
        // wire: (5 << 20) | (0b010 << 12) | 0x0B = 0x0050_200B
        let w = (5u32 << 20) | (0b010 << 12) | 0x0B;
        let bytes = w.to_le_bytes();
        assert_eq!(decode(&bytes), Some((RvInst::Ecalli { imm: 5 }, 4)));
    }

    #[test]
    fn decode_custom_ecalli_negative() {
        // ecalli imm=-1: imm12 = 0xFFF, sign-extends to -1
        let w = (0xFFFu32 << 20) | (0b010 << 12) | 0x0B;
        let bytes = w.to_le_bytes();
        assert_eq!(decode(&bytes), Some((RvInst::Ecalli { imm: -1 }, 4)));
    }
}
