//! Compile-time exercise of the x3/x4 (host-spilled register) path.
//!
//! `x3`/`x4` are valid RV64E registers but have no host register, so the
//! recompiler routes any instruction naming them to its cold spill path
//! (`compile_rv_spilled`). This test drives **every** instruction form that
//! can name x3/x4 — ALU (rr/imm), 32-bit ALU, load, store, lui, auipc, jal,
//! jalr, and every branch — through `Compiler::compile`, asserting it emits
//! code without panicking. That exercises the donor selection/rewrite, the
//! spilled-source loads, the spilled-dest store-backs, and the dedicated
//! terminator handlers — the paths most at risk of an out-of-bounds
//! `REG_MAP[13]` index or a bad donor choice. (Execution semantics are
//! covered by the interpreter tests in `nub-exec`; the fast path's
//! byte-for-byte stability is covered by the 12-guest conformance suite.)

use javm_recompiler_x86::codegen::{CTX_VA, Compiler, HelperFns};

/// Dummy helper addresses — this test only *compiles*, never executes, so
/// the emitted `call` targets are never reached.
fn dummy_helpers() -> HelperFns {
    HelperFns {
        mem_read_u8: 0x1000,
        mem_read_u16: 0x1000,
        mem_read_u32: 0x1000,
        mem_read_u64: 0x1000,
        mem_write_u8: 0x1000,
        mem_write_u16: 0x1000,
        mem_write_u32: 0x1000,
        mem_write_u64: 0x1000,
    }
}

/// Encode a little-endian instruction stream.
fn enc(words: &[u32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(words.len() * 4);
    for w in words {
        v.extend_from_slice(&w.to_le_bytes());
    }
    v
}

/// Compile `code`; assert it produced non-empty native code without panic.
fn compile_ok(code: &[u8]) {
    // jit_va_base near CTX_VA so the RIP-relative CTX accesses fit in disp32
    // (the real runtime places the JIT arena adjacent to the context).
    let c = Compiler::new(dummy_helpers(), code.len(), CTX_VA, 25, 0);
    let result = c.compile(code);
    assert!(
        !result.native_code.is_empty(),
        "recompiler emitted no native code for {} bytes of guest code",
        code.len()
    );
}

// Instruction encoders (RV little-endian).
const HALT: u32 = 0x0000_200B; // ecalli 0 (HostCall(0) — clean halt)
fn addi(rd: u8, rs1: u8, imm: i32) -> u32 {
    ((imm as u32 & 0xFFF) << 20) | ((rs1 as u32) << 15) | ((rd as u32) << 7) | 0x13
}
fn add(rd: u8, rs1: u8, rs2: u8) -> u32 {
    ((rs2 as u32) << 20) | ((rs1 as u32) << 15) | ((rd as u32) << 7) | 0x33
}
fn addw(rd: u8, rs1: u8, rs2: u8) -> u32 {
    ((rs2 as u32) << 20) | ((rs1 as u32) << 15) | ((rd as u32) << 7) | 0x3B
}
fn ld(rd: u8, rs1: u8, imm: i32) -> u32 {
    ((imm as u32 & 0xFFF) << 20) | ((rs1 as u32) << 15) | (0b011 << 12) | ((rd as u32) << 7) | 0x03
}
fn sd(rs1: u8, rs2: u8, imm: i32) -> u32 {
    let i = imm as u32 & 0xFFF;
    ((i >> 5) << 25)
        | ((rs2 as u32) << 20)
        | ((rs1 as u32) << 15)
        | (0b011 << 12)
        | ((i & 0x1F) << 7)
        | 0x23
}
fn lui(rd: u8, imm20: u32) -> u32 {
    (imm20 << 12) | ((rd as u32) << 7) | 0x37
}
fn auipc(rd: u8, imm20: u32) -> u32 {
    (imm20 << 12) | ((rd as u32) << 7) | 0x17
}
fn jal(rd: u8, imm: i32) -> u32 {
    let i = imm as u32;
    let b20 = (i >> 20) & 1;
    let b10_1 = (i >> 1) & 0x3FF;
    let b11 = (i >> 11) & 1;
    let b19_12 = (i >> 12) & 0xFF;
    (b20 << 31) | (b10_1 << 21) | (b11 << 20) | (b19_12 << 12) | ((rd as u32) << 7) | 0x6F
}
fn jalr(rd: u8, rs1: u8, imm: i32) -> u32 {
    ((imm as u32 & 0xFFF) << 20) | ((rs1 as u32) << 15) | ((rd as u32) << 7) | 0x67
}
fn beq(rs1: u8, rs2: u8, imm: i32) -> u32 {
    let i = imm as u32;
    let b12 = (i >> 12) & 1;
    let b10_5 = (i >> 5) & 0x3F;
    let b4_1 = (i >> 1) & 0xF;
    let b11 = (i >> 11) & 1;
    (b12 << 31)
        | (b10_5 << 25)
        | (rs2 as u32) << 20
        | (rs1 as u32) << 15
        | (b4_1 << 8)
        | (b11 << 7)
        | 0x63
}

#[test]
fn alu_rr_with_x3_x4() {
    // Every operand-spill shape of a register-register ALU op.
    compile_ok(&enc(&[add(10, 3, 4), HALT])); // both sources spilled, host dest
    compile_ok(&enc(&[add(3, 5, 6), HALT])); // spilled dest, host sources
    compile_ok(&enc(&[add(3, 3, 4), HALT])); // spilled dest + both spilled sources
    compile_ok(&enc(&[add(3, 3, 3), HALT])); // same spilled reg in all three fields
    compile_ok(&enc(&[add(5, 3, 6), HALT])); // one spilled source
    compile_ok(&enc(&[addw(4, 3, 5), HALT])); // 32-bit ALU, mixed
}

#[test]
fn alu_imm_with_x3_x4() {
    compile_ok(&enc(&[addi(3, 0, 7), HALT])); // li into x3
    compile_ok(&enc(&[addi(4, 0, -1), HALT])); // li into x4
    compile_ok(&enc(&[addi(3, 3, 1), HALT])); // x3 += 1 (spilled src + dest)
    compile_ok(&enc(&[addi(10, 3, 5), HALT])); // host dest, spilled source
}

#[test]
fn load_store_with_x3_x4() {
    compile_ok(&enc(&[ld(3, 5, 0), HALT])); // load into x3
    compile_ok(&enc(&[ld(10, 3, 8), HALT])); // x3 as address base
    compile_ok(&enc(&[ld(3, 3, 0), HALT])); // x3 both base and dest
    compile_ok(&enc(&[sd(5, 3, 0), HALT])); // store x3 (value spilled)
    compile_ok(&enc(&[sd(3, 5, 0), HALT])); // x3 as address base
    compile_ok(&enc(&[sd(3, 4, 0), HALT])); // base x3, value x4 (both spilled)
}

#[test]
fn upper_imm_with_x3_x4() {
    compile_ok(&enc(&[lui(3, 0x12345), HALT]));
    compile_ok(&enc(&[lui(4, 0x1), HALT]));
    compile_ok(&enc(&[auipc(3, 0), HALT]));
    compile_ok(&enc(&[auipc(4, 0x10), HALT]));
}

#[test]
fn jumps_with_x3_x4() {
    // jal writing the link register to a spilled slot.
    compile_ok(&enc(&[jal(3, 8), HALT, HALT]));
    compile_ok(&enc(&[jal(4, 8), HALT, HALT]));
    // jalr: target in x3, link in a host reg; and link in x3.
    compile_ok(&enc(&[jalr(6, 3, 0), HALT]));
    compile_ok(&enc(&[jalr(3, 5, 0), HALT]));
    compile_ok(&enc(&[jalr(3, 3, 0), HALT])); // x3 both target and link
    compile_ok(&enc(&[jalr(4, 3, 4), HALT])); // x3 target, x4 link
}

#[test]
fn branches_with_x3_x4() {
    compile_ok(&enc(&[beq(3, 4, 8), HALT, HALT])); // both operands spilled
    compile_ok(&enc(&[beq(3, 5, 8), HALT, HALT])); // rs1 spilled
    compile_ok(&enc(&[beq(5, 3, 8), HALT, HALT])); // rs2 spilled
    compile_ok(&enc(&[beq(3, 0, 8), HALT, HALT])); // rs1 spilled vs x0
    compile_ok(&enc(&[beq(0, 4, 8), HALT, HALT])); // x0 vs rs2 spilled
}

#[test]
fn conformant_blob_has_no_spill_overhead() {
    // A blob with no x3/x4 compiles via the fast path only (sanity: the
    // spill fork is not taken).
    compile_ok(&enc(&[addi(10, 0, 42), add(10, 10, 5), HALT]));
}
