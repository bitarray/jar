//! Interpreter ↔ recompiler execution differential for the host-spilled
//! registers `x3`/`x4`.
//!
//! The jar toolchain never emits x3/x4, so no normal guest exercises them.
//! This test hand-assembles small RV64E programs that *do*, builds a raw
//! Image, and runs each one through both engines:
//!
//! - **Interpreter** (`Nub::local`) — executes x3/x4 as ordinary slot
//!   13/14 GPRs.
//! - **Recompiler** (in-kernel Hyperlight JIT) — routes them to the cold
//!   spill path (donor re-dispatch for ALU, dedicated branch handler).
//!
//! It asserts both agree **bit-for-bit** on the return value (`φ[7]` = x10)
//! and gas — the consensus property. This is the only test that validates
//! the *executed* result of the spilled emit (the compile-time structural
//! coverage lives in `javm-recompiler-x86/tests/x3_x4_spill.rs`).
//!
//! `javm-bench` (and its `BuiltCaps` / `run_*` harness) is gated to
//! linux/x86_64, so this whole test is too. The interpreter's x3/x4
//! semantics are additionally covered cross-platform by the unit test in
//! `nub-exec` (`x3_x4_execute_as_real_registers`).
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use javm_bench::{BuiltCaps, run_interpreter};
use javm_cap::Key;
use javm_cap::image::{EndpointDef, Image};
use std::collections::BTreeMap;

const HALT: u32 = 0x0000_200B; // ecalli 0 — HostCall(0); return_value = φ[7] (x10)

fn addi(rd: u8, rs1: u8, imm: i32) -> u32 {
    ((imm as u32 & 0xFFF) << 20) | ((rs1 as u32) << 15) | ((rd as u32) << 7) | 0x13
}
fn add(rd: u8, rs1: u8, rs2: u8) -> u32 {
    ((rs2 as u32) << 20) | ((rs1 as u32) << 15) | ((rd as u32) << 7) | 0x33
}
fn sub(rd: u8, rs1: u8, rs2: u8) -> u32 {
    (0x20 << 25) | ((rs2 as u32) << 20) | ((rs1 as u32) << 15) | ((rd as u32) << 7) | 0x33
}
fn beq(rs1: u8, rs2: u8, imm: i32) -> u32 {
    let i = imm as u32;
    ((i >> 12) & 1) << 31
        | ((i >> 5) & 0x3F) << 25
        | (rs2 as u32) << 20
        | (rs1 as u32) << 15
        | ((i >> 1) & 0xF) << 8
        | ((i >> 11) & 1) << 7
        | 0x63
}

fn enc(words: &[u32]) -> Vec<u8> {
    let mut v = Vec::new();
    for w in words {
        v.extend_from_slice(&w.to_le_bytes());
    }
    v
}

fn image(code: Vec<u8>) -> Image {
    let mut img = Image::with_code(code);
    img.endpoints.insert(
        Key::from(0u8),
        EndpointDef {
            entry_pc: 0,
            arg_registers: 0,
            arg_cnode_size: 0,
            initial_regs: BTreeMap::new(),
        },
    );
    img
}

/// Run `code` through the interpreter; assert the return value. On
/// linux/x86_64 also run the in-kernel recompiler and assert both engines
/// agree bit-for-bit on return value and gas.
fn diff(code: Vec<u8>, expected_return: u64) {
    let built = BuiltCaps::for_image(&image(code), 0);
    let (i_ret, _i_gas) = run_interpreter(&built);
    assert_eq!(i_ret, expected_return, "interpreter return value");

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let (r_ret, r_gas) = javm_bench::run_recompiler(&built);
        assert_eq!(i_ret, r_ret, "interp vs recomp return value");
        assert_eq!(_i_gas, r_gas, "interp vs recomp gas");
    }
}

#[test]
fn x3_x4_alu_and_branch_match() {
    // The Hyperlight sandbox is a process singleton; keep all recompiler
    // invocations in one test fn so they serialise on its lock.

    // Donor ALU: add x10, x3, x4 (both sources spilled, host dest).
    diff(
        enc(&[addi(3, 0, 100), addi(4, 0, 23), add(10, 3, 4), HALT]),
        123,
    );

    // Spilled destination, then read it back: x3 = x3 + x4; x10 = x3.
    diff(
        enc(&[
            addi(3, 0, 40),
            addi(4, 0, 2),
            add(3, 3, 4),  // spilled dest + both spilled sources
            add(10, 3, 0), // host dest ← spilled source (mv)
            HALT,
        ]),
        42,
    );

    // sub with spilled operands: x10 = x3 - x4 = 70 - 28.
    diff(
        enc(&[addi(3, 0, 70), addi(4, 0, 28), sub(10, 3, 4), HALT]),
        42,
    );

    // Spilled register reused in all three fields: x3 = x3 + x3 = 21*2.
    diff(
        enc(&[addi(3, 0, 21), add(3, 3, 3), add(10, 3, 0), HALT]),
        42,
    );

    // Branch on spilled operands — taken path (x3 == x4).
    //   0: addi x3,x0,5   1: addi x4,x0,5   2: beq x3,x4,+12 (→ pc 5)
    //   3: addi x10,x0,99 4: HALT           5: addi x10,x0,42  6: HALT
    diff(
        enc(&[
            addi(3, 0, 5),
            addi(4, 0, 5),
            beq(3, 4, 12),
            addi(10, 0, 99),
            HALT,
            addi(10, 0, 42),
            HALT,
        ]),
        42,
    );

    // Branch on spilled operands — not-taken path (x3 != x4).
    diff(
        enc(&[
            addi(3, 0, 5),
            addi(4, 0, 6),
            beq(3, 4, 12),
            addi(10, 0, 42),
            HALT,
            addi(10, 0, 99),
            HALT,
        ]),
        42,
    );

    // Branch with one spilled operand vs a host register.
    diff(
        enc(&[
            addi(3, 0, 8),
            addi(5, 0, 8),
            beq(3, 5, 12),
            addi(10, 0, 99),
            HALT,
            addi(10, 0, 42),
            HALT,
        ]),
        42,
    );
}
