//! Recompiler granular bug-pattern tests, routed through the nub
//! kernel JIT path via the cache-based RPC. These are the translated
//! descendants of the `tests::test_recompile_*` block that used to
//! live in `javm-recompiler-x86/src/lib.rs` against the now-removed
//! host `RecompiledPvm` / `FlatMemory` surface.
//!
//! Translation rules:
//! - Each program runs through `Nub::publish_instance` + `invoke_cached`.
//!   The host sees `InvocationResult::{exit_reason, exit_arg,
//!   return_value, gas_remaining}` — `return_value` is φ[7] at exit.
//! - To observe φ[k] for k != 7, append `move φ[7] ← φ[k]`
//!   (MoveReg/TwoReg, opcode 100, 2 bytes) before the halting
//!   instruction (`ecalli 0` or `trap`).
//! - Exit reasons come straight from
//!   `nub-arch-x86-abi::InvocationResult.exit_reason`, matching the
//!   `EXIT_*` constants in `javm-recompiler-x86::codegen` (1=Panic,
//!   2=OOG, 4=HostCall, 7=Trap).
//!
//! Each `tests/*.rs` integration test is its own test binary, so
//! the singleton `Nub` thread_local is private to this file.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use javm_cap::image::{EndpointDef, Image};
use nub::Nub;
use std::cell::RefCell;
use std::collections::BTreeMap;

thread_local! {
    static NUB: RefCell<Option<Nub>> = const { RefCell::new(None) };
}

const EXIT_OOG: u32 = 2;
const EXIT_HOSTCALL: u32 = 4;
const EXIT_TRAP: u32 = 7;

#[derive(Default)]
struct ProgSpec {
    code: Vec<u8>,
    bitmask: Vec<u8>,
    registers: [u64; 13],
    gas: u64,
    mem_size: u32,
    rw_start: u32,
    rw_data: Vec<u8>,
}

struct RunResult {
    exit_reason: u32,
    exit_arg: u32,
    return_value: u64,
}

fn run(ps: ProgSpec) -> RunResult {
    // Build a minimal Image whose endpoint 0 enters at PC=0.
    let mut img = Image::empty();
    img.code = ps.code;
    img.packed_bitmask = ps.bitmask;
    let mut endpoints: BTreeMap<u8, EndpointDef> = BTreeMap::new();
    endpoints.insert(
        0,
        EndpointDef {
            entry_pc: 0,
            arg_registers: 0,
            arg_cnode_size: 0,
            initial_regs: BTreeMap::new(),
        },
    );
    img.endpoints = endpoints;

    let mem_size = ps.mem_size.max(4096);
    let overlay_vec: Vec<(u32, &[u8])> = if ps.rw_data.is_empty() {
        Vec::new()
    } else {
        vec![(ps.rw_start, ps.rw_data.as_slice())]
    };

    NUB.with(|cell| {
        let mut borrow = cell.borrow_mut();
        if borrow.is_none() {
            *borrow = Some(Nub::new_hyperlight().expect("Hyperlight sandbox"));
        }
        let nub = borrow.as_mut().expect("nub initialised above");
        let image_h = nub.publish_image(&img).expect("publish_image");
        let cnode_h = nub.publish_cnode(0, &[]).expect("publish_cnode");
        let instance_h = nub
            .publish_instance(
                [0u8; 32],
                image_h,
                cnode_h,
                &overlay_vec,
                mem_size,
                ps.registers,
                0,
                0,
            )
            .expect("publish_instance");
        let r = nub
            .invoke_cached(instance_h, 0, [0; 4], ps.gas)
            .expect("invoke_cached");
        RunResult {
            exit_reason: r.exit_reason,
            exit_arg: r.exit_arg,
            return_value: r.return_value,
        }
    })
}

/// Append `move φ[7] ← φ[k]` (MoveReg/TwoReg, opcode 100, 2 bytes)
/// so the host can observe φ[k] via `result.return_value`.
fn observe_reg(code: &mut Vec<u8>, bitmask: &mut Vec<u8>, k: u8) {
    code.push(100);
    code.push((k << 4) | 7);
    bitmask.push(1);
    bitmask.push(0);
}

fn ecalli_zero(code: &mut Vec<u8>, bitmask: &mut Vec<u8>) {
    code.push(10);
    code.push(0);
    bitmask.push(1);
    bitmask.push(0);
}

fn trap(code: &mut Vec<u8>, bitmask: &mut Vec<u8>) {
    code.push(0);
    bitmask.push(1);
}

// === Direct ports of the host tests ===

#[test]
fn recompile_trap() {
    let r = run(ProgSpec {
        code: vec![0u8],
        bitmask: vec![1u8],
        gas: 1000,
        ..Default::default()
    });
    assert_eq!(r.exit_reason, EXIT_TRAP);
}

#[test]
fn recompile_ecalli() {
    let r = run(ProgSpec {
        code: vec![10, 42],
        bitmask: vec![1, 0],
        gas: 1000,
        ..Default::default()
    });
    assert_eq!(r.exit_reason, EXIT_HOSTCALL);
    assert_eq!(r.exit_arg, 42);
}

#[test]
fn recompile_load_imm() {
    // load_imm φ[0], 123; move φ[7] ← φ[0]; trap
    let mut code = vec![51u8, 0, 123];
    let mut bitmask = vec![1u8, 0, 0];
    observe_reg(&mut code, &mut bitmask, 0);
    trap(&mut code, &mut bitmask);
    let r = run(ProgSpec {
        code,
        bitmask,
        gas: 1000,
        ..Default::default()
    });
    assert_eq!(r.exit_reason, EXIT_TRAP);
    assert_eq!(r.return_value, 123);
}

#[test]
fn recompile_add64() {
    let mut code = vec![
        51, 0, 10, // load_imm φ[0], 10
        51, 1, 20, // load_imm φ[1], 20
        200, 0x10, 2, // add64 φ[2] = φ[0] + φ[1]
    ];
    let mut bitmask = vec![1u8, 0, 0, 1, 0, 0, 1, 0, 0];
    observe_reg(&mut code, &mut bitmask, 2);
    ecalli_zero(&mut code, &mut bitmask);
    let r = run(ProgSpec {
        code,
        bitmask,
        gas: 1000,
        ..Default::default()
    });
    assert_eq!(r.exit_reason, EXIT_HOSTCALL);
    assert_eq!(r.exit_arg, 0);
    assert_eq!(r.return_value, 30);
}

#[test]
fn recompile_out_of_gas() {
    let r = run(ProgSpec {
        code: vec![51, 0, 42],
        bitmask: vec![1, 0, 0],
        gas: 0,
        ..Default::default()
    });
    assert_eq!(r.exit_reason, EXIT_OOG);
}

// --- Carry-flag fusion: same bytecode observed at φ[2] and φ[3] ---

fn run_carry_flag_program(observe: u8, regs: [u64; 13]) -> RunResult {
    // r2 = r0 + r1
    // r3 = (r2 < r1) ? 1 : 0  (carry detection via SetLtU)
    let mut code = vec![
        200, 0x01, 2, // add64: rd=2, ra=0, rb=1
        216, 0x12, 3, // setLtU: rd=3, ra=2, rb=1
    ];
    let mut bitmask = vec![1u8, 0, 0, 1, 0, 0];
    observe_reg(&mut code, &mut bitmask, observe);
    ecalli_zero(&mut code, &mut bitmask);
    run(ProgSpec {
        code,
        bitmask,
        registers: regs,
        gas: 10000,
        ..Default::default()
    })
}

#[test]
fn carry_flag_fusion_overflow_r2() {
    let mut regs = [0u64; 13];
    regs[0] = u64::MAX;
    regs[1] = 1;
    let r = run_carry_flag_program(2, regs);
    assert_eq!(r.exit_reason, EXIT_HOSTCALL);
    assert_eq!(r.return_value, 0); // u64::MAX + 1 = 0
}

#[test]
fn carry_flag_fusion_overflow_r3() {
    let mut regs = [0u64; 13];
    regs[0] = u64::MAX;
    regs[1] = 1;
    let r = run_carry_flag_program(3, regs);
    assert_eq!(r.exit_reason, EXIT_HOSTCALL);
    assert_eq!(r.return_value, 1); // overflow → carry = 1
}

#[test]
fn carry_flag_fusion_no_overflow_r2() {
    let mut regs = [0u64; 13];
    regs[0] = 5;
    regs[1] = 3;
    let r = run_carry_flag_program(2, regs);
    assert_eq!(r.exit_reason, EXIT_HOSTCALL);
    assert_eq!(r.return_value, 8); // 5 + 3 = 8
}

#[test]
fn carry_flag_fusion_no_overflow_r3() {
    let mut regs = [0u64; 13];
    regs[0] = 5;
    regs[1] = 3;
    let r = run_carry_flag_program(3, regs);
    assert_eq!(r.exit_reason, EXIT_HOSTCALL);
    assert_eq!(r.return_value, 0); // no overflow → carry = 0
}

// --- ShloLImm64 variants ---

#[test]
fn recompile_shlo_l_imm_64() {
    // ShloLImm64 (opcode 151): φ[rd] = φ[rb] << imm
    let mut code = vec![
        51, 0, 5, // load_imm φ[0], 5
        151, 0x00, 3, 0, 0, 0, // shlo_l_imm_64 φ[0] = φ[0] << 3  (= 40)
    ];
    let mut bitmask = vec![1u8, 0, 0, 1, 0, 0, 0, 0, 0];
    observe_reg(&mut code, &mut bitmask, 0);
    ecalli_zero(&mut code, &mut bitmask);
    let r = run(ProgSpec {
        code,
        bitmask,
        gas: 10000,
        ..Default::default()
    });
    assert_eq!(r.exit_reason, EXIT_HOSTCALL);
    assert_eq!(r.return_value, 40);
}

fn shlo_l_imm_64_different_regs_program(observe: u8) -> RunResult {
    // rd=2 (T0), rb=0 (RA): [151, 2|(0<<4), 1, 0, 0, 0]
    let mut code = vec![
        51, 0, 10, // load_imm φ[0], 10
        151, 0x02, 1, 0, 0, 0, // shlo_l_imm_64 φ[2] = φ[0] << 1  (= 20)
    ];
    let mut bitmask = vec![1u8, 0, 0, 1, 0, 0, 0, 0, 0];
    observe_reg(&mut code, &mut bitmask, observe);
    ecalli_zero(&mut code, &mut bitmask);
    run(ProgSpec {
        code,
        bitmask,
        gas: 10000,
        ..Default::default()
    })
}

#[test]
fn recompile_shlo_l_imm_64_different_regs_r0() {
    // Source unchanged: φ[0] still 10.
    let r = shlo_l_imm_64_different_regs_program(0);
    assert_eq!(r.exit_reason, EXIT_HOSTCALL);
    assert_eq!(r.return_value, 10);
}

#[test]
fn recompile_shlo_l_imm_64_different_regs_r2() {
    let r = shlo_l_imm_64_different_regs_program(2);
    assert_eq!(r.exit_reason, EXIT_HOSTCALL);
    assert_eq!(r.return_value, 20); // 10 << 1
}

fn shlo_l_imm_64_as_address_program(observe: u8) -> RunResult {
    // Test shift result used as memory address (the bench bug scenario).
    let mut regs = [0u64; 13];
    regs[1] = 0xDEAD;
    let mut code = vec![
        51, 0, 4, // load_imm φ[0], 4 (base index)
        151, 0x00, 2, 0, 0, 0, // shlo_l_imm_64 φ[0] = φ[0] << 2  (= 16)
        // store_ind_u32 [φ[0] + 0] ← φ[1] (value 0xDEAD)
        122, 0x01, 0, 0, 0, 0, // load_ind_u32 φ[2] = [φ[0] + 0]
        128, 0x02, 0, 0, 0, 0,
    ];
    let mut bitmask = vec![
        1u8, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
    ];
    observe_reg(&mut code, &mut bitmask, observe);
    ecalli_zero(&mut code, &mut bitmask);
    run(ProgSpec {
        code,
        bitmask,
        registers: regs,
        gas: 10000,
        mem_size: 4096,
        rw_start: 0,
        rw_data: vec![0u8; 256],
    })
}

#[test]
fn recompile_shlo_l_imm_64_as_address_r0() {
    let r = shlo_l_imm_64_as_address_program(0);
    assert_eq!(r.exit_reason, EXIT_HOSTCALL);
    assert_eq!(r.return_value, 16); // 4 << 2
}

#[test]
fn recompile_shlo_l_imm_64_as_address_r2() {
    let r = shlo_l_imm_64_as_address_program(2);
    assert_eq!(r.exit_reason, EXIT_HOSTCALL);
    assert_eq!(r.return_value, 0xDEAD); // loaded back the stored value
}

fn shlo_l_imm_64_then_add_program(observe: u8) -> RunResult {
    // Shift then add — verifies the shift result persists across basic blocks.
    let mut code = vec![
        51, 0, 4, // load_imm φ[0], 4
        151, 0x00, 2, 0, 0, 0, // shlo_l_imm_64 φ[0] = φ[0] << 2  (= 16)
        149, 0x02, 1, 0, 0, 0, // add_imm_64 φ[2] = φ[0] + 1  (= 17)
    ];
    let mut bitmask = vec![1u8, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0];
    observe_reg(&mut code, &mut bitmask, observe);
    ecalli_zero(&mut code, &mut bitmask);
    run(ProgSpec {
        code,
        bitmask,
        gas: 10000,
        ..Default::default()
    })
}

#[test]
fn recompile_shlo_l_imm_64_then_add_r0() {
    let r = shlo_l_imm_64_then_add_program(0);
    assert_eq!(r.exit_reason, EXIT_HOSTCALL);
    assert_eq!(r.return_value, 16); // 4 << 2
}

#[test]
fn recompile_shlo_l_imm_64_then_add_r2() {
    let r = shlo_l_imm_64_then_add_program(2);
    assert_eq!(r.exit_reason, EXIT_HOSTCALL);
    assert_eq!(r.return_value, 17); // 16 + 1
}

// --- Helpers: ThreeReg / TwoReg with LoadImm64 setup ---

fn run_three_reg_op(opcode: u8, a: u64, b: u64) -> u64 {
    let mut code = vec![
        20,
        0, // LoadImm64 φ[0], <8 bytes>
        a as u8,
        (a >> 8) as u8,
        (a >> 16) as u8,
        (a >> 24) as u8,
        (a >> 32) as u8,
        (a >> 40) as u8,
        (a >> 48) as u8,
        (a >> 56) as u8,
        20,
        1, // LoadImm64 φ[1]
        b as u8,
        (b >> 8) as u8,
        (b >> 16) as u8,
        (b >> 24) as u8,
        (b >> 32) as u8,
        (b >> 40) as u8,
        (b >> 48) as u8,
        (b >> 56) as u8,
        opcode,
        0x10,
        2, // ThreeReg: ra=0, rb=1, rd=2
    ];
    let mut bitmask = vec![
        1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0,
    ];
    observe_reg(&mut code, &mut bitmask, 2);
    ecalli_zero(&mut code, &mut bitmask);
    let r = run(ProgSpec {
        code,
        bitmask,
        gas: 100_000,
        ..Default::default()
    });
    assert_eq!(r.exit_reason, EXIT_HOSTCALL);
    r.return_value
}

fn run_two_reg_op(opcode: u8, input: u64) -> u64 {
    let mut code = vec![
        20,
        0, // LoadImm64 φ[0], <8 bytes>
        input as u8,
        (input >> 8) as u8,
        (input >> 16) as u8,
        (input >> 24) as u8,
        (input >> 32) as u8,
        (input >> 40) as u8,
        (input >> 48) as u8,
        (input >> 56) as u8,
        opcode,
        0x01, // TwoReg: rd=1, ra=0
    ];
    let mut bitmask = vec![1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0];
    observe_reg(&mut code, &mut bitmask, 1);
    ecalli_zero(&mut code, &mut bitmask);
    let r = run(ProgSpec {
        code,
        bitmask,
        gas: 10000,
        ..Default::default()
    });
    assert_eq!(r.exit_reason, EXIT_HOSTCALL);
    r.return_value
}

// === Division / multiplication tests ===

#[test]
fn recompile_div_u64() {
    assert_eq!(run_three_reg_op(203, 100, 7), 14);
    assert_eq!(run_three_reg_op(203, 42, 0), u64::MAX);
    assert_eq!(run_three_reg_op(203, 0, 5), 0);
    assert_eq!(run_three_reg_op(203, u64::MAX, 2), u64::MAX / 2);
}

#[test]
fn recompile_div_s64() {
    assert_eq!(run_three_reg_op(204, 100, 7), 14);
    let neg100 = (-100i64) as u64;
    let neg14 = (-14i64) as u64;
    assert_eq!(run_three_reg_op(204, neg100, 7), neg14);
    assert_eq!(run_three_reg_op(204, 42, 0), u64::MAX);
}

#[test]
fn recompile_rem_u64() {
    assert_eq!(run_three_reg_op(205, 100, 7), 2);
    assert_eq!(run_three_reg_op(205, 42, 0), 42);
    assert_eq!(run_three_reg_op(205, 0, 5), 0);
}

#[test]
fn recompile_rem_s64() {
    assert_eq!(run_three_reg_op(206, 100, 7), 2);
    let neg100 = (-100i64) as u64;
    let neg2 = (-2i64) as u64;
    assert_eq!(run_three_reg_op(206, neg100, 7), neg2);
    assert_eq!(run_three_reg_op(206, 42, 0), 42);
}

#[test]
fn recompile_mul64() {
    assert_eq!(run_three_reg_op(202, 6, 7), 42);
    assert_eq!(run_three_reg_op(202, 0, 1000), 0);
    assert_eq!(run_three_reg_op(202, u64::MAX, 2), u64::MAX.wrapping_mul(2));
}

#[test]
fn recompile_mul_upper_uu() {
    assert_eq!(run_three_reg_op(214, 1u64 << 63, 2), 1);
    assert_eq!(run_three_reg_op(214, 100, 200), 0);
    assert_eq!(run_three_reg_op(214, u64::MAX, u64::MAX), u64::MAX - 1);
}

#[test]
fn recompile_mul_upper_ss() {
    assert_eq!(run_three_reg_op(213, u64::MAX, u64::MAX), 0);
    assert_eq!(run_three_reg_op(213, u64::MAX, 1), u64::MAX);
    assert_eq!(run_three_reg_op(213, 100, 200), 0);
}

// === 32-bit ops (sign-extending result to 64-bit) ===

#[test]
fn recompile_add32() {
    assert_eq!(run_three_reg_op(190, 0x7FFFFFFF, 1), 0xFFFFFFFF80000000u64);
    assert_eq!(run_three_reg_op(190, 5, 3), 8);
}

#[test]
fn recompile_sub32() {
    assert_eq!(run_three_reg_op(191, 0, 1), 0xFFFFFFFFFFFFFFFFu64);
    assert_eq!(run_three_reg_op(191, 10, 3), 7);
}

#[test]
fn recompile_mul32() {
    assert_eq!(run_three_reg_op(192, 6, 7), 42);
    assert_eq!(run_three_reg_op(192, 0x10000, 0x10000), 0);
    assert_eq!(run_three_reg_op(192, 0xFFFF, 0xFFFF), 0xFFFFFFFFFFFE0001u64);
}

// === Sign-extension TwoReg ops ===

#[test]
fn recompile_sign_extend_8() {
    assert_eq!(run_two_reg_op(108, 0x7F), 0x7F);
    assert_eq!(run_two_reg_op(108, 0x80), 0xFFFFFFFFFFFFFF80u64);
    assert_eq!(run_two_reg_op(108, 0xFF), 0xFFFFFFFFFFFFFFFFu64);
    assert_eq!(run_two_reg_op(108, 0x100), 0);
}

#[test]
fn recompile_sign_extend_16() {
    assert_eq!(run_two_reg_op(109, 0x7FFF), 0x7FFF);
    assert_eq!(run_two_reg_op(109, 0x8000), 0xFFFFFFFFFFFF8000u64);
    assert_eq!(run_two_reg_op(109, 0xFFFF), 0xFFFFFFFFFFFFFFFFu64);
}
