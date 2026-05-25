use javm_exec::decode::{
    compute_basic_block_starts, compute_block_gas_costs, compute_gas_block_starts,
};
use javm_exec::{
    EcallHandler, EcallKind, EcallResult, ExitReason, GasCounter, Interpreter, Mem, Memory,
    PanickingHandler, PvmProgram, REG_COUNT, Regs,
};

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
        fn handle(&mut self, kind: EcallKind, _r: &mut Regs, _m: &mut dyn Memory) -> EcallResult {
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
// Conformance tests: cherry-picked from v2 `javm/src/interpreter/mod.rs::tests`.
// Each test ports a v2 single-step test by extending its program with a
// trailing trap so the v3 `run()` exit reason is `Trap` and final
// register state can be observed afterward.
// ====================================================================

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
    let (r, _, _) = run_with_regs(vec![1u8; 100], vec![1u8; 100], [0; REG_COUNT], 5);
    assert_eq!(r, ExitReason::OutOfGas);
}

#[test]
fn empty_program_panics() {
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
    let code = vec![51, 0x00, 42, 0, 0, 0, 0];
    let bitmask = vec![1, 0, 0, 0, 0, 0, 1];
    let (r, regs, _) = run_with_regs(code, bitmask, [0; REG_COUNT], 100);
    assert_eq!(r, ExitReason::Trap);
    assert_eq!(regs.gpr[0], 42);
}

#[test]
fn add_imm_64_two_reg_one_imm() {
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
    let code = vec![101, 0x00];
    let bitmask = vec![1, 0];
    let (r, _, _) = run_with_regs(code, bitmask, [0; REG_COUNT], 100);
    assert_eq!(r, ExitReason::Panic);
}

#[test]
fn page_fault_on_unmapped_load() {
    let code = vec![52, 0x00, 0x00, 0x10, 0x00, 0x00, 0];
    let bitmask = vec![1, 0, 0, 0, 0, 0, 1];
    let (r, _, _) = run_with_regs(code, bitmask, [0; REG_COUNT], 100);
    assert_eq!(r, ExitReason::PageFault(0x1000));
}

/// Branch-target / gas-block boundary: v2 issue #155 regression.
/// Verifies that branch targets are valid basic-block landing sites but
/// do NOT introduce new gas-block starts.
#[test]
fn gas_blocks_exclude_branch_targets() {
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
