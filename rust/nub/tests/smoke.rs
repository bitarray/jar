//! End-to-end smoke for both `Nub` backends. Each builds a trivial
//! `InvocationSpec` (PVM `ecalli 42`), ships it via `invoke_spec`,
//! and verifies the result agrees on `exit_reason=4` (HostCall) +
//! `exit_arg=42` (the ecalli imm).
//!
//! - **Hyperlight**: exercises host SCALE-encode → Hyperlight call →
//!   guest decode/JIT → ring-3 entry → ring-0 reentry → encode.
//! - **Local**: exercises the in-process byte-PVM interpreter wired
//!   through `nub_arch_local::run_invocation_spec`.

use nub::{InvocationSpec, Nub, PvmRegs};

fn ecalli_42_spec() -> InvocationSpec {
    InvocationSpec {
        code: vec![10u8, 42],
        bitmask: vec![1u8, 0],
        jump_table: vec![],
        entry_pc: 0,
        initial_gas: 1_000,
        initial_regs: PvmRegs::zeros(),
        mem_size: 0,
        arg_start: 0,
        arg_data: vec![],
        ro_start: 0,
        ro_data: vec![],
        rw_start: 0,
        rw_data: vec![],
    }
}

#[test]
fn hyperlight_invoke_spec_ecalli() {
    let spec = ecalli_42_spec();
    let mut hl = Nub::new_hyperlight().expect("hyperlight sandbox should open");
    let result = hl.invoke_spec(&spec).expect("invoke_spec");
    assert_eq!(result.exit_reason, 4, "expected HostCall exit");
    assert_eq!(result.exit_arg, 42, "expected ecalli imm");
}

#[test]
fn local_invoke_spec_ecalli() {
    let spec = ecalli_42_spec();
    let mut nub = Nub::new_local();
    let result = nub.invoke_spec(&spec).expect("invoke_spec");
    assert_eq!(result.exit_reason, 4, "expected HostCall exit");
    assert_eq!(result.exit_arg, 42, "expected ecalli imm");
}
