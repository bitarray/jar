//! Smoke tests: exercise both `Nub` backends end-to-end. The original
//! stub path (`invoke`) returns 42 on both backends — wiring check.
//! `invoke_spec` actually ships a PVM program into the guest and
//! verifies it runs to completion.

use nub::{InstanceRef, InvocationSpec, InvokeOptions, Nub, PvmRegs};

#[test]
fn local_invoke_returns_42() {
    let mut nub = Nub::new_local();
    let outcome = nub
        .invoke(
            InstanceRef::from_hash([0; 32]),
            0,
            &[],
            InvokeOptions::default(),
        )
        .unwrap();
    assert_eq!(outcome.return_value, 42);
}

#[test]
fn hyperlight_invoke_returns_42() {
    let mut nub = Nub::new_hyperlight().expect("hyperlight sandbox should open");
    let outcome = nub
        .invoke(
            InstanceRef::from_hash([0; 32]),
            0,
            &[],
            InvokeOptions::default(),
        )
        .unwrap();
    assert_eq!(outcome.return_value, 42);
}

/// Build a trivial `InvocationSpec` (PVM `ecalli 42`) and run it
/// through the Hyperlight backend. Asserts the in-guest JIT path
/// reports exit_reason=4 (HostCall) + exit_arg=42 (the ecalli imm).
#[test]
fn hyperlight_invoke_spec_ecalli() {
    let spec = InvocationSpec {
        code: vec![10u8, 42],
        bitmask: vec![1u8, 0],
        jump_table: vec![],
        entry_pc: 0,
        initial_gas: 1_000,
        initial_regs: PvmRegs::zeros(),
    };
    let mut hl = Nub::new_hyperlight().expect("hyperlight sandbox should open");
    let result = hl.invoke_spec(&spec).expect("invoke_spec");
    assert_eq!(result.exit_reason, 4, "expected HostCall exit");
    assert_eq!(result.exit_arg, 42, "expected ecalli imm");
}
