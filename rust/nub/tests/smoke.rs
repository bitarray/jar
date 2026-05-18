//! End-to-end smoke for the `Nub` Hyperlight backend: build a trivial
//! `InvocationSpec` (PVM `ecalli 42`), ship it via `invoke_spec`,
//! verify the in-guest JIT path reports `exit_reason=4` (HostCall) +
//! `exit_arg=42` (the ecalli imm).
//!
//! This exercises the full production stack — host SCALE-encode,
//! Hyperlight call, guest decode, compile, ring-3 JIT, ring-0 reentry,
//! result encode. The skeleton `Nub::invoke` / `LocalArch::invoke`
//! paths (currently both return a hard-coded 42) intentionally have
//! no test coverage: they'll get real tests when Stage 3 wires them up
//! to actual kernel dispatch.

use nub::{InvocationSpec, Nub, PvmRegs};

#[test]
fn hyperlight_invoke_spec_ecalli() {
    let spec = InvocationSpec {
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
    };
    let mut hl = Nub::new_hyperlight().expect("hyperlight sandbox should open");
    let result = hl.invoke_spec(&spec).expect("invoke_spec");
    assert_eq!(result.exit_reason, 4, "expected HostCall exit");
    assert_eq!(result.exit_arg, 42, "expected ecalli imm");
}
