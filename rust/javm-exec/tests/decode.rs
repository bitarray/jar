use javm_exec::decode::{compute_gas_block_starts, predecode};
use javm_exec::{DecodedInst, Opcode, PvmProgram};

#[test]
fn decoded_inst_is_40_bytes() {
    assert_eq!(core::mem::size_of::<DecodedInst>(), 40);
}

#[test]
fn predecode_empty_program() {
    let prog = PvmProgram::new(vec![], vec![], vec![], 25).unwrap();
    let p = predecode(&prog);
    // Just the sentinel.
    assert_eq!(p.decoded_insts.len(), 1);
    assert_eq!(p.decoded_insts[0].opcode, Opcode::Trap);
}

#[test]
fn predecode_single_trap() {
    // Opcode 0 (Trap), 1-byte instruction.
    let prog = PvmProgram::new(vec![0u8], vec![1u8], vec![], 25).unwrap();
    let p = predecode(&prog);
    // One real + one sentinel.
    assert_eq!(p.decoded_insts.len(), 2);
    assert_eq!(p.decoded_insts[0].opcode, Opcode::Trap);
    assert_eq!(p.decoded_insts[1].opcode, Opcode::Trap);
    // PC 0 is a basic-block start (and gas-block start).
    assert!(p.basic_block_starts[0]);
    assert!(p.block_gas_costs[0] >= 1);
}

#[test]
fn predecode_pc_to_idx() {
    // Two 1-byte traps.
    let prog = PvmProgram::new(vec![0u8, 0], vec![1u8, 1], vec![], 25).unwrap();
    let p = predecode(&prog);
    assert_eq!(p.pc_to_idx[0], 0);
    assert_eq!(p.pc_to_idx[1], 1);
}

#[test]
fn gas_block_starts_excludes_non_terminators() {
    // Three 1-byte traps: only PC=0 is a "block start" technically;
    // but post-terminator PCs are also gas-block starts. Trap is a
    // terminator (per Opcode::is_terminator), so the byte after each
    // trap that has bitmask=1 is also a gas-block start.
    let prog = PvmProgram::new(vec![0u8, 0, 0], vec![1u8, 1, 1], vec![], 25).unwrap();
    let starts = compute_gas_block_starts(&prog.code, &prog.bitmask);
    assert!(starts[0]);
    assert!(starts[1]); // post-Trap
    assert!(starts[2]); // post-Trap
}
