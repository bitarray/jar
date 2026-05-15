//! PVM bytecode predecoding.
//!
//! Cherry-picked from v2 `javm/src/interpreter/mod.rs` (the predecode
//! pass — basic-block / gas-block detection, per-block gas costs,
//! flattened `DecodedInst` array, `pc_to_idx` map). No cap awareness.
//!
//! Entry point: [`predecode`] takes a [`PvmProgram`] and returns a
//! [`Predecoded`] bundle that the interpreter (and recompiler) execute
//! against. The expensive one-time work (gas-block computation,
//! per-instruction predecoding, target resolution) is done here so the
//! hot loop in `interp` is branch-light.

use crate::args::{self, Args};
use crate::instruction::Opcode;
use crate::program::PvmProgram;

/// Pre-decoded instruction for the fast interpreter / JIT path.
///
/// Flattened representation: all operands stored directly (no enum
/// discrimination at runtime). 40 bytes.
#[derive(Clone, Copy, Debug)]
pub struct DecodedInst {
    pub opcode: Opcode,
    /// Register A (first register operand, context-dependent).
    pub ra: u8,
    /// Register B (second register operand, context-dependent).
    pub rb: u8,
    /// Register D (destination register, context-dependent).
    pub rd: u8,
    /// First immediate / offset value.
    pub imm1: u64,
    /// Second immediate / offset value.
    pub imm2: u64,
    /// Byte offset of this instruction in the code.
    pub pc: u32,
    /// Byte offset of the next sequential instruction.
    pub next_pc: u32,
    /// Pre-resolved instruction index for the next sequential instruction.
    pub next_idx: u32,
    /// Pre-resolved instruction index for the branch/jump target.
    /// `u32::MAX` = invalid (out-of-program target).
    pub target_idx: u32,
    /// Gas cost to charge at gas-block entry (0 for non-gas-block-start
    /// instructions). Gas blocks = {PC=0} ∪ {post-terminator PCs};
    /// branch targets are NOT gas-block starts.
    pub bb_gas_cost: u32,
}

const _: () = assert!(core::mem::size_of::<DecodedInst>() == 40);

/// Bundle of predecoded state shared by interp / JIT.
#[derive(Clone, Debug)]
pub struct Predecoded {
    pub decoded_insts: Vec<DecodedInst>,
    /// Map from PC byte offset → instruction index. `u32::MAX` = invalid.
    pub pc_to_idx: Vec<u32>,
    /// Valid basic-block starts (post-terminator PCs ∪ static branch targets).
    pub basic_block_starts: Vec<bool>,
    /// Gas-block start cost (indexed by PC). Only entries at gas-block
    /// starts are meaningful; others are 0.
    pub block_gas_costs: Vec<u32>,
}

/// Predecode a program: compute block starts, gas costs, and flat
/// `DecodedInst` array.
pub fn predecode(program: &PvmProgram) -> Predecoded {
    let basic_block_starts = compute_basic_block_starts(&program.code, &program.bitmask);
    let gas_block_starts = compute_gas_block_starts(&program.code, &program.bitmask);
    let block_gas_costs = compute_block_gas_costs(
        &program.code,
        &program.bitmask,
        &gas_block_starts,
        program.mem_cycles,
    );
    let (decoded_insts, pc_to_idx) = predecode_instructions(
        &program.code,
        &program.bitmask,
        &basic_block_starts,
        &gas_block_starts,
        &block_gas_costs,
    );
    Predecoded {
        decoded_insts,
        pc_to_idx,
        basic_block_starts,
        block_gas_costs,
    }
}

// ---- Basic-block / gas-block start detection ----

pub fn compute_basic_block_starts_with_skips(code: &[u8], bitmask: &[u8]) -> (Vec<bool>, Vec<u8>) {
    compute_bb_starts_inner(code, bitmask)
}

pub fn compute_basic_block_starts(code: &[u8], bitmask: &[u8]) -> Vec<bool> {
    compute_bb_starts_inner(code, bitmask).0
}

/// Compute gas block starts per the JAM spec: `{PC=0} ∪ {post-terminator PCs}`.
///
/// Unlike `compute_basic_block_starts`, this does NOT include branch
/// targets. Gas blocks are defined solely by terminator boundaries.
pub fn compute_gas_block_starts(code: &[u8], bitmask: &[u8]) -> Vec<bool> {
    let len = code.len();
    if len == 0 {
        return vec![];
    }
    let mut starts = vec![false; len];

    if !bitmask.is_empty() && bitmask[0] == 1 && Opcode::from_byte(code[0]).is_some() {
        starts[0] = true;
    }

    let mut i = 0;
    while i < len {
        if i >= bitmask.len() || bitmask[i] != 1 {
            i += 1;
            continue;
        }
        let Some(op) = Opcode::from_byte(code[i]) else {
            i += 1;
            continue;
        };

        let skip = {
            let mut s = 0;
            for j in 0..25 {
                let idx = i + 1 + j;
                let bit = if idx < bitmask.len() { bitmask[idx] } else { 1 };
                if bit == 1 {
                    s = j;
                    break;
                }
            }
            s
        };

        if op.is_terminator() {
            let next = i + 1 + skip;
            if next < len && next < bitmask.len() && bitmask[next] == 1 {
                starts[next] = true;
            }
        }
        i += 1 + skip;
    }

    starts
}

fn compute_bb_starts_inner(code: &[u8], bitmask: &[u8]) -> (Vec<bool>, Vec<u8>) {
    let len = code.len();
    if len == 0 {
        return (vec![], vec![]);
    }
    let mut starts = vec![false; len];
    let mut skip_table = vec![0u8; len];

    if !bitmask.is_empty() && bitmask[0] == 1 && Opcode::from_byte(code[0]).is_some() {
        starts[0] = true;
    }

    let mut i = 0;
    while i < len {
        if i >= bitmask.len() || bitmask[i] != 1 {
            i += 1;
            continue;
        }
        let Some(op) = Opcode::from_byte(code[i]) else {
            i += 1;
            continue;
        };

        let skip = {
            let mut s = 0;
            for j in 0..25 {
                let idx = i + 1 + j;
                let bit = if idx < bitmask.len() { bitmask[idx] } else { 1 };
                if bit == 1 {
                    s = j;
                    break;
                }
            }
            s
        };
        skip_table[i] = skip as u8;

        if op.is_terminator() {
            let next = i + 1 + skip;
            if next < len && next < bitmask.len() && bitmask[next] == 1 {
                starts[next] = true;
            }
        }

        // For static branch / jump targets, mark the target.
        let cat = op.category();
        match cat {
            crate::instruction::InstructionCategory::OneOffset if i + 5 <= len => {
                let off = i32::from_le_bytes([code[i + 1], code[i + 2], code[i + 3], code[i + 4]]);
                let target = (i as i64 + off as i64) as usize;
                if target < len && target < bitmask.len() && bitmask[target] == 1 {
                    starts[target] = true;
                }
            }
            crate::instruction::InstructionCategory::TwoRegOneOffset if i + 6 <= len => {
                let off = i32::from_le_bytes([code[i + 2], code[i + 3], code[i + 4], code[i + 5]]);
                let target = (i as i64 + off as i64) as usize;
                if target < len && target < bitmask.len() && bitmask[target] == 1 {
                    starts[target] = true;
                }
            }
            crate::instruction::InstructionCategory::OneRegImmOffset if i + 2 <= len => {
                let reg_byte = code[i + 1];
                let lx = ((reg_byte as usize / 16) % 8).min(4);
                let ly = if skip > lx + 1 {
                    (skip - lx - 1).min(4)
                } else {
                    0
                };
                let off_start = i + 2 + lx;
                if ly > 0 && off_start + ly <= len {
                    let mut buf = [0u8; 4];
                    buf[..ly].copy_from_slice(&code[off_start..off_start + ly]);
                    if ly < 4 && buf[ly - 1] & 0x80 != 0 {
                        for b in &mut buf[ly..4] {
                            *b = 0xFF;
                        }
                    }
                    let off = i32::from_le_bytes(buf);
                    let target = (i as i64 + off as i64) as usize;
                    if target < len && target < bitmask.len() && bitmask[target] == 1 {
                        starts[target] = true;
                    }
                }
            }
            _ => {}
        }

        i += 1 + skip;
    }

    (starts, skip_table)
}

// ---- Per-block gas costs ----

/// Compute gas cost per basic block using `GasSimulator`. Indexed by PC;
/// only basic-block-start entries are meaningful.
pub fn compute_block_gas_costs(
    code: &[u8],
    bitmask: &[u8],
    basic_block_starts: &[bool],
    mem_cycles: u8,
) -> Vec<u32> {
    use crate::gas_cost::{fast_cost_from_raw, skip_distance};
    use crate::gas_sim::GasSimulator;

    let len = code.len();
    let mut costs = vec![0u32; len];
    let mut sim = GasSimulator::new();
    let mut block_start: usize = 0;
    let mut in_block = false;

    let mut pc = 0;
    while pc < len {
        if !basic_block_starts[pc] && !in_block {
            pc += 1;
            continue;
        }

        if basic_block_starts[pc] {
            if in_block {
                costs[block_start] = sim.flush_and_get_cost();
                sim.reset();
            }
            block_start = pc;
            in_block = true;
        }

        let opcode_byte = code[pc];
        let raw_ra = if pc + 1 < len {
            code[pc + 1] & 0x0F
        } else {
            0xFF
        };
        let raw_rb = if pc + 1 < len {
            (code[pc + 1] >> 4) & 0x0F
        } else {
            0xFF
        };
        let raw_rd = if pc + 2 < len {
            code[pc + 2] & 0x0F
        } else {
            0xFF
        };

        let fc = fast_cost_from_raw(
            opcode_byte,
            raw_ra,
            raw_rb,
            raw_rd,
            pc as u32,
            code,
            bitmask,
            mem_cycles,
        );
        sim.feed(&fc);

        let skip = skip_distance(bitmask, pc);
        pc += 1 + skip;
    }

    if in_block {
        costs[block_start] = sim.flush_and_get_cost();
    }

    costs
}

// ---- Predecode ----

fn flatten_args(args: &Args) -> (u8, u8, u8, u64, u64) {
    match *args {
        Args::None => (0, 0, 0, 0, 0),
        Args::Imm { imm } => (0, 0, 0, imm, 0),
        Args::RegExtImm { ra, imm } => (ra as u8, 0, 0, imm, 0),
        Args::TwoImm { imm_x, imm_y } => (0, 0, 0, imm_x, imm_y),
        Args::Offset { offset } => (0, 0, 0, offset, 0),
        Args::RegImm { ra, imm } => (ra as u8, 0, 0, imm, 0),
        Args::RegTwoImm { ra, imm_x, imm_y } => (ra as u8, 0, 0, imm_x, imm_y),
        Args::RegImmOffset { ra, imm, offset } => (ra as u8, 0, 0, imm, offset),
        Args::TwoReg { rd, ra } => (ra as u8, 0, rd as u8, 0, 0),
        Args::TwoRegImm { ra, rb, imm } => (ra as u8, rb as u8, 0, imm, 0),
        Args::TwoRegOffset { ra, rb, offset } => (ra as u8, rb as u8, 0, offset, 0),
        Args::TwoRegTwoImm {
            ra,
            rb,
            imm_x,
            imm_y,
        } => (ra as u8, rb as u8, 0, imm_x, imm_y),
        Args::ThreeReg { ra, rb, rd } => (ra as u8, rb as u8, rd as u8, 0, 0),
    }
}

/// Pre-decode all instructions into a flat array for fast execution.
fn predecode_instructions(
    code: &[u8],
    bitmask: &[u8],
    basic_block_starts: &[bool],
    gas_block_starts: &[bool],
    block_gas_costs: &[u32],
) -> (Vec<DecodedInst>, Vec<u32>) {
    let len = code.len();
    let mut insts = Vec::new();
    let mut pc_to_idx = vec![u32::MAX; len + 1];

    let skip_at = |i: usize| -> usize {
        for j in 0..25 {
            let idx = i + 1 + j;
            let bit = if idx < bitmask.len() { bitmask[idx] } else { 1 };
            if bit == 1 {
                return j;
            }
        }
        24
    };

    let mut pc = 0;
    while pc < len {
        #[allow(clippy::collapsible_if)]
        if pc < bitmask.len() && bitmask[pc] == 1 {
            if let Some(opcode) = Opcode::from_byte(code[pc]) {
                let skip = skip_at(pc);
                let next_pc = (pc + 1 + skip) as u32;
                let category = opcode.category();
                let args = args::decode_args(code, pc, skip, category);
                let bb_gas_cost = if pc < gas_block_starts.len() && gas_block_starts[pc] {
                    block_gas_costs[pc]
                } else {
                    0
                };

                let (ra, rb, rd, imm1, imm2) = flatten_args(&args);

                let idx = insts.len() as u32;
                pc_to_idx[pc] = idx;
                insts.push(DecodedInst {
                    opcode,
                    ra,
                    rb,
                    rd,
                    imm1,
                    imm2,
                    pc: pc as u32,
                    next_pc,
                    next_idx: u32::MAX,
                    target_idx: u32::MAX,
                    bb_gas_cost,
                });

                pc = next_pc as usize;
                continue;
            }
        }
        pc += 1;
    }

    let sentinel_idx = insts.len() as u32;
    // Sentinel trap at end so sequential advance past last insn doesn't OOB.
    insts.push(DecodedInst {
        opcode: Opcode::Trap,
        ra: 0,
        rb: 0,
        rd: 0,
        imm1: 0,
        imm2: 0,
        pc: len as u32,
        next_pc: len as u32 + 1,
        next_idx: sentinel_idx,
        target_idx: u32::MAX,
        bb_gas_cost: 1,
    });

    // Second pass: resolve next_idx and target_idx.
    #[allow(clippy::needless_range_loop)]
    for i in 0..insts.len() {
        let inst = &insts[i];
        let np = inst.next_pc as usize;
        let next_idx = if np < pc_to_idx.len() {
            let ni = pc_to_idx[np];
            if ni != u32::MAX { ni } else { sentinel_idx }
        } else {
            sentinel_idx
        };

        let target_idx = {
            let op = inst.opcode;
            let target_from_imm1 = matches!(
                op,
                Opcode::Jump
                    | Opcode::BranchEq
                    | Opcode::BranchNe
                    | Opcode::BranchLtU
                    | Opcode::BranchLtS
                    | Opcode::BranchGeU
                    | Opcode::BranchGeS
            );
            let target_from_imm2 = matches!(
                op,
                Opcode::LoadImmJump
                    | Opcode::BranchEqImm
                    | Opcode::BranchNeImm
                    | Opcode::BranchLtUImm
                    | Opcode::BranchLeUImm
                    | Opcode::BranchGeUImm
                    | Opcode::BranchGtUImm
                    | Opcode::BranchLtSImm
                    | Opcode::BranchLeSImm
                    | Opcode::BranchGeSImm
                    | Opcode::BranchGtSImm
            );
            let target_pc_opt = if target_from_imm1 {
                Some(inst.imm1 as usize)
            } else if target_from_imm2 {
                Some(inst.imm2 as usize)
            } else {
                None
            };
            if let Some(target_pc) = target_pc_opt {
                if target_pc < basic_block_starts.len()
                    && basic_block_starts[target_pc]
                    && target_pc < pc_to_idx.len()
                {
                    pc_to_idx[target_pc]
                } else {
                    u32::MAX
                }
            } else {
                u32::MAX
            }
        };

        insts[i].next_idx = next_idx;
        insts[i].target_idx = target_idx;
    }

    (insts, pc_to_idx)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
