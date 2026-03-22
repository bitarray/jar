//! Pre-decode PVM bytecode into a flat instruction stream for fast codegen.
//!
//! Replaces the byte-by-byte bitmask scan in the codegen loop with a single
//! upfront decode pass. The codegen then iterates a `&[PreDecodedInst]` slice,
//! eliminating redundant `compute_skip()` and `decode_args()` calls.

use crate::args::{self, Args};
use crate::instruction::Opcode;

/// Pre-decoded PVM instruction. Stores everything the codegen needs per instruction.
#[derive(Clone, Copy, Debug)]
pub struct PreDecodedInst {
    /// PVM opcode (for compile_instruction match dispatch).
    pub opcode: Opcode,
    /// Decoded arguments (registers, immediates, offsets).
    pub args: Args,
    /// PVM byte offset of this instruction.
    pub pc: u32,
    /// PVM byte offset of the next instruction.
    pub next_pc: u32,
    /// Gas cost if this is a gas block start (>0), 0 otherwise.
    /// Set by single-pass codegen via placeholder + patch.
    pub gas_cost: u32,
    /// Whether this instruction starts a gas metering block.
    pub is_gas_block_start: bool,
    /// Flat register fields for fast gas cost lookup (avoids Args enum match).
    pub ra: u8,
    pub rb: u8,
    pub rd: u8,
}

/// Pre-decode all instructions from raw code+bitmask into a flat array.
///
/// Three passes:
/// 1. Decode each instruction (opcode, args, pc, next_pc)
/// 2. Identify gas block boundaries (branch targets, post-terminators, jump table)
/// 3. Compute gas cost for each gas block start
pub fn predecode(code: &[u8], bitmask: &[u8], jump_table: &[u32]) -> Vec<PreDecodedInst> {
    // --- Pass 1: Decode instructions ---
    let estimated_count = bitmask.iter().filter(|&&b| b == 1).count();
    let mut instrs: Vec<PreDecodedInst> = Vec::with_capacity(estimated_count);

    let mut pc: usize = 0;
    while pc < code.len() {
        if pc < bitmask.len() && bitmask[pc] != 1 {
            pc += 1;
            continue;
        }

        let opcode = Opcode::from_byte(code[pc]).unwrap_or(Opcode::Trap);
        let skip = compute_skip(pc, bitmask);
        let next_pc = pc + 1 + skip;
        let category = opcode.category();
        let args = args::decode_args(code, pc, skip, category);

        // Extract flat register fields for fast gas cost lookup
        let (ra, rb, rd) = match args {
            Args::ThreeReg { ra, rb, rd } => (ra as u8, rb as u8, rd as u8),
            Args::TwoReg { rd: d, ra: a } => (a as u8, 0xFF, d as u8),
            Args::TwoRegImm { ra, rb, .. } | Args::TwoRegOffset { ra, rb, .. }
            | Args::TwoRegTwoImm { ra, rb, .. } => (ra as u8, rb as u8, 0xFF),
            Args::RegImm { ra, .. } | Args::RegExtImm { ra, .. }
            | Args::RegTwoImm { ra, .. } | Args::RegImmOffset { ra, .. } => (ra as u8, 0xFF, 0xFF),
            _ => (0xFF, 0xFF, 0xFF),
        };
        instrs.push(PreDecodedInst {
            opcode, args,
            pc: pc as u32,
            next_pc: next_pc as u32,
            gas_cost: 0,
            is_gas_block_start: false,
            ra, rb, rd,
        });

        pc = next_pc;
    }

    // --- Pass 2: Mark gas block starts ---
    // Build PC → instruction index map for O(1) target lookup.
    let mut pc_to_idx: Vec<u32> = vec![u32::MAX; code.len() + 1];
    for (i, instr) in instrs.iter().enumerate() {
        pc_to_idx[instr.pc as usize] = i as u32;
    }

    let mut is_gas_start = vec![false; instrs.len()];

    // PC=0 always starts a gas block
    if !instrs.is_empty() {
        is_gas_start[0] = true;
    }

    // Jump table entries
    for &target in jump_table {
        let t = target as usize;
        if t < pc_to_idx.len() && pc_to_idx[t] != u32::MAX {
            is_gas_start[pc_to_idx[t] as usize] = true;
        }
    }

    // Branch/jump targets and post-terminator fallthroughs
    for i in 0..instrs.len() {
        let instr = &instrs[i];

        // Extract branch/jump target from decoded args
        let target_pc = match instr.args {
            Args::Offset { offset } => Some(offset as usize),
            Args::RegImmOffset { offset, .. } => Some(offset as usize),
            Args::TwoRegOffset { offset, .. } => Some(offset as usize),
            _ => None,
        };
        if let Some(t) = target_pc {
            if t < pc_to_idx.len() && pc_to_idx[t] != u32::MAX {
                is_gas_start[pc_to_idx[t] as usize] = true;
            }
        }

        // Fallthrough after terminator
        if instr.opcode.is_terminator() && i + 1 < instrs.len() {
            is_gas_start[i + 1] = true;
        }

        // Ecalli: next instruction is a re-entry point
        if matches!(instr.opcode, Opcode::Ecalli) && i + 1 < instrs.len() {
            is_gas_start[i + 1] = true;
        }
    }

    // --- Mark gas block start flags on instructions ---
    // Gas costs are computed inline during codegen (single-pass).
    for i in 0..instrs.len() {
        if is_gas_start[i] {
            instrs[i].is_gas_block_start = true;
        }
    }

    instrs
}

/// Compute gas block start bitmap from raw code+bitmask (no full Args decoding).
/// Returns Vec<bool> indexed by PVM byte offset. True = this PC starts a gas block.
pub fn compute_gas_blocks(code: &[u8], bitmask: &[u8], jump_table: &[u32]) -> Vec<bool> {
    let mut gas_starts = vec![false; code.len()];

    // PC=0 always starts a gas block
    if !code.is_empty() {
        gas_starts[0] = true;
    }

    // Jump table entries
    for &target in jump_table {
        let t = target as usize;
        if t < code.len() && t < bitmask.len() && bitmask[t] == 1 {
            gas_starts[t] = true;
        }
    }

    // Scan instructions for branch targets and terminators
    let mut pc: usize = 0;
    while pc < code.len() {
        if pc < bitmask.len() && bitmask[pc] != 1 {
            pc += 1;
            continue;
        }

        let opcode = Opcode::from_byte(code[pc]);
        let skip = compute_skip(pc, bitmask);
        let next_pc = pc + 1 + skip;

        if let Some(op) = opcode {
            // Extract branch/jump targets from raw bytes
            let category = op.category();
            let target_pc = match category {
                crate::instruction::InstructionCategory::OneOffset => {
                    // Jump: offset is signed, relative to pc
                    let raw = args::decode_args(code, pc, skip, category);
                    match raw { Args::Offset { offset } => Some(offset as usize), _ => None }
                }
                crate::instruction::InstructionCategory::OneRegImmOffset => {
                    let raw = args::decode_args(code, pc, skip, category);
                    match raw { Args::RegImmOffset { offset, .. } => Some(offset as usize), _ => None }
                }
                crate::instruction::InstructionCategory::TwoRegOneOffset => {
                    let raw = args::decode_args(code, pc, skip, category);
                    match raw { Args::TwoRegOffset { offset, .. } => Some(offset as usize), _ => None }
                }
                _ => None,
            };
            if let Some(t) = target_pc {
                if t < code.len() && t < bitmask.len() && bitmask[t] == 1 {
                    gas_starts[t] = true;
                }
            }

            // Post-terminator fallthrough
            if op.is_terminator() && next_pc < code.len() {
                gas_starts[next_pc] = true;
            }

            // Post-ecalli
            if matches!(op, Opcode::Ecalli) && next_pc < code.len() {
                gas_starts[next_pc] = true;
            }
        }

        pc = next_pc;
    }

    gas_starts
}

/// Compute skip(i) — distance to next instruction start.
fn compute_skip(pc: usize, bitmask: &[u8]) -> usize {
    for j in 0..25 {
        let idx = pc + 1 + j;
        let bit = if idx < bitmask.len() { bitmask[idx] } else { 1 };
        if bit == 1 {
            return j;
        }
    }
    24
}
