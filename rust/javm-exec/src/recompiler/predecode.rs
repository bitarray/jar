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
            Args::TwoRegImm { ra, rb, .. }
            | Args::TwoRegOffset { ra, rb, .. }
            | Args::TwoRegTwoImm { ra, rb, .. } => (ra as u8, rb as u8, 0xFF),
            Args::RegImm { ra, .. }
            | Args::RegExtImm { ra, .. }
            | Args::RegTwoImm { ra, .. }
            | Args::RegImmOffset { ra, .. } => (ra as u8, 0xFF, 0xFF),
            _ => (0xFF, 0xFF, 0xFF),
        };
        instrs.push(PreDecodedInst {
            opcode,
            args,
            pc: pc as u32,
            next_pc: next_pc as u32,
            gas_cost: 0,
            is_gas_block_start: false,
            ra,
            rb,
            rd,
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
        if let Some(t) = target_pc
            && t < pc_to_idx.len()
            && pc_to_idx[t] != u32::MAX
        {
            is_gas_start[pc_to_idx[t] as usize] = true;
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
/// Returns `Vec<bool>` indexed by PVM byte offset. True = this PC starts a gas block.
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
                    match raw {
                        Args::Offset { offset } => Some(offset as usize),
                        _ => None,
                    }
                }
                crate::instruction::InstructionCategory::OneRegImmOffset => {
                    let raw = args::decode_args(code, pc, skip, category);
                    match raw {
                        Args::RegImmOffset { offset, .. } => Some(offset as usize),
                        _ => None,
                    }
                }
                crate::instruction::InstructionCategory::TwoRegOneOffset => {
                    let raw = args::decode_args(code, pc, skip, category);
                    match raw {
                        Args::TwoRegOffset { offset, .. } => Some(offset as usize),
                        _ => None,
                    }
                }
                _ => None,
            };
            if let Some(t) = target_pc
                && t < code.len()
                && t < bitmask.len()
                && bitmask[t] == 1
            {
                gas_starts[t] = true;
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

#[cfg(test)]
mod tests {
    use super::*;

    // === predecode ===

    #[test]
    fn test_predecode_empty() {
        let instrs = predecode(&[], &[], &[]);
        assert!(instrs.is_empty());
    }

    #[test]
    fn test_predecode_single_trap() {
        // Trap = opcode 0, no arguments
        let code = vec![0u8];
        let bitmask = vec![1u8];
        let instrs = predecode(&code, &bitmask, &[]);

        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].opcode, Opcode::Trap);
        assert_eq!(instrs[0].pc, 0);
        assert_eq!(instrs[0].next_pc, 1);
        assert!(
            instrs[0].is_gas_block_start,
            "PC=0 is always a gas block start"
        );
    }

    #[test]
    fn test_predecode_sequence() {
        // load_imm(51) r0, 42; ecalli(10) 0
        let code = vec![51, 0, 42, 10, 0];
        let bitmask = vec![1, 0, 0, 1, 0];

        let instrs = predecode(&code, &bitmask, &[]);
        assert_eq!(instrs.len(), 2);
        assert_eq!(instrs[0].opcode, Opcode::LoadImm);
        assert_eq!(instrs[0].pc, 0);
        assert_eq!(instrs[0].next_pc, 3);
        assert_eq!(instrs[1].opcode, Opcode::Ecalli);
        assert_eq!(instrs[1].pc, 3);
    }

    #[test]
    fn test_predecode_gas_block_after_terminator() {
        // trap(0); load_imm(51) r0, 1
        // Trap is a terminator, so load_imm starts a new gas block
        let code = vec![0, 51, 0, 1];
        let bitmask = vec![1, 1, 0, 0];

        let instrs = predecode(&code, &bitmask, &[]);
        assert_eq!(instrs.len(), 2);
        assert!(instrs[0].is_gas_block_start, "PC=0 always");
        assert!(
            instrs[1].is_gas_block_start,
            "post-terminator should be gas block start"
        );
    }

    #[test]
    fn test_predecode_gas_block_after_ecalli() {
        // ecalli(10) 0; load_imm(51) r0, 1
        let code = vec![10, 0, 51, 0, 1];
        let bitmask = vec![1, 0, 1, 0, 0];

        let instrs = predecode(&code, &bitmask, &[]);
        assert_eq!(instrs.len(), 2);
        assert!(
            instrs[1].is_gas_block_start,
            "post-ecalli should be gas block start"
        );
    }

    #[test]
    fn test_predecode_branch_target_is_gas_start() {
        // jump(40) offset=-5 (targets PC=0); load_imm(51) r0, 1
        // Jump at PC=0 targets PC=0 (self-loop)
        let offset: i32 = 0; // targets self (PC + 0 = 0)
        let code = vec![
            40,
            offset as u8,
            (offset >> 8) as u8,
            (offset >> 16) as u8,
            (offset >> 24) as u8,
            51,
            0,
            1, // load_imm after the jump
        ];
        let bitmask = vec![1, 0, 0, 0, 0, 1, 0, 0];

        let instrs = predecode(&code, &bitmask, &[]);
        assert_eq!(instrs.len(), 2);
        // PC=0 is both the first instruction AND a branch target
        assert!(instrs[0].is_gas_block_start);
        // Post-terminator (jump is a terminator)
        assert!(instrs[1].is_gas_block_start);
    }

    #[test]
    fn test_predecode_jump_table_target_is_gas_start() {
        // Two instructions: load_imm at PC=0, load_imm at PC=3
        // Jump table says PC=3 is a target
        let code = vec![51, 0, 1, 51, 1, 2];
        let bitmask = vec![1, 0, 0, 1, 0, 0];

        let instrs = predecode(&code, &bitmask, &[3]);
        assert_eq!(instrs.len(), 2);
        assert!(instrs[0].is_gas_block_start, "PC=0 always");
        assert!(
            instrs[1].is_gas_block_start,
            "jump table target should be gas block start"
        );
    }

    #[test]
    fn test_predecode_non_target_not_gas_start() {
        // Two consecutive load_imm instructions, no branches
        let code = vec![51, 0, 1, 51, 1, 2];
        let bitmask = vec![1, 0, 0, 1, 0, 0];

        let instrs = predecode(&code, &bitmask, &[]);
        assert_eq!(instrs.len(), 2);
        assert!(instrs[0].is_gas_block_start, "PC=0 always");
        assert!(
            !instrs[1].is_gas_block_start,
            "not a target, not post-terminator"
        );
    }

    // === compute_gas_blocks ===

    #[test]
    fn test_gas_blocks_empty() {
        let blocks = compute_gas_blocks(&[], &[], &[]);
        assert!(blocks.is_empty());
    }

    #[test]
    fn test_gas_blocks_pc0_always_start() {
        let code = vec![51, 0, 1];
        let bitmask = vec![1, 0, 0];
        let blocks = compute_gas_blocks(&code, &bitmask, &[]);
        assert!(blocks[0], "PC=0 should always be a gas block start");
    }

    #[test]
    fn test_gas_blocks_jump_table() {
        let code = vec![51, 0, 1, 51, 1, 2];
        let bitmask = vec![1, 0, 0, 1, 0, 0];
        let blocks = compute_gas_blocks(&code, &bitmask, &[3]);
        assert!(blocks[0]);
        assert!(blocks[3], "jump table target should be gas block start");
    }

    #[test]
    fn test_gas_blocks_post_terminator() {
        let code = vec![0, 51, 0, 1]; // trap; load_imm
        let bitmask = vec![1, 1, 0, 0];
        let blocks = compute_gas_blocks(&code, &bitmask, &[]);
        assert!(blocks[0]);
        assert!(blocks[1], "post-terminator should be gas block start");
    }

    // === compute_skip ===

    #[test]
    fn test_skip_single_byte() {
        // Next byte is an instruction start
        assert_eq!(compute_skip(0, &[1, 1]), 0);
    }

    #[test]
    fn test_skip_multi_byte() {
        // Two continuation bytes before next instruction start
        assert_eq!(compute_skip(0, &[1, 0, 0, 1]), 2);
    }

    #[test]
    fn test_skip_at_end() {
        // Past end of bitmask → treated as instruction start
        assert_eq!(compute_skip(0, &[1]), 0);
    }
}
