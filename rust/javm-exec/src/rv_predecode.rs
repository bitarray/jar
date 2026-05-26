//! Single-pass predecode for PVM2 (RV+C+custom-0) byte streams.
//!
//! Walks the code from PC=0, decoding every instruction and recording:
//!
//! - **Decoded instruction array** (`Vec<RvPreDecodedInst>`): one entry
//!   per static instruction, with PC + next-PC pre-computed so the
//!   codegen loop doesn't redo decoding.
//! - **Valid-PC set** (`Vec<bool>`, byte-indexed): true at every byte
//!   offset where an instruction begins. Used at runtime for JALR
//!   target validation (PVM2-Base divergence (4) — see
//!   `~/docs/pvm-isa/05-pvm2-rv-diff.md`).
//! - **Gas-block-start markers**: PC=0, branch/jump targets,
//!   post-terminator fallthroughs (post-trap, post-ecall, post-jal,
//!   post-jalr, post-conditional-branch).
//!
//! Gas cost per instruction is filled in via [`rv_gas_cost`]. For now
//! this returns 1 for every instruction (placeholder); calibration is
//! a follow-up.

use crate::rv_instruction::{RvInst, decode};
use alloc::vec;
use alloc::vec::Vec;

/// One decoded instruction with its PC, next-PC, gas cost, and
/// block-start flag.
#[derive(Debug, Clone, Copy)]
pub struct RvPreDecodedInst {
    pub inst: RvInst,
    pub pc: u32,
    pub next_pc: u32,
    pub gas_cost: u32,
    pub is_gas_block_start: bool,
}

/// Output of the predecode pass over an RV+C+custom-0 code section.
#[derive(Debug, Clone)]
pub struct RvPredecode {
    /// One entry per static instruction.
    pub insts: Vec<RvPreDecodedInst>,
    /// Byte-indexed: `valid_pc[i]` == true iff byte offset `i` is an
    /// instruction start (and thus a valid JALR target). Length =
    /// code.len().
    pub valid_pc: Vec<bool>,
    /// If decode hit a reserved/illegal encoding, the byte offset of
    /// the first one. `None` on success.
    pub decode_error_at: Option<u32>,
}

/// Predecode an entire RV+C+custom-0 code section.
///
/// Linear pass; no recursion, no bitmask consultation. The
/// self-describing length encoding (`op[1:0]` tells you 2-byte vs
/// 4-byte) makes every advance unambiguous.
pub fn predecode_rv(code: &[u8]) -> RvPredecode {
    let mut insts: Vec<RvPreDecodedInst> = Vec::with_capacity(code.len() / 4);
    let mut valid_pc: Vec<bool> = vec![false; code.len()];
    let mut decode_error_at: Option<u32> = None;

    // ---- Pass 1: decode every instruction ----------------------------
    let mut pc: usize = 0;
    while pc < code.len() {
        let Some((inst, len)) = decode(&code[pc..]) else {
            decode_error_at = Some(pc as u32);
            break;
        };
        if matches!(inst, RvInst::Reserved { .. }) && decode_error_at.is_none() {
            decode_error_at = Some(pc as u32);
        }
        valid_pc[pc] = true;
        let next_pc = (pc + len as usize) as u32;
        insts.push(RvPreDecodedInst {
            inst,
            pc: pc as u32,
            next_pc,
            gas_cost: rv_gas_cost(inst),
            is_gas_block_start: false,
        });
        pc = next_pc as usize;
    }

    // ---- Pass 2: mark gas-block starts -------------------------------
    // PC=0 is always a block start (entry).
    if let Some(first) = insts.first_mut() {
        first.is_gas_block_start = true;
    }

    // Build a PC -> index map for O(1) target lookup.
    let mut pc_to_idx: Vec<u32> = vec![u32::MAX; code.len() + 1];
    for (i, ip) in insts.iter().enumerate() {
        pc_to_idx[ip.pc as usize] = i as u32;
    }

    // Branch/jump targets + post-terminator marks.
    for i in 0..insts.len() {
        let ip = insts[i];
        // Static branch/jump targets (only relative jumps; jalr is
        // dynamic and not pre-resolvable).
        if let Some(target_byte) = static_target(&ip) {
            if target_byte < pc_to_idx.len()
                && pc_to_idx[target_byte] != u32::MAX
            {
                let idx = pc_to_idx[target_byte] as usize;
                insts[idx].is_gas_block_start = true;
            }
        }
        // Post-terminator: the next instruction starts a fresh block.
        if is_terminator(&ip.inst) && i + 1 < insts.len() {
            insts[i + 1].is_gas_block_start = true;
        }
        // Post-ecalli: re-entry point.
        if matches!(ip.inst, RvInst::Ecalli { .. }) && i + 1 < insts.len() {
            insts[i + 1].is_gas_block_start = true;
        }
    }

    RvPredecode {
        insts,
        valid_pc,
        decode_error_at,
    }
}

/// Return the target byte offset of a statically-resolvable branch or
/// jump. `None` for indirect jumps (`jalr`), non-control-flow ops, and
/// other shapes.
///
/// Targets are computed as `pc + imm` (signed). For RV B-type and
/// J-type, `imm` is in bytes. For RV+C, decompression has already
/// converted to byte offsets so the same `pc + imm` rule applies.
fn static_target(ip: &RvPreDecodedInst) -> Option<usize> {
    let pc = ip.pc as i64;
    let off: i64 = match ip.inst {
        RvInst::Jal { imm, .. } => imm as i64,
        RvInst::Beq { imm, .. }
        | RvInst::Bne { imm, .. }
        | RvInst::Blt { imm, .. }
        | RvInst::Bge { imm, .. }
        | RvInst::Bltu { imm, .. }
        | RvInst::Bgeu { imm, .. } => imm as i64,
        _ => return None,
    };
    let t = pc + off;
    if t < 0 {
        None
    } else {
        Some(t as usize)
    }
}

/// Block-terminating instructions: anything that *can* leave the
/// fall-through path. Used to mark the next instruction as a
/// gas-block start.
fn is_terminator(inst: &RvInst) -> bool {
    matches!(
        inst,
        RvInst::Jal { .. }
            | RvInst::Jalr { .. }
            | RvInst::Beq { .. }
            | RvInst::Bne { .. }
            | RvInst::Blt { .. }
            | RvInst::Bge { .. }
            | RvInst::Bltu { .. }
            | RvInst::Bgeu { .. }
            | RvInst::Trap
            | RvInst::EcallJar
            | RvInst::Reserved { .. }
    )
}

/// Per-instruction gas cost. Placeholder — returns 1 for every
/// instruction. Calibration with a real cost model (mapping to the
/// PVM gas costs for analogous ops) is a follow-up.
pub fn rv_gas_cost(_inst: RvInst) -> u32 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn enc(insns: &[u32]) -> Vec<u8> {
        let mut v = Vec::with_capacity(insns.len() * 4);
        for w in insns {
            v.extend_from_slice(&w.to_le_bytes());
        }
        v
    }

    #[test]
    fn empty_code_yields_empty() {
        let r = predecode_rv(&[]);
        assert!(r.insts.is_empty());
        assert!(r.valid_pc.is_empty());
        assert!(r.decode_error_at.is_none());
    }

    #[test]
    fn linear_sequence() {
        // addi x10, x11, 1 ; addi x10, x10, 2 ; jal x0, -8 (loop back)
        let code = enc(&[
            0x00158513, // addi x10, x11, 1
            0x00250513, // addi x10, x10, 2
            // jal x0, -8: J-type imm = -8 bytes
            // J encoding: imm[20|10:1|11|19:12] | rd | opcode
            // imm = -8 = 0xFFFFFFF8 = 1111...11111000 in 21-bit
            // Manually: jal x0, .-8 = 0xFF9FF06F
            0xFF9FF06F,
        ]);
        let r = predecode_rv(&code);
        assert_eq!(r.insts.len(), 3);
        assert_eq!(r.insts[0].pc, 0);
        assert_eq!(r.insts[0].next_pc, 4);
        assert_eq!(r.insts[1].pc, 4);
        assert_eq!(r.insts[1].next_pc, 8);
        assert_eq!(r.insts[2].pc, 8);
        assert_eq!(r.insts[2].next_pc, 12);
        // PC=0 always a block start; target of the jal (at PC=0) marks insts[0]; no others
        assert!(r.insts[0].is_gas_block_start);
        // Post-terminator: nothing after the jal (last insn).
        assert!(r.valid_pc[0]);
        assert!(r.valid_pc[4]);
        assert!(r.valid_pc[8]);
        // No reserved encodings.
        assert!(r.decode_error_at.is_none());
    }

    #[test]
    fn branch_target_marked_block_start() {
        // 0: beq x0, x0, 8  (skip the next insn)
        // 4: addi x10, x10, 1  (this is fall-through, branch-not-taken path)
        // 8: addi x11, x11, 2  (branch target → block start)
        let beq = {
            // beq x0, x0, +8: rs1=0, rs2=0, imm=8
            // B encoding: imm[12|10:5|4:1|11] split
            // 8 = 0b0000_0000_1000; bits: 12=0, 11=0, 10:5=000000, 4:1=0100, 0=0
            // word = funct7(7) rs2(5) rs1(5) funct3(3) rd(5) op(7) — but for B the imm fields replace rd & funct7
            // imm[12|10:5] -> bits[31|30:25]; imm[4:1|11] -> bits[11:8|7]
            // funct3=000 (beq), opcode=1100011
            // imm=8: bits set: imm[3]=1, so imm[4:1]=0100 -> bits[11:8] = 0100
            // = 0x00000463
            0x00000463u32
        };
        let code = enc(&[beq, 0x00150513, 0x00158593]);
        let r = predecode_rv(&code);
        assert_eq!(r.insts.len(), 3);
        // PC=0 always block start
        assert!(r.insts[0].is_gas_block_start);
        // Post-terminator (post-beq, since beq is conditional terminator) → PC=4 is block start
        assert!(r.insts[1].is_gas_block_start);
        // Branch target PC=8 also block start
        assert!(r.insts[2].is_gas_block_start);
    }

    #[test]
    fn reserved_encoding_recorded() {
        // ecall (standard) = 0x00000073 → Reserved
        let code = enc(&[0x00000073]);
        let r = predecode_rv(&code);
        assert_eq!(r.insts.len(), 1);
        assert_eq!(r.decode_error_at, Some(0));
        assert!(matches!(r.insts[0].inst, RvInst::Reserved { .. }));
    }

    #[test]
    fn compressed_then_standard() {
        // c.li x10, 5 (2 bytes) ; addi x11, x11, 1 (4 bytes)
        // c.li x10, 5: per spec CI imm6=5, rd=10, opcode=01, funct3=010
        // h = (0<<12) | (10<<7) | (5<<2) | 0b01 with f3=010 in bits 15:13
        // = (0b010 << 13) | (10 << 7) | (5 << 2) | 0b01
        // = 0x4000 | 0x500 | 0x14 | 0x01 = 0x4515
        let cli = 0x4515u16.to_le_bytes();
        let mut code = vec![cli[0], cli[1]];
        code.extend_from_slice(&0x00158593u32.to_le_bytes());
        let r = predecode_rv(&code);
        assert_eq!(r.insts.len(), 2);
        assert_eq!(r.insts[0].pc, 0);
        assert_eq!(r.insts[0].next_pc, 2);
        assert_eq!(r.insts[1].pc, 2);
        assert_eq!(r.insts[1].next_pc, 6);
        assert!(r.valid_pc[0]);
        assert!(r.valid_pc[2]);
        assert!(!r.valid_pc[1]); // mid-instruction byte
        assert!(!r.valid_pc[3]); // mid-instruction byte
    }
}
