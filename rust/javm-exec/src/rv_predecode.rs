//! Single-pass predecode for PVM2 (RV+C+custom-0+custom-1) byte streams.
//!
//! Walks the code from PC=0, decoding every instruction and recording:
//!
//! - **Decoded instruction array** (`Vec<RvPreDecodedInst>`): one entry
//!   per static instruction, with PC + next-PC pre-computed so the
//!   codegen loop doesn't redo decoding.
//! - **Valid-PC set** (`Vec<bool>`, byte-indexed): true at every byte
//!   offset where an instruction begins. Used at deblob for branch /
//!   call target alignment checks (a static-target reaching a non-
//!   instruction-start byte is a program error).
//! - **Gas-block-start markers**: PC=0 plus every PC immediately
//!   following a terminator. PVM2's pure-static-dispatch design lets us
//!   tighten this to the strict post-terminator set (was: "every
//!   instruction", a workaround for runtime JALR validation back when
//!   PVM2 still had JALR).
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

    // ---- Pass 2: mark gas-block starts (strict post-terminator) ------
    //
    // PVM2 has no runtime indirect dispatch (no JALR; calls/returns are
    // `callf`/`retf` lowered to native call/ret on the guest stack).
    // The set of legal gas-block-starts is therefore:
    //
    //     {0} ∪ { pc | pc immediately follows a terminator instruction }
    //
    // The linker invariant (analogous to PVM's
    // `ensure_branch_targets_are_block_starts`) guarantees every
    // statically-reachable branch / callf target lands in this set —
    // it injects `Fallthrough` (a terminator no-op) before any target
    // that isn't naturally post-terminator.
    //
    // OOG happens at the per-block gas check at the block start, so
    // a paused PC is always in this set.
    if !insts.is_empty() {
        insts[0].is_gas_block_start = true;
    }
    for i in 1..insts.len() {
        let prev_is_terminator = is_terminator(&insts[i - 1].inst);
        if prev_is_terminator {
            insts[i].is_gas_block_start = true;
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
#[allow(dead_code)]
fn static_target(ip: &RvPreDecodedInst) -> Option<usize> {
    let pc = ip.pc as i64;
    let off: i64 = match ip.inst {
        RvInst::Jal { imm, .. } => imm as i64,
        RvInst::Callf { imm, .. } => imm as i64,
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
        // PC-relative jumps and calls.
        RvInst::Jal { .. }
            | RvInst::Callf { .. }
            | RvInst::Retf
            // Static branches.
            | RvInst::Beq { .. }
            | RvInst::Bne { .. }
            | RvInst::Blt { .. }
            | RvInst::Bge { .. }
            | RvInst::Bltu { .. }
            | RvInst::Bgeu { .. }
            // Custom-0 control transfers.
            | RvInst::Trap
            | RvInst::EcallJar
            | RvInst::Ecalli { .. }
            | RvInst::Fallthrough
            // Reserved encodings panic at runtime.
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
    fn post_terminator_is_block_start_branch_target_isnt() {
        // 0: beq x0, x0, 8  (terminator — post-PC=4 is block start)
        // 4: addi x10, x10, 1  (post-terminator — block start)
        // 8: addi x11, x11, 2  (branch target — NOT post-terminator,
        //                       so not a block start in strict mode;
        //                       the linker would inject `fallthrough`
        //                       before PC=8 in a real build)
        let beq = 0x00000463u32; // beq x0, x0, +8
        let code = enc(&[beq, 0x00150513, 0x00158593]);
        let r = predecode_rv(&code);
        assert_eq!(r.insts.len(), 3);
        // PC=0 always block start.
        assert!(r.insts[0].is_gas_block_start);
        // Post-beq → PC=4 is block start.
        assert!(r.insts[1].is_gas_block_start);
        // PC=8 is a branch target but the previous instruction (addi at
        // PC=4) is not a terminator. The linker is responsible for
        // injecting `fallthrough` before such targets in real builds;
        // the predecode pass itself doesn't infer it.
        assert!(!r.insts[2].is_gas_block_start);
    }

    #[test]
    fn fallthrough_creates_block_start() {
        // 0: addi x10, x10, 1   (not a terminator)
        // 4: fallthrough         (terminator — post-PC=8 is block start)
        // 8: addi x11, x11, 2   (post-fallthrough — block start)
        // custom-0 with funct3=0b100 is the fallthrough encoding.
        // Major opcode = 0b00_010 (0x2), bits[1:0]=11.
        // Word = (funct3<<12) | (op_custom_0<<2) | 0b11 = (4<<12) | (2<<2) | 3 = 0x400B
        let fallthrough_word = 0x0000_400Bu32;
        let code = enc(&[0x00150513, fallthrough_word, 0x00158593]);
        let r = predecode_rv(&code);
        assert_eq!(r.insts.len(), 3);
        assert!(r.insts[0].is_gas_block_start);   // PC=0
        assert!(!r.insts[1].is_gas_block_start);  // PC=4 post-addi (not terminator)
        assert!(r.insts[2].is_gas_block_start);   // PC=8 post-fallthrough
        assert!(matches!(r.insts[1].inst, RvInst::Fallthrough));
    }

    #[test]
    fn callf_is_terminator() {
        // callf imm=+8 (custom-1, J-type).
        // J-type word: imm bits + rd + opcode. rd=0 (required for callf).
        // Major opcode 0b01_010 = 0xA; bits[1:0]=11. Major bits[6:2]=0b01010=10.
        // word = imm_j_field | (rd<<7) | (major<<2) | 0b11
        // For imm=+8: J-format imm encoding = 0x00800000 wait, let me compute
        // J imm bits in instruction word:
        //   bit 31 = imm[20]
        //   bits 30:21 = imm[10:1]
        //   bit 20 = imm[11]
        //   bits 19:12 = imm[19:12]
        // imm=8 means imm[3]=1 (bit pos 3 in 21-bit signed).
        // imm[10:1] = 0000000100 (bit 3 set in 10-bit field = 0x004)
        // bits 30:21 = 0x004 → contribution = 0x004 << 21 = 0x00800000
        // word = 0x00800000 | (0 << 7) | (0xA << 2) | 0b11 = 0x0080002Bu32
        let callf_word = 0x0080_002Bu32;
        let code = enc(&[callf_word, 0x00150513]);
        let r = predecode_rv(&code);
        assert_eq!(r.insts.len(), 2);
        assert!(matches!(r.insts[0].inst, RvInst::Callf { imm: 8 }));
        assert!(r.insts[0].is_gas_block_start);   // PC=0
        assert!(r.insts[1].is_gas_block_start);   // post-callf
    }

    #[test]
    fn jalr_is_rejected() {
        // jalr x0, x1, 0 (= c.ret pattern in uncompressed form)
        // I-type: rd=0, rs1=1, imm=0, funct3=0, opcode=1100111
        // word = (0<<20) | (1<<15) | (0<<12) | (0<<7) | 0b1100111 = 0x00008067
        let jalr = 0x00008067u32;
        let code = enc(&[jalr]);
        let r = predecode_rv(&code);
        assert_eq!(r.insts.len(), 1);
        assert!(matches!(r.insts[0].inst, RvInst::Reserved { .. }));
        assert_eq!(r.decode_error_at, Some(0));
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
