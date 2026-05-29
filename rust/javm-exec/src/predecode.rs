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
//! - **Gas-block-start markers**: `{0} ∪ post-terminator PCs ∪ 4 KiB
//!   page starts` (see Pass 2). All three are derived from the
//!   instruction stream / PC — never trusted from linker metadata,
//!   since the recompiler runs untrusted code. `jalr` targets are
//!   validated against this set at runtime.
//!
//! Per-block gas costs are computed by running the pipeline simulator
//! in [`crate::gas_cost::rv_gas_cost_for_block`] once per basic block;
//! the results are stored in [`Predecode::block_costs`].

use crate::instruction::{Inst, decode};
use crate::mem::PAGE_SIZE;
use alloc::vec;
use alloc::vec::Vec;

/// Pre-resolved metadata used by the per-block gas accountant. The
/// fields are computed once at decode time so the gas hot path does
/// not have to re-match the `Inst` variant on each invocation.
///
/// - `kind` is an index into `gas_cost::RV_GAS_COST_LUT`.
/// - `src1_slot`/`src2_slot`/`dst_slot` are PVM2 register slots
///   (0..12, ordered x1, x2, x5..x15) or `0xFF` for "no register"
///   (x0, x3, x4, or an unused register slot for this opcode).
#[derive(Debug, Clone, Copy, Default)]
pub struct RvGasMeta {
    pub kind: u8,
    pub src1_slot: u8,
    pub src2_slot: u8,
    pub dst_slot: u8,
}

/// One decoded instruction with its PC, next-PC, block-start flag,
/// and pre-resolved gas metadata.
#[derive(Debug, Clone, Copy)]
pub struct RvPreDecodedInst {
    pub inst: Inst,
    pub pc: u32,
    pub next_pc: u32,
    pub is_gas_block_start: bool,
    pub gas_meta: RvGasMeta,
}

/// Output of the predecode pass over an RV+C+custom-0 code section.
#[derive(Debug, Clone)]
pub struct Predecode {
    /// One entry per static instruction.
    pub insts: Vec<RvPreDecodedInst>,
    /// Byte-indexed: `valid_pc[i]` == true iff byte offset `i` is an
    /// instruction start. Length = `code.len()`. Used at deblob for
    /// branch / call target alignment checks (a static-target reaching
    /// a non-instruction-start byte is a program error).
    pub valid_pc: Vec<bool>,
    /// Pre-computed per-basic-block gas cost. Aligned with `insts`:
    /// `block_costs[i]` is meaningful only when
    /// `insts[i].is_gas_block_start == true`; entries at non-
    /// block-start indices are 0. Each meaningful entry is
    /// `max(simulation_cycles - 3, 1)` for the block starting at
    /// that instruction, computed by the pipeline simulator in
    /// `gas_cost::rv_gas_cost_for_block`.
    pub block_costs: Vec<u32>,
    /// If decode hit a reserved/illegal encoding, the byte offset of
    /// the first one. `None` on success.
    pub decode_error_at: Option<u32>,
}

/// Predecode an entire RV+C+custom-0 code section.
///
/// Linear pass; no recursion, no bitmask consultation. The
/// self-describing length encoding (`op[1:0]` tells you 2-byte vs
/// 4-byte) makes every advance unambiguous.
///
/// Per-block gas costs are computed by running the pipeline
/// simulator from `gas_cost::rv_gas_cost_for_block` over every basic
/// block. `mem_cycles` is the load/store cycle latency for the
/// active memory tier (mirrors `DEFAULT_MEM_CYCLES = 25` from the
/// PVM gas table).
pub fn predecode(code: &[u8]) -> Predecode {
    predecode_rv_with_mem_cycles(code, crate::gas_cost::DEFAULT_MEM_CYCLES)
}

/// Like `predecode` but takes an explicit `mem_cycles` parameter.
/// Used by callers that want to override the default L2-hit latency
/// (e.g. for tier-specific gas modeling).
pub fn predecode_rv_with_mem_cycles(code: &[u8], mem_cycles: u8) -> Predecode {
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
        if matches!(inst, Inst::Reserved { .. }) && decode_error_at.is_none() {
            decode_error_at = Some(pc as u32);
        }
        valid_pc[pc] = true;
        let next_pc = (pc + len as usize) as u32;
        let gas_meta = crate::gas_cost::rv_gas_meta(&inst);
        insts.push(RvPreDecodedInst {
            inst,
            pc: pc as u32,
            next_pc,
            is_gas_block_start: false,
            gas_meta,
        });
        pc = next_pc as usize;
    }

    // ---- Invariant 10: no instruction crosses a 4 KiB page boundary --
    //
    // A straddling instruction would let lazy per-page compilation split
    // it across a compile boundary. The linker pads with `c.nop` to
    // prevent this; reject a blob that violates it (defense — both
    // engines trust the instruction stream, not an external layout
    // guarantee). Only 4-byte instructions can straddle (RV+C is 2-byte
    // aligned, pages are even).
    if decode_error_at.is_none() {
        for ip in &insts {
            if ip.pc / PAGE_SIZE != (ip.next_pc - 1) / PAGE_SIZE {
                decode_error_at = Some(ip.pc);
                break;
            }
        }
    }

    // ---- Pass 2: mark gas-block starts -------------------------------
    //
    // The set of legal gas-block-starts is
    //
    //     {0} ∪ { pc | pc follows a terminator } ∪ { pc | pc % 4 KiB == 0 }
    //
    // all derived purely from the instruction stream / PC, never trusted
    // from linker metadata (the recompiler runs untrusted code). `jalr`
    // targets are validated against this set at runtime.
    //
    //  - Post-terminator: the linker injects `Fallthrough` (a terminator
    //    no-op) before any branch / jump / endpoint / code-pointer target
    //    that isn't naturally post-terminator, so every reachable static
    //    target is covered.
    //  - Page starts: every 4 KiB page boundary partitions a gas block so
    //    lazy per-page compilation enters each page at a dispatchable
    //    block and both engines agree on the partition (invariant 11).
    //
    // OOG happens at the per-block gas check at the block start, so a
    // paused PC is always in this set.
    for i in 0..insts.len() {
        let post_terminator = i > 0 && is_terminator(&insts[i - 1].inst);
        if insts[i].pc.is_multiple_of(PAGE_SIZE) || post_terminator {
            insts[i].is_gas_block_start = true;
        }
    }

    // ---- Pass 3: per-block gas costs via pipeline simulation ---------
    let block_costs = compute_block_costs(&insts, mem_cycles);

    Predecode {
        insts,
        valid_pc,
        block_costs,
        decode_error_at,
    }
}

/// Run the pipeline simulator once per basic block; write the
/// resulting cost into `block_costs[block_start_idx]` for each
/// gas-block-start. Non-block-start indices remain 0.
fn compute_block_costs(insts: &[RvPreDecodedInst], mem_cycles: u8) -> Vec<u32> {
    let mut block_costs = vec![0u32; insts.len()];
    for i in 0..insts.len() {
        if insts[i].is_gas_block_start {
            block_costs[i] = crate::gas_cost::rv_gas_cost_for_block(insts, i, mem_cycles);
        }
    }
    block_costs
}

/// Block-terminating instructions: anything that *can* leave the
/// fall-through path. Used to mark the next instruction as a
/// gas-block start.
pub fn is_terminator(inst: &Inst) -> bool {
    matches!(
        inst,
        // PC-relative jumps.
        Inst::Jal { .. }
            // Indirect jumps (returns, indirect calls).
            | Inst::Jalr { .. }
            // Static branches.
            | Inst::Beq { .. }
            | Inst::Bne { .. }
            | Inst::Blt { .. }
            | Inst::Bge { .. }
            | Inst::Bltu { .. }
            | Inst::Bgeu { .. }
            // Custom-0 control transfers.
            | Inst::Trap
            | Inst::EcallJar
            | Inst::Ecalli { .. }
            | Inst::Fallthrough
            // Reserved encodings panic at runtime.
            | Inst::Reserved { .. }
    )
}

// `rv_gas_cost` (flat per-instruction sum) replaced by pipeline-aware
// per-block simulation. See `gas_cost::rv_fast_cost` for the per-op
// FastCost table and `gas_cost::rv_gas_cost_for_block` for the
// block-cost wrapper. Costs are precomputed in `predecode` and
// returned via `Predecode::block_costs`.

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
        let r = predecode(&[]);
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
        let r = predecode(&code);
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
        let r = predecode(&code);
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
        let r = predecode(&code);
        assert_eq!(r.insts.len(), 3);
        assert!(r.insts[0].is_gas_block_start); // PC=0
        assert!(!r.insts[1].is_gas_block_start); // PC=4 post-addi (not terminator)
        assert!(r.insts[2].is_gas_block_start); // PC=8 post-fallthrough
        assert!(matches!(r.insts[1].inst, Inst::Fallthrough));
    }

    #[test]
    fn jalr_is_terminator() {
        // jalr x0, x1, 0 (= the `ret` idiom). I-type: rd=0, rs1=1,
        // imm=0, funct3=0, opcode=1100111 → 0x00008067.
        let jalr = 0x00008067u32;
        let code = enc(&[jalr, 0x00150513]);
        let r = predecode(&code);
        assert_eq!(r.insts.len(), 2);
        assert!(matches!(
            r.insts[0].inst,
            Inst::Jalr {
                rd: 0,
                rs1: 1,
                imm: 0
            }
        ));
        assert!(r.insts[0].is_gas_block_start); // PC=0
        assert!(r.insts[1].is_gas_block_start); // post-jalr (terminator)
        assert_eq!(r.decode_error_at, None);
    }

    #[test]
    fn auipc_decodes() {
        // auipc x10, 0x12 → rd=10, imm=(0x12<<12). opcode=0010111.
        // word = (0x12 << 12) | (10 << 7) | 0b0010111 = 0x00012517
        let auipc = 0x00012517u32;
        let code = enc(&[auipc]);
        let r = predecode(&code);
        assert_eq!(r.insts.len(), 1);
        assert!(matches!(
            r.insts[0].inst,
            Inst::Auipc {
                rd: 10,
                imm: 0x12000
            }
        ));
        // auipc is a plain ALU op, NOT a terminator.
        assert_eq!(r.decode_error_at, None);
    }

    #[test]
    fn reserved_encoding_recorded() {
        // ecall (standard) = 0x00000073 → Reserved
        let code = enc(&[0x00000073]);
        let r = predecode(&code);
        assert_eq!(r.insts.len(), 1);
        assert_eq!(r.decode_error_at, Some(0));
        assert!(matches!(r.insts[0].inst, Inst::Reserved { .. }));
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
        let r = predecode(&code);
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
