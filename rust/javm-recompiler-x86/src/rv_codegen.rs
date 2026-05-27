//! RV+C+custom-0 → x86-64 code generation (PVM2 path).
//!
//! Parallel front-end to [`super::codegen::Compiler::compile`]: takes a
//! raw RV+C+custom byte stream, predecodes it (see
//! `javm_exec::rv_predecode`), and emits native code by dispatching each
//! [`RvInst`] variant to the existing PVM-shaped `emit_*` helpers.
//!
//! Register-file mapping:
//!
//! | RV reg  | role        | slot | x86 reg |
//! |---------|-------------|------|---------|
//! | x0      | zero        | —    | const 0 |
//! | x1      | ra          | 0    | RBP     |
//! | x2      | sp          | 1    | RBX     |
//! | x3      | reserved    | —    | trap    |
//! | x4      | reserved    | —    | trap    |
//! | x5–x15  | general     | 2–12 | R12..RCX|
//!
//! Slot 0..12 is the existing PVM register slot — so every emit helper
//! that takes a `usize` slot index works unchanged.

use alloc::vec;
use alloc::vec::Vec;

use super::asm::{Cc, Label, Reg};
use super::codegen::{
    CTX_CODE_BASE, CTX_DISPATCH_TABLE, CTX_EXIT_ARG, CTX_EXIT_REASON, CTX_JT_PTR, CTX_PC,
    CompileResult, Compiler, EXIT_ECALL, EXIT_HOST_CALL, EXIT_PANIC, EXIT_TRAP, GAS, REG_MAP,
    SCRATCH,
};
use javm_exec::rv_instruction::RvInst;
pub use javm_exec::rv_predecode::{RvPredecode, predecode_rv};

// ----------------------------------------------------------------------
// RV opcode majors (bits [6:2]). Bits [1:0] are always 0b11 for 4-byte.
// Mirrors `javm_exec::rv_instruction::OP_*`; redeclared here to keep the
// recompiler self-contained on the byte-dispatch hot path. Only majors
// PVM2 accepts are named — AUIPC, JALR, SYSTEM, CUSTOM_1, AMO, FP* etc.
// are routed through the catch-all default branch in `compile_rv4`.
// ----------------------------------------------------------------------
const OP_LOAD: u32 = 0b00_000;
const OP_MISC_MEM: u32 = 0b00_011;
const OP_IMM: u32 = 0b00_100;
const OP_OP_IMM_32: u32 = 0b00_110;
const OP_STORE: u32 = 0b01_000;
const OP_OP: u32 = 0b01_100;
const OP_LUI: u32 = 0b01_101;
const OP_OP_32: u32 = 0b01_110;
const OP_BRANCH: u32 = 0b11_000;
const OP_JAL: u32 = 0b11_011;
const OP_CUSTOM_0: u32 = 0b00_010;

// Sign-extended immediates straight off a 4-byte RV word. Mirrors the
// canonical encoders in `javm_exec::rv_instruction`.
#[inline]
fn imm_i(w: u32) -> i32 {
    (w as i32) >> 20
}
#[inline]
fn imm_s(w: u32) -> i32 {
    let hi = (w >> 25) & 0x7F;
    let lo = (w >> 7) & 0x1F;
    let raw = ((hi << 5) | lo) as i32;
    (raw << 20) >> 20
}
#[inline]
fn imm_b(w: u32) -> i32 {
    let b12 = (w >> 31) & 1;
    let b11 = (w >> 7) & 1;
    let b10_5 = (w >> 25) & 0x3F;
    let b4_1 = (w >> 8) & 0xF;
    let raw = (b12 << 12) | (b11 << 11) | (b10_5 << 5) | (b4_1 << 1);
    ((raw as i32) << 19) >> 19
}
#[inline]
fn imm_j(w: u32) -> i32 {
    let b20 = (w >> 31) & 1;
    let b10_1 = (w >> 21) & 0x3FF;
    let b11 = (w >> 20) & 1;
    let b19_12 = (w >> 12) & 0xFF;
    let raw = (b20 << 20) | (b19_12 << 12) | (b11 << 11) | (b10_1 << 1);
    ((raw as i32) << 11) >> 11
}
#[inline]
fn imm_u(w: u32) -> i32 {
    (w & 0xFFFFF000) as i32
}

/// Map an RV register index to its PVM slot (0..=12).
///
/// Returns `None` for x0 (hardwired zero), x3, x4 (reserved). Callers
/// handle x0 by loading an immediate 0; x3/x4 cause a runtime panic at
/// the offending PC (the transpiler is expected to reject them at
/// deblob, so this is just defence-in-depth).
#[inline]
fn rv_slot(x: u8) -> Option<usize> {
    match x {
        1 => Some(0),
        2 => Some(1),
        5..=15 => Some((x as usize) - 3),
        _ => None,
    }
}

/// True for x3 and x4 — registers that PVM2 reserves and the transpiler
/// must reject. If we ever see them at codegen time, we trap.
#[inline]
fn rv_is_reserved(x: u8) -> bool {
    x == 3 || x == 4
}

impl Compiler {
    /// Compile an RV+C+custom-0 byte stream into x86-64 in a single
    /// streaming pass.
    ///
    /// Decode + valid-PC + gas-block detection + gas simulation +
    /// codegen all happen in one walk over `code`. No `RvPredecode`
    /// intermediary — that was 57% of the old cold-path compile time
    /// on the large guests (ed25519, ecrecover).
    ///
    /// `jump_table_offsets` is the Image's CSR-style sub-table boundary
    /// array — see [`javm_cap::image::Image::jump_table_offsets`].
    /// Empty implies no br_table dispatch is used. Each
    /// `BrTable { table_id, .. }` instruction dispatches through sub-
    /// table `table_id`, whose entries live at
    /// `jt_ptr[jump_table_offsets[table_id] ..
    /// jump_table_offsets[table_id+1]]`.
    ///
    /// The returned `CompileResult.valid_pc` is the byte-indexed
    /// "valid branch target" bitmap the runtime BB region needs. A bit
    /// is set iff the PC is a gas-block start (= dispatchable entry in
    /// the gas-block dispatch table). Built incrementally during the
    /// streaming pass — no separate length-only pre-pass.
    pub fn compile_rv(mut self, code: &[u8], jump_table_offsets: &[u32]) -> CompileResult {
        self.rv_jt_offsets = jump_table_offsets.to_vec();

        // valid_pc is populated incrementally as the streaming pass
        // binds gas-block starts. The pointer is stable across mutation
        // (Vec doesn't reallocate from `vec![false; n]` with in-place
        // index assignment), so `is_basic_block_start` reads through
        // the raw pointer remain coherent.
        self.rv_valid_pc = vec![false; code.len()];
        self.bitmask_ptr = self.rv_valid_pc.as_ptr() as *const u8;
        self.bitmask_len = self.rv_valid_pc.len();
        self.rv_streaming = true;

        self.emit_prologue();

        let mut pending_gas: Option<(Label, u32, usize)> = None;
        let mut next_is_gas_start = true;
        let mut pc: usize = 0;

        while pc < code.len() {
            self.asm.ensure_capacity(512);

            // Length encoding lives in bits [1:0] of byte 0: `xx11` is
            // 4-byte, anything else is 2-byte (RVC). Decode no further
            // than that — the dispatcher inspects raw bits directly.
            if pc + 2 > code.len() {
                self.rv_emit_panic_at(pc as u32);
                break;
            }
            let is_4byte = code[pc] & 0b11 == 0b11;
            let base_len = if is_4byte { 4 } else { 2 };
            if pc + base_len > code.len() {
                self.rv_emit_panic_at(pc as u32);
                break;
            }

            let inst_pc = pc as u32;

            if next_is_gas_start {
                self.bind_rv_gas_block_start_streaming(inst_pc, &mut pending_gas);
                next_is_gas_start = false;
            }

            // Byte-based dispatch. Each path returns
            // `(is_terminator, preserve_cf, extra_bytes)`. `extra_bytes`
            // counts the *additional* bytes consumed beyond `base_len`
            // for lookahead fusion (e.g., Ld→Add fuses an extra 4-byte
            // Add). `preserve_cf` tells us whether to keep
            // `last_add_cf` alive for a following Sltu fusion.
            let rest = &code[pc + base_len..];
            let (term, preserve_cf, extra) = if is_4byte {
                let w = u32::from_le_bytes([code[pc], code[pc + 1], code[pc + 2], code[pc + 3]]);
                self.compile_rv4(w, inst_pc, rest)
            } else {
                let h = u16::from_le_bytes([code[pc], code[pc + 1]]);
                self.compile_rvc(h, inst_pc, rest)
            };

            if !preserve_cf {
                self.last_add_cf = None;
            }

            if term {
                next_is_gas_start = true;
            }

            pc += base_len + extra;
        }

        // Finalize the last gas block — patch its cost in.
        if let Some((stub_label, block_pc, patch_offset)) = pending_gas.take() {
            let cost = self.gas_sim.flush_and_get_cost();
            self.asm.patch_i32(patch_offset, cost as i32);
            self.oog_stubs.push((stub_label, block_pc, cost));
        }

        // Resolve deferred forward branches now that valid_pc is fully
        // populated. For each forward branch recorded with target > pc
        // at emit time:
        //   - valid target: label_for_pc(target) was bound during the
        //     streaming pass; the existing fixup resolves naturally.
        //   - invalid target: append a per-branch panic stub and
        //     redirect the fixup to it. Keeps the source PC of the
        //     branch in the exit report.
        // We disable rv_streaming first so emit_branch_* / panic helpers
        // called below take their non-deferred path.
        self.rv_streaming = false;
        let pending = core::mem::take(&mut self.rv_pending_fwd_branches);
        for (target, branch_pc, fixup_idx) in pending {
            if !self.is_basic_block_start(target) {
                let stub = self.asm.new_label();
                self.asm.bind_label(stub);
                self.asm.mov_store32_rip_rel_imm(CTX_PC, branch_pc as i32);
                self.asm.jmp_label(self.panic_label);
                self.asm.redirect_fixup(fixup_idx, stub);
            }
        }

        self.emit_exit_sequences();

        // Sparse dispatch entries — caller writes only these into the
        // (page-zero-filled) arena dispatch region. No code.len() + 1
        // intermediate Vec.
        let mut dispatch_entries: Vec<(u32, i32)> = Vec::with_capacity(self.gas_block_pcs.len());
        for &pc in self.gas_block_pcs.iter() {
            let label = Label(self.label_base + pc);
            if let Some(off) = self.asm.label_offset(label) {
                dispatch_entries.push((pc, off as i32));
            }
        }

        let exit_label_offset = self.asm.label_offset(self.exit_label).unwrap_or(0) as u32;
        let trap_table = core::mem::take(&mut self.trap_entries);
        let valid_pc = core::mem::take(&mut self.rv_valid_pc);

        CompileResult {
            native_code: self.asm.finalize(),
            dispatch_entries,
            trap_table,
            exit_label_offset,
            valid_pc,
        }
    }

    /// Streaming gas-block-start hook: bind label, flush prior block's
    /// cost into its `sub` patch, emit a fresh `sub r15, 0; js stub`
    /// placeholder and stash the patch offset in `pending`. Mirrors
    /// `Compiler::emit_gas_block_start` on the PVM path. Drives
    /// `self.gas_sim` directly so the per-arm `feed_gas_rv` calls in
    /// `compile_rv_instruction` see a coherent simulator.
    fn bind_rv_gas_block_start_streaming(
        &mut self,
        pc: u32,
        pending: &mut Option<(Label, u32, usize)>,
    ) {
        let label = Label(self.label_base + pc);
        self.asm.bind_label(label);
        self.gas_block_pcs.push(pc);
        // valid_pc is the gas-block-start bitmap consulted by both the
        // codegen-time `is_basic_block_start` check and the runtime's
        // djump validation. Set it here so backward branches emit time
        // see the bit (we walk PCs in order, so any T < cur_pc has
        // already passed through here if it's a gas-block start).
        // bitmask_ptr points to rv_valid_pc's heap buffer, so this
        // mutation is visible to subsequent is_basic_block_start reads.
        if (pc as usize) < self.rv_valid_pc.len() {
            self.rv_valid_pc[pc as usize] = true;
        }

        // Peephole state must not leak across gas-block boundaries: the
        // dispatch table can enter this block from any predecessor.
        self.invalidate_all_regs();
        self.last_add_cf = None;

        if let Some((stub_label, block_pc, patch_offset)) = pending.take() {
            let cost = self.gas_sim.flush_and_get_cost();
            self.asm.patch_i32(patch_offset, cost as i32);
            self.oog_stubs.push((stub_label, block_pc, cost));
        }
        self.gas_sim.reset();

        let stub_label = self.asm.new_label();
        self.asm.sub_r64_imm32_patchable(GAS, 0);
        let patch_offset = self.asm.offset() - 4;
        self.asm.jcc_label(Cc::S, stub_label);
        *pending = Some((stub_label, pc, patch_offset));
    }

    /// 4-byte RV instruction dispatch (byte-based).
    ///
    /// Returns `(is_terminator, preserve_cf, extra_bytes)`. `extra_bytes`
    /// counts the additional bytes (beyond the 4-byte base) consumed by
    /// lookahead fusion. `preserve_cf` tells the streaming loop whether
    /// to keep `last_add_cf` alive for a following Sltu fusion.
    ///
    /// Hot path: walks the opcode-major tree directly on raw bits, no
    /// `RvInst` enum constructed. Fusion sites (Ld→Add, Mul-pair) are
    /// inline at their dispatchers.
    fn compile_rv4(&mut self, w: u32, pc: u32, rest: &[u8]) -> (bool, bool, usize) {
        use javm_exec::gas_cost::*;
        let opcode = (w >> 2) & 0x1F;
        let rd = ((w >> 7) & 0x1F) as u8;
        let rs1 = ((w >> 15) & 0x1F) as u8;
        let rs2 = ((w >> 20) & 0x1F) as u8;
        let f3 = ((w >> 12) & 0x07) as u8;
        let f7 = ((w >> 25) & 0x7F) as u8;

        match opcode {
            OP_LOAD => self.compile_load(rd, rs1, f3, w, pc, rest),
            OP_STORE => self.compile_store(rs1, rs2, f3, w, pc),
            OP_IMM => self.compile_op_imm(rd, rs1, f3, w, pc),
            OP_OP_IMM_32 => self.compile_op_imm_32(rd, rs1, f3, w, pc),
            OP_OP => self.compile_op(rd, rs1, rs2, f3, f7, w, pc, rest),
            OP_OP_32 => self.compile_op_32(rd, rs1, rs2, f3, f7, w, pc),
            OP_LUI => self.compile_lui(rd, w, pc),
            OP_JAL => self.compile_jal(rd, w, pc),
            OP_BRANCH => self.compile_branch(rs1, rs2, f3, w, pc),
            OP_CUSTOM_0 => self.compile_custom_0(rd, rs1, f3, w, pc),
            OP_MISC_MEM => {
                // Fence / FenceI — no-op emit.
                self.feed_gas_rv(RV_KIND_FENCE, 0, 0, 0);
                (false, false, 0)
            }
            // OP_AUIPC, OP_JALR, OP_SYSTEM, OP_CUSTOM_1 etc. — all
            // forbidden in PVM2 and rejected by the linker's validator.
            // Defence in depth: emit a runtime panic if we ever see one.
            _ => {
                self.rv_emit_panic_at(pc);
                self.feed_gas_rv(RV_KIND_RESERVED, 0, 0, 0);
                (true, false, 0)
            }
        }
    }

    /// 2-byte RVC dispatch. Compressed instructions are rare in the
    /// gap-driving guests (~99% of code is uncompressed), so for now we
    /// bridge through `decompress` + `compile_rv_instruction` rather
    /// than duplicate the bit-shuffling for an RVC-native path. Forward
    /// `next_pc = pc + 2` to match what the legacy 2-byte fallthrough
    /// produced.
    fn compile_rvc(&mut self, h: u16, pc: u32, _rest: &[u8]) -> (bool, bool, usize) {
        let bytes = h.to_le_bytes();
        let (inst, _len) = javm_exec::rv_instruction::decode(&bytes)
            .expect("2-byte RVC decode of a valid prefix should not fail");
        let preserve_cf = matches!(inst, RvInst::Add { .. } | RvInst::Sltu { .. });
        let term = self.compile_rv_instruction(inst, pc, pc + 2);
        (term, preserve_cf, 0)
    }

    // === Per-opcode dispatchers (4-byte path) =====================

    fn compile_load(
        &mut self,
        rd: u8,
        rs1: u8,
        f3: u8,
        w: u32,
        pc: u32,
        rest: &[u8],
    ) -> (bool, bool, usize) {
        use javm_exec::gas_cost::*;
        let imm = imm_i(w);
        let (width, signed) = match f3 {
            0b000 => (1u32, true),
            0b001 => (2, true),
            0b010 => (4, true),
            0b011 => (8, false),
            0b100 => (1, false),
            0b101 => (2, false),
            0b110 => (4, false),
            _ => {
                self.rv_emit_panic_at(pc);
                self.feed_gas_rv(RV_KIND_RESERVED, 0, 0, 0);
                return (true, false, 0);
            }
        };
        // Ld→Add fusion: only triggers on the 64-bit `ld` (f3 == 0b011).
        // The fast-path mask test on the next word lets us cheaply reject
        // the common "Ld not followed by Add" case before extracting
        // fields. See commit `perf(pvm2): Ld→Add lookahead fusion`.
        if width == 8 && rd != 0 && !rv_is_reserved(rd) && !rv_is_reserved(rs1) && rest.len() >= 4 {
            let w2 = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]);
            if w2 & 0xFE00_707F == 0x0000_0033 {
                let a_rd = ((w2 >> 7) & 0x1F) as u8;
                let a_rs1 = ((w2 >> 15) & 0x1F) as u8;
                let a_rs2 = ((w2 >> 20) & 0x1F) as u8;
                if a_rd != 0
                    && !rv_is_reserved(a_rd)
                    && (a_rs1 == rd || a_rs2 == rd)
                    && (a_rs1 == 0 || !rv_is_reserved(a_rs1))
                    && (a_rs2 == 0 || !rv_is_reserved(a_rs2))
                {
                    self.rv_load(rd, rs1, imm, 8, false, pc);
                    self.feed_gas_rv(RV_KIND_LOAD, rs1, 0, rd);
                    let next_pc = pc + 4;
                    self.rv_alu_rr(a_rd, a_rs1, a_rs2, AluOp::Add, next_pc);
                    if a_rd != a_rs1 && a_rd != a_rs2 {
                        self.track_add_scaledadd(a_rd, a_rs1, a_rs2);
                    }
                    self.feed_gas_rv(RV_KIND_ADD, a_rs1, a_rs2, a_rd);
                    // The fused trailing op is an Add → preserve CF for
                    // a possible subsequent Sltu fusion.
                    return (false, true, 4);
                }
            }
        }
        self.rv_load(rd, rs1, imm, width, signed, pc);
        let term = self.feed_gas_rv(RV_KIND_LOAD, rs1, 0, rd);
        (term, false, 0)
    }

    fn compile_store(&mut self, rs1: u8, rs2: u8, f3: u8, w: u32, pc: u32) -> (bool, bool, usize) {
        use javm_exec::gas_cost::*;
        let imm = imm_s(w);
        let width = match f3 {
            0b000 => 1u32,
            0b001 => 2,
            0b010 => 4,
            0b011 => 8,
            _ => {
                self.rv_emit_panic_at(pc);
                self.feed_gas_rv(RV_KIND_RESERVED, 0, 0, 0);
                return (true, false, 0);
            }
        };
        self.rv_store(rs1, rs2, imm, width, pc);
        let term = self.feed_gas_rv(RV_KIND_STORE, rs1, rs2, 0);
        (term, false, 0)
    }

    fn compile_op_imm(&mut self, rd: u8, rs1: u8, f3: u8, w: u32, pc: u32) -> (bool, bool, usize) {
        use javm_exec::gas_cost::*;
        match f3 {
            0b000 => {
                // Addi
                let imm = imm_i(w);
                self.rv_alu_imm(rd, rs1, imm, AluImmOp::Add, pc);
                if rs1 == 0 {
                    self.track_const(rd, imm);
                }
                let term = self.feed_gas_rv(RV_KIND_ADDI, rs1, 0, rd);
                (term, false, 0)
            }
            0b010 => {
                let imm = imm_i(w);
                self.rv_slt_imm(rd, rs1, imm, true, pc);
                let term = self.feed_gas_rv(RV_KIND_ADDI, rs1, 0, rd);
                (term, false, 0)
            }
            0b011 => {
                let imm = imm_i(w);
                self.rv_slt_imm(rd, rs1, imm, false, pc);
                let term = self.feed_gas_rv(RV_KIND_ADDI, rs1, 0, rd);
                (term, false, 0)
            }
            0b100 => {
                let imm = imm_i(w);
                self.rv_alu_imm(rd, rs1, imm, AluImmOp::Xor, pc);
                let term = self.feed_gas_rv(RV_KIND_ADDI, rs1, 0, rd);
                (term, false, 0)
            }
            0b110 => {
                let imm = imm_i(w);
                self.rv_alu_imm(rd, rs1, imm, AluImmOp::Or, pc);
                let term = self.feed_gas_rv(RV_KIND_ADDI, rs1, 0, rd);
                (term, false, 0)
            }
            0b111 => {
                let imm = imm_i(w);
                self.rv_alu_imm(rd, rs1, imm, AluImmOp::And, pc);
                let term = self.feed_gas_rv(RV_KIND_ADDI, rs1, 0, rd);
                (term, false, 0)
            }
            0b001 => {
                // SLLI / Zbs Bclri / Bseti / Binvi / Zbb unary (clz, ctz,
                // cpop, sext.b, sext.h) — distinguished by funct6 (the
                // top 6 bits) + rs2 field for Zbb unaries.
                let shtype = (w >> 26) & 0x3F;
                let shamt = ((w >> 20) & 0x3F) as u8;
                let rs2_field = (w >> 20) & 0x1F;
                match shtype {
                    0b000000 => {
                        self.rv_shift_imm(rd, rs1, shamt, ShiftOp::Shl64, pc);
                        if (1..=3).contains(&shamt) && rs1 != rd {
                            self.track_shifted(rd, rs1, shamt);
                        }
                        let term = self.feed_gas_rv(RV_KIND_ADDI, rs1, 0, rd);
                        (term, false, 0)
                    }
                    0b010010 => {
                        self.rv_bit_imm(rd, rs1, shamt, BitOp::Clear, pc);
                        let term = self.feed_gas_rv(RV_KIND_ZBS_IMM, rs1, 0, rd);
                        (term, false, 0)
                    }
                    0b001010 => {
                        self.rv_bit_imm(rd, rs1, shamt, BitOp::Set, pc);
                        let term = self.feed_gas_rv(RV_KIND_ZBS_IMM, rs1, 0, rd);
                        (term, false, 0)
                    }
                    0b011010 => {
                        self.rv_bit_imm(rd, rs1, shamt, BitOp::Invert, pc);
                        let term = self.feed_gas_rv(RV_KIND_ZBS_IMM, rs1, 0, rd);
                        (term, false, 0)
                    }
                    0b011000 => {
                        let (op, kind) = match rs2_field {
                            0b00000 => (UnaryOp::Clz64, RV_KIND_ZBB_U1),
                            0b00001 => (UnaryOp::Ctz64, RV_KIND_ZBB_CTZ),
                            0b00010 => (UnaryOp::Popcnt64, RV_KIND_ZBB_U1),
                            0b00100 => (UnaryOp::SextB, RV_KIND_ZBB_U1),
                            0b00101 => (UnaryOp::SextH, RV_KIND_ZBB_U1),
                            _ => {
                                self.rv_emit_panic_at(pc);
                                self.feed_gas_rv(RV_KIND_RESERVED, 0, 0, 0);
                                return (true, false, 0);
                            }
                        };
                        self.rv_unary(rd, rs1, op, pc);
                        let term = self.feed_gas_rv(kind, rs1, 0, rd);
                        (term, false, 0)
                    }
                    _ => {
                        self.rv_emit_panic_at(pc);
                        self.feed_gas_rv(RV_KIND_RESERVED, 0, 0, 0);
                        (true, false, 0)
                    }
                }
            }
            0b101 => {
                // SRLI / SRAI / Bexti / Rori / OrcB / Rev8.
                let shtype = (w >> 26) & 0x3F;
                let shamt = ((w >> 20) & 0x3F) as u8;
                let rs2_field = (w >> 20) & 0x1F;
                match shtype {
                    0b000000 => {
                        self.rv_shift_imm(rd, rs1, shamt, ShiftOp::Shr64, pc);
                        let term = self.feed_gas_rv(RV_KIND_ADDI, rs1, 0, rd);
                        (term, false, 0)
                    }
                    0b010000 => {
                        self.rv_shift_imm(rd, rs1, shamt, ShiftOp::Sar64, pc);
                        let term = self.feed_gas_rv(RV_KIND_ADDI, rs1, 0, rd);
                        (term, false, 0)
                    }
                    0b010010 => {
                        self.rv_bit_imm(rd, rs1, shamt, BitOp::Extract, pc);
                        let term = self.feed_gas_rv(RV_KIND_ZBS_IMM, rs1, 0, rd);
                        (term, false, 0)
                    }
                    0b011000 => {
                        self.rv_shift_imm(rd, rs1, shamt, ShiftOp::Ror64, pc);
                        let term = self.feed_gas_rv(RV_KIND_ZBB_RORI, rs1, 0, rd);
                        (term, false, 0)
                    }
                    0b001010 if rs2_field == 0b00111 => {
                        self.rv_unary(rd, rs1, UnaryOp::OrcB, pc);
                        let term = self.feed_gas_rv(RV_KIND_ZBB_U1, rs1, 0, rd);
                        (term, false, 0)
                    }
                    0b011010 if rs2_field == 0b11000 => {
                        self.rv_unary(rd, rs1, UnaryOp::Rev8, pc);
                        let term = self.feed_gas_rv(RV_KIND_ZBB_U1, rs1, 0, rd);
                        (term, false, 0)
                    }
                    _ => {
                        self.rv_emit_panic_at(pc);
                        self.feed_gas_rv(RV_KIND_RESERVED, 0, 0, 0);
                        (true, false, 0)
                    }
                }
            }
            _ => {
                self.rv_emit_panic_at(pc);
                self.feed_gas_rv(RV_KIND_RESERVED, 0, 0, 0);
                (true, false, 0)
            }
        }
    }

    fn compile_op_imm_32(
        &mut self,
        rd: u8,
        rs1: u8,
        f3: u8,
        w: u32,
        pc: u32,
    ) -> (bool, bool, usize) {
        use javm_exec::gas_cost::*;
        match f3 {
            0b000 => {
                let imm = imm_i(w);
                self.rv_alu_imm(rd, rs1, imm, AluImmOp::Addw, pc);
                let term = self.feed_gas_rv(RV_KIND_ADDIW, rs1, 0, rd);
                (term, false, 0)
            }
            0b001 => {
                let f7 = (w >> 25) & 0x7F;
                let shamt5 = ((w >> 20) & 0x1F) as u8;
                match f7 {
                    0b0000000 => {
                        self.rv_shift_imm(rd, rs1, shamt5, ShiftOp::Shl32, pc);
                        let term = self.feed_gas_rv(RV_KIND_ADDIW, rs1, 0, rd);
                        (term, false, 0)
                    }
                    0b0000100 => {
                        // Slli.uw — uses 6-bit shamt (RV64).
                        let shamt6 = ((w >> 20) & 0x3F) as u8;
                        self.rv_slliuw(rd, rs1, shamt6, pc);
                        let term = self.feed_gas_rv(RV_KIND_ZBA_IMM, rs1, 0, rd);
                        (term, false, 0)
                    }
                    0b0110000 => {
                        let rs2_field = (w >> 20) & 0x1F;
                        let op = match rs2_field {
                            0b00000 => UnaryOp::Clz32,
                            0b00001 => UnaryOp::Ctz32,
                            0b00010 => UnaryOp::Popcnt32,
                            _ => {
                                self.rv_emit_panic_at(pc);
                                self.feed_gas_rv(RV_KIND_RESERVED, 0, 0, 0);
                                return (true, false, 0);
                            }
                        };
                        let kind = if matches!(op, UnaryOp::Ctz32) {
                            RV_KIND_ZBB_CTZ
                        } else {
                            RV_KIND_ZBB_U1
                        };
                        self.rv_unary(rd, rs1, op, pc);
                        let term = self.feed_gas_rv(kind, rs1, 0, rd);
                        (term, false, 0)
                    }
                    _ => {
                        self.rv_emit_panic_at(pc);
                        self.feed_gas_rv(RV_KIND_RESERVED, 0, 0, 0);
                        (true, false, 0)
                    }
                }
            }
            0b101 => {
                let f7 = (w >> 25) & 0x7F;
                let shamt5 = ((w >> 20) & 0x1F) as u8;
                match f7 {
                    0b0000000 => {
                        self.rv_shift_imm(rd, rs1, shamt5, ShiftOp::Shr32, pc);
                        let term = self.feed_gas_rv(RV_KIND_ADDIW, rs1, 0, rd);
                        (term, false, 0)
                    }
                    0b0100000 => {
                        self.rv_shift_imm(rd, rs1, shamt5, ShiftOp::Sar32, pc);
                        let term = self.feed_gas_rv(RV_KIND_ADDIW, rs1, 0, rd);
                        (term, false, 0)
                    }
                    0b0110000 => {
                        self.rv_shift_imm(rd, rs1, shamt5, ShiftOp::Ror32, pc);
                        let term = self.feed_gas_rv(RV_KIND_ZBB_RORIW, rs1, 0, rd);
                        (term, false, 0)
                    }
                    _ => {
                        self.rv_emit_panic_at(pc);
                        self.feed_gas_rv(RV_KIND_RESERVED, 0, 0, 0);
                        (true, false, 0)
                    }
                }
            }
            _ => {
                self.rv_emit_panic_at(pc);
                self.feed_gas_rv(RV_KIND_RESERVED, 0, 0, 0);
                (true, false, 0)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn compile_op(
        &mut self,
        rd: u8,
        rs1: u8,
        rs2: u8,
        f3: u8,
        f7: u8,
        w: u32,
        pc: u32,
        rest: &[u8],
    ) -> (bool, bool, usize) {
        use javm_exec::gas_cost::*;
        // Mul-pair fusion: a 64-bit `mul` (f7=0000001, f3=000) followed
        // by `mulh`/`mulhu` on the SAME operand pair folds into a single
        // x86 imul/mul that produces RDX:RAX (lo:hi). See commit
        // `perf(pvm2): mul-pair fusion`.
        if f7 == 0b0000001
            && f3 == 0b000
            && let Some(extra) = self.try_fuse_mul_pair_bytes(rd, rs1, rs2, rest, pc)
        {
            return (false, false, extra);
        }
        match (f7, f3) {
            (0b0000000, 0b000) => {
                self.rv_alu_rr(rd, rs1, rs2, AluOp::Add, pc);
                if rd != rs1 && rd != rs2 {
                    self.track_add_scaledadd(rd, rs1, rs2);
                }
                let term = self.feed_gas_rv(RV_KIND_ADD, rs1, rs2, rd);
                (term, true, 0)
            }
            (0b0100000, 0b000) => {
                self.rv_alu_rr(rd, rs1, rs2, AluOp::Sub, pc);
                let term = self.feed_gas_rv(RV_KIND_ADD, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0000000, 0b001) => {
                self.rv_shift_rr(rd, rs1, rs2, ShiftOp::Shl64, pc);
                let term = self.feed_gas_rv(RV_KIND_SLL, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0000000, 0b010) => {
                self.rv_slt_rr(rd, rs1, rs2, true, pc);
                let term = self.feed_gas_rv(RV_KIND_SLT, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0000000, 0b011) => {
                // Sltu — preserve_cf so the next-instruction CF clear
                // doesn't trample a pending Add's flags before rv_slt_rr
                // had a chance to consume them. (Note: rv_slt_rr already
                // handles the case where last_add_cf is stale; we just
                // skip the post-emit clear here to mirror the legacy
                // behaviour.)
                self.rv_slt_rr(rd, rs1, rs2, false, pc);
                let term = self.feed_gas_rv(RV_KIND_SLT, rs1, rs2, rd);
                (term, true, 0)
            }
            (0b0000000, 0b100) => {
                self.rv_alu_rr(rd, rs1, rs2, AluOp::Xor, pc);
                let term = self.feed_gas_rv(RV_KIND_ADD, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0000000, 0b101) => {
                self.rv_shift_rr(rd, rs1, rs2, ShiftOp::Shr64, pc);
                let term = self.feed_gas_rv(RV_KIND_SLL, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0100000, 0b101) => {
                self.rv_shift_rr(rd, rs1, rs2, ShiftOp::Sar64, pc);
                let term = self.feed_gas_rv(RV_KIND_SLL, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0000000, 0b110) => {
                self.rv_alu_rr(rd, rs1, rs2, AluOp::Or, pc);
                let term = self.feed_gas_rv(RV_KIND_ADD, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0000000, 0b111) => {
                self.rv_alu_rr(rd, rs1, rs2, AluOp::And, pc);
                let term = self.feed_gas_rv(RV_KIND_ADD, rs1, rs2, rd);
                (term, false, 0)
            }
            // M extension
            (0b0000001, 0b000) => {
                self.rv_alu_rr(rd, rs1, rs2, AluOp::Mul, pc);
                let term = self.feed_gas_rv(RV_KIND_MUL, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0000001, 0b001) => {
                self.rv_mulh(rd, rs1, rs2, true, true, pc);
                let term = self.feed_gas_rv(RV_KIND_MULH, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0000001, 0b010) => {
                self.rv_mulh(rd, rs1, rs2, true, false, pc);
                let term = self.feed_gas_rv(RV_KIND_MULHSU, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0000001, 0b011) => {
                self.rv_mulh(rd, rs1, rs2, false, false, pc);
                let term = self.feed_gas_rv(RV_KIND_MULH, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0000001, 0b100) => {
                self.rv_div_rem(rd, rs1, rs2, true, false, false, pc);
                let term = self.feed_gas_rv(RV_KIND_DIV, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0000001, 0b101) => {
                self.rv_div_rem(rd, rs1, rs2, false, false, false, pc);
                let term = self.feed_gas_rv(RV_KIND_DIV, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0000001, 0b110) => {
                self.rv_div_rem(rd, rs1, rs2, true, true, false, pc);
                let term = self.feed_gas_rv(RV_KIND_DIV, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0000001, 0b111) => {
                self.rv_div_rem(rd, rs1, rs2, false, true, false, pc);
                let term = self.feed_gas_rv(RV_KIND_DIV, rs1, rs2, rd);
                (term, false, 0)
            }
            // Zbb inv / xnor / min / max
            (0b0100000, 0b111) => {
                self.rv_alu_rr(rd, rs1, rs2, AluOp::Andn, pc);
                let term = self.feed_gas_rv(RV_KIND_ZBB_INV, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0100000, 0b110) => {
                self.rv_alu_rr(rd, rs1, rs2, AluOp::Orn, pc);
                let term = self.feed_gas_rv(RV_KIND_ZBB_INV, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0100000, 0b100) => {
                self.rv_alu_rr(rd, rs1, rs2, AluOp::Xnor, pc);
                let term = self.feed_gas_rv(RV_KIND_ZBB_XNOR, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0000101, 0b100) => {
                self.rv_alu_rr(rd, rs1, rs2, AluOp::Min, pc);
                let term = self.feed_gas_rv(RV_KIND_ZBB_MINMAX, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0000101, 0b101) => {
                self.rv_alu_rr(rd, rs1, rs2, AluOp::Minu, pc);
                let term = self.feed_gas_rv(RV_KIND_ZBB_MINMAX, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0000101, 0b110) => {
                self.rv_alu_rr(rd, rs1, rs2, AluOp::Max, pc);
                let term = self.feed_gas_rv(RV_KIND_ZBB_MINMAX, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0000101, 0b111) => {
                self.rv_alu_rr(rd, rs1, rs2, AluOp::Maxu, pc);
                let term = self.feed_gas_rv(RV_KIND_ZBB_MINMAX, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0110000, 0b001) => {
                self.rv_shift_rr(rd, rs1, rs2, ShiftOp::Rol64, pc);
                let term = self.feed_gas_rv(RV_KIND_ZBB_ROT, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0110000, 0b101) => {
                self.rv_shift_rr(rd, rs1, rs2, ShiftOp::Ror64, pc);
                let term = self.feed_gas_rv(RV_KIND_ZBB_ROT, rs1, rs2, rd);
                (term, false, 0)
            }
            // Zba shift-add
            (0b0010000, 0b010) => {
                self.rv_shadd(rd, rs1, rs2, 1, false, pc);
                self.record_scaledadd(rd, rs1, rs2, 1);
                let term = self.feed_gas_rv(RV_KIND_ZBA, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0010000, 0b100) => {
                self.rv_shadd(rd, rs1, rs2, 2, false, pc);
                self.record_scaledadd(rd, rs1, rs2, 2);
                let term = self.feed_gas_rv(RV_KIND_ZBA, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0010000, 0b110) => {
                self.rv_shadd(rd, rs1, rs2, 3, false, pc);
                self.record_scaledadd(rd, rs1, rs2, 3);
                let term = self.feed_gas_rv(RV_KIND_ZBA, rs1, rs2, rd);
                (term, false, 0)
            }
            // Zbs
            (0b0100100, 0b001) => {
                self.rv_bit_rr(rd, rs1, rs2, BitOp::Clear, pc);
                let term = self.feed_gas_rv(RV_KIND_ZBS, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0010100, 0b001) => {
                self.rv_bit_rr(rd, rs1, rs2, BitOp::Set, pc);
                let term = self.feed_gas_rv(RV_KIND_ZBS, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0110100, 0b001) => {
                self.rv_bit_rr(rd, rs1, rs2, BitOp::Invert, pc);
                let term = self.feed_gas_rv(RV_KIND_ZBS, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0100100, 0b101) => {
                self.rv_bit_rr(rd, rs1, rs2, BitOp::Extract, pc);
                let term = self.feed_gas_rv(RV_KIND_ZBS, rs1, rs2, rd);
                (term, false, 0)
            }
            // Zicond
            (0b0000111, 0b101) => {
                self.rv_czero(rd, rs1, rs2, Cc::E, pc);
                let term = self.feed_gas_rv(RV_KIND_ZICOND, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0000111, 0b111) => {
                self.rv_czero(rd, rs1, rs2, Cc::NE, pc);
                let term = self.feed_gas_rv(RV_KIND_ZICOND, rs1, rs2, rd);
                (term, false, 0)
            }
            // Zbb zext.h via pack rd, rs1, x0
            (0b0000100, 0b100) if rs2 == 0 => {
                self.rv_unary(rd, rs1, UnaryOp::ZextH, pc);
                let term = self.feed_gas_rv(RV_KIND_ZBB_U1, rs1, 0, rd);
                (term, false, 0)
            }
            _ => {
                let _ = w;
                self.rv_emit_panic_at(pc);
                self.feed_gas_rv(RV_KIND_RESERVED, 0, 0, 0);
                (true, false, 0)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn compile_op_32(
        &mut self,
        rd: u8,
        rs1: u8,
        rs2: u8,
        f3: u8,
        f7: u8,
        w: u32,
        pc: u32,
    ) -> (bool, bool, usize) {
        use javm_exec::gas_cost::*;
        match (f7, f3) {
            (0b0000000, 0b000) => {
                self.rv_alu_rr(rd, rs1, rs2, AluOp::Addw, pc);
                let term = self.feed_gas_rv(RV_KIND_ADDW, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0100000, 0b000) => {
                self.rv_alu_rr(rd, rs1, rs2, AluOp::Subw, pc);
                let term = self.feed_gas_rv(RV_KIND_ADDW, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0000000, 0b001) => {
                self.rv_shift_rr(rd, rs1, rs2, ShiftOp::Shl32, pc);
                let term = self.feed_gas_rv(RV_KIND_SLLW, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0000000, 0b101) => {
                self.rv_shift_rr(rd, rs1, rs2, ShiftOp::Shr32, pc);
                let term = self.feed_gas_rv(RV_KIND_SLLW, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0100000, 0b101) => {
                self.rv_shift_rr(rd, rs1, rs2, ShiftOp::Sar32, pc);
                let term = self.feed_gas_rv(RV_KIND_SLLW, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0000001, 0b000) => {
                self.rv_alu_rr(rd, rs1, rs2, AluOp::Mulw, pc);
                let term = self.feed_gas_rv(RV_KIND_MULW, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0000001, 0b100) => {
                self.rv_div_rem(rd, rs1, rs2, true, false, true, pc);
                let term = self.feed_gas_rv(RV_KIND_DIV, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0000001, 0b101) => {
                self.rv_div_rem(rd, rs1, rs2, false, false, true, pc);
                let term = self.feed_gas_rv(RV_KIND_DIV, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0000001, 0b110) => {
                self.rv_div_rem(rd, rs1, rs2, true, true, true, pc);
                let term = self.feed_gas_rv(RV_KIND_DIV, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0000001, 0b111) => {
                self.rv_div_rem(rd, rs1, rs2, false, true, true, pc);
                let term = self.feed_gas_rv(RV_KIND_DIV, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0110000, 0b001) => {
                self.rv_shift_rr(rd, rs1, rs2, ShiftOp::Rol32, pc);
                let term = self.feed_gas_rv(RV_KIND_ZBB_ROTW, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0110000, 0b101) => {
                self.rv_shift_rr(rd, rs1, rs2, ShiftOp::Ror32, pc);
                let term = self.feed_gas_rv(RV_KIND_ZBB_ROTW, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0000100, 0b000) => {
                self.rv_adduw(rd, rs1, rs2, pc);
                let term = self.feed_gas_rv(RV_KIND_ZBA, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0010000, 0b010) => {
                self.rv_shadd(rd, rs1, rs2, 1, true, pc);
                let term = self.feed_gas_rv(RV_KIND_ZBA, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0010000, 0b100) => {
                self.rv_shadd(rd, rs1, rs2, 2, true, pc);
                let term = self.feed_gas_rv(RV_KIND_ZBA, rs1, rs2, rd);
                (term, false, 0)
            }
            (0b0010000, 0b110) => {
                self.rv_shadd(rd, rs1, rs2, 3, true, pc);
                let term = self.feed_gas_rv(RV_KIND_ZBA, rs1, rs2, rd);
                (term, false, 0)
            }
            _ => {
                let _ = w;
                self.rv_emit_panic_at(pc);
                self.feed_gas_rv(RV_KIND_RESERVED, 0, 0, 0);
                (true, false, 0)
            }
        }
    }

    fn compile_lui(&mut self, rd: u8, w: u32, pc: u32) -> (bool, bool, usize) {
        use javm_exec::gas_cost::*;
        let imm = imm_u(w);
        self.rv_lui(rd, imm, pc);
        self.track_const(rd, imm);
        let term = self.feed_gas_rv(RV_KIND_LUI, 0, 0, rd);
        (term, false, 0)
    }

    fn compile_jal(&mut self, rd: u8, w: u32, pc: u32) -> (bool, bool, usize) {
        use javm_exec::gas_cost::*;
        let imm = imm_j(w);
        let next_pc = pc + 4;
        self.rv_jal(rd, imm, pc, next_pc);
        let term = self.feed_gas_rv(RV_KIND_JAL, 0, 0, rd);
        (term, false, 0)
    }

    fn compile_branch(&mut self, rs1: u8, rs2: u8, f3: u8, w: u32, pc: u32) -> (bool, bool, usize) {
        use javm_exec::gas_cost::*;
        let imm = imm_b(w);
        let next_pc = pc + 4;
        let cc = match f3 {
            0b000 => Cc::E,
            0b001 => Cc::NE,
            0b100 => Cc::L,
            0b101 => Cc::GE,
            0b110 => Cc::B,
            0b111 => Cc::AE,
            _ => {
                self.rv_emit_panic_at(pc);
                self.feed_gas_rv(RV_KIND_RESERVED, 0, 0, 0);
                return (true, false, 0);
            }
        };
        self.rv_branch(rs1, rs2, imm, cc, pc, next_pc);
        let term = self.feed_gas_rv(RV_KIND_BRANCH, rs1, rs2, 0);
        (term, false, 0)
    }

    fn compile_custom_0(
        &mut self,
        rd: u8,
        rs1: u8,
        f3: u8,
        w: u32,
        pc: u32,
    ) -> (bool, bool, usize) {
        use javm_exec::gas_cost::*;
        // PVM2 custom-0 encoding:
        //   f3=000 → trap     (other fields ignored)
        //   f3=001 → ecall.jar
        //   f3=010 → ecalli imm
        //   f3=011 → br_table table_id, rs1 (rd must be 0)
        //   f3=100 → fallthrough (terminator no-op)
        let next_pc = pc + 4;
        match f3 {
            0b000 => {
                self.rv_trap(pc);
                let term = self.feed_gas_rv(RV_KIND_TRAP, 0, 0, 0);
                (term, false, 0)
            }
            0b001 => {
                self.rv_ecall_jar(next_pc);
                let term = self.feed_gas_rv(RV_KIND_ECALL_JAR, 0, 0, 0);
                (term, false, 0)
            }
            0b010 => {
                let imm = imm_i(w);
                self.rv_ecalli(imm, next_pc);
                let term = self.feed_gas_rv(RV_KIND_ECALLI, 0, 0, 0);
                (term, false, 0)
            }
            0b011 => {
                if rd != 0 {
                    self.rv_emit_panic_at(pc);
                    self.feed_gas_rv(RV_KIND_RESERVED, 0, 0, 0);
                    return (true, false, 0);
                }
                let table_id = ((w >> 20) & 0xFFF) as u16;
                self.rv_br_table(table_id, rs1, pc, next_pc);
                let term = self.feed_gas_rv(RV_KIND_BR_TABLE, rs1, 0, 0);
                (term, false, 0)
            }
            0b100 => {
                let term = self.feed_gas_rv(RV_KIND_FALLTHROUGH, 0, 0, 0);
                (term, false, 0)
            }
            _ => {
                self.rv_emit_panic_at(pc);
                self.feed_gas_rv(RV_KIND_RESERVED, 0, 0, 0);
                (true, false, 0)
            }
        }
    }

    /// Byte-based Mul-pair fusion: a 64-bit `mul rd1, rs1, rs2` followed
    /// by `mulh`/`mulhu rd2, rs1, rs2` (same operand pair, different
    /// destination) folds into a single x86 mul/imul that produces
    /// RDX:RAX. Returns `Some(extra_bytes_consumed)` on success.
    fn try_fuse_mul_pair_bytes(
        &mut self,
        m_rd: u8,
        m_rs1: u8,
        m_rs2: u8,
        rest: &[u8],
        _pc: u32,
    ) -> Option<usize> {
        use javm_exec::gas_cost::*;
        if rest.len() < 4 {
            return None;
        }
        let w2 = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]);
        // Mulh: f7=0000001 f3=001. Mulhu: f7=0000001 f3=011.
        // Mask catches both: opcode 0x33 + f7=1 + (f3=001 or f3=011).
        let signed = match w2 & 0xFE00_707F {
            0x0200_1033 => true,  // Mulh
            0x0200_3033 => false, // Mulhu
            _ => return None,
        };
        let u_rd = ((w2 >> 7) & 0x1F) as u8;
        let u_rs1 = ((w2 >> 15) & 0x1F) as u8;
        let u_rs2 = ((w2 >> 20) & 0x1F) as u8;
        if u_rs1 != m_rs1 || u_rs2 != m_rs2 || u_rd == m_rd {
            return None;
        }
        if rv_is_reserved(m_rd) || rv_is_reserved(u_rd) {
            return None;
        }
        if rv_is_reserved(m_rs1) || rv_is_reserved(m_rs2) {
            return None;
        }
        let (rs1_slot, rs2_slot) = (rv_slot(m_rs1)?, rv_slot(m_rs2)?);
        let (lo_slot, hi_slot) = (rv_slot(m_rd)?, rv_slot(u_rd)?);

        let a = REG_MAP[rs1_slot];
        let b = REG_MAP[rs2_slot];
        let rd_lo = REG_MAP[lo_slot];
        let rd_hi = REG_MAP[hi_slot];
        let phi11 = REG_MAP[11];

        let need_save_phi11 = rd_lo != phi11 && rd_hi != phi11;
        if need_save_phi11 {
            self.asm.push(phi11);
        }
        let mul_src = if b == phi11 {
            if need_save_phi11 {
                self.asm.mov_load64(SCRATCH, Reg::RSP, 0);
            } else {
                self.asm.mov_rr(SCRATCH, b);
            }
            SCRATCH
        } else {
            b
        };
        if a != phi11 {
            self.asm.mov_rr(phi11, a);
        }
        if signed {
            self.asm.imul_rdx_rax(mul_src);
        } else {
            self.asm.mul_rdx_rax(mul_src);
        }
        if rd_lo != phi11 {
            self.asm.mov_rr(rd_lo, phi11);
        }
        if rd_hi != Reg::RDX {
            self.asm.mov_rr(rd_hi, Reg::RDX);
        }
        if need_save_phi11 {
            self.asm.pop(phi11);
        }

        self.invalidate_reg(lo_slot);
        self.invalidate_reg(hi_slot);
        self.last_add_cf = None;

        // Feed gas for both consumed instructions (Mul + Mulh/Mulhu).
        // Both Mulh and Mulhu use RV_KIND_MULH per the gas table.
        let _ = signed;
        self.feed_gas_rv(RV_KIND_MUL, m_rs1, m_rs2, m_rd);
        self.feed_gas_rv(RV_KIND_MULH, u_rs1, u_rs2, u_rd);

        Some(4)
    }

    /// Legacy: single match over `RvInst`. Used only by the predecode
    /// path's smoke testing; the streaming compile loop now dispatches
    /// directly on raw bytes via [`Compiler::compile_rv4`] /
    /// [`Compiler::compile_rvc`]. Each arm:
    ///
    /// 1. Calls its `rv_*` emit helper.
    /// 2. Calls `self.feed_gas_rv(KIND, rs1, rs2, rd)` — the kind is a
    ///    compile-time constant matching the (kind, rs1, rs2, rd)
    ///    tuple produced by `rv_op_metadata` in `gas_cost.rs`. Slot
    ///    translation (RV reg → 0..12 or 0xFF) is handled inside
    ///    `feed_gas_rv` via `rv_slot_or_ff`.
    /// 3. Returns `is_terminator` directly from `feed_gas_rv` (the
    ///    RVF_TERM flag from the LUT entry).
    ///
    /// Pairs/groups of variants that share a gas-kind (e.g. all
    /// 64-bit I-type ALU ops use RV_KIND_ADDI) collapse via or-
    /// patterns where the emit op differs only in a helper argument.
    fn compile_rv_instruction(&mut self, inst: RvInst, pc: u32, next_pc: u32) -> bool {
        use RvInst::*;
        use javm_exec::gas_cost::*;
        match inst {
            // ---- RV64I loads (all RV_KIND_LOAD) ----
            Lb { rd, rs1, imm } => {
                self.rv_load(rd, rs1, imm, 1, true, pc);
                self.feed_gas_rv(RV_KIND_LOAD, rs1, 0, rd)
            }
            Lh { rd, rs1, imm } => {
                self.rv_load(rd, rs1, imm, 2, true, pc);
                self.feed_gas_rv(RV_KIND_LOAD, rs1, 0, rd)
            }
            Lw { rd, rs1, imm } => {
                self.rv_load(rd, rs1, imm, 4, true, pc);
                self.feed_gas_rv(RV_KIND_LOAD, rs1, 0, rd)
            }
            Ld { rd, rs1, imm } => {
                self.rv_load(rd, rs1, imm, 8, false, pc);
                self.feed_gas_rv(RV_KIND_LOAD, rs1, 0, rd)
            }
            Lbu { rd, rs1, imm } => {
                self.rv_load(rd, rs1, imm, 1, false, pc);
                self.feed_gas_rv(RV_KIND_LOAD, rs1, 0, rd)
            }
            Lhu { rd, rs1, imm } => {
                self.rv_load(rd, rs1, imm, 2, false, pc);
                self.feed_gas_rv(RV_KIND_LOAD, rs1, 0, rd)
            }
            Lwu { rd, rs1, imm } => {
                self.rv_load(rd, rs1, imm, 4, false, pc);
                self.feed_gas_rv(RV_KIND_LOAD, rs1, 0, rd)
            }

            // ---- RV64I stores (all RV_KIND_STORE) ----
            Sb { rs1, rs2, imm } => {
                self.rv_store(rs1, rs2, imm, 1, pc);
                self.feed_gas_rv(RV_KIND_STORE, rs1, rs2, 0)
            }
            Sh { rs1, rs2, imm } => {
                self.rv_store(rs1, rs2, imm, 2, pc);
                self.feed_gas_rv(RV_KIND_STORE, rs1, rs2, 0)
            }
            Sw { rs1, rs2, imm } => {
                self.rv_store(rs1, rs2, imm, 4, pc);
                self.feed_gas_rv(RV_KIND_STORE, rs1, rs2, 0)
            }
            Sd { rs1, rs2, imm } => {
                self.rv_store(rs1, rs2, imm, 8, pc);
                self.feed_gas_rv(RV_KIND_STORE, rs1, rs2, 0)
            }

            // ---- RV64I ALU imm (64-bit) — RV_KIND_ADDI ----
            Addi { rd, rs1, imm } => {
                self.rv_alu_imm(rd, rs1, imm, AluImmOp::Add, pc);
                if rs1 == 0 {
                    // canonical RV `li rd, imm` — track Const
                    self.track_const(rd, imm);
                }
                self.feed_gas_rv(RV_KIND_ADDI, rs1, 0, rd)
            }
            Slti { rd, rs1, imm } => {
                self.rv_slt_imm(rd, rs1, imm, true, pc);
                self.feed_gas_rv(RV_KIND_ADDI, rs1, 0, rd)
            }
            Sltiu { rd, rs1, imm } => {
                self.rv_slt_imm(rd, rs1, imm, false, pc);
                self.feed_gas_rv(RV_KIND_ADDI, rs1, 0, rd)
            }
            Andi { rd, rs1, imm } => {
                self.rv_alu_imm(rd, rs1, imm, AluImmOp::And, pc);
                self.feed_gas_rv(RV_KIND_ADDI, rs1, 0, rd)
            }
            Ori { rd, rs1, imm } => {
                self.rv_alu_imm(rd, rs1, imm, AluImmOp::Or, pc);
                self.feed_gas_rv(RV_KIND_ADDI, rs1, 0, rd)
            }
            Xori { rd, rs1, imm } => {
                self.rv_alu_imm(rd, rs1, imm, AluImmOp::Xor, pc);
                self.feed_gas_rv(RV_KIND_ADDI, rs1, 0, rd)
            }
            Slli { rd, rs1, shamt } => {
                self.rv_shift_imm(rd, rs1, shamt, ShiftOp::Shl64, pc);
                if (1..=3).contains(&shamt) && rs1 != rd {
                    self.track_shifted(rd, rs1, shamt);
                }
                self.feed_gas_rv(RV_KIND_ADDI, rs1, 0, rd)
            }
            Srli { rd, rs1, shamt } => {
                self.rv_shift_imm(rd, rs1, shamt, ShiftOp::Shr64, pc);
                self.feed_gas_rv(RV_KIND_ADDI, rs1, 0, rd)
            }
            Srai { rd, rs1, shamt } => {
                self.rv_shift_imm(rd, rs1, shamt, ShiftOp::Sar64, pc);
                self.feed_gas_rv(RV_KIND_ADDI, rs1, 0, rd)
            }

            // ---- RV64I ALU imm (32-bit, sign-extended) — RV_KIND_ADDIW ----
            Addiw { rd, rs1, imm } => {
                self.rv_alu_imm(rd, rs1, imm, AluImmOp::Addw, pc);
                self.feed_gas_rv(RV_KIND_ADDIW, rs1, 0, rd)
            }
            Slliw { rd, rs1, shamt } => {
                self.rv_shift_imm(rd, rs1, shamt, ShiftOp::Shl32, pc);
                self.feed_gas_rv(RV_KIND_ADDIW, rs1, 0, rd)
            }
            Srliw { rd, rs1, shamt } => {
                self.rv_shift_imm(rd, rs1, shamt, ShiftOp::Shr32, pc);
                self.feed_gas_rv(RV_KIND_ADDIW, rs1, 0, rd)
            }
            Sraiw { rd, rs1, shamt } => {
                self.rv_shift_imm(rd, rs1, shamt, ShiftOp::Sar32, pc);
                self.feed_gas_rv(RV_KIND_ADDIW, rs1, 0, rd)
            }

            // ---- RV64I ALU reg-reg (64-bit) — RV_KIND_ADD ----
            Add { rd, rs1, rs2 } => {
                self.rv_alu_rr(rd, rs1, rs2, AluOp::Add, pc);
                if rd != rs1 && rd != rs2 {
                    // Promote to ScaledAdd if one operand is Shifted.
                    self.track_add_scaledadd(rd, rs1, rs2);
                }
                self.feed_gas_rv(RV_KIND_ADD, rs1, rs2, rd)
            }
            Sub { rd, rs1, rs2 } => {
                self.rv_alu_rr(rd, rs1, rs2, AluOp::Sub, pc);
                self.feed_gas_rv(RV_KIND_ADD, rs1, rs2, rd)
            }
            Xor { rd, rs1, rs2 } => {
                self.rv_alu_rr(rd, rs1, rs2, AluOp::Xor, pc);
                self.feed_gas_rv(RV_KIND_ADD, rs1, rs2, rd)
            }
            Or { rd, rs1, rs2 } => {
                self.rv_alu_rr(rd, rs1, rs2, AluOp::Or, pc);
                self.feed_gas_rv(RV_KIND_ADD, rs1, rs2, rd)
            }
            And { rd, rs1, rs2 } => {
                self.rv_alu_rr(rd, rs1, rs2, AluOp::And, pc);
                self.feed_gas_rv(RV_KIND_ADD, rs1, rs2, rd)
            }
            // 64-bit shifts — RV_KIND_SLL
            Sll { rd, rs1, rs2 } => {
                self.rv_shift_rr(rd, rs1, rs2, ShiftOp::Shl64, pc);
                self.feed_gas_rv(RV_KIND_SLL, rs1, rs2, rd)
            }
            Srl { rd, rs1, rs2 } => {
                self.rv_shift_rr(rd, rs1, rs2, ShiftOp::Shr64, pc);
                self.feed_gas_rv(RV_KIND_SLL, rs1, rs2, rd)
            }
            Sra { rd, rs1, rs2 } => {
                self.rv_shift_rr(rd, rs1, rs2, ShiftOp::Sar64, pc);
                self.feed_gas_rv(RV_KIND_SLL, rs1, rs2, rd)
            }
            // 64-bit compare — RV_KIND_SLT
            Slt { rd, rs1, rs2 } => {
                self.rv_slt_rr(rd, rs1, rs2, true, pc);
                self.feed_gas_rv(RV_KIND_SLT, rs1, rs2, rd)
            }
            Sltu { rd, rs1, rs2 } => {
                self.rv_slt_rr(rd, rs1, rs2, false, pc);
                self.feed_gas_rv(RV_KIND_SLT, rs1, rs2, rd)
            }

            // ---- RV64I ALU reg-reg (32-bit) — RV_KIND_ADDW ----
            Addw { rd, rs1, rs2 } => {
                self.rv_alu_rr(rd, rs1, rs2, AluOp::Addw, pc);
                self.feed_gas_rv(RV_KIND_ADDW, rs1, rs2, rd)
            }
            Subw { rd, rs1, rs2 } => {
                self.rv_alu_rr(rd, rs1, rs2, AluOp::Subw, pc);
                self.feed_gas_rv(RV_KIND_ADDW, rs1, rs2, rd)
            }
            // 32-bit shifts — RV_KIND_SLLW
            Sllw { rd, rs1, rs2 } => {
                self.rv_shift_rr(rd, rs1, rs2, ShiftOp::Shl32, pc);
                self.feed_gas_rv(RV_KIND_SLLW, rs1, rs2, rd)
            }
            Srlw { rd, rs1, rs2 } => {
                self.rv_shift_rr(rd, rs1, rs2, ShiftOp::Shr32, pc);
                self.feed_gas_rv(RV_KIND_SLLW, rs1, rs2, rd)
            }
            Sraw { rd, rs1, rs2 } => {
                self.rv_shift_rr(rd, rs1, rs2, ShiftOp::Sar32, pc);
                self.feed_gas_rv(RV_KIND_SLLW, rs1, rs2, rd)
            }

            // ---- M extension ----
            Mul { rd, rs1, rs2 } => {
                self.rv_alu_rr(rd, rs1, rs2, AluOp::Mul, pc);
                self.feed_gas_rv(RV_KIND_MUL, rs1, rs2, rd)
            }
            Mulw { rd, rs1, rs2 } => {
                self.rv_alu_rr(rd, rs1, rs2, AluOp::Mulw, pc);
                self.feed_gas_rv(RV_KIND_MULW, rs1, rs2, rd)
            }
            Mulh { rd, rs1, rs2 } => {
                self.rv_mulh(rd, rs1, rs2, true, true, pc);
                self.feed_gas_rv(RV_KIND_MULH, rs1, rs2, rd)
            }
            Mulhu { rd, rs1, rs2 } => {
                self.rv_mulh(rd, rs1, rs2, false, false, pc);
                self.feed_gas_rv(RV_KIND_MULH, rs1, rs2, rd)
            }
            Mulhsu { rd, rs1, rs2 } => {
                self.rv_mulh(rd, rs1, rs2, true, false, pc);
                self.feed_gas_rv(RV_KIND_MULHSU, rs1, rs2, rd)
            }
            Div { rd, rs1, rs2 } => {
                self.rv_div_rem(rd, rs1, rs2, true, false, false, pc);
                self.feed_gas_rv(RV_KIND_DIV, rs1, rs2, rd)
            }
            Divu { rd, rs1, rs2 } => {
                self.rv_div_rem(rd, rs1, rs2, false, false, false, pc);
                self.feed_gas_rv(RV_KIND_DIV, rs1, rs2, rd)
            }
            Rem { rd, rs1, rs2 } => {
                self.rv_div_rem(rd, rs1, rs2, true, true, false, pc);
                self.feed_gas_rv(RV_KIND_DIV, rs1, rs2, rd)
            }
            Remu { rd, rs1, rs2 } => {
                self.rv_div_rem(rd, rs1, rs2, false, true, false, pc);
                self.feed_gas_rv(RV_KIND_DIV, rs1, rs2, rd)
            }
            Divw { rd, rs1, rs2 } => {
                self.rv_div_rem(rd, rs1, rs2, true, false, true, pc);
                self.feed_gas_rv(RV_KIND_DIV, rs1, rs2, rd)
            }
            Divuw { rd, rs1, rs2 } => {
                self.rv_div_rem(rd, rs1, rs2, false, false, true, pc);
                self.feed_gas_rv(RV_KIND_DIV, rs1, rs2, rd)
            }
            Remw { rd, rs1, rs2 } => {
                self.rv_div_rem(rd, rs1, rs2, true, true, true, pc);
                self.feed_gas_rv(RV_KIND_DIV, rs1, rs2, rd)
            }
            Remuw { rd, rs1, rs2 } => {
                self.rv_div_rem(rd, rs1, rs2, false, true, true, pc);
                self.feed_gas_rv(RV_KIND_DIV, rs1, rs2, rd)
            }

            // ---- Zbb 1-cycle unary — RV_KIND_ZBB_U1 ----
            Clz { rd, rs1 } => {
                self.rv_unary(rd, rs1, UnaryOp::Clz64, pc);
                self.feed_gas_rv(RV_KIND_ZBB_U1, rs1, 0, rd)
            }
            Clzw { rd, rs1 } => {
                self.rv_unary(rd, rs1, UnaryOp::Clz32, pc);
                self.feed_gas_rv(RV_KIND_ZBB_U1, rs1, 0, rd)
            }
            Cpop { rd, rs1 } => {
                self.rv_unary(rd, rs1, UnaryOp::Popcnt64, pc);
                self.feed_gas_rv(RV_KIND_ZBB_U1, rs1, 0, rd)
            }
            Cpopw { rd, rs1 } => {
                self.rv_unary(rd, rs1, UnaryOp::Popcnt32, pc);
                self.feed_gas_rv(RV_KIND_ZBB_U1, rs1, 0, rd)
            }
            SextB { rd, rs1 } => {
                self.rv_unary(rd, rs1, UnaryOp::SextB, pc);
                self.feed_gas_rv(RV_KIND_ZBB_U1, rs1, 0, rd)
            }
            SextH { rd, rs1 } => {
                self.rv_unary(rd, rs1, UnaryOp::SextH, pc);
                self.feed_gas_rv(RV_KIND_ZBB_U1, rs1, 0, rd)
            }
            ZextH { rd, rs1 } => {
                self.rv_unary(rd, rs1, UnaryOp::ZextH, pc);
                self.feed_gas_rv(RV_KIND_ZBB_U1, rs1, 0, rd)
            }
            Rev8 { rd, rs1 } => {
                self.rv_unary(rd, rs1, UnaryOp::Rev8, pc);
                self.feed_gas_rv(RV_KIND_ZBB_U1, rs1, 0, rd)
            }
            OrcB { rd, rs1 } => {
                self.rv_unary(rd, rs1, UnaryOp::OrcB, pc);
                self.feed_gas_rv(RV_KIND_ZBB_U1, rs1, 0, rd)
            }
            // Zbb 2-cycle (ctz) — RV_KIND_ZBB_CTZ
            Ctz { rd, rs1 } => {
                self.rv_unary(rd, rs1, UnaryOp::Ctz64, pc);
                self.feed_gas_rv(RV_KIND_ZBB_CTZ, rs1, 0, rd)
            }
            Ctzw { rd, rs1 } => {
                self.rv_unary(rd, rs1, UnaryOp::Ctz32, pc);
                self.feed_gas_rv(RV_KIND_ZBB_CTZ, rs1, 0, rd)
            }
            // Zbb min/max — RV_KIND_ZBB_MINMAX
            Min { rd, rs1, rs2 } => {
                self.rv_alu_rr(rd, rs1, rs2, AluOp::Min, pc);
                self.feed_gas_rv(RV_KIND_ZBB_MINMAX, rs1, rs2, rd)
            }
            Minu { rd, rs1, rs2 } => {
                self.rv_alu_rr(rd, rs1, rs2, AluOp::Minu, pc);
                self.feed_gas_rv(RV_KIND_ZBB_MINMAX, rs1, rs2, rd)
            }
            Max { rd, rs1, rs2 } => {
                self.rv_alu_rr(rd, rs1, rs2, AluOp::Max, pc);
                self.feed_gas_rv(RV_KIND_ZBB_MINMAX, rs1, rs2, rd)
            }
            Maxu { rd, rs1, rs2 } => {
                self.rv_alu_rr(rd, rs1, rs2, AluOp::Maxu, pc);
                self.feed_gas_rv(RV_KIND_ZBB_MINMAX, rs1, rs2, rd)
            }
            // Zbb inv-bitwise — RV_KIND_ZBB_INV
            Andn { rd, rs1, rs2 } => {
                self.rv_alu_rr(rd, rs1, rs2, AluOp::Andn, pc);
                self.feed_gas_rv(RV_KIND_ZBB_INV, rs1, rs2, rd)
            }
            Orn { rd, rs1, rs2 } => {
                self.rv_alu_rr(rd, rs1, rs2, AluOp::Orn, pc);
                self.feed_gas_rv(RV_KIND_ZBB_INV, rs1, rs2, rd)
            }
            // Zbb xnor — RV_KIND_ZBB_XNOR
            Xnor { rd, rs1, rs2 } => {
                self.rv_alu_rr(rd, rs1, rs2, AluOp::Xnor, pc);
                self.feed_gas_rv(RV_KIND_ZBB_XNOR, rs1, rs2, rd)
            }
            // Zbb rotates — RV_KIND_ZBB_ROT / ROTW / RORI / RORIW
            Rol { rd, rs1, rs2 } => {
                self.rv_shift_rr(rd, rs1, rs2, ShiftOp::Rol64, pc);
                self.feed_gas_rv(RV_KIND_ZBB_ROT, rs1, rs2, rd)
            }
            Ror { rd, rs1, rs2 } => {
                self.rv_shift_rr(rd, rs1, rs2, ShiftOp::Ror64, pc);
                self.feed_gas_rv(RV_KIND_ZBB_ROT, rs1, rs2, rd)
            }
            Rori { rd, rs1, shamt } => {
                self.rv_shift_imm(rd, rs1, shamt, ShiftOp::Ror64, pc);
                self.feed_gas_rv(RV_KIND_ZBB_RORI, rs1, 0, rd)
            }
            Rolw { rd, rs1, rs2 } => {
                self.rv_shift_rr(rd, rs1, rs2, ShiftOp::Rol32, pc);
                self.feed_gas_rv(RV_KIND_ZBB_ROTW, rs1, rs2, rd)
            }
            Rorw { rd, rs1, rs2 } => {
                self.rv_shift_rr(rd, rs1, rs2, ShiftOp::Ror32, pc);
                self.feed_gas_rv(RV_KIND_ZBB_ROTW, rs1, rs2, rd)
            }
            Roriw { rd, rs1, shamt } => {
                self.rv_shift_imm(rd, rs1, shamt, ShiftOp::Ror32, pc);
                self.feed_gas_rv(RV_KIND_ZBB_RORIW, rs1, 0, rd)
            }

            // ---- Zba — RV_KIND_ZBA / ZBA_IMM ----
            Sh1add { rd, rs1, rs2 } => {
                self.rv_shadd(rd, rs1, rs2, 1, false, pc);
                self.record_scaledadd(rd, rs1, rs2, 1);
                self.feed_gas_rv(RV_KIND_ZBA, rs1, rs2, rd)
            }
            Sh2add { rd, rs1, rs2 } => {
                self.rv_shadd(rd, rs1, rs2, 2, false, pc);
                self.record_scaledadd(rd, rs1, rs2, 2);
                self.feed_gas_rv(RV_KIND_ZBA, rs1, rs2, rd)
            }
            Sh3add { rd, rs1, rs2 } => {
                self.rv_shadd(rd, rs1, rs2, 3, false, pc);
                self.record_scaledadd(rd, rs1, rs2, 3);
                self.feed_gas_rv(RV_KIND_ZBA, rs1, rs2, rd)
            }
            Sh1adduw { rd, rs1, rs2 } => {
                self.rv_shadd(rd, rs1, rs2, 1, true, pc);
                self.feed_gas_rv(RV_KIND_ZBA, rs1, rs2, rd)
            }
            Sh2adduw { rd, rs1, rs2 } => {
                self.rv_shadd(rd, rs1, rs2, 2, true, pc);
                self.feed_gas_rv(RV_KIND_ZBA, rs1, rs2, rd)
            }
            Sh3adduw { rd, rs1, rs2 } => {
                self.rv_shadd(rd, rs1, rs2, 3, true, pc);
                self.feed_gas_rv(RV_KIND_ZBA, rs1, rs2, rd)
            }
            Adduw { rd, rs1, rs2 } => {
                self.rv_adduw(rd, rs1, rs2, pc);
                self.feed_gas_rv(RV_KIND_ZBA, rs1, rs2, rd)
            }
            Slliuw { rd, rs1, shamt } => {
                self.rv_slliuw(rd, rs1, shamt, pc);
                self.feed_gas_rv(RV_KIND_ZBA_IMM, rs1, 0, rd)
            }

            // ---- Zbs — RV_KIND_ZBS / ZBS_IMM ----
            Bclr { rd, rs1, rs2 } => {
                self.rv_bit_rr(rd, rs1, rs2, BitOp::Clear, pc);
                self.feed_gas_rv(RV_KIND_ZBS, rs1, rs2, rd)
            }
            Bset { rd, rs1, rs2 } => {
                self.rv_bit_rr(rd, rs1, rs2, BitOp::Set, pc);
                self.feed_gas_rv(RV_KIND_ZBS, rs1, rs2, rd)
            }
            Binv { rd, rs1, rs2 } => {
                self.rv_bit_rr(rd, rs1, rs2, BitOp::Invert, pc);
                self.feed_gas_rv(RV_KIND_ZBS, rs1, rs2, rd)
            }
            Bext { rd, rs1, rs2 } => {
                self.rv_bit_rr(rd, rs1, rs2, BitOp::Extract, pc);
                self.feed_gas_rv(RV_KIND_ZBS, rs1, rs2, rd)
            }
            Bclri { rd, rs1, shamt } => {
                self.rv_bit_imm(rd, rs1, shamt, BitOp::Clear, pc);
                self.feed_gas_rv(RV_KIND_ZBS_IMM, rs1, 0, rd)
            }
            Bseti { rd, rs1, shamt } => {
                self.rv_bit_imm(rd, rs1, shamt, BitOp::Set, pc);
                self.feed_gas_rv(RV_KIND_ZBS_IMM, rs1, 0, rd)
            }
            Binvi { rd, rs1, shamt } => {
                self.rv_bit_imm(rd, rs1, shamt, BitOp::Invert, pc);
                self.feed_gas_rv(RV_KIND_ZBS_IMM, rs1, 0, rd)
            }
            Bexti { rd, rs1, shamt } => {
                self.rv_bit_imm(rd, rs1, shamt, BitOp::Extract, pc);
                self.feed_gas_rv(RV_KIND_ZBS_IMM, rs1, 0, rd)
            }

            // ---- Zicond — RV_KIND_ZICOND ----
            CzeroEqz { rd, rs1, rs2 } => {
                self.rv_czero(rd, rs1, rs2, Cc::E, pc);
                self.feed_gas_rv(RV_KIND_ZICOND, rs1, rs2, rd)
            }
            CzeroNez { rd, rs1, rs2 } => {
                self.rv_czero(rd, rs1, rs2, Cc::NE, pc);
                self.feed_gas_rv(RV_KIND_ZICOND, rs1, rs2, rd)
            }

            // ---- LUI — RV_KIND_LUI ----
            Lui { rd, imm } => {
                self.rv_lui(rd, imm, pc);
                self.track_const(rd, imm);
                self.feed_gas_rv(RV_KIND_LUI, 0, 0, rd)
            }

            // ---- Jumps & branches (terminators) ----
            Jal { rd, imm } => {
                self.rv_jal(rd, imm, pc, next_pc);
                self.feed_gas_rv(RV_KIND_JAL, 0, 0, rd)
            }
            Beq { rs1, rs2, imm } => {
                self.rv_branch(rs1, rs2, imm, Cc::E, pc, next_pc);
                self.feed_gas_rv(RV_KIND_BRANCH, rs1, rs2, 0)
            }
            Bne { rs1, rs2, imm } => {
                self.rv_branch(rs1, rs2, imm, Cc::NE, pc, next_pc);
                self.feed_gas_rv(RV_KIND_BRANCH, rs1, rs2, 0)
            }
            Blt { rs1, rs2, imm } => {
                self.rv_branch(rs1, rs2, imm, Cc::L, pc, next_pc);
                self.feed_gas_rv(RV_KIND_BRANCH, rs1, rs2, 0)
            }
            Bge { rs1, rs2, imm } => {
                self.rv_branch(rs1, rs2, imm, Cc::GE, pc, next_pc);
                self.feed_gas_rv(RV_KIND_BRANCH, rs1, rs2, 0)
            }
            Bltu { rs1, rs2, imm } => {
                self.rv_branch(rs1, rs2, imm, Cc::B, pc, next_pc);
                self.feed_gas_rv(RV_KIND_BRANCH, rs1, rs2, 0)
            }
            Bgeu { rs1, rs2, imm } => {
                self.rv_branch(rs1, rs2, imm, Cc::AE, pc, next_pc);
                self.feed_gas_rv(RV_KIND_BRANCH, rs1, rs2, 0)
            }

            // ---- Fences (no-op emit) — RV_KIND_FENCE (not a terminator) ----
            Fence | FenceI => self.feed_gas_rv(RV_KIND_FENCE, 0, 0, 0),

            // ---- custom-0 (terminators) ----
            Trap => {
                self.rv_trap(pc);
                self.feed_gas_rv(RV_KIND_TRAP, 0, 0, 0)
            }
            EcallJar => {
                self.rv_ecall_jar(next_pc);
                self.feed_gas_rv(RV_KIND_ECALL_JAR, 0, 0, 0)
            }
            Ecalli { imm } => {
                self.rv_ecalli(imm, next_pc);
                self.feed_gas_rv(RV_KIND_ECALLI, 0, 0, 0)
            }
            BrTable { table_id, rs1 } => {
                self.rv_br_table(table_id, rs1, pc, next_pc);
                self.feed_gas_rv(RV_KIND_BR_TABLE, rs1, 0, 0)
            }
            // Fallthrough is a no-op terminator (emit nothing).
            Fallthrough => self.feed_gas_rv(RV_KIND_FALLTHROUGH, 0, 0, 0),

            // Reserved encodings panic at runtime (terminator).
            Reserved { .. } => {
                self.rv_emit_panic_at(pc);
                self.feed_gas_rv(RV_KIND_RESERVED, 0, 0, 0)
            }
        }
    }

    // ----------------------------------------------------------------
    // RV-side helpers — resolve x0/x3/x4 aliases and call through asm.
    // ----------------------------------------------------------------

    /// Read RV source register into `dst_reg`. x0 → load 0; x3/x4 → panic.
    fn rv_read(&mut self, rs: u8, dst_reg: Reg, pc: u32) {
        if rs == 0 {
            self.asm.mov_ri64(dst_reg, 0);
        } else if rv_is_reserved(rs) {
            self.rv_emit_panic_at(pc);
        } else {
            self.asm.mov_rr(dst_reg, REG_MAP[rv_slot(rs).unwrap()]);
        }
    }

    /// Return the x86 register holding rs's value. For x0, materialise 0
    /// into `scratch` and return `scratch`.
    fn rv_read_into(&mut self, rs: u8, scratch: Reg, pc: u32) -> Reg {
        if rs == 0 {
            self.asm.mov_ri64(scratch, 0);
            scratch
        } else if rv_is_reserved(rs) {
            self.rv_emit_panic_at(pc);
            scratch
        } else {
            REG_MAP[rv_slot(rs).unwrap()]
        }
    }

    /// Resolve an RV destination register. None when rd == x0 (discard).
    /// x3/x4 emit a panic and return None.
    fn rv_dst(&mut self, rd: u8, pc: u32) -> Option<Reg> {
        if rd == 0 {
            None
        } else if rv_is_reserved(rd) {
            self.rv_emit_panic_at(pc);
            None
        } else {
            Some(REG_MAP[rv_slot(rd).unwrap()])
        }
    }

    // ---- LUI ---------------------------------------------------------

    fn rv_lui(&mut self, rd: u8, imm: i32, pc: u32) {
        if let Some(d) = self.rv_dst(rd, pc) {
            // imm has bits in [31:12]; sign-extend to 64.
            self.asm.mov_ri64(d, imm as i64 as u64);
            self.invalidate_reg(rv_slot(rd).unwrap());
        }
    }

    // ---- Loads / stores ---------------------------------------------

    fn rv_load(&mut self, rd: u8, rs1: u8, imm: i32, width: u32, signed: bool, pc: u32) {
        if rv_is_reserved(rd) || rv_is_reserved(rs1) {
            self.rv_emit_panic_at(pc);
            return;
        }
        self.rv_addr_to_scratch(rs1, imm, pc);
        let fn_addr = match width {
            1 => self.helpers.mem_read_u8,
            2 => self.helpers.mem_read_u16,
            4 => self.helpers.mem_read_u32,
            _ => self.helpers.mem_read_u64,
        };
        let dst = match self.rv_dst(rd, pc) {
            Some(r) => r,
            None => SCRATCH, // x0: load discarded but trap-on-OOB still fires
        };
        self.emit_mem_read_sized(dst, fn_addr, width, pc);
        if signed && width < 8 && rd != 0 {
            match width {
                1 => self.asm.movsx_8_64(dst, dst),
                2 => self.asm.movsx_16_64(dst, dst),
                4 => self.asm.movsxd(dst, dst),
                _ => {}
            }
        }
        if rd != 0 {
            self.invalidate_reg(rv_slot(rd).unwrap());
        }
    }

    fn rv_store(&mut self, rs1: u8, rs2: u8, imm: i32, width: u32, pc: u32) {
        if rv_is_reserved(rs1) || rv_is_reserved(rs2) {
            self.rv_emit_panic_at(pc);
            return;
        }
        let fn_addr = match width {
            1 => self.helpers.mem_write_u8,
            2 => self.helpers.mem_write_u16,
            4 => self.helpers.mem_write_u32,
            _ => self.helpers.mem_write_u64,
        };
        if rs2 == 0 {
            // Materialise 0 into a temp register so SCRATCH can hold the
            // addr. Compute the address FIRST — rs1 might map to RAX
            // (x14), in which case clobbering RAX before reading rs1
            // would feed the address calc the wrong value.
            self.rv_addr_to_scratch(rs1, imm, pc);
            self.asm.push(Reg::RAX);
            self.asm.mov_ri64(Reg::RAX, 0);
            self.emit_mem_write(true, Reg::RAX, fn_addr, pc);
            self.asm.pop(Reg::RAX);
        } else {
            let val = REG_MAP[rv_slot(rs2).unwrap()];
            self.rv_addr_to_scratch(rs1, imm, pc);
            self.emit_mem_write(true, val, fn_addr, pc);
        }
    }

    /// Build `addr = (rs1 + imm) & 0xFFFFFFFF` into SCRATCH.
    fn rv_addr_to_scratch(&mut self, rs1: u8, imm: i32, pc: u32) {
        use super::codegen::RegDef;
        if rs1 == 0 {
            self.asm.mov_ri32(SCRATCH, imm as u32);
            return;
        }
        if rv_is_reserved(rs1) {
            self.rv_emit_panic_at(pc);
            return;
        }
        // Ported from PVM's emit_addr_to_scratch peephole: fold a known
        // constant address (set by `addi rd, x0, imm` / `lui`) directly
        // into the immediate, skipping the lea/movzx entirely.
        let slot = rv_slot(rs1).unwrap();
        if let RegDef::Const(addr) = self.reg_defs[slot] {
            let effective = addr.wrapping_add(imm as u32);
            self.asm.mov_ri32(SCRATCH, effective);
            return;
        }
        // Use SIB addressing for scaled-index patterns when imm == 0
        // (sh{1,2,3}add or slli+add chains tracked via reg_defs).
        // Tracking guarantees rd didn't alias rs1/rs2 (record_scaledadd
        // refuses self-referential defs), so base/idx still hold their
        // pre-emit values at the consumer site.
        if imm == 0
            && let RegDef::ScaledAdd { base, idx, shift } = self.reg_defs[slot]
        {
            self.asm
                .lea_sib_scaled_32(SCRATCH, REG_MAP[base], REG_MAP[idx], shift);
            return;
        }
        let base = REG_MAP[slot];
        if imm != 0 {
            self.asm.lea_32(SCRATCH, base, imm);
        } else {
            self.asm.movzx_32_64(SCRATCH, base);
        }
    }

    // ---- ALU --------------------------------------------------------

    fn rv_alu_imm(&mut self, rd: u8, rs1: u8, imm: i32, op: AluImmOp, pc: u32) {
        let Some(d) = self.rv_dst(rd, pc) else { return };
        // Phase 5: `addi rd, x0, imm` is the canonical RV "li" form. The
        // generic path would emit `xor d, d; add d, imm` (2 ops); we can
        // do it as a single sign-extended move.
        if rs1 == 0 && matches!(op, AluImmOp::Add) {
            self.asm.mov_ri64(d, imm as i64 as u64);
            self.invalidate_reg(rv_slot(rd).unwrap());
            return;
        }
        self.rv_read(rs1, d, pc);
        match op {
            AluImmOp::Add => self.asm.add_ri(d, imm),
            AluImmOp::And => self.asm.and_ri(d, imm),
            AluImmOp::Or => self.asm.or_ri(d, imm),
            AluImmOp::Xor => self.asm.xor_ri(d, imm),
            AluImmOp::Addw => {
                self.asm.add_ri32(d, imm);
                self.asm.movsxd(d, d);
            }
        }
        if rd != 0 {
            self.invalidate_reg(rv_slot(rd).unwrap());
        }
    }

    fn rv_alu_rr(&mut self, rd: u8, rs1: u8, rs2: u8, op: AluOp, pc: u32) {
        let Some(d) = self.rv_dst(rd, pc) else { return };
        if rv_is_reserved(rs1) || rv_is_reserved(rs2) {
            self.rv_emit_panic_at(pc);
            return;
        }
        // Phase 5: `add rd, rs, x0` / `add rd, x0, rs` — canonical RV `mv`.
        // Generic path emits `mov SCRATCH, 0; mov d, rs; add d, SCRATCH`
        // (or `xor d, d; add d, rs`); the single `mov d, rs` (with rs2=x0
        // src=rs1, or vice versa) is one op. mov_rr doesn't touch CF.
        //
        // This path bypasses the Phase 4 last_add_cf set at the bottom,
        // and the main-loop clearing keeps last_add_cf alive across the
        // Add instruction. If the mv's rd was the previous add's D/A/B,
        // the carry handoff is no longer meaningful — clear conservatively.
        if matches!(op, AluOp::Add) && (rs1 == 0 || rs2 == 0) {
            let src = if rs1 == 0 { rs2 } else { rs1 };
            self.rv_read(src, d, pc);
            self.invalidate_reg(rv_slot(rd).unwrap());
            self.last_add_cf = None;
            return;
        }
        // PVM-ported peephole: `sub rd, rs1, rs2` where rd_slot == rs2_slot
        // and rs1 != rs2. Generic path snapshots rs2 to SCRATCH (because d
        // aliases rs2), then mov d, rs1, then sub d, SCRATCH — 3 ops.
        // We can compute the same result as `neg d; add d, rs1` in 2 ops
        // since d already holds rs2's value.
        if matches!(op, AluOp::Sub) && rs1 != 0 && rs2 != 0 && rs1 != rs2 {
            let r1_x86 = REG_MAP[rv_slot(rs1).unwrap()];
            let r2_x86 = REG_MAP[rv_slot(rs2).unwrap()];
            if d == r2_x86 {
                self.asm.neg64(d);
                self.asm.add_rr(d, r1_x86);
                self.invalidate_reg(rv_slot(rd).unwrap());
                self.last_add_cf = None;
                return;
            }
        }
        // Aliasing analysis: rv_read(rs1, d) might write d, which can
        // clobber rs2's value if rd's slot equals rs2's slot. Save rs2
        // into SCRATCH first whenever d aliases rs2 (and rs2 != rs1).
        // x0 is handled specially since it has no mapped register.
        let r1_is_x0 = rs1 == 0;
        let r2_is_x0 = rs2 == 0;
        let r1 = if r1_is_x0 {
            None
        } else {
            Some(REG_MAP[rv_slot(rs1).unwrap()])
        };
        let r2 = if r2_is_x0 {
            None
        } else {
            Some(REG_MAP[rv_slot(rs2).unwrap()])
        };

        let b_reg = if r2_is_x0 {
            // rs2 == 0: materialise 0 in SCRATCH. rv_read of rs1 below
            // won't touch SCRATCH (mov_rr / mov_ri64).
            self.asm.mov_ri64(SCRATCH, 0);
            SCRATCH
        } else if Some(d) == r2 && r1 != r2 {
            // d aliases r2 and rs1 != rs2 — rv_read(rs1, d) would
            // clobber rs2. Snapshot rs2 into SCRATCH first.
            self.asm.mov_rr(SCRATCH, r2.unwrap());
            SCRATCH
        } else {
            r2.unwrap()
        };
        // Now safe to load rs1 into d.
        self.rv_read(rs1, d, pc);
        self.apply_alu_op(op, d, b_reg);
        if rd != 0 {
            self.invalidate_reg(rv_slot(rd).unwrap());
        }
        // Phase 4: record carry-flag handoff. Only 64-bit `add` sets CF
        // in a way that matches a subsequent `sltu rd, rs1, rs2` checking
        // unsigned overflow of rs1+rs2. Addw operates on the 32-bit view
        // and sign-extends — CF reflects 32-bit overflow, not 64-bit,
        // so a 64-bit sltu against the sign-extended sum would be wrong.
        // Skip x0 source/dest cases: degenerate, not worth tracking.
        if matches!(op, AluOp::Add)
            && rd != 0
            && rs1 != 0
            && rs2 != 0
            && let (Some(d_s), Some(a_s), Some(b_s)) = (rv_slot(rd), rv_slot(rs1), rv_slot(rs2))
        {
            self.last_add_cf = Some((d_s, a_s, b_s));
        }
    }

    fn apply_alu_op(&mut self, op: AluOp, d: Reg, s: Reg) {
        match op {
            AluOp::Add => self.asm.add_rr(d, s),
            AluOp::Sub => self.asm.sub_rr(d, s),
            AluOp::And => self.asm.and_rr(d, s),
            AluOp::Or => self.asm.or_rr(d, s),
            AluOp::Xor => self.asm.xor_rr(d, s),
            AluOp::Mul => self.asm.imul_rr(d, s),
            AluOp::Addw => {
                self.asm.add_rr32(d, s);
                self.asm.movsxd(d, d);
            }
            AluOp::Subw => {
                self.asm.sub_rr32(d, s);
                self.asm.movsxd(d, d);
            }
            AluOp::Mulw => {
                self.asm.imul_rr32(d, s);
                self.asm.movsxd(d, d);
            }
            AluOp::Min => {
                self.asm.cmp_rr(d, s);
                self.asm.cmovcc(Cc::G, d, s);
            }
            AluOp::Max => {
                self.asm.cmp_rr(d, s);
                self.asm.cmovcc(Cc::L, d, s);
            }
            AluOp::Minu => {
                self.asm.cmp_rr(d, s);
                self.asm.cmovcc(Cc::A, d, s);
            }
            AluOp::Maxu => {
                self.asm.cmp_rr(d, s);
                self.asm.cmovcc(Cc::B, d, s);
            }
            AluOp::Andn => {
                self.asm.mov_rr(SCRATCH, s);
                self.asm.not64(SCRATCH);
                self.asm.and_rr(d, SCRATCH);
            }
            AluOp::Orn => {
                self.asm.mov_rr(SCRATCH, s);
                self.asm.not64(SCRATCH);
                self.asm.or_rr(d, SCRATCH);
            }
            AluOp::Xnor => {
                self.asm.xor_rr(d, s);
                self.asm.not64(d);
            }
        }
    }

    fn rv_slt_imm(&mut self, rd: u8, rs1: u8, imm: i32, signed: bool, pc: u32) {
        let Some(d) = self.rv_dst(rd, pc) else { return };
        if rv_is_reserved(rs1) {
            self.rv_emit_panic_at(pc);
            return;
        }
        // Snapshot rs1 into SCRATCH if d aliases its register — zeroing
        // d below would otherwise clobber rs1 before the cmp.
        let src = if rs1 == 0 {
            self.asm.mov_ri64(SCRATCH, 0);
            SCRATCH
        } else {
            let r1 = REG_MAP[rv_slot(rs1).unwrap()];
            if d == r1 {
                self.asm.mov_rr(SCRATCH, r1);
                SCRATCH
            } else {
                r1
            }
        };
        // Zero d FIRST (mov_ri64 with 0 uses XOR → clobbers flags).
        // Then cmp sets flags fresh for setcc.
        self.asm.mov_ri64(d, 0);
        self.asm.cmp_ri(src, imm);
        self.asm.setcc(if signed { Cc::L } else { Cc::B }, d);
        if rd != 0 {
            self.invalidate_reg(rv_slot(rd).unwrap());
        }
    }

    fn rv_slt_rr(&mut self, rd: u8, rs1: u8, rs2: u8, signed: bool, pc: u32) {
        let Some(d) = self.rv_dst(rd, pc) else { return };
        if rv_is_reserved(rs1) || rv_is_reserved(rs2) {
            self.rv_emit_panic_at(pc);
            return;
        }
        // Phase 4: carry-flag fast path for `sltu d, rs1, rs2` immediately
        // following `add rs1, A, B` (with rs2 ∈ {A, B}). CF already holds
        // the unsigned-overflow bit, so we skip the cmp and emit just
        // `setb d` + zero-extension. Mirrors PVM's SetLtU fusion.
        //
        // If the conditions don't match, the general path below emits
        // `mov_ri64(d, 0); cmp; setcc` — the first of which clobbers CF
        // via xor. last_add_cf is single-shot: cleared on entry to keep
        // any *subsequent* sltu from reading the (now-stale) add flags.
        if !signed && let Some((add_d, add_a, add_b)) = self.last_add_cf {
            let rs1_s = rv_slot(rs1);
            let rs2_s = rv_slot(rs2);
            let rd_s = rv_slot(rd);
            if let (Some(rs1_s), Some(rs2_s), Some(rd_s)) = (rs1_s, rs2_s, rd_s)
                && rs1_s == add_d
                && rs2_s != add_d
                && (rs2_s == add_a || rs2_s == add_b)
                && rd_s != rs2_s
            {
                // CF is valid. Zero d first via mov_ri32 (`mov r32, 0`,
                // no flag effect), then setb writes the low byte. This
                // avoids the partial-register dependency that a bare
                // `setcc; movzx` sequence would create.
                self.asm.mov_ri32(d, 0);
                self.asm.setcc(Cc::B, d);
                self.invalidate_reg(rd_s);
                // setb/movzx don't touch CF — a *further* consecutive sltu
                // against the same add still has the live carry available,
                // so leave last_add_cf intact.
                return;
            }
        }
        // Fell through: the general path below clobbers CF. Clear the
        // tracked carry so a subsequent sltu doesn't fuse spuriously.
        self.last_add_cf = None;
        // Snapshot operands into SCRATCH and/or read original mapped
        // registers BEFORE touching d. Zero d up front; the cmp below
        // sets flags fresh for the setcc.
        let r1 = if rs1 == 0 {
            None
        } else {
            Some(REG_MAP[rv_slot(rs1).unwrap()])
        };
        let r2 = if rs2 == 0 {
            None
        } else {
            Some(REG_MAP[rv_slot(rs2).unwrap()])
        };
        // Choose registers for a and b without writing d yet.
        // Strategy: if d aliases r1 or r2, snapshot one of them to
        // SCRATCH. We only have one SCRATCH (RDX) so handle carefully.
        let (a_reg, b_reg) = match (r1, r2) {
            (Some(ra), Some(rb)) => {
                if d == ra && d == rb {
                    // Both r1 and r2 are d. cmp d, d → ZF=1 always; SLT=0.
                    (ra, rb)
                } else if d == ra {
                    // We'll write d = 0 then load a into d. But that
                    // overwrites b if d == ra... wait, ra is d. Snapshot
                    // ra into SCRATCH BEFORE zeroing d.
                    self.asm.mov_rr(SCRATCH, ra);
                    (SCRATCH, rb)
                } else if d == rb {
                    self.asm.mov_rr(SCRATCH, rb);
                    (ra, SCRATCH)
                } else {
                    (ra, rb)
                }
            }
            (None, Some(rb)) => {
                // a is x0. result = (0 < rb), i.e. (rb > 0) signed or
                // (rb != 0) unsigned. Cc::G == "ZF=0 && SF=0" after a
                // test against self (OF=0), so it captures rb > 0
                // signed; Cc::A == "ZF=0" after the same test, capturing
                // rb != 0 (= 0 < rb unsigned).
                if d == rb {
                    // Snapshot rb (d will be clobbered to receive the
                    // setcc byte). mov_rr does not clobber flags but we
                    // haven't set them yet; the test_rr below sets fresh
                    // flags after mov_ri64 (which uses XOR and clobbers
                    // flags). Order matters.
                    self.asm.mov_rr(SCRATCH, rb);
                    self.asm.mov_ri64(d, 0);
                    self.asm.test_rr(SCRATCH, SCRATCH);
                    self.asm.setcc(if signed { Cc::G } else { Cc::A }, d);
                    if rd != 0 {
                        self.invalidate_reg(rv_slot(rd).unwrap());
                    }
                    return;
                } else {
                    self.asm.mov_ri64(d, 0);
                    self.asm.test_rr(rb, rb);
                    self.asm.setcc(if signed { Cc::G } else { Cc::A }, d);
                    if rd != 0 {
                        self.invalidate_reg(rv_slot(rd).unwrap());
                    }
                    return;
                }
            }
            (Some(ra), None) => {
                // b is x0.
                if d == ra {
                    self.asm.mov_rr(SCRATCH, ra);
                    self.asm.mov_ri64(d, 0);
                    self.asm.cmp_ri(SCRATCH, 0);
                    self.asm.setcc(if signed { Cc::L } else { Cc::B }, d);
                    if rd != 0 {
                        self.invalidate_reg(rv_slot(rd).unwrap());
                    }
                    return;
                } else {
                    // cmp ra, 0 — no need for SCRATCH.
                    self.asm.mov_ri64(d, 0);
                    self.asm.cmp_ri(ra, 0);
                    self.asm.setcc(if signed { Cc::L } else { Cc::B }, d);
                    if rd != 0 {
                        self.invalidate_reg(rv_slot(rd).unwrap());
                    }
                    return;
                }
            }
            (None, None) => {
                // x0 < x0 — always false; d = 0.
                self.asm.mov_ri64(d, 0);
                if rd != 0 {
                    self.invalidate_reg(rv_slot(rd).unwrap());
                }
                return;
            }
        };
        // a_reg and b_reg now point at the actual values.
        self.asm.mov_ri64(d, 0);
        self.asm.cmp_rr(a_reg, b_reg);
        self.asm.setcc(if signed { Cc::L } else { Cc::B }, d);
        if rd != 0 {
            self.invalidate_reg(rv_slot(rd).unwrap());
        }
    }

    // ---- Shifts -----------------------------------------------------

    fn rv_shift_imm(&mut self, rd: u8, rs1: u8, shamt: u8, op: ShiftOp, pc: u32) {
        let Some(d) = self.rv_dst(rd, pc) else { return };
        self.rv_read(rs1, d, pc);
        match op {
            ShiftOp::Shl64 => self.asm.shl_ri64(d, shamt & 63),
            ShiftOp::Shr64 => self.asm.shr_ri64(d, shamt & 63),
            ShiftOp::Sar64 => self.asm.sar_ri64(d, shamt & 63),
            ShiftOp::Shl32 => {
                self.asm.shl_ri32(d, shamt & 31);
                self.asm.movsxd(d, d);
            }
            ShiftOp::Shr32 => {
                self.asm.movzx_32_64(d, d);
                self.asm.shr_ri32(d, shamt & 31);
                self.asm.movsxd(d, d);
            }
            ShiftOp::Sar32 => {
                self.asm.sar_ri32(d, shamt & 31);
                self.asm.movsxd(d, d);
            }
            ShiftOp::Ror64 => self.asm.ror_ri64(d, shamt & 63),
            ShiftOp::Ror32 => {
                self.asm.movzx_32_64(d, d);
                self.asm.ror_ri32(d, shamt & 31);
                self.asm.movsxd(d, d);
            }
            ShiftOp::Rol64 | ShiftOp::Rol32 => {
                // No imm-rol instruction in PVM2 — should not reach.
                self.rv_emit_panic_at(pc);
            }
        }
        if rd != 0 {
            self.invalidate_reg(rv_slot(rd).unwrap());
        }
    }

    fn rv_shift_rr(&mut self, rd: u8, rs1: u8, rs2: u8, op: ShiftOp, pc: u32) {
        let Some(d) = self.rv_dst(rd, pc) else { return };
        if rv_is_reserved(rs1) || rv_is_reserved(rs2) {
            self.rv_emit_panic_at(pc);
            return;
        }
        // Snapshot rs2 to SCRATCH if d would clobber it.
        let r2 = if rs2 == 0 {
            None
        } else {
            Some(REG_MAP[rv_slot(rs2).unwrap()])
        };
        let r1 = if rs1 == 0 {
            None
        } else {
            Some(REG_MAP[rv_slot(rs1).unwrap()])
        };
        let shift_src = if rs2 == 0 {
            self.asm.mov_ri64(SCRATCH, 0);
            SCRATCH
        } else if Some(d) == r2 && r1 != r2 {
            self.asm.mov_rr(SCRATCH, r2.unwrap());
            SCRATCH
        } else {
            r2.unwrap()
        };
        self.rv_read(rs1, d, pc);
        let sub_op: u8 = match op {
            ShiftOp::Shl64 | ShiftOp::Shl32 => 4,
            ShiftOp::Shr64 | ShiftOp::Shr32 => 5,
            ShiftOp::Sar64 | ShiftOp::Sar32 => 7,
            ShiftOp::Rol64 | ShiftOp::Rol32 => 0,
            ShiftOp::Ror64 | ShiftOp::Ror32 => 1,
        };
        let is_32 = matches!(
            op,
            ShiftOp::Shl32 | ShiftOp::Shr32 | ShiftOp::Sar32 | ShiftOp::Rol32 | ShiftOp::Ror32
        );
        if is_32 {
            if matches!(op, ShiftOp::Shr32 | ShiftOp::Ror32) {
                self.asm.movzx_32_64(d, d);
            }
            self.emit_shift_by_reg32(d, shift_src, sub_op);
            self.asm.movsxd(d, d);
        } else {
            self.emit_shift_by_reg64(d, shift_src, sub_op);
        }
        if rd != 0 {
            self.invalidate_reg(rv_slot(rd).unwrap());
        }
    }

    // ---- Multiply-high ----------------------------------------------

    fn rv_mulh(&mut self, rd: u8, rs1: u8, rs2: u8, a_signed: bool, b_signed: bool, pc: u32) {
        let Some(d) = self.rv_dst(rd, pc) else { return };
        if rv_is_reserved(rs1) || rv_is_reserved(rs2) {
            self.rv_emit_panic_at(pc);
            return;
        }
        // Spill RAX (if d != RAX) and materialise both operands.
        let save_rax = d != Reg::RAX;
        let r2_mapped = if rs2 == 0 {
            None
        } else {
            Some(REG_MAP[rv_slot(rs2).unwrap()])
        };
        // Snapshot rs2 into SCRATCH up-front if rs2 maps to RAX (x14) —
        // we're about to clobber RAX. This covers both save_rax=true
        // (where RAX is also on stack, but reading from stack costs a
        // load) and save_rax=false (where RAX is the only live copy of
        // both rs2 and rd; we must capture rs2 before the load of rs1).
        let snapshot_rs2 = r2_mapped == Some(Reg::RAX);
        if snapshot_rs2 {
            self.asm.mov_rr(SCRATCH, Reg::RAX);
        }
        if save_rax {
            self.asm.push(Reg::RAX);
        }
        // Load rs1 into RAX.
        if rs1 == 0 {
            self.asm.mov_ri64(Reg::RAX, 0);
        } else {
            let r1 = REG_MAP[rv_slot(rs1).unwrap()];
            if r1 != Reg::RAX {
                self.asm.mov_rr(Reg::RAX, r1);
            }
            // If r1 == RAX but we saved RAX, the value is on stack — reload.
            if r1 == Reg::RAX && save_rax {
                self.asm.mov_load64(Reg::RAX, Reg::RSP, 0);
            }
        }
        // b is a mapped reg or 0; if 0, materialise into SCRATCH.
        let b_reg = if rs2 == 0 {
            self.asm.mov_ri64(SCRATCH, 0);
            SCRATCH
        } else if snapshot_rs2 {
            // rs2 already snapshotted into SCRATCH above.
            SCRATCH
        } else {
            r2_mapped.unwrap()
        };
        if a_signed && b_signed {
            self.asm.imul_rdx_rax(b_reg);
        } else if !a_signed && !b_signed {
            self.asm.mul_rdx_rax(b_reg);
        } else {
            // mulhsu: hi = unsigned_mul_hi(a, b) - (a < 0 ? b : 0).
            self.asm.push(b_reg);
            self.asm.push(Reg::RAX); // save a for sign check
            self.asm.mul_rdx_rax(b_reg);
            self.asm.pop(Reg::RAX); // a (signed)
            let skip = self.asm.new_label();
            self.asm.test_rr(Reg::RAX, Reg::RAX);
            self.asm.jcc_label(Cc::NS, skip);
            self.asm.pop(Reg::RAX); // pop saved b
            self.asm.sub_rr(SCRATCH, Reg::RAX);
            let done = self.asm.new_label();
            self.asm.jmp_label(done);
            self.asm.bind_label(skip);
            self.asm.add_ri(Reg::RSP, 8); // discard saved b
            self.asm.bind_label(done);
        }
        // High word in RDX (SCRATCH).
        if save_rax {
            self.asm.mov_rr(d, SCRATCH);
            self.asm.pop(Reg::RAX);
        } else {
            self.asm.mov_rr(Reg::RAX, SCRATCH);
        }
        if rd != 0 {
            self.invalidate_reg(rv_slot(rd).unwrap());
        }
    }

    // ---- Division / remainder ---------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn rv_div_rem(
        &mut self,
        rd: u8,
        rs1: u8,
        rs2: u8,
        signed: bool,
        remainder: bool,
        is_32bit: bool,
        pc: u32,
    ) {
        let Some(d) = self.rv_dst(rd, pc) else { return };
        if rv_is_reserved(rs1) || rv_is_reserved(rs2) {
            self.rv_emit_panic_at(pc);
            return;
        }
        // ---- prologue (push spills once; both branches share a single
        // cleanup epilogue at `join`) ----
        let save_rax = d != Reg::RAX;
        if save_rax {
            self.asm.push(Reg::RAX);
        }
        // RCX is spilled when rs2 maps to nothing (x0) — we materialise
        // 0 into RCX — or when rs2 maps to RAX (we move the divisor to
        // RCX before loading the dividend into RAX).
        let r2 = if rs2 == 0 {
            None
        } else {
            Some(REG_MAP[rv_slot(rs2).unwrap()])
        };
        let spilled_rcx = rs2 == 0 || r2 == Some(Reg::RAX);
        if spilled_rcx {
            self.asm.push(Reg::RCX);
        }
        // Determine the divisor register (b_reg).
        let b_reg = if rs2 == 0 {
            self.asm.mov_ri64(Reg::RCX, 0);
            Reg::RCX
        } else if r2 == Some(Reg::RAX) {
            // rs2 mapped to RAX (x14). Get its value into RCX.
            if save_rax {
                // RAX was pushed first, RCX next. RSP+8 holds saved RAX.
                self.asm.mov_load64(Reg::RCX, Reg::RSP, 8);
            } else {
                // RAX wasn't pushed (d == RAX) — rs2's value is still
                // live in RAX. Snapshot to RCX before we load rs1 below.
                self.asm.mov_rr(Reg::RCX, Reg::RAX);
            }
            Reg::RCX
        } else {
            r2.unwrap()
        };
        // Load dividend (a) into RAX.
        if rs1 == 0 {
            self.asm.mov_ri64(Reg::RAX, 0);
        } else {
            let r1 = REG_MAP[rv_slot(rs1).unwrap()];
            if r1 == Reg::RAX {
                if save_rax {
                    let off = if spilled_rcx { 8 } else { 0 };
                    self.asm.mov_load64(Reg::RAX, Reg::RSP, off);
                }
                // else: already in RAX.
            } else {
                self.asm.mov_rr(Reg::RAX, r1);
            }
        }
        // ---- branch on divisor == 0 ----
        self.asm.test_rr(b_reg, b_reg);
        let nonzero = self.asm.new_label();
        let join = self.asm.new_label();
        self.asm.jcc_label(Cc::NE, nonzero);
        // Divisor == 0: div → -1 (all-ones); remainder → dividend.
        if remainder {
            if d != Reg::RAX {
                self.asm.mov_rr(d, Reg::RAX);
            }
            if is_32bit {
                self.asm.movsxd(d, d);
            }
        } else {
            self.asm.mov_ri64(d, u64::MAX);
            // u64::MAX is sign-extended -1 in both 32/64-bit views.
        }
        self.asm.jmp_label(join);

        // ---- nonzero branch: real DIV/IDIV ----
        self.asm.bind_label(nonzero);
        if is_32bit {
            if signed {
                self.asm.movsxd(Reg::RAX, Reg::RAX);
                self.asm.cdq();
                self.asm.idiv32(b_reg);
            } else {
                self.asm.movzx_32_64(Reg::RAX, Reg::RAX);
                self.asm.mov_ri64(SCRATCH, 0);
                self.asm.div32(b_reg);
            }
        } else if signed {
            self.asm.cqo();
            self.asm.idiv64(b_reg);
        } else {
            self.asm.mov_ri64(SCRATCH, 0);
            self.asm.div64(b_reg);
        }
        let result_reg = if remainder { SCRATCH } else { Reg::RAX };
        if d != result_reg {
            self.asm.mov_rr(d, result_reg);
        }
        if is_32bit {
            self.asm.movsxd(d, d);
        }

        // ---- single epilogue ----
        self.asm.bind_label(join);
        if spilled_rcx {
            self.asm.pop(Reg::RCX);
        }
        if save_rax {
            self.asm.pop(Reg::RAX);
        }
        if rd != 0 {
            self.invalidate_reg(rv_slot(rd).unwrap());
        }
    }

    // ---- Unary ops (Zbb) --------------------------------------------

    fn rv_unary(&mut self, rd: u8, rs1: u8, op: UnaryOp, pc: u32) {
        let Some(d) = self.rv_dst(rd, pc) else { return };
        let src = if rs1 == 0 {
            self.asm.mov_ri64(SCRATCH, 0);
            SCRATCH
        } else if rv_is_reserved(rs1) {
            self.rv_emit_panic_at(pc);
            return;
        } else {
            REG_MAP[rv_slot(rs1).unwrap()]
        };
        match op {
            UnaryOp::Clz64 => self.asm.lzcnt64(d, src),
            UnaryOp::Clz32 => self.asm.lzcnt32(d, src),
            UnaryOp::Ctz64 => self.asm.tzcnt64(d, src),
            UnaryOp::Ctz32 => self.asm.tzcnt32(d, src),
            UnaryOp::Popcnt64 => self.asm.popcnt64(d, src),
            UnaryOp::Popcnt32 => self.asm.popcnt32(d, src),
            UnaryOp::SextB => self.asm.movsx_8_64(d, src),
            UnaryOp::SextH => self.asm.movsx_16_64(d, src),
            UnaryOp::ZextH => self.asm.movzx_16_64(d, src),
            UnaryOp::Rev8 => {
                if d != src {
                    self.asm.mov_rr(d, src);
                }
                self.asm.bswap64(d);
            }
            UnaryOp::OrcB => {
                // orc.b: byte-wise OR-combine. Each byte becomes 0xFF if
                // any bit was set in the source byte, else 0x00. No
                // single x86 instruction; emulate or panic in Phase 1.
                self.rv_emit_panic_at(pc);
            }
        }
        if rd != 0 {
            self.invalidate_reg(rv_slot(rd).unwrap());
        }
    }

    // ---- Zba shift-add ----------------------------------------------

    fn rv_shadd(&mut self, rd: u8, rs1: u8, rs2: u8, shift: u8, uw: bool, pc: u32) {
        let Some(d) = self.rv_dst(rd, pc) else { return };
        if rv_is_reserved(rs1) || rv_is_reserved(rs2) {
            self.rv_emit_panic_at(pc);
            return;
        }
        // SCRATCH = (zext32 if uw else val)(rs1) << shift
        if rs1 == 0 {
            self.asm.mov_ri64(SCRATCH, 0);
        } else {
            let r1 = REG_MAP[rv_slot(rs1).unwrap()];
            if uw {
                self.asm.movzx_32_64(SCRATCH, r1);
            } else {
                self.asm.mov_rr(SCRATCH, r1);
            }
        }
        self.asm.shl_ri64(SCRATCH, shift);
        // d = rs2; d += SCRATCH
        if rs2 == 0 {
            self.asm.mov_ri64(d, 0);
        } else {
            let r2 = REG_MAP[rv_slot(rs2).unwrap()];
            if d != r2 {
                self.asm.mov_rr(d, r2);
            }
        }
        self.asm.add_rr(d, SCRATCH);
        if rd != 0 {
            self.invalidate_reg(rv_slot(rd).unwrap());
        }
    }

    fn rv_adduw(&mut self, rd: u8, rs1: u8, rs2: u8, pc: u32) {
        let Some(d) = self.rv_dst(rd, pc) else { return };
        if rv_is_reserved(rs1) || rv_is_reserved(rs2) {
            self.rv_emit_panic_at(pc);
            return;
        }
        if rs1 == 0 {
            self.asm.mov_ri64(SCRATCH, 0);
        } else {
            let r1 = REG_MAP[rv_slot(rs1).unwrap()];
            self.asm.movzx_32_64(SCRATCH, r1);
        }
        if rs2 == 0 {
            self.asm.mov_ri64(d, 0);
        } else {
            let r2 = REG_MAP[rv_slot(rs2).unwrap()];
            if d != r2 {
                self.asm.mov_rr(d, r2);
            }
        }
        self.asm.add_rr(d, SCRATCH);
        if rd != 0 {
            self.invalidate_reg(rv_slot(rd).unwrap());
        }
    }

    fn rv_slliuw(&mut self, rd: u8, rs1: u8, shamt: u8, pc: u32) {
        let Some(d) = self.rv_dst(rd, pc) else { return };
        if rs1 == 0 {
            self.asm.mov_ri64(d, 0);
        } else if rv_is_reserved(rs1) {
            self.rv_emit_panic_at(pc);
            return;
        } else {
            let r1 = REG_MAP[rv_slot(rs1).unwrap()];
            self.asm.movzx_32_64(d, r1);
            self.asm.shl_ri64(d, shamt & 63);
        }
        if rd != 0 {
            self.invalidate_reg(rv_slot(rd).unwrap());
        }
    }

    // ---- Zbs single-bit ---------------------------------------------

    fn rv_bit_rr(&mut self, rd: u8, rs1: u8, rs2: u8, op: BitOp, pc: u32) {
        let Some(d) = self.rv_dst(rd, pc) else { return };
        if rv_is_reserved(rs1) || rv_is_reserved(rs2) {
            self.rv_emit_panic_at(pc);
            return;
        }
        // SCRATCH = 1 << (rs2 & 0x3F).
        self.asm.mov_ri64(SCRATCH, 1);
        if rs2 != 0 {
            let r2 = REG_MAP[rv_slot(rs2).unwrap()];
            if r2 == Reg::RCX {
                self.asm.shl_cl64(SCRATCH);
            } else {
                self.asm.push(Reg::RCX);
                self.asm.mov_rr(Reg::RCX, r2);
                self.asm.shl_cl64(SCRATCH);
                self.asm.pop(Reg::RCX);
            }
        }
        // Apply.
        self.rv_read(rs1, d, pc);
        match op {
            BitOp::Clear => {
                self.asm.not64(SCRATCH);
                self.asm.and_rr(d, SCRATCH);
            }
            BitOp::Set => self.asm.or_rr(d, SCRATCH),
            BitOp::Invert => self.asm.xor_rr(d, SCRATCH),
            BitOp::Extract => {
                // test sets ZF; mov_ri32 (not mov_ri64-zero) writes 0
                // to d WITHOUT clobbering flags so setcc sees ZF.
                self.asm.test_rr(d, SCRATCH);
                self.asm.mov_ri32(d, 0);
                self.asm.setcc(Cc::NE, d);
            }
        }
        if rd != 0 {
            self.invalidate_reg(rv_slot(rd).unwrap());
        }
    }

    fn rv_bit_imm(&mut self, rd: u8, rs1: u8, shamt: u8, op: BitOp, pc: u32) {
        let Some(d) = self.rv_dst(rd, pc) else { return };
        if rv_is_reserved(rs1) {
            self.rv_emit_panic_at(pc);
            return;
        }
        let s = shamt & 0x3F;
        if s < 31 {
            let mask_lo: i32 = 1i32 << s;
            self.rv_read(rs1, d, pc);
            match op {
                BitOp::Clear => self.asm.and_ri(d, !mask_lo),
                BitOp::Set => self.asm.or_ri(d, mask_lo),
                BitOp::Invert => self.asm.xor_ri(d, mask_lo),
                BitOp::Extract => {
                    self.asm.shr_ri64(d, s);
                    self.asm.and_ri(d, 1);
                }
            }
        } else {
            let mask: u64 = 1u64 << s;
            self.asm.mov_ri64(SCRATCH, mask);
            self.rv_read(rs1, d, pc);
            match op {
                BitOp::Clear => {
                    self.asm.not64(SCRATCH);
                    self.asm.and_rr(d, SCRATCH);
                }
                BitOp::Set => self.asm.or_rr(d, SCRATCH),
                BitOp::Invert => self.asm.xor_rr(d, SCRATCH),
                BitOp::Extract => {
                    self.asm.shr_ri64(d, s);
                    self.asm.and_ri(d, 1);
                }
            }
        }
        if rd != 0 {
            self.invalidate_reg(rv_slot(rd).unwrap());
        }
    }

    // ---- Zicond -----------------------------------------------------

    /// Semantics:
    ///   `cond = Cc::E`  → czero.eqz rd, rs1, rs2 = (rs2 == 0) ? 0 : rs1
    ///   `cond = Cc::NE` → czero.nez rd, rs1, rs2 = (rs2 != 0) ? 0 : rs1
    ///
    /// We build a mask `M = -1` when **rs1 should be kept** (the
    /// "false" branch of the condition), else `M = 0`, then compute
    /// `d = rs1 & M`. The mask uses the *inverted* condition because
    /// the spec zeroes out when the condition holds.
    fn rv_czero(&mut self, rd: u8, rs1: u8, rs2: u8, cond: Cc, pc: u32) {
        let Some(d) = self.rv_dst(rd, pc) else { return };
        if rv_is_reserved(rs1) || rv_is_reserved(rs2) {
            self.rv_emit_panic_at(pc);
            return;
        }
        if rs2 == 0 {
            // rs2 hardwired zero: condition is statically known.
            //   eqz (Cc::E): rs2 == 0 is always true → d = 0
            //   nez (Cc::NE): rs2 == 0 is true, rs2 != 0 is false → d = rs1
            if matches!(cond, Cc::E) {
                self.asm.mov_ri64(d, 0);
            } else {
                self.rv_read(rs1, d, pc);
            }
            if rd != 0 {
                self.invalidate_reg(rv_slot(rd).unwrap());
            }
            return;
        }
        let inv_cond = match cond {
            Cc::E => Cc::NE,
            Cc::NE => Cc::E,
            _ => unreachable!("rv_czero only accepts E/NE"),
        };
        let r2 = REG_MAP[rv_slot(rs2).unwrap()];
        if d == r2 {
            // d aliases r2 — snapshot r2's value into SCRATCH first,
            // then read rs1 into d while we still can. We reuse SCRATCH
            // to build the mask afterward (it briefly held rs2's value,
            // but we don't need that snapshot after the test_rr below).
            //
            // We CANNOT use push/pop RAX as scratch here: rs1 may map to
            // RAX (x14), in which case overwriting RAX before rv_read
            // would feed rv_read the wrong value.
            self.asm.mov_rr(SCRATCH, r2);
            self.rv_read(rs1, d, pc);
            self.asm.test_rr(SCRATCH, SCRATCH);
            // `mov rN, imm32` (mov_ri32) is a real mov-imm, NOT XOR —
            // it preserves the flags from the test above into setcc.
            self.asm.mov_ri32(SCRATCH, 0);
            self.asm.setcc(inv_cond, SCRATCH);
            self.asm.neg64(SCRATCH);
            self.asm.and_rr(d, SCRATCH);
        } else {
            self.asm.test_rr(r2, r2);
            self.asm.mov_ri32(SCRATCH, 0);
            self.asm.setcc(inv_cond, SCRATCH);
            self.asm.neg64(SCRATCH);
            self.rv_read(rs1, d, pc);
            self.asm.and_rr(d, SCRATCH);
        }
        if rd != 0 {
            self.invalidate_reg(rv_slot(rd).unwrap());
        }
    }

    // ---- Jumps & branches -------------------------------------------

    fn rv_jal(&mut self, rd: u8, imm: i32, pc: u32, next_pc: u32) {
        if rv_is_reserved(rd) {
            self.rv_emit_panic_at(pc);
            return;
        }
        if rd != 0 {
            let slot = rv_slot(rd).unwrap();
            self.asm.mov_ri64(REG_MAP[slot], next_pc as u64);
            self.invalidate_reg(slot);
        }
        let target = (pc as i64).wrapping_add(imm as i64) as u32;
        self.emit_static_branch(target, true, next_pc, pc);
    }

    /// Emit a PVM2 `br_table table_id, rs1` — indirect-jump terminator
    /// dispatching through `Image.jump_table[table_id]`.
    ///
    /// The `rs1` register carries the index encoded as `2*idx + 1`.
    /// Decode:
    ///   1. If `rs1 == 0` → fall through (uninitialised register is a
    ///      sentinel for "no valid target").
    ///   2. `idx = (rs1 - 1) >> 1`. If the LSB of `rs1` was 0 (raw PC
    ///      shape), `idx` underflows to a huge value and the bounds
    ///      check fails → fall through.
    ///   3. If `idx >= table_len[table_id]` → fall through.
    ///   4. `target_pc = jt[jt_offsets[table_id] + idx]`.
    ///   5. `native_addr = code_base + dispatch_table[target_pc]`.
    ///   6. `jmp native_addr`.
    ///
    /// `table_base_byte_offset` and `table_len` are baked in as
    /// immediates at JIT time; they come from `self.rv_jt_offsets`
    /// (the Image's `jump_table_offsets`).
    fn rv_br_table(&mut self, table_id: u16, rs1: u8, pc: u32, next_pc: u32) {
        use super::asm::Cc;

        // Validate table_id against the compiled jump_table_offsets.
        // (linker_rv guarantees this; this is defence-in-depth.)
        let nt = self.rv_jt_offsets.len().saturating_sub(1);
        if (table_id as usize) >= nt {
            self.rv_emit_panic_at(pc);
            return;
        }
        let table_start_entries = self.rv_jt_offsets[table_id as usize];
        let table_end_entries = self.rv_jt_offsets[(table_id as usize) + 1];
        if table_end_entries < table_start_entries {
            self.rv_emit_panic_at(pc);
            return;
        }
        let table_len = table_end_entries - table_start_entries;
        let table_byte_offset = (table_start_entries as i32)
            .checked_mul(4)
            .unwrap_or(i32::MAX);

        if rv_is_reserved(rs1) {
            self.rv_emit_panic_at(pc);
            return;
        }

        // OOB / sentinel handling: per spec the default behavior is
        // to fall through to the next instruction (LLVM-friendly
        // default-case shape). For PVM2 function returns this should
        // never fire — caller always passes a valid encoded idx. We
        // route to panic during bring-up to surface bugs; once stable
        // this can be relaxed to `let fallthrough = label_for_pc(next_pc);`
        // and bind a real fallthrough.
        let oob_target = self.panic_label;

        if rs1 == 0 {
            // rs1 = x0: never dispatch.
            self.asm.jmp_label(oob_target);
            let _ = next_pc;
            return;
        }
        // Load the encoded idx from rs1 into SCRATCH.
        self.rv_read(rs1, SCRATCH, pc);

        // Check rs1 == 0 → OOB.
        self.asm.test_rr(SCRATCH, SCRATCH);
        self.asm.jcc_label(Cc::E, oob_target);

        // idx = (rs1 - 1) >> 1.
        self.asm.sub_ri(SCRATCH, 1);
        self.asm.shr_ri64(SCRATCH, 1);

        // Bounds check: idx < table_len.
        if table_len == 0 {
            self.asm.jmp_label(oob_target);
        } else {
            self.asm.cmp_ri32(SCRATCH, table_len as i32);
            self.asm.jcc_label(Cc::AE, oob_target);
        }

        // target_pc = jt_ptr[table_byte_offset + idx*4]
        //           = *((u32*) (jt_ptr + table_byte_offset + idx*4))
        self.asm.push(Reg::RAX); // save RAX (= x14)
        self.asm.shl_ri64(SCRATCH, 2); // idx *= 4
        self.asm.mov_load64_rip_rel(Reg::RAX, CTX_JT_PTR);
        if table_byte_offset != 0 {
            self.asm.add_ri(Reg::RAX, table_byte_offset);
        }
        // Load the u32 PVM2 PC from [RAX + SCRATCH].
        self.asm.add_rr(Reg::RAX, SCRATCH);
        self.asm.mov_load32(SCRATCH, Reg::RAX, 0); // SCRATCH = target_pc

        // native_addr = code_base + dispatch_table[target_pc]
        self.asm.mov_load64_rip_rel(Reg::RAX, CTX_DISPATCH_TABLE);
        self.asm.movsxd_load_sib4(Reg::RAX, Reg::RAX, SCRATCH);
        self.asm.add_r64_mem_rip_rel(Reg::RAX, CTX_CODE_BASE);
        // Record the target PC for gas-block tracking / pause attribution.
        self.asm.mov_store32_rip_rel(CTX_PC, SCRATCH);
        // RAX holds native addr; restore the saved RAX (= x14) value.
        // Use SCRATCH as the parking lot for the native addr while we pop.
        self.asm.mov_rr(SCRATCH, Reg::RAX);
        self.asm.pop(Reg::RAX);
        self.asm.jmp_reg(SCRATCH);

        // OOB targets `panic_label` directly (see oob_target above);
        // no per-instruction bind needed here.
        let _ = next_pc;
    }

    fn rv_branch(&mut self, rs1: u8, rs2: u8, imm: i32, cc: Cc, pc: u32, next_pc: u32) {
        if rv_is_reserved(rs1) || rv_is_reserved(rs2) {
            self.rv_emit_panic_at(pc);
            return;
        }
        let target = (pc as i64).wrapping_add(imm as i64) as u32;
        let a = self.rv_read_into(rs1, SCRATCH, pc);
        let b = if a == SCRATCH {
            if rs2 == 0 {
                // both x0: cmp SCRATCH, SCRATCH (0 vs 0).
                SCRATCH
            } else {
                REG_MAP[rv_slot(rs2).unwrap()]
            }
        } else if rs2 == 0 {
            self.asm.mov_ri64(SCRATCH, 0);
            SCRATCH
        } else {
            REG_MAP[rv_slot(rs2).unwrap()]
        };
        self.emit_branch_reg(a, b, cc, target, next_pc, pc);
    }

    // ---- custom-0 ---------------------------------------------------

    fn rv_trap(&mut self, pc: u32) {
        self.asm.mov_store32_rip_rel_imm(CTX_PC, pc as i32);
        self.asm
            .mov_store32_rip_rel_imm(CTX_EXIT_REASON, EXIT_TRAP as i32);
        self.asm.mov_store32_rip_rel_imm(CTX_EXIT_ARG, 0);
        self.asm.jmp_label(self.exit_label);
    }

    fn rv_ecall_jar(&mut self, next_pc: u32) {
        self.asm.mov_store32_rip_rel_imm(CTX_PC, next_pc as i32);
        self.asm
            .mov_store32_rip_rel_imm(CTX_EXIT_REASON, EXIT_ECALL as i32);
        self.asm.mov_store32_rip_rel_imm(CTX_EXIT_ARG, 0);
        self.asm.jmp_label(self.exit_label);
    }

    fn rv_ecalli(&mut self, imm: i32, next_pc: u32) {
        self.asm.mov_store32_rip_rel_imm(CTX_PC, next_pc as i32);
        self.asm
            .mov_store32_rip_rel_imm(CTX_EXIT_REASON, EXIT_HOST_CALL as i32);
        self.asm.mov_store32_rip_rel_imm(CTX_EXIT_ARG, imm);
        self.asm.jmp_label(self.exit_label);
    }

    /// Generic "panic at this PC" exit.
    fn rv_emit_panic_at(&mut self, pc: u32) {
        self.asm.mov_store32_rip_rel_imm(CTX_PC, pc as i32);
        self.asm
            .mov_store32_rip_rel_imm(CTX_EXIT_REASON, EXIT_PANIC as i32);
        self.asm.jmp_label(self.exit_label);
    }

    // ----------------------------------------------------------------
    // Peephole tracking helpers — called inline from the tracked arms
    // of `compile_rv_instruction`. They replace the old separate
    // `update_reg_defs_rv` match pass (strict single-pass refactor).
    //
    // Each helper short-circuits when the destination register can't
    // produce a useful tracking entry (x0 / x3 / x4) or when the arm-
    // specific alias guard fires. The per-op emit helper has already
    // cleared `rd` via `invalidate_reg`, so the helper just installs
    // the new RegDef when applicable.
    // ----------------------------------------------------------------

    /// `addi rd, x0, imm` / `lui rd, imm` — canonical constant load.
    /// Records `RegDef::Const(imm as u32)` so subsequent address
    /// formations can fold the constant directly.
    #[inline]
    fn track_const(&mut self, rd: u8, imm: i32) {
        use super::codegen::RegDef;
        if let Some(slot) = rv_slot(rd) {
            self.reg_defs[slot] = RegDef::Const(imm as u32);
            self.reg_defs_active |= 1u16 << slot;
            self.invalidate_dependents(slot);
        }
    }

    /// `slli rd, rs1, shamt` with `shamt ∈ {1,2,3}` and `rs1 != rd`.
    /// Records `RegDef::Shifted` so a following Add can promote to
    /// ScaledAdd for SIB-style LEA. The arm-side guards (range and
    /// aliasing) live in the caller so this helper just installs.
    #[inline]
    fn track_shifted(&mut self, rd: u8, rs1: u8, shamt: u8) {
        use super::codegen::RegDef;
        if let (Some(d), Some(s)) = (rv_slot(rd), rv_slot(rs1)) {
            self.reg_defs[d] = RegDef::Shifted {
                src: s,
                shift: shamt,
            };
            self.reg_defs_active |= 1u16 << d;
            self.invalidate_dependents(d);
        }
    }

    /// `add rd, rs1, rs2` with `rd != rs1 && rd != rs2`. Promotes to
    /// `RegDef::ScaledAdd` when one operand is already tracked as
    /// `Shifted`. Mirrors PVM's update_reg_defs for Add64.
    #[inline]
    fn track_add_scaledadd(&mut self, rd: u8, rs1: u8, rs2: u8) {
        use super::codegen::RegDef;
        let (Some(d), Some(a), Some(b)) = (rv_slot(rd), rv_slot(rs1), rv_slot(rs2)) else {
            return;
        };
        let def = if let RegDef::Shifted { src, shift } = self.reg_defs[b] {
            Some(RegDef::ScaledAdd {
                base: a,
                idx: src,
                shift,
            })
        } else if let RegDef::Shifted { src, shift } = self.reg_defs[a] {
            Some(RegDef::ScaledAdd {
                base: b,
                idx: src,
                shift,
            })
        } else {
            None
        };
        if let Some(def) = def {
            self.reg_defs[d] = def;
            self.reg_defs_active |= 1u16 << d;
            self.invalidate_dependents(d);
        }
        // else: per-op handler already invalidated rd.
    }

    /// Helper for Sh{1,2,3}add → ScaledAdd tracking.
    ///
    /// `sh{N}add rd, rs1, rs2` writes `rd = rs2 + (rs1 << N)`. If rd
    /// aliases either operand, the post-emit value of rd no longer
    /// equals base+idx<<shift in terms of the *new* register state —
    /// any subsequent use of the tracked def would substitute the
    /// already-overwritten value. Skip tracking in those cases
    /// (mirrors PVM's update_reg_defs guard for Add64).
    #[inline]
    fn record_scaledadd(&mut self, rd: u8, rs1: u8, rs2: u8, shift: u8) {
        use super::codegen::RegDef;
        if rd == rs1 || rd == rs2 {
            return;
        }
        let (Some(d), Some(idx), Some(base)) = (rv_slot(rd), rv_slot(rs1), rv_slot(rs2)) else {
            return;
        };
        self.reg_defs[d] = RegDef::ScaledAdd { base, idx, shift };
        self.reg_defs_active |= 1u16 << d;
        self.invalidate_dependents(d);
    }
}

#[derive(Clone, Copy)]
enum AluImmOp {
    Add,
    And,
    Or,
    Xor,
    Addw,
}

#[derive(Clone, Copy)]
enum AluOp {
    Add,
    Sub,
    And,
    Or,
    Xor,
    Mul,
    Addw,
    Subw,
    Mulw,
    Min,
    Max,
    Minu,
    Maxu,
    Andn,
    Orn,
    Xnor,
}

#[derive(Clone, Copy)]
enum ShiftOp {
    Shl64,
    Shr64,
    Sar64,
    Shl32,
    Shr32,
    Sar32,
    Rol64,
    Ror64,
    Rol32,
    Ror32,
}

#[derive(Clone, Copy)]
enum BitOp {
    Clear,
    Set,
    Invert,
    Extract,
}

#[derive(Clone, Copy)]
enum UnaryOp {
    Clz64,
    Clz32,
    Ctz64,
    Ctz32,
    Popcnt64,
    Popcnt32,
    SextB,
    SextH,
    ZextH,
    Rev8,
    OrcB,
}
