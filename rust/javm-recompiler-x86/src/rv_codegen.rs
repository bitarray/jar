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

use super::asm::{Cc, Label, Reg};
use super::codegen::{
    CTX_CODE_BASE, CTX_DISPATCH_TABLE, CTX_EXIT_ARG, CTX_EXIT_REASON, CTX_JT_PTR, CTX_PC,
    CompileResult, Compiler, EXIT_ECALL, EXIT_HOST_CALL, EXIT_PANIC, EXIT_TRAP, GAS, REG_MAP,
    SCRATCH,
};
use javm_exec::rv_instruction::RvInst;
pub use javm_exec::rv_predecode::{RvPredecode, predecode_rv};

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
    /// Compile an RV+C+custom-0 byte stream into x86-64.
    ///
    /// The caller produces a [`RvPredecode`] up front (the result is
    /// also needed to populate the runtime BB / valid-PC region the
    /// JIT consults).
    ///
    /// `jump_table_offsets` is the Image's CSR-style sub-table boundary
    /// array — see [`javm_cap::image::Image::jump_table_offsets`].
    /// Empty implies no br_table dispatch is used (no function calls in
    /// the program). Each `BrTable { table_id, .. }` instruction
    /// dispatches through sub-table `table_id`, whose entries live at
    /// `jt_ptr[jump_table_offsets[table_id] ..
    /// jump_table_offsets[table_id+1]]`.
    pub fn compile_rv(
        mut self,
        code: &[u8],
        pd: &RvPredecode,
        jump_table_offsets: &[u32],
    ) -> CompileResult {
        self.rv_jt_offsets = jump_table_offsets.to_vec();
        // Re-point the "valid target" array used by emit_static_branch /
        // emit_branch_reg / emit_branch_imm at the RV valid-PC set. The
        // existing `is_basic_block_start(byte_offset)` reads byte i from
        // bitmask_ptr and treats `1` as a valid jump target; `Vec<bool>`
        // is 1 byte/element with 0/1 representation, so reinterpreting
        // its base pointer as `*const u8` is sound.
        self.bitmask_ptr = pd.valid_pc.as_ptr() as *const u8;
        self.bitmask_len = pd.valid_pc.len();

        // Per-block gas costs are pre-computed by the predecoder
        // (pipeline simulation in `gas_cost::rv_gas_cost_for_block`).
        // Each meaningful entry is `max(simulation_cycles − 3, 1)`.
        let block_cost: &[u32] = &pd.block_costs;

        self.emit_prologue();

        let mut i = 0usize;
        while i < pd.insts.len() {
            self.asm.ensure_capacity(512);
            let pdi = &pd.insts[i];
            if pdi.is_gas_block_start {
                self.bind_rv_gas_block_start(pdi.pc, block_cost[i]);
            }
            // Phase 2: try multi-instruction fusions before the per-op
            // dispatch. On success, advance past the consumed window and
            // skip the normal compile path; reg_defs is invalidated by
            // the fusion routine itself.
            if let Some(advance) = self.try_fuse_rv_mul_pair(&pd.insts, i) {
                i += advance;
                continue;
            }
            self.compile_rv_instruction(pdi.inst, pdi.pc, pdi.next_pc);
            self.update_reg_defs_rv(&pdi.inst);
            // Phase 4: carry-flag fusion bookkeeping. Add sets last_add_cf
            // from inside rv_alu_rr; Sltu consumes it from inside rv_slt_rr.
            // Any other instruction (including a *failed* Sltu that fell
            // through to the general code) clobbers CF; clear so subsequent
            // unrelated Sltu doesn't read a stale add's flags.
            if !matches!(pdi.inst, RvInst::Add { .. } | RvInst::Sltu { .. }) {
                self.last_add_cf = None;
            }
            i += 1;
        }

        self.emit_exit_sequences();

        // Dispatch table: PVM PC → native code offset.
        let table_len = code.len() + 1;
        let mut dispatch_table = vec![0i32; table_len];
        for &pc in self.gas_block_pcs.iter() {
            let label = Label(self.label_base + pc);
            if let Some(off) = self.asm.label_offset(label) {
                dispatch_table[pc as usize] = off as i32;
            }
        }

        let exit_label_offset = self.asm.label_offset(self.exit_label).unwrap_or(0) as u32;
        let trap_table = core::mem::take(&mut self.trap_entries);

        CompileResult {
            native_code: self.asm.finalize(),
            dispatch_table,
            trap_table,
            exit_label_offset,
        }
    }

    /// Bind the PC label and emit `sub r15, cost; js stub`.
    fn bind_rv_gas_block_start(&mut self, pc: u32, cost: u32) {
        let label = Label(self.label_base + pc);
        self.asm.bind_label(label);
        self.gas_block_pcs.push(pc);

        // Peephole state must not leak across gas-block boundaries: the
        // dispatch table can enter this block from any predecessor, so
        // anything we tracked from the previous instruction stream is
        // not necessarily true on entry.
        self.invalidate_all_regs();
        self.last_add_cf = None;

        let stub_label = self.asm.new_label();
        self.asm.sub_r64_imm32_patchable(GAS, cost as i32);
        self.asm.jcc_label(Cc::S, stub_label);
        self.oog_stubs.push((stub_label, pc, cost));
    }

    /// Dispatch one decoded RV instruction. Each arm is small and reuses
    /// existing helpers wherever possible.
    fn compile_rv_instruction(&mut self, inst: RvInst, pc: u32, next_pc: u32) {
        use RvInst::*;
        match inst {
            // ---- RV64I loads ----
            Lb { rd, rs1, imm } => self.rv_load(rd, rs1, imm, 1, true, pc),
            Lh { rd, rs1, imm } => self.rv_load(rd, rs1, imm, 2, true, pc),
            Lw { rd, rs1, imm } => self.rv_load(rd, rs1, imm, 4, true, pc),
            Ld { rd, rs1, imm } => self.rv_load(rd, rs1, imm, 8, false, pc),
            Lbu { rd, rs1, imm } => self.rv_load(rd, rs1, imm, 1, false, pc),
            Lhu { rd, rs1, imm } => self.rv_load(rd, rs1, imm, 2, false, pc),
            Lwu { rd, rs1, imm } => self.rv_load(rd, rs1, imm, 4, false, pc),

            // ---- RV64I stores ----
            Sb { rs1, rs2, imm } => self.rv_store(rs1, rs2, imm, 1, pc),
            Sh { rs1, rs2, imm } => self.rv_store(rs1, rs2, imm, 2, pc),
            Sw { rs1, rs2, imm } => self.rv_store(rs1, rs2, imm, 4, pc),
            Sd { rs1, rs2, imm } => self.rv_store(rs1, rs2, imm, 8, pc),

            // ---- RV64I ALU imm (64-bit) ----
            Addi { rd, rs1, imm } => self.rv_alu_imm(rd, rs1, imm, AluImmOp::Add, pc),
            Slti { rd, rs1, imm } => self.rv_slt_imm(rd, rs1, imm, true, pc),
            Sltiu { rd, rs1, imm } => self.rv_slt_imm(rd, rs1, imm, false, pc),
            Andi { rd, rs1, imm } => self.rv_alu_imm(rd, rs1, imm, AluImmOp::And, pc),
            Ori { rd, rs1, imm } => self.rv_alu_imm(rd, rs1, imm, AluImmOp::Or, pc),
            Xori { rd, rs1, imm } => self.rv_alu_imm(rd, rs1, imm, AluImmOp::Xor, pc),
            Slli { rd, rs1, shamt } => self.rv_shift_imm(rd, rs1, shamt, ShiftOp::Shl64, pc),
            Srli { rd, rs1, shamt } => self.rv_shift_imm(rd, rs1, shamt, ShiftOp::Shr64, pc),
            Srai { rd, rs1, shamt } => self.rv_shift_imm(rd, rs1, shamt, ShiftOp::Sar64, pc),

            // ---- RV64I ALU imm (32-bit, sign-extended) ----
            Addiw { rd, rs1, imm } => self.rv_alu_imm(rd, rs1, imm, AluImmOp::Addw, pc),
            Slliw { rd, rs1, shamt } => self.rv_shift_imm(rd, rs1, shamt, ShiftOp::Shl32, pc),
            Srliw { rd, rs1, shamt } => self.rv_shift_imm(rd, rs1, shamt, ShiftOp::Shr32, pc),
            Sraiw { rd, rs1, shamt } => self.rv_shift_imm(rd, rs1, shamt, ShiftOp::Sar32, pc),

            // ---- RV64I ALU reg-reg (64-bit) ----
            Add { rd, rs1, rs2 } => self.rv_alu_rr(rd, rs1, rs2, AluOp::Add, pc),
            Sub { rd, rs1, rs2 } => self.rv_alu_rr(rd, rs1, rs2, AluOp::Sub, pc),
            Sll { rd, rs1, rs2 } => self.rv_shift_rr(rd, rs1, rs2, ShiftOp::Shl64, pc),
            Srl { rd, rs1, rs2 } => self.rv_shift_rr(rd, rs1, rs2, ShiftOp::Shr64, pc),
            Sra { rd, rs1, rs2 } => self.rv_shift_rr(rd, rs1, rs2, ShiftOp::Sar64, pc),
            Slt { rd, rs1, rs2 } => self.rv_slt_rr(rd, rs1, rs2, true, pc),
            Sltu { rd, rs1, rs2 } => self.rv_slt_rr(rd, rs1, rs2, false, pc),
            Xor { rd, rs1, rs2 } => self.rv_alu_rr(rd, rs1, rs2, AluOp::Xor, pc),
            Or { rd, rs1, rs2 } => self.rv_alu_rr(rd, rs1, rs2, AluOp::Or, pc),
            And { rd, rs1, rs2 } => self.rv_alu_rr(rd, rs1, rs2, AluOp::And, pc),

            // ---- RV64I ALU reg-reg (32-bit, sign-extended) ----
            Addw { rd, rs1, rs2 } => self.rv_alu_rr(rd, rs1, rs2, AluOp::Addw, pc),
            Subw { rd, rs1, rs2 } => self.rv_alu_rr(rd, rs1, rs2, AluOp::Subw, pc),
            Sllw { rd, rs1, rs2 } => self.rv_shift_rr(rd, rs1, rs2, ShiftOp::Shl32, pc),
            Srlw { rd, rs1, rs2 } => self.rv_shift_rr(rd, rs1, rs2, ShiftOp::Shr32, pc),
            Sraw { rd, rs1, rs2 } => self.rv_shift_rr(rd, rs1, rs2, ShiftOp::Sar32, pc),

            // ---- M extension ----
            Mul { rd, rs1, rs2 } => self.rv_alu_rr(rd, rs1, rs2, AluOp::Mul, pc),
            Mulh { rd, rs1, rs2 } => self.rv_mulh(rd, rs1, rs2, true, true, pc),
            Mulhsu { rd, rs1, rs2 } => self.rv_mulh(rd, rs1, rs2, true, false, pc),
            Mulhu { rd, rs1, rs2 } => self.rv_mulh(rd, rs1, rs2, false, false, pc),
            Div { rd, rs1, rs2 } => self.rv_div_rem(rd, rs1, rs2, true, false, false, pc),
            Divu { rd, rs1, rs2 } => self.rv_div_rem(rd, rs1, rs2, false, false, false, pc),
            Rem { rd, rs1, rs2 } => self.rv_div_rem(rd, rs1, rs2, true, true, false, pc),
            Remu { rd, rs1, rs2 } => self.rv_div_rem(rd, rs1, rs2, false, true, false, pc),
            Mulw { rd, rs1, rs2 } => self.rv_alu_rr(rd, rs1, rs2, AluOp::Mulw, pc),
            Divw { rd, rs1, rs2 } => self.rv_div_rem(rd, rs1, rs2, true, false, true, pc),
            Divuw { rd, rs1, rs2 } => self.rv_div_rem(rd, rs1, rs2, false, false, true, pc),
            Remw { rd, rs1, rs2 } => self.rv_div_rem(rd, rs1, rs2, true, true, true, pc),
            Remuw { rd, rs1, rs2 } => self.rv_div_rem(rd, rs1, rs2, false, true, true, pc),

            // ---- Zbb (basic bit manipulation) ----
            Clz { rd, rs1 } => self.rv_unary(rd, rs1, UnaryOp::Clz64, pc),
            Clzw { rd, rs1 } => self.rv_unary(rd, rs1, UnaryOp::Clz32, pc),
            Ctz { rd, rs1 } => self.rv_unary(rd, rs1, UnaryOp::Ctz64, pc),
            Ctzw { rd, rs1 } => self.rv_unary(rd, rs1, UnaryOp::Ctz32, pc),
            Cpop { rd, rs1 } => self.rv_unary(rd, rs1, UnaryOp::Popcnt64, pc),
            Cpopw { rd, rs1 } => self.rv_unary(rd, rs1, UnaryOp::Popcnt32, pc),
            SextB { rd, rs1 } => self.rv_unary(rd, rs1, UnaryOp::SextB, pc),
            SextH { rd, rs1 } => self.rv_unary(rd, rs1, UnaryOp::SextH, pc),
            ZextH { rd, rs1 } => self.rv_unary(rd, rs1, UnaryOp::ZextH, pc),
            Rev8 { rd, rs1 } => self.rv_unary(rd, rs1, UnaryOp::Rev8, pc),
            OrcB { rd, rs1 } => self.rv_unary(rd, rs1, UnaryOp::OrcB, pc),
            Min { rd, rs1, rs2 } => self.rv_alu_rr(rd, rs1, rs2, AluOp::Min, pc),
            Minu { rd, rs1, rs2 } => self.rv_alu_rr(rd, rs1, rs2, AluOp::Minu, pc),
            Max { rd, rs1, rs2 } => self.rv_alu_rr(rd, rs1, rs2, AluOp::Max, pc),
            Maxu { rd, rs1, rs2 } => self.rv_alu_rr(rd, rs1, rs2, AluOp::Maxu, pc),
            Andn { rd, rs1, rs2 } => self.rv_alu_rr(rd, rs1, rs2, AluOp::Andn, pc),
            Orn { rd, rs1, rs2 } => self.rv_alu_rr(rd, rs1, rs2, AluOp::Orn, pc),
            Xnor { rd, rs1, rs2 } => self.rv_alu_rr(rd, rs1, rs2, AluOp::Xnor, pc),
            Rol { rd, rs1, rs2 } => self.rv_shift_rr(rd, rs1, rs2, ShiftOp::Rol64, pc),
            Ror { rd, rs1, rs2 } => self.rv_shift_rr(rd, rs1, rs2, ShiftOp::Ror64, pc),
            Rolw { rd, rs1, rs2 } => self.rv_shift_rr(rd, rs1, rs2, ShiftOp::Rol32, pc),
            Rorw { rd, rs1, rs2 } => self.rv_shift_rr(rd, rs1, rs2, ShiftOp::Ror32, pc),
            Rori { rd, rs1, shamt } => self.rv_shift_imm(rd, rs1, shamt, ShiftOp::Ror64, pc),
            Roriw { rd, rs1, shamt } => self.rv_shift_imm(rd, rs1, shamt, ShiftOp::Ror32, pc),

            // ---- Zba (shift-add) ----
            Sh1add { rd, rs1, rs2 } => self.rv_shadd(rd, rs1, rs2, 1, false, pc),
            Sh2add { rd, rs1, rs2 } => self.rv_shadd(rd, rs1, rs2, 2, false, pc),
            Sh3add { rd, rs1, rs2 } => self.rv_shadd(rd, rs1, rs2, 3, false, pc),
            Sh1adduw { rd, rs1, rs2 } => self.rv_shadd(rd, rs1, rs2, 1, true, pc),
            Sh2adduw { rd, rs1, rs2 } => self.rv_shadd(rd, rs1, rs2, 2, true, pc),
            Sh3adduw { rd, rs1, rs2 } => self.rv_shadd(rd, rs1, rs2, 3, true, pc),
            Adduw { rd, rs1, rs2 } => self.rv_adduw(rd, rs1, rs2, pc),
            Slliuw { rd, rs1, shamt } => self.rv_slliuw(rd, rs1, shamt, pc),

            // ---- Zbs (single-bit) ----
            Bclr { rd, rs1, rs2 } => self.rv_bit_rr(rd, rs1, rs2, BitOp::Clear, pc),
            Bset { rd, rs1, rs2 } => self.rv_bit_rr(rd, rs1, rs2, BitOp::Set, pc),
            Binv { rd, rs1, rs2 } => self.rv_bit_rr(rd, rs1, rs2, BitOp::Invert, pc),
            Bext { rd, rs1, rs2 } => self.rv_bit_rr(rd, rs1, rs2, BitOp::Extract, pc),
            Bclri { rd, rs1, shamt } => self.rv_bit_imm(rd, rs1, shamt, BitOp::Clear, pc),
            Bseti { rd, rs1, shamt } => self.rv_bit_imm(rd, rs1, shamt, BitOp::Set, pc),
            Binvi { rd, rs1, shamt } => self.rv_bit_imm(rd, rs1, shamt, BitOp::Invert, pc),
            Bexti { rd, rs1, shamt } => self.rv_bit_imm(rd, rs1, shamt, BitOp::Extract, pc),

            // ---- Zicond ----
            CzeroEqz { rd, rs1, rs2 } => self.rv_czero(rd, rs1, rs2, Cc::E, pc),
            CzeroNez { rd, rs1, rs2 } => self.rv_czero(rd, rs1, rs2, Cc::NE, pc),

            // ---- LUI ----
            Lui { rd, imm } => self.rv_lui(rd, imm, pc),

            // ---- Jumps & branches ----
            Jal { rd, imm } => self.rv_jal(rd, imm, pc, next_pc),
            Beq { rs1, rs2, imm } => self.rv_branch(rs1, rs2, imm, Cc::E, pc, next_pc),
            Bne { rs1, rs2, imm } => self.rv_branch(rs1, rs2, imm, Cc::NE, pc, next_pc),
            Blt { rs1, rs2, imm } => self.rv_branch(rs1, rs2, imm, Cc::L, pc, next_pc),
            Bge { rs1, rs2, imm } => self.rv_branch(rs1, rs2, imm, Cc::GE, pc, next_pc),
            Bltu { rs1, rs2, imm } => self.rv_branch(rs1, rs2, imm, Cc::B, pc, next_pc),
            Bgeu { rs1, rs2, imm } => self.rv_branch(rs1, rs2, imm, Cc::AE, pc, next_pc),

            // ---- Fences (no-op) ----
            RvInst::Fence | RvInst::FenceI => {}

            // ---- custom-0 ----
            RvInst::Trap => self.rv_trap(pc),
            RvInst::EcallJar => self.rv_ecall_jar(next_pc),
            RvInst::Ecalli { imm } => self.rv_ecalli(imm, next_pc),
            // PVM2 control flow. br_table dispatches through a per-
            // function jump table; fallthrough is a no-op terminator
            // (just a bb_start marker handled by predecode).
            RvInst::BrTable { table_id, rs1 } => self.rv_br_table(table_id, rs1, pc, next_pc),
            RvInst::Fallthrough => {}

            RvInst::Reserved { .. } => self.rv_emit_panic_at(pc),
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
        if rs1 == 0 {
            self.asm.mov_ri32(SCRATCH, imm as u32);
            return;
        }
        if rv_is_reserved(rs1) {
            self.rv_emit_panic_at(pc);
            return;
        }
        let base = REG_MAP[rv_slot(rs1).unwrap()];
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
        if matches!(op, AluOp::Add) && rd != 0 && rs1 != 0 && rs2 != 0 {
            if let (Some(d_s), Some(a_s), Some(b_s)) =
                (rv_slot(rd), rv_slot(rs1), rv_slot(rs2))
            {
                self.last_add_cf = Some((d_s, a_s, b_s));
            }
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
        if !signed
            && let Some((add_d, add_a, add_b)) = self.last_add_cf
        {
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
    // Peephole tracking — RV-side analogue of update_reg_defs.
    //
    // Called by the main compile_rv loop after every per-op handler.
    // For the handful of opcodes that produce trackable patterns we
    // record the new definition; the per-op handler has already
    // cleared rd via invalidate_reg, so for non-trackable opcodes we
    // just need to leave reg_defs alone.
    // ----------------------------------------------------------------
    fn update_reg_defs_rv(&mut self, inst: &RvInst) {
        use super::codegen::RegDef;
        // Helper: record def for rd (RV reg index). x0/x3/x4 short-circuit.
        // Returns true if recorded (so caller can skip the fall-through).
        let _ = (); // doc anchor

        match *inst {
            // `addi rd, x0, imm`  — canonical RV "li rd, imm".
            //
            // Track as Const so address-formation peepholes (PVM-style
            // emit_addr_to_scratch fold) can fire. Const stores u32 — the
            // common addressing case fits, and Addi with x0+imm fits in i32
            // anyway, so sign-extension into u32 is fine.
            RvInst::Addi { rd, rs1: 0, imm } => {
                if let Some(slot) = rv_slot(rd) {
                    self.reg_defs[slot] = RegDef::Const(imm as u32);
                    self.reg_defs_active |= 1u16 << slot;
                    self.invalidate_dependents(slot);
                }
            }
            // `lui rd, imm` — imm field already carries the shifted value
            // (decode_lui in rv_instruction.rs does `imm = w & 0xFFFF_F000`).
            RvInst::Lui { rd, imm } => {
                if let Some(slot) = rv_slot(rd) {
                    self.reg_defs[slot] = RegDef::Const(imm as u32);
                    self.reg_defs_active |= 1u16 << slot;
                    self.invalidate_dependents(slot);
                }
            }
            // `slli rd, rs, sh` with sh ∈ {1,2,3}: track as Shifted so a
            // following Add can promote to ScaledAdd for SIB-style LEA.
            // Self-aliasing (rs == rd) overwrites the source value and
            // would make Shifted{src=rd} self-referential — skip.
            RvInst::Slli { rd, rs1, shamt } if (1..=3).contains(&shamt) && rs1 != rd => {
                if let (Some(d), Some(s)) = (rv_slot(rd), rv_slot(rs1)) {
                    self.reg_defs[d] = RegDef::Shifted {
                        src: s,
                        shift: shamt,
                    };
                    self.reg_defs_active |= 1u16 << d;
                    self.invalidate_dependents(d);
                }
            }
            // `add rd, rs1, rs2` — promote to ScaledAdd when one operand
            // is a tracked Shifted def. Mirrors PVM's update_reg_defs
            // for Add64, minus the in-place doubling case (which RV
            // expresses as `slli rd, rd, 1`).
            RvInst::Add { rd, rs1, rs2 } => {
                let d = match rv_slot(rd) {
                    Some(s) => s,
                    None => return,
                };
                let s1 = rv_slot(rs1);
                let s2 = rv_slot(rs2);
                let def = match (s1, s2) {
                    (Some(a), Some(b)) => {
                        if let RegDef::Shifted { src, shift } = self.reg_defs[b] {
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
                        }
                    }
                    _ => None,
                };
                if let Some(def) = def {
                    self.reg_defs[d] = def;
                    self.reg_defs_active |= 1u16 << d;
                    self.invalidate_dependents(d);
                }
                // else: per-op handler already invalidated rd; nothing to do.
            }
            // Zba shift-add: `rd = rs2 + (rs1 << shift)`. This is exactly
            // ScaledAdd{base:rs2, idx:rs1, shift}. lld emits these directly
            // for indexed access, which is the cleanest fusion target.
            RvInst::Sh1add { rd, rs1, rs2 } => {
                self.record_scaledadd(rd, rs1, rs2, 1);
            }
            RvInst::Sh2add { rd, rs1, rs2 } => {
                self.record_scaledadd(rd, rs1, rs2, 2);
            }
            RvInst::Sh3add { rd, rs1, rs2 } => {
                self.record_scaledadd(rd, rs1, rs2, 3);
            }
            _ => {
                // Non-trackable. Per-op handler's invalidate_reg has
                // already cleared rd; nothing to do here.
            }
        }
    }

    /// Helper for Sh{1,2,3}add → ScaledAdd tracking.
    #[inline]
    fn record_scaledadd(&mut self, rd: u8, rs1: u8, rs2: u8, shift: u8) {
        use super::codegen::RegDef;
        let (Some(d), Some(idx), Some(base)) = (rv_slot(rd), rv_slot(rs1), rv_slot(rs2)) else {
            return;
        };
        self.reg_defs[d] = RegDef::ScaledAdd { base, idx, shift };
        self.reg_defs_active |= 1u16 << d;
        self.invalidate_dependents(d);
    }

    // ----------------------------------------------------------------
    // Phase 2: multiply-pair fusion.
    //
    // Detect `mul D_lo, A, B` immediately followed by
    // `mulhu/mulh D_hi, A, B` and emit a single x86 `mul`/`imul`
    // producing the 128-bit result in rdx:rax.
    //
    // mulhsu (signed×unsigned high) requires correction logic that x86
    // doesn't fold into one instruction; skip.
    //
    // Returns Some(advance) on success (the number of pd.insts entries
    // consumed — always 2). None means no fusion; caller proceeds with
    // the normal per-op dispatch.
    // ----------------------------------------------------------------
    fn try_fuse_rv_mul_pair(
        &mut self,
        insts: &[javm_exec::rv_predecode::RvPreDecodedInst],
        i: usize,
    ) -> Option<usize> {
        let cur = &insts[i];
        let (m_rd, m_rs1, m_rs2) = match cur.inst {
            RvInst::Mul { rd, rs1, rs2 } => (rd, rs1, rs2),
            _ => return None,
        };
        let next = insts.get(i + 1)?;
        // Don't cross gas-block boundaries: the next instruction must not
        // be a fresh entry point (dispatch could land between mul and mulh).
        if next.is_gas_block_start {
            return None;
        }
        let (u_rd, u_rs1, u_rs2, signed) = match next.inst {
            RvInst::Mulhu { rd, rs1, rs2 } => (rd, rs1, rs2, false),
            RvInst::Mulh { rd, rs1, rs2 } => (rd, rs1, rs2, true),
            _ => return None,
        };
        // Both must reference the same source pair, and the two destinations
        // must differ (otherwise only one of {lo, hi} would be observable).
        if u_rs1 != m_rs1 || u_rs2 != m_rs2 || u_rd == m_rd {
            return None;
        }
        // Reserved-x3/x4 must not appear; x0 destinations are silently
        // unobservable, but for simplicity require both dests to be real.
        if rv_is_reserved(m_rd) || rv_is_reserved(u_rd) {
            return None;
        }
        if rv_is_reserved(m_rs1) || rv_is_reserved(m_rs2) {
            return None;
        }
        let (Some(rs1_slot), Some(rs2_slot)) = (rv_slot(m_rs1), rv_slot(m_rs2)) else {
            // m_rs1 or m_rs2 is x0 — multiplying by 0 is a degenerate case,
            // not worth fusing (the per-op fallback handles it correctly
            // anyway).
            return None;
        };
        let (Some(lo_slot), Some(hi_slot)) = (rv_slot(m_rd), rv_slot(u_rd)) else {
            return None;
        };

        let a = REG_MAP[rs1_slot];
        let b = REG_MAP[rs2_slot];
        let rd_lo = REG_MAP[lo_slot];
        let rd_hi = REG_MAP[hi_slot];
        let phi11 = REG_MAP[11]; // RAX

        // Strategy (same as PVM's try_fuse_mul_pair_raw):
        //   1. Save φ[11] if neither rd_lo nor rd_hi will overwrite RAX.
        //   2. Move A into RAX, B into a non-RAX/RDX register (= mul_src).
        //   3. mul/imul mul_src → RDX:RAX.
        //   4. Move RAX → rd_lo, RDX → rd_hi.
        //   5. Restore φ[11].
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
        // rd_hi from RDX (SCRATCH). rd_hi can never equal SCRATCH (SCRATCH
        // isn't a PVM-mapped register), so the unconditional mov is safe.
        self.asm.mov_rr(rd_hi, SCRATCH);

        if need_save_phi11 {
            self.asm.pop(phi11);
        }

        // Both destinations changed; clear any tracking on them.
        self.invalidate_reg(lo_slot);
        self.invalidate_reg(hi_slot);
        // mul/imul clobbers CF; a subsequent Sltu must not fuse against
        // a stale prior-add's flags.
        self.last_add_cf = None;

        Some(2)
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
