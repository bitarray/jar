//! PVM-to-x86-64 code generation.
//!
//! Compiles PVM bytecode into native x86-64 machine code. Each PVM basic block
//! becomes a native basic block with gas metering at entry. PVM registers are
//! mapped to x86-64 registers for the duration of execution.
//!
//! Register mapping (PVM `φ[i]` → x86-64):
//!   `φ[0]`  → RBP   (callee-saved) — RA, rarely used as memory base
//!   `φ[1]`  → RBX   (callee-saved) — SP, avoids RBP encoding penalty
//!   `φ[2]`  → R12   (callee-saved)
//!   `φ[3]`  → R13   (callee-saved)
//!   `φ[4]`  → R14   (callee-saved)
//!   `φ[5]`  → RSI   (caller-saved)
//!   `φ[6]`  → RDI   (caller-saved)
//!   `φ[7]`  → R8    (caller-saved)
//!   `φ[8]`  → R9    (caller-saved)
//!   `φ[9]`  → R10   (caller-saved)
//!   `φ[10]` → R11   (caller-saved)
//!   `φ[11]` → RAX   (caller-saved)
//!   `φ[12]` → RCX   (caller-saved)
//!
//! Reserved: R15 = gas meter, RDX = scratch, RSP = native stack.

use alloc::vec::Vec;

use super::asm::{Assembler, Cc, Label, Reg};
use javm_exec::gas_sim::GasSimulator;

/// Map RV register index (0..12) to x86-64 register.
/// All 13 PVM registers live in x86 registers.
pub(crate) const REG_MAP: [Reg; 13] = [
    Reg::RBP, // φ[0] — RA (rarely used as memory base, so RBP encoding penalty is acceptable)
    Reg::RBX, // φ[1] — SP (frequently used as memory base, RBX avoids RBP disp8 penalty)
    Reg::R12, // φ[2]
    Reg::R13, // φ[3]
    Reg::R14, // φ[4]
    Reg::RSI, // φ[5]
    Reg::RDI, // φ[6]
    Reg::R8,  // φ[7]
    Reg::R9,  // φ[8]
    Reg::R10, // φ[9]
    Reg::R11, // φ[10]
    Reg::RAX, // φ[11]
    Reg::RCX, // φ[12]
];

/// Scratch register (not mapped to any PVM register).
pub(crate) const SCRATCH: Reg = Reg::RDX;

/// RV register number → PVM2 slot (0..12), or `0xFF` for "no slot"
/// (x0, reserved x3/x4, or any out-of-range value). Mirrors the
/// slot encoding used by `rv_op_metadata` so that gas accounting
/// agrees bit-for-bit with the predecode-cached path.
#[inline(always)]
pub(crate) fn rv_slot_or_ff(x: u8) -> u8 {
    match x {
        1 => 0,
        2 => 1,
        5..=15 => x - 3,
        _ => 0xFF,
    }
}
/// R15 = gas meter. Loaded from `ctx.gas` at the prologue, decremented
/// once per basic block, flushed back to `ctx.gas` at every exit.
pub(crate) const GAS: Reg = Reg::R15;

/// JitContext lives above the PVM u32 address space (no bounds check
/// on guest mem — the full low 4 GiB of native VA belongs to the
/// program). CTX is reached via RIP-relative `[rip+disp32]`, which
/// gives ±2 GiB range from the JIT code, so CTX must be **adjacent**
/// to the JIT region.
///
/// In the nub-x86 microkernel, CTX and the per-Image JIT arena both
/// live in PML4 slot 1 (base 512 GiB). Sharing one PML4 slot lets
/// the Image's PDPT subtree be cached as a template across all
/// Instances (per-call PT just shallow-clones the slot's entry). MEM
/// stays in `PML4[0]` at VA 0 so PVM addr == native VA still holds.
pub const CTX_VA: u64 = 1u64 << 39;

use super::JitContext;
use memoffset::offset_of;

pub const CTX_REGS: u64 = CTX_VA + offset_of!(JitContext, regs) as u64;
pub const CTX_GAS: u64 = CTX_VA + offset_of!(JitContext, gas) as u64;
pub const CTX_EXIT_REASON: u64 = CTX_VA + offset_of!(JitContext, exit_reason) as u64;
pub const CTX_EXIT_ARG: u64 = CTX_VA + offset_of!(JitContext, exit_arg) as u64;
pub const CTX_HEAP_BASE: u64 = CTX_VA + offset_of!(JitContext, heap_base) as u64;
pub const CTX_HEAP_TOP: u64 = CTX_VA + offset_of!(JitContext, heap_top) as u64;
pub const CTX_JT_PTR: u64 = CTX_VA + offset_of!(JitContext, jt_ptr) as u64;
pub const CTX_JT_LEN: u64 = CTX_VA + offset_of!(JitContext, jt_len) as u64;
pub const CTX_BB_STARTS: u64 = CTX_VA + offset_of!(JitContext, bb_starts) as u64;
pub const CTX_BB_LEN: u64 = CTX_VA + offset_of!(JitContext, bb_len) as u64;
pub const CTX_ENTRY_PC: u64 = CTX_VA + offset_of!(JitContext, entry_pc) as u64;
pub const CTX_PC: u64 = CTX_VA + offset_of!(JitContext, pc) as u64;
pub const CTX_DISPATCH_TABLE: u64 = CTX_VA + offset_of!(JitContext, dispatch_table) as u64;
pub const CTX_CODE_BASE: u64 = CTX_VA + offset_of!(JitContext, code_base) as u64;
pub const CTX_FAST_REENTRY: u64 = CTX_VA + offset_of!(JitContext, fast_reentry) as u64;
pub const CTX_HOST_RSP_BASE: u64 = CTX_VA + offset_of!(JitContext, host_rsp_base) as u64;

/// Exit reason codes (matching ExitReason enum).
pub const EXIT_HALT: u32 = 0;
pub const EXIT_PANIC: u32 = 1;
pub const EXIT_OOG: u32 = 2;
pub const EXIT_PAGE_FAULT: u32 = 3;
pub const EXIT_HOST_CALL: u32 = 4;
pub const EXIT_ECALL: u32 = 6;
pub const EXIT_TRAP: u32 = 7;

/// Result of compilation.
pub struct CompileResult {
    pub native_code: Vec<u8>,
    /// Sparse dispatch entries — `(pvm_pc, native_offset)` for every
    /// gas-block start. The runtime arena's dispatch region is
    /// page-zero-filled, so callers only need to write these
    /// non-zero entries instead of materialising a dense
    /// `code.len() + 1`-sized array.
    pub dispatch_entries: Vec<(u32, i32)>,
    pub trap_table: Vec<(u32, u32)>,
    pub exit_label_offset: u32,
    /// Byte-indexed validity map (RV path only): true at every PC where
    /// an instruction begins. Empty for the PVM path — `compile()`
    /// consumes its own bitmask argument, no need to surface it.
    pub valid_pc: Vec<bool>,
}

/// Helper function pointers passed to compiled code.
#[repr(C)]
pub struct HelperFns {
    pub mem_read_u8: u64,
    pub mem_read_u16: u64,
    pub mem_read_u32: u64,
    pub mem_read_u64: u64,
    pub mem_write_u8: u64,
    pub mem_write_u16: u64,
    pub mem_write_u32: u64,
    pub mem_write_u64: u64,
    pub sbrk_helper: u64,
}

/// Tracks what a PVM register was last set to, for peephole optimization.
#[derive(Clone, Copy, Debug)]
pub(crate) enum RegDef {
    /// Unknown or complex value.
    Unknown,
    /// Known compile-time constant (32-bit address or immediate).
    Const(u32),
    /// reg = src << shift (shift 1..=3, i.e. *2, *4, *8).
    /// Built from: add D,A,A → Shifted{src:A, shift:1}
    ///             add D,D,D where D=Shifted{src,s} → Shifted{src, shift:s+1}
    Shifted { src: usize, shift: u8 },
    /// reg = base + (idx << shift) (shift 0..=3, i.e. *1, *2, *4, *8).
    /// Built from: add D,BASE,S where S=Shifted{src,s} → ScaledAdd{base:BASE, idx:src, shift:s}
    ScaledAdd { base: usize, idx: usize, shift: u8 },
}

/// PVM-to-x86-64 compiler.
pub struct Compiler {
    pub asm: Assembler,
    /// Base label ID for PC labels. label_for_pc(pc) = Label(label_base + pc).
    /// Labels are bulk-allocated in the assembler with LABEL_UNBOUND=0 (zeroed pages).
    pub(crate) label_base: u32,
    /// Gas block start PCs discovered during compilation (for dispatch table).
    pub(crate) gas_block_pcs: Vec<u32>,
    /// Label for the exit sequence.
    pub(crate) exit_label: Label,
    /// Label for the shared out-of-gas exit (sets EXIT_OOG + jumps to exit).
    oog_label: Label,
    /// Label for panic exit.
    pub(crate) panic_label: Label,
    /// Label for OOG handler that reads PC from SCRATCH: stores PC, then falls through to oog_label.
    oog_pc_label: Label,
    /// Per-gas-block OOG stubs: (label, pvm_pc) — emitted as cold code after main body.
    pub(crate) oog_stubs: Vec<(Label, u32, u32)>, // (label, pvm_pc, block_cost)
    /// Helper function addresses.
    pub(crate) helpers: HelperFns,
    /// Bitmask reference (1 = instruction start). Stored as raw pointer for self-referential use.
    pub(crate) bitmask_ptr: *const u8,
    pub(crate) bitmask_len: usize,
    /// Peephole: tracks how each PVM register was last defined.
    pub(crate) reg_defs: [RegDef; 13],
    /// Bitmask of registers that have non-Unknown reg_defs (for fast invalidation).
    pub(crate) reg_defs_active: u16,
    /// Carry flag fusion: after an `add64 D, A, B`, CF = overflow(A+B).
    /// Stores (D, A, B) so that a subsequent `setLtU C, D, A` or `setLtU C, D, B`
    /// can use CF directly instead of emitting a redundant `cmp`.
    /// Cleared by any instruction that clobbers flags (i.e., everything except the
    /// immediately following setLtU).
    pub(crate) last_add_cf: Option<(usize, usize, usize)>,
    /// Trap table for signal-based bounds checking: (native_offset, pvm_pc).
    pub(crate) trap_entries: Vec<(u32, u32)>,
    /// Memory tier load/store cycles for gas simulation.
    pub(crate) mem_cycles: u8,
    /// Pipeline simulator for per-block gas costing. The RV streaming
    /// compile path drives this directly from `compile_rv_instruction`
    /// arms (so the per-instruction loop performs ONE match over
    /// `RvInst`); `bind_rv_gas_block_start_streaming` flushes it at
    /// block boundaries. The PVM `compile()` path uses its own local
    /// simulator and leaves this one untouched.
    pub(crate) gas_sim: GasSimulator,
    /// PVM2: per-function `br_table` sub-table CSR offsets. Each
    /// `BrTable { table_id, .. }` instruction dispatches through
    /// entries `jt_ptr[rv_jt_offsets[table_id] ..
    /// rv_jt_offsets[table_id + 1]]`. Empty for PVM legacy.
    pub(crate) rv_jt_offsets: Vec<u32>,
    /// True during RV streaming compile (`compile_rv`). When set, branch
    /// emit helpers defer forward-target validation (`target > pc`) to a
    /// post-pass instead of consulting `bitmask_ptr`. Off for PVM, whose
    /// caller-supplied bitmask is fully populated at emit time.
    pub(crate) rv_streaming: bool,
    /// Forward branches whose target validity could not be determined at
    /// emit time. Resolved post-pass: each entry is
    /// `(target_pc, branch_pc, fixup_idx)`. If `valid_pc[target]` is
    /// false after the streaming pass, the fixup is redirected to a
    /// per-branch panic stub.
    pub(crate) rv_pending_fwd_branches: Vec<(u32, u32, usize)>,
    /// Backing storage for `bitmask_ptr` during RV streaming compile.
    /// Built incrementally in `bind_rv_gas_block_start_streaming`. Empty
    /// for the PVM path (uses the caller-supplied bitmask).
    pub(crate) rv_valid_pc: Vec<bool>,
}

impl Compiler {
    pub fn new(
        bitmask: &[u8],
        _jump_table: &[u32],
        helpers: HelperFns,
        code_len: usize,
        jit_va_base: u64,
        mem_cycles: u8,
    ) -> Self {
        // Estimate native code size: ~3x PVM code provides safety margin for
        // direct-write emission (no per-byte capacity checks in hot loop).
        let estimated_native = code_len * 3 + 8192;
        // Labels: one per PC (dense array) + fixed overhead for exit/oog/stubs.
        let estimated_labels = code_len + 1024;
        // mmap-backed assembler buffer was a host-only path; the recompiler is
        // now embedded only by `nub-arch-x86`, which uses the Vec-backed form.
        let mut asm = Assembler::with_capacity(estimated_native, estimated_labels);
        // RIP-relative CTX accesses need the eventual load VA to compute
        // disp32. Callers from a per-invocation runtime pass JIT_VA_M;
        // tests pass 0 (encodings reference offset 0).
        asm.set_jit_va_base(jit_va_base);
        // Reserve label 0 so label IDs start from 1 (for consistency with fixed labels).
        let _reserved = asm.new_label(); // Label(0)
        let exit_label = asm.new_label();
        let oog_label = asm.new_label();
        let panic_label = asm.new_label();
        let oog_pc_label = asm.new_label();
        // Pre-create one label per PC for O(1) lookup in label_for_pc.
        // With LABEL_UNBOUND=0, bulk allocation uses zeroed pages (calloc/COW).
        // Only the ~640 labels that get bound trigger page faults — the other
        // ~110K labels stay on zero pages and cost nothing.
        let label_base = asm.labels_len() as u32;
        asm.bulk_create_labels(code_len + 1);
        Self {
            label_base,
            gas_block_pcs: Vec::with_capacity(1024),
            asm,
            exit_label,
            oog_label,
            panic_label,
            oog_pc_label,
            oog_stubs: Vec::with_capacity(1024),
            reg_defs: [RegDef::Unknown; 13],
            reg_defs_active: 0,
            last_add_cf: None,
            helpers,
            bitmask_ptr: bitmask.as_ptr(),
            bitmask_len: bitmask.len(),
            trap_entries: Vec::with_capacity(2048),
            mem_cycles,
            gas_sim: GasSimulator::new(),
            rv_jt_offsets: Vec::new(),
            rv_streaming: false,
            rv_pending_fwd_branches: Vec::new(),
            rv_valid_pc: Vec::new(),
        }
    }

    /// RV streaming-compile gas feed. Each `compile_rv_instruction`
    /// arm calls this once with its kind constant + raw RV register
    /// indices; we slot-translate inline and call
    /// `rv_feed_gas_kind` against `self.gas_sim`. Returns
    /// `is_terminator` (RVF_TERM flag from the LUT entry).
    #[inline(always)]
    pub(crate) fn feed_gas_rv(&mut self, kind: u8, rs1: u8, rs2: u8, rd: u8) -> bool {
        javm_exec::gas_cost::rv_feed_gas_kind(
            kind,
            rv_slot_or_ff(rs1),
            rv_slot_or_ff(rs2),
            rv_slot_or_ff(rd),
            &mut self.gas_sim,
            self.mem_cycles,
        )
    }

    /// Look up the pre-created label for a PVM PC. O(1) arithmetic.
    #[inline]
    pub(crate) fn label_for_pc(&self, pc: u32) -> Label {
        Label(self.label_base + pc)
    }

    pub(crate) fn is_basic_block_start(&self, idx: u32) -> bool {
        let i = idx as usize;
        // SAFETY: bitmask_ptr points to the start of a valid &[u8] slice of length
        // bitmask_len, and i < bitmask_len is checked before the dereference.
        i < self.bitmask_len && unsafe { *self.bitmask_ptr.add(i) } == 1
    }

    /// Emit memory read with bounds check (cold fault path).
    /// Hot path: cmp + jae + load (2 instructions, no extra stores).
    /// No bounds check — SIGSEGV handler catches OOB.
    pub(crate) fn emit_mem_read_sized(
        &mut self,
        dst: Reg,
        fn_addr: u64,
        width_bytes: u32,
        pvm_pc: u32,
    ) {
        let w = if width_bytes > 0 {
            width_bytes
        } else if fn_addr == self.helpers.mem_read_u8 {
            1
        } else if fn_addr == self.helpers.mem_read_u16 {
            2
        } else if fn_addr == self.helpers.mem_read_u32 {
            4
        } else {
            8
        };

        // Record trap entry before the load instruction (for SIGSEGV handler).
        self.trap_entries.push((self.asm.offset() as u32, pvm_pc));

        match w {
            1 => self.asm.movzx_load8_at_index(dst, SCRATCH),
            2 => self.asm.movzx_load16_at_index(dst, SCRATCH),
            4 => self.asm.mov_load32_at_index(dst, SCRATCH),
            8 => self.asm.mov_load64_at_index(dst, SCRATCH),
            _ => unreachable!(),
        }
    }

    /// Emit sign extension after a memory load, if the opcode is a signed variant.
    /// Handles both direct loads (LoadI8/I16/I32) and indirect loads (LoadIndI8/I16/I32).
    pub(crate) fn emit_mem_write(
        &mut self,
        _addr_in_scratch: bool,
        val_reg: Reg,
        fn_addr: u64,
        pvm_pc: u32,
    ) {
        let w = if fn_addr == self.helpers.mem_write_u8 {
            1u32
        } else if fn_addr == self.helpers.mem_write_u16 {
            2
        } else if fn_addr == self.helpers.mem_write_u32 {
            4
        } else {
            8
        };

        // Record trap entry before the store instruction (for SIGSEGV handler).
        self.trap_entries.push((self.asm.offset() as u32, pvm_pc));

        match w {
            1 => self.asm.mov_store8_at_index(SCRATCH, val_reg),
            2 => self.asm.mov_store16_at_index(SCRATCH, val_reg),
            4 => self.asm.mov_store32_at_index(SCRATCH, val_reg),
            8 => self.asm.mov_store64_at_index(SCRATCH, val_reg),
            _ => unreachable!(),
        }
    }

    /// Emit store-immediate-indirect: store an immediate value to memory.
    /// Inline SIB store (no function call needed).
    ///
    pub(crate) fn invalidate_dependents(&mut self, reg: usize) {
        // Only iterate registers that have active (non-Unknown) defs
        let mut active = self.reg_defs_active & !(1u16 << reg);
        while active != 0 {
            let i = active.trailing_zeros() as usize;
            active &= active - 1;
            let depends = match self.reg_defs[i] {
                RegDef::Shifted { src, .. } => src == reg,
                RegDef::ScaledAdd { base, idx, .. } => base == reg || idx == reg,
                _ => false,
            };
            if depends {
                self.reg_defs[i] = RegDef::Unknown;
                self.reg_defs_active &= !(1u16 << i);
            }
        }
    }

    /// Invalidate a register's tracked definition and any dependents.
    #[inline]
    pub(crate) fn invalidate_reg(&mut self, reg: usize) {
        self.reg_defs[reg] = RegDef::Unknown;
        self.reg_defs_active &= !(1u16 << reg);
        self.invalidate_dependents(reg);
    }

    /// Invalidate all register definitions (on block boundaries, calls, etc.)
    #[inline]
    pub(crate) fn invalidate_all_regs(&mut self) {
        self.reg_defs = [RegDef::Unknown; 13];
        self.reg_defs_active = 0;
    }

    /// Emit gas block boundary: bind label, flush previous block cost, emit new gas check.
    ///
    /// Called at every gas block start (PC=0 and post-terminator PCs) to:
    /// 1. Bind the PC label for branch resolution
    /// 2. Patch the previous block's gas cost (deferred until block end)
    /// 3. Emit a new `sub [ctx+gas], cost; js oog_stub` sequence
    pub(crate) fn emit_static_branch(
        &mut self,
        target: u32,
        condition: bool,
        _fallthrough: u32,
        pc: u32,
    ) {
        if !condition {
            return;
        }
        if self.rv_streaming && target > pc {
            let label = self.label_for_pc(target);
            let fixup_idx = self.asm.fixups_len();
            self.asm.jmp_label(label);
            self.rv_pending_fwd_branches.push((target, pc, fixup_idx));
            return;
        }
        if !self.is_basic_block_start(target) {
            self.asm.mov_store32_rip_rel_imm(CTX_PC, pc as i32);
            self.emit_exit(EXIT_PANIC, 0);
            return;
        }
        let label = self.label_for_pc(target);
        self.asm.jmp_label(label);
    }

    /// Emit a dynamic jump (through jump table).
    pub(crate) fn emit_branch_reg(
        &mut self,
        a: Reg,
        b: Reg,
        cc: Cc,
        target: u32,
        _fallthrough: u32,
        pc: u32,
    ) {
        if self.rv_streaming && target > pc {
            self.asm.cmp_rr(a, b);
            let label = self.label_for_pc(target);
            let fixup_idx = self.asm.fixups_len();
            self.asm.jcc_label(cc, label);
            self.rv_pending_fwd_branches.push((target, pc, fixup_idx));
            return;
        }
        if !self.is_basic_block_start(target) {
            self.asm.mov_store32_rip_rel_imm(CTX_PC, pc as i32);
            self.asm.cmp_rr(a, b);
            self.asm.jcc_label(cc, self.panic_label);
            return;
        }
        self.asm.cmp_rr(a, b);
        let label = self.label_for_pc(target);
        self.asm.jcc_label(cc, label);
    }

    /// Emit a shift by register value using CL.
    /// shift_op: 4=SHL, 5=SHR, 7=SAR, 0=ROL, 1=ROR
    pub(crate) fn emit_shift_by_reg32(&mut self, dst: Reg, shift_reg: Reg, shift_op: u8) {
        // Need shift amount in CL (RCX = φ[12])
        // If shift_reg is already RCX, great. Otherwise save/restore.
        if shift_reg == Reg::RCX {
            self.asm.shift_cl32(shift_op, dst);
        } else if dst == Reg::RCX {
            // dst is CL — need to swap
            self.asm.push(shift_reg);
            self.asm.mov_rr(Reg::RCX, shift_reg);
            // But we also need dst's value which was in RCX
            // We pushed shift_reg, not dst. Let me handle this differently.
            // Move dst to SCRATCH, put shift in CL, shift SCRATCH, move back.
            self.asm.pop(shift_reg); // undo push
            self.asm.mov_rr(SCRATCH, dst);
            self.asm.push(Reg::RCX);
            self.asm.mov_rr(Reg::RCX, shift_reg);
            self.asm.shift_cl32(shift_op, SCRATCH);
            self.asm.pop(Reg::RCX);
            self.asm.mov_rr(dst, SCRATCH);
        } else {
            self.asm.push(Reg::RCX);
            self.asm.mov_rr(Reg::RCX, shift_reg);
            self.asm.shift_cl32(shift_op, dst);
            self.asm.pop(Reg::RCX);
        }
    }

    pub(crate) fn emit_shift_by_reg64(&mut self, dst: Reg, shift_reg: Reg, shift_op: u8) {
        if shift_reg == Reg::RCX {
            self.asm.shift_cl64(shift_op, dst);
        } else if dst == Reg::RCX {
            self.asm.mov_rr(SCRATCH, dst);
            self.asm.push(Reg::RCX);
            self.asm.mov_rr(Reg::RCX, shift_reg);
            self.asm.shift_cl64(shift_op, SCRATCH);
            self.asm.pop(Reg::RCX);
            self.asm.mov_rr(dst, SCRATCH);
        } else {
            self.asm.push(Reg::RCX);
            self.asm.mov_rr(Reg::RCX, shift_reg);
            self.asm.shift_cl64(shift_op, dst);
            self.asm.pop(Reg::RCX);
        }
    }

    /// Three-register 64-bit ALU with optional commutativity optimization.
    /// When `commutative` is true and rd == rb, emit `op(d, a)` directly
    /// instead of saving/restoring via SCRATCH.

    /// Emit an exit sequence that sets exit_reason and exit_arg.
    pub(crate) fn emit_exit(&mut self, reason: u32, arg: u32) {
        self.asm
            .mov_store32_rip_rel_imm(CTX_EXIT_REASON, reason as i32);
        self.asm.mov_store32_rip_rel_imm(CTX_EXIT_ARG, arg as i32);
        self.asm.jmp_label(self.exit_label);
    }

    /// Emit prologue: save callee-saved, load PVM registers from context,
    /// then dispatch to the correct basic block based on entry_pc.
    pub(crate) fn emit_prologue(&mut self) {
        self.asm.ensure_capacity(512); // prologue needs ~200 bytes
        // Save callee-saved registers
        self.asm.push(Reg::RBX);
        self.asm.push(Reg::RBP);
        self.asm.push(Reg::R12);
        self.asm.push(Reg::R13);
        self.asm.push(Reg::R14);
        self.asm.push(Reg::R15);

        // Stack alignment: after 6 callee-saved pushes + return address
        // (7 * 8 = 56 bytes), RSP mod 16 = 8. Push one extra 8 bytes so
        // RSP mod 16 = 0 — the SysV ABI alignment any helper CALL we
        // emit below expects at the call site.
        self.asm.push(SCRATCH); // alignment padding

        // Save the post-callee-saved RSP into the context. The exit
        // path restores RSP from this slot before popping the 7 entries
        // above, so any unmatched `call` pushes from the guest's
        // `callf` / `retf` chain (e.g. an OOG or page-fault redirect
        // mid-function with stack frames still pending) get discarded
        // cleanly instead of corrupting the exit pops.
        self.asm.mov_store64_rip_rel(CTX_HOST_RSP_BASE, Reg::RSP);

        // R15 = gas register. Loaded from ctx.gas at prologue, decremented
        // per basic block, flushed back to ctx.gas at exit. Mem accesses
        // are baseless `[rdx]` (PVM addr == native VA); CTX is reached via
        // absolute SIB. Neither path reads R15.
        self.asm.mov_load64_rip_rel(GAS, CTX_GAS);

        // Clear exit reason
        self.asm.mov_store32_rip_rel_imm(CTX_EXIT_REASON, 0);

        // --- O(1) dispatch via table lookup (before loading PVM regs) ---
        self.asm.mov_load32_rip_rel(SCRATCH, CTX_ENTRY_PC);
        self.asm.mov_load64_rip_rel(Reg::RAX, CTX_DISPATCH_TABLE);
        self.asm.movsxd_load_sib4(Reg::RAX, Reg::RAX, SCRATCH);
        self.asm.mov_load64_rip_rel(SCRATCH, CTX_CODE_BASE);
        self.asm.add_rr(Reg::RAX, SCRATCH);
        self.asm.push(Reg::RAX);

        // Load all 13 PVM registers from context
        for (i, &reg) in REG_MAP.iter().enumerate() {
            self.asm.mov_load64_rip_rel(reg, CTX_REGS + (i as u64) * 8);
        }

        // Jump to the dispatch target (pop into SCRATCH, then indirect jump)
        self.asm.pop(SCRATCH);
        self.asm.jmp_reg(SCRATCH);
    }

    /// Emit exit sequences and epilogue.
    pub(crate) fn emit_exit_sequences(&mut self) {
        // Reserve capacity for exit sequences + all OOG stubs.
        // Each OOG stub is ~12 bytes.
        let needed = 512 + self.oog_stubs.len() * 16;
        self.asm.ensure_capacity(needed);
        // Shared OOG handler that reads PC from SCRATCH — emitted BEFORE OOG
        // stubs so backward jumps from stubs can use jmp rel8 (2 bytes).
        self.asm.bind_label(self.oog_pc_label);
        self.asm.mov_store32_rip_rel(CTX_PC, SCRATCH);
        // fall through to oog_label:
        self.asm.bind_label(self.oog_label);
        self.asm
            .mov_store32_rip_rel_imm(CTX_EXIT_REASON, EXIT_OOG as i32);
        self.asm.jmp_label(self.exit_label);

        // Per-gas-block OOG stubs: compact format — load PC into SCRATCH,
        // jump to shared handler. Saves ~6 bytes per stub vs inline PC store.
        let stubs = core::mem::take(&mut self.oog_stubs);
        for (label, pvm_pc, _cost) in &stubs {
            self.asm.bind_label(*label);
            self.asm.mov_ri32(SCRATCH, *pvm_pc);
            self.asm.jmp_label(self.oog_pc_label);
        }

        // Page faults are handled by the SIGSEGV handler (signal.rs).

        // Panic exit
        self.asm.bind_label(self.panic_label);
        self.asm
            .mov_store32_rip_rel_imm(CTX_EXIT_REASON, EXIT_PANIC as i32);
        // fall through to exit_label

        // Common exit: flush gas (R15) → ctx.gas, then save PVM regs.
        self.asm.bind_label(self.exit_label);
        self.asm.mov_store64_rip_rel(CTX_GAS, GAS);
        for (i, &reg) in REG_MAP.iter().enumerate() {
            self.asm.mov_store64_rip_rel(CTX_REGS + (i as u64) * 8, reg);
        }

        // Restore RSP to the post-prologue baseline. Drops any pending
        // native-`call` frames the guest pushed via `callf` (PVM2). For
        // a balanced clean exit (every `callf` already matched by a
        // `retf`), RSP is already at the baseline and the mov is a
        // no-op; for OOG / page-fault / mid-function trap paths it
        // truncates the stack back to where the 7 callee-saved entries
        // sit on top.
        self.asm.mov_load64_rip_rel(Reg::RSP, CTX_HOST_RSP_BASE);

        // Restore callee-saved (+ alignment padding)
        self.asm.pop(SCRATCH); // alignment padding
        self.asm.pop(Reg::R15);
        self.asm.pop(Reg::R14);
        self.asm.pop(Reg::R13);
        self.asm.pop(Reg::R12);
        self.asm.pop(Reg::RBP);
        self.asm.pop(Reg::RBX);
        self.asm.ret();
    }
}
