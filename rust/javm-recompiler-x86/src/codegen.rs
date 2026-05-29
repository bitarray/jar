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

use alloc::vec;
use alloc::vec::Vec;

use super::asm::{Assembler, Cc, Label, Reg};
use javm_exec::gas_sim::GasSimulator;
pub use javm_exec::predecode::{Predecode, predecode};

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

/// RV register (5-bit, 0..31) → PVM2 slot (0..12), or `0xFF` for "no
/// slot" (x0, reserved x3/x4, x16..x31). A 32-byte const lookup table:
/// one load replaces the range-match, which the profiler showed at
/// ~8.8% of compile (called ~6×/instruction across codegen + gas feed).
/// Values mirror the original match exactly, so gas stays bit-identical.
pub(crate) const RV_SLOT_LUT: [u8; 32] = {
    let mut t = [0xFFu8; 32];
    t[1] = 0;
    t[2] = 1;
    let mut x = 5usize;
    while x <= 15 {
        t[x] = (x - 3) as u8;
        x += 1;
    }
    t
};

/// RV register number → PVM2 slot (0..12), or `0xFF` for "no slot".
/// Mirrors the slot encoding used by `rv_op_metadata` so that gas
/// accounting agrees bit-for-bit with the predecode-cached path.
#[inline(always)]
pub(crate) fn rv_slot_or_ff(x: u8) -> u8 {
    RV_SLOT_LUT[(x & 31) as usize]
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
    /// `Inst`); `bind_rv_gas_block_start_streaming` flushes it at
    /// block boundaries. The PVM `compile()` path uses its own local
    /// simulator and leaves this one untouched.
    pub(crate) gas_sim: GasSimulator,
    /// Guest VA the code region is mapped at. `jalr`/`auipc` produce
    /// and consume code addresses as `code_base + offset`; the
    /// dispatch/bb tables are offset-indexed (offset = VA - code_base).
    pub(crate) code_base: u32,
    /// Code region length in bytes — the upper bound for jalr target
    /// offsets (== `bb_starts` / dispatch-table length).
    pub(crate) code_len: u32,
    /// True during RV streaming compile (`compile`). When set, branch
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
        helpers: HelperFns,
        code_len: usize,
        jit_va_base: u64,
        mem_cycles: u8,
        code_base: u32,
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
            bitmask_ptr: core::ptr::null(),
            bitmask_len: 0,
            trap_entries: Vec::with_capacity(2048),
            mem_cycles,
            gas_sim: GasSimulator::new(),
            code_base,
            code_len: code_len as u32,
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

/// Detect a trailing ALU-rr instruction in raw bytes, for streaming-fusion
/// lookahead. Handles both 4-byte OP_OP forms (Add/Xor/Or/And with funct7=0)
/// and the 2-byte RVC equivalents (`c.add`, `c.xor`, `c.or`, `c.and`).
///
/// Returns `(op, rd, rs1, rs2, consumed_bytes)`. For RVC's two-operand forms
/// (`rd <- rd ⊕ rs2`), we surface `rs1 == rd` so callers don't need separate
/// RVC-aware logic.
///
/// Roughly half of PVM2 guest code is RVC (49–71% across the gap-driving
/// guests), so missing the compressed-Add form here would forfeit most of
/// the win from these fusions.
#[inline]
fn peek_alu_rr_trailer(rest: &[u8]) -> Option<(AluOp, u8, u8, u8, usize)> {
    if rest.len() < 2 {
        return None;
    }
    // 4-byte path: only when `rest[0]`'s low 2 bits == 0b11.
    if rest[0] & 0b11 == 0b11 {
        if rest.len() < 4 {
            return None;
        }
        let w = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]);
        let op = match w & 0xFE00_707F {
            0x0000_0033 => AluOp::Add,
            0x0000_4033 => AluOp::Xor,
            0x0000_6033 => AluOp::Or,
            0x0000_7033 => AluOp::And,
            _ => return None,
        };
        let rd = ((w >> 7) & 0x1F) as u8;
        let rs1 = ((w >> 15) & 0x1F) as u8;
        let rs2 = ((w >> 20) & 0x1F) as u8;
        return Some((op, rd, rs1, rs2, 4));
    }
    // 2-byte RVC path.
    let h = u16::from_le_bytes([rest[0], rest[1]]);
    // c.add — q2 (bits[1:0]=10), funct4=1001, bits[12]=1, rd!=0, rs2!=0.
    // mask 0xF003 == 0x9002.
    if h & 0xF003 == 0x9002 {
        let rd = ((h >> 7) & 0x1F) as u8;
        let rs2 = ((h >> 2) & 0x1F) as u8;
        if rd != 0 && rs2 != 0 {
            return Some((AluOp::Add, rd, rd, rs2, 2));
        }
        return None;
    }
    // c.{and,or,xor,sub} — q1 misc_alu, funct6=100011, bits[1:0]=01.
    // mask 0xFC03 == 0x8C01. funct2 (bits[6:5]) selects op.
    if h & 0xFC03 == 0x8C01 {
        let op = match (h >> 5) & 0x3 {
            0b01 => AluOp::Xor,
            0b10 => AluOp::Or,
            0b11 => AluOp::And,
            _ => return None, // 0b00 = c.sub, not in fusion set
        };
        let rd = ((h >> 7) & 0x7) as u8 + 8; // creg
        let rs2 = ((h >> 2) & 0x7) as u8 + 8; // creg
        return Some((op, rd, rd, rs2, 2));
    }
    None
}

// ----------------------------------------------------------------------
// RV opcode majors (bits [6:2]). Bits [1:0] are always 0b11 for 4-byte.
// Mirrors `javm_exec::instruction::OP_*`; redeclared here to keep the
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
const OP_AUIPC: u32 = 0b00_101;
const OP_OP_32: u32 = 0b01_110;
const OP_BRANCH: u32 = 0b11_000;
const OP_JAL: u32 = 0b11_011;
const OP_JALR: u32 = 0b11_001;
const OP_CUSTOM_0: u32 = 0b00_010;

// Sign-extended immediates straight off a 4-byte RV word. Mirrors the
// canonical encoders in `javm_exec::instruction`.
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

// ----------------------------------------------------------------------
// Encoders for synthesising a 4-byte RV word from RVC fields. RVC is
// rare enough (~1% of code on the gap-driving guests) that the natural
// implementation is: extract the relevant RVC fields, re-encode as the
// equivalent 4-byte word, and feed it through `compile_rv4`. This lets
// all the funct3/funct7 dispatch + fusion logic live in one place.
//
// The `opcode5` parameter is the 5-bit opcode major (bits [6:2]); we OR
// in `0b11` for bits [1:0] automatically.
// ----------------------------------------------------------------------
#[inline]
fn enc_i(opcode5: u32, f3: u32, rd: u8, rs1: u8, imm: i32) -> u32 {
    let imm12 = (imm as u32) & 0xFFF;
    (imm12 << 20) | ((rs1 as u32) << 15) | (f3 << 12) | ((rd as u32) << 7) | (opcode5 << 2) | 0b11
}
#[inline]
fn enc_s(opcode5: u32, f3: u32, rs1: u8, rs2: u8, imm: i32) -> u32 {
    let imm12 = (imm as u32) & 0xFFF;
    ((imm12 >> 5) << 25)
        | ((rs2 as u32) << 20)
        | ((rs1 as u32) << 15)
        | (f3 << 12)
        | ((imm12 & 0x1F) << 7)
        | (opcode5 << 2)
        | 0b11
}
#[inline]
fn enc_b(opcode5: u32, f3: u32, rs1: u8, rs2: u8, imm: i32) -> u32 {
    let imm13 = (imm as u32) & 0x1FFF;
    let b12 = (imm13 >> 12) & 1;
    let b11 = (imm13 >> 11) & 1;
    let b10_5 = (imm13 >> 5) & 0x3F;
    let b4_1 = (imm13 >> 1) & 0xF;
    (b12 << 31)
        | (b10_5 << 25)
        | ((rs2 as u32) << 20)
        | ((rs1 as u32) << 15)
        | (f3 << 12)
        | (b4_1 << 8)
        | (b11 << 7)
        | (opcode5 << 2)
        | 0b11
}
#[inline]
fn enc_j(opcode5: u32, rd: u8, imm: i32) -> u32 {
    let imm21 = (imm as u32) & 0x1FFFFF;
    let b20 = (imm21 >> 20) & 1;
    let b10_1 = (imm21 >> 1) & 0x3FF;
    let b11 = (imm21 >> 11) & 1;
    let b19_12 = (imm21 >> 12) & 0xFF;
    (b20 << 31)
        | (b10_1 << 21)
        | (b11 << 20)
        | (b19_12 << 12)
        | ((rd as u32) << 7)
        | (opcode5 << 2)
        | 0b11
}
#[inline]
fn enc_u(opcode5: u32, rd: u8, imm: i32) -> u32 {
    let imm_u = (imm as u32) & 0xFFFFF000;
    imm_u | ((rd as u32) << 7) | (opcode5 << 2) | 0b11
}
#[inline]
fn enc_r(opcode5: u32, f3: u32, f7: u32, rd: u8, rs1: u8, rs2: u8) -> u32 {
    (f7 << 25)
        | ((rs2 as u32) << 20)
        | ((rs1 as u32) << 15)
        | (f3 << 12)
        | ((rd as u32) << 7)
        | (opcode5 << 2)
        | 0b11
}
#[inline]
fn enc_shimm6(opcode5: u32, f3: u32, shtype6: u32, rd: u8, rs1: u8, shamt6: u8) -> u32 {
    (shtype6 << 26)
        | ((shamt6 as u32) << 20)
        | ((rs1 as u32) << 15)
        | (f3 << 12)
        | ((rd as u32) << 7)
        | (opcode5 << 2)
        | 0b11
}

// RVC compressed-register field (3 bits) maps to x8..x15.
#[inline]
fn creg(r: u16) -> u8 {
    (r + 8) as u8
}

// CI-format 6-bit signed immediate.
#[inline]
fn decode_ci_imm6(h: u16) -> i32 {
    let imm = (((h >> 12) & 1) << 5) | ((h >> 2) & 0x1F);
    ((imm as i32) << 26) >> 26
}

// CJ-format 12-bit signed immediate (byte offset).
#[inline]
fn decode_cj_imm(h: u16) -> i32 {
    let b11 = (h >> 12) & 1;
    let b4 = (h >> 11) & 1;
    let b9_8 = (h >> 9) & 0x3;
    let b10 = (h >> 8) & 1;
    let b6 = (h >> 7) & 1;
    let b7 = (h >> 6) & 1;
    let b3_1 = (h >> 3) & 0x7;
    let b5 = (h >> 2) & 1;
    let imm = (b11 << 11)
        | (b10 << 10)
        | (b9_8 << 8)
        | (b7 << 7)
        | (b6 << 6)
        | (b5 << 5)
        | (b4 << 4)
        | (b3_1 << 1);
    ((imm as i32) << 20) >> 20
}

// CB-format 9-bit signed immediate (byte offset).
#[inline]
fn decode_cb_imm(h: u16) -> i32 {
    let b8 = (h >> 12) & 1;
    let b4_3 = (h >> 10) & 0x3;
    let b7_6 = (h >> 5) & 0x3;
    let b2_1 = (h >> 3) & 0x3;
    let b5 = (h >> 2) & 1;
    let imm = (b8 << 8) | (b7_6 << 6) | (b5 << 5) | (b4_3 << 3) | (b2_1 << 1);
    ((imm as i32) << 23) >> 23
}

/// Expand a 2-byte RVC encoding to its 4-byte equivalent. Returns
/// `None` for PVM2-forbidden RVC encodings (c.jr, c.jalr, c.ebreak,
/// c.illegal) and for malformed encodings (reserved sub-cases).
///
/// The caller (`compile_rvc`) feeds the result through `compile_rv4`,
/// so any shape `compile_rv4` understands is acceptable here. RVC
/// expansions never set the JAL `rd` to a non-zero value (c.jal is
/// RV32-only and doesn't exist in our target), so the `next_pc`
/// hardcoded in `compile_rv4`'s jal/branch sub-dispatchers is unused
/// — RVC's actual `pc + 2` advance happens in the streaming loop.
fn expand_rvc(h: u16) -> Option<u32> {
    // c.illegal is encoding 0x0000.
    if h == 0 {
        return None;
    }
    let op = h & 0b11;
    let f3 = (h >> 13) & 0b111;
    match op {
        0b00 => expand_rvc_q0(h, f3),
        0b01 => expand_rvc_q1(h, f3),
        0b10 => expand_rvc_q2(h, f3),
        _ => None,
    }
}

fn expand_rvc_q0(h: u16, f3: u16) -> Option<u32> {
    let rs1c = creg((h >> 7) & 0b111);
    let rdrs2c = creg((h >> 2) & 0b111);
    match f3 {
        0b000 => {
            // c.addi4spn -> addi rd', x2, nzuimm
            // nzuimm bits: h[12:11] -> [5:4], h[10:7] -> [9:6], h[6] -> [2], h[5] -> [3].
            let n = (((h >> 11) & 0x3) << 4)
                | (((h >> 7) & 0xF) << 6)
                | (((h >> 6) & 0x1) << 2)
                | (((h >> 5) & 0x1) << 3);
            if n == 0 {
                return None;
            }
            Some(enc_i(OP_IMM, 0b000, rdrs2c, 2, n as i32))
        }
        0b010 => {
            // c.lw -> lw rd', uimm(rs1')
            let imm = (((h >> 10) & 0x7) << 3) | (((h >> 6) & 0x1) << 2) | (((h >> 5) & 0x1) << 6);
            Some(enc_i(OP_LOAD, 0b010, rdrs2c, rs1c, imm as i32))
        }
        0b011 => {
            // c.ld -> ld rd', uimm(rs1')
            let imm = (((h >> 10) & 0x7) << 3) | (((h >> 5) & 0x3) << 6);
            Some(enc_i(OP_LOAD, 0b011, rdrs2c, rs1c, imm as i32))
        }
        0b110 => {
            // c.sw
            let imm = (((h >> 10) & 0x7) << 3) | (((h >> 6) & 0x1) << 2) | (((h >> 5) & 0x1) << 6);
            Some(enc_s(OP_STORE, 0b010, rs1c, rdrs2c, imm as i32))
        }
        0b111 => {
            // c.sd
            let imm = (((h >> 10) & 0x7) << 3) | (((h >> 5) & 0x3) << 6);
            Some(enc_s(OP_STORE, 0b011, rs1c, rdrs2c, imm as i32))
        }
        _ => None,
    }
}

fn expand_rvc_q1(h: u16, f3: u16) -> Option<u32> {
    match f3 {
        0b000 => {
            // c.nop / c.addi
            let rd = ((h >> 7) & 0x1F) as u8;
            let imm = decode_ci_imm6(h);
            if rd == 0 {
                Some(enc_i(OP_IMM, 0b000, 0, 0, 0)) // c.nop
            } else {
                Some(enc_i(OP_IMM, 0b000, rd, rd, imm))
            }
        }
        0b001 => {
            // c.addiw (RV64) — rd != 0
            let rd = ((h >> 7) & 0x1F) as u8;
            if rd == 0 {
                return None;
            }
            Some(enc_i(OP_OP_IMM_32, 0b000, rd, rd, decode_ci_imm6(h)))
        }
        0b010 => {
            // c.li -> addi rd, x0, imm
            let rd = ((h >> 7) & 0x1F) as u8;
            if rd == 0 {
                return None;
            }
            Some(enc_i(OP_IMM, 0b000, rd, 0, decode_ci_imm6(h)))
        }
        0b011 => {
            // c.addi16sp / c.lui
            let rd = ((h >> 7) & 0x1F) as u8;
            if rd == 2 {
                let imm = (((h >> 12) & 1) << 9)
                    | (((h >> 6) & 1) << 4)
                    | (((h >> 5) & 1) << 6)
                    | (((h >> 3) & 0x3) << 7)
                    | (((h >> 2) & 1) << 5);
                let sx = ((imm as i32) << 22) >> 22;
                if sx == 0 {
                    return None;
                }
                Some(enc_i(OP_IMM, 0b000, 2, 2, sx))
            } else if rd == 0 {
                None
            } else {
                let h_u = h as u32;
                let imm = (((h_u >> 12) & 1) << 17) | (((h_u >> 2) & 0x1F) << 12);
                let sx = ((imm as i32) << 14) >> 14;
                if sx == 0 {
                    return None;
                }
                Some(enc_u(OP_LUI, rd, sx))
            }
        }
        0b100 => expand_rvc_q1_misc_alu(h),
        0b101 => {
            // c.j -> jal x0, off
            Some(enc_j(OP_JAL, 0, decode_cj_imm(h)))
        }
        0b110 | 0b111 => {
            // c.beqz / c.bnez (rs1 = creg)
            let rs1 = creg((h >> 7) & 0b111);
            let imm = decode_cb_imm(h);
            let f3b = if f3 == 0b110 { 0b000 } else { 0b001 };
            Some(enc_b(OP_BRANCH, f3b, rs1, 0, imm))
        }
        _ => None,
    }
}

fn expand_rvc_q1_misc_alu(h: u16) -> Option<u32> {
    let f6_10 = (h >> 10) & 0b11;
    let rdrs1c = creg((h >> 7) & 0b111);
    match f6_10 {
        0b00 | 0b01 => {
            // c.srli / c.srai (RV64 shamt: bit12||bits6:2)
            let shamt = ((((h >> 12) & 1) << 5) | ((h >> 2) & 0x1F)) as u8;
            let shtype = if f6_10 == 0b00 { 0b000000 } else { 0b010000 };
            Some(enc_shimm6(OP_IMM, 0b101, shtype, rdrs1c, rdrs1c, shamt))
        }
        0b10 => {
            // c.andi
            Some(enc_i(OP_IMM, 0b111, rdrs1c, rdrs1c, decode_ci_imm6(h)))
        }
        0b11 => {
            // c.sub/xor/or/and (bit12=0) or c.subw/c.addw (bit12=1)
            let rs2c = creg((h >> 2) & 0b111);
            let bit12 = (h >> 12) & 1;
            let f2 = (h >> 5) & 0b11;
            match (bit12, f2) {
                // OP family (bit12=0)
                (0, 0b00) => Some(enc_r(OP_OP, 0b000, 0b0100000, rdrs1c, rdrs1c, rs2c)), // sub
                (0, 0b01) => Some(enc_r(OP_OP, 0b100, 0b0000000, rdrs1c, rdrs1c, rs2c)), // xor
                (0, 0b10) => Some(enc_r(OP_OP, 0b110, 0b0000000, rdrs1c, rdrs1c, rs2c)), // or
                (0, 0b11) => Some(enc_r(OP_OP, 0b111, 0b0000000, rdrs1c, rdrs1c, rs2c)), // and
                // OP_32 family (bit12=1)
                (1, 0b00) => Some(enc_r(OP_OP_32, 0b000, 0b0100000, rdrs1c, rdrs1c, rs2c)), // subw
                (1, 0b01) => Some(enc_r(OP_OP_32, 0b000, 0b0000000, rdrs1c, rdrs1c, rs2c)), // addw
                _ => None,
            }
        }
        _ => None,
    }
}

fn expand_rvc_q2(h: u16, f3: u16) -> Option<u32> {
    let rdrs1 = ((h >> 7) & 0x1F) as u8;
    let rs2 = ((h >> 2) & 0x1F) as u8;
    match f3 {
        0b000 => {
            // c.slli (RV64 shamt: bit12||bits6:2)
            if rdrs1 == 0 {
                return None;
            }
            let shamt = ((((h >> 12) & 1) << 5) | ((h >> 2) & 0x1F)) as u8;
            Some(enc_shimm6(OP_IMM, 0b001, 0b000000, rdrs1, rdrs1, shamt))
        }
        0b010 => {
            // c.lwsp -> lw rd, uimm(x2)
            if rdrs1 == 0 {
                return None;
            }
            let imm = (((h >> 12) & 1) << 5) | (((h >> 4) & 0x7) << 2) | (((h >> 2) & 0x3) << 6);
            Some(enc_i(OP_LOAD, 0b010, rdrs1, 2, imm as i32))
        }
        0b011 => {
            // c.ldsp -> ld rd, uimm(x2)
            if rdrs1 == 0 {
                return None;
            }
            let imm = (((h >> 12) & 1) << 5) | (((h >> 5) & 0x3) << 3) | (((h >> 2) & 0x7) << 6);
            Some(enc_i(OP_LOAD, 0b011, rdrs1, 2, imm as i32))
        }
        0b100 => {
            // (bit12, rdrs1, rs2):
            //   (0, r, 0)  r!=0 -> c.jr     -> jalr x0, r, 0  (return)
            //   (0, r, s)  both!=0 -> c.mv  -> add rd, x0, rs2
            //   (1, 0, 0)         -> c.ebreak (FORBIDDEN)
            //   (1, r, 0)  r!=0 -> c.jalr   -> jalr x1, r, 0  (indirect call)
            //   (1, r, s)  both!=0 -> c.add -> add rd, rd, rs2
            let bit12 = (h >> 12) & 1;
            if rs2 == 0 {
                // c.jr (bit12=0) / c.jalr (bit12=1): native jalr. rdrs1=0
                // is c.ebreak (bit12=1) or reserved (bit12=0) — forbidden.
                if rdrs1 == 0 {
                    return None;
                }
                let rd = if bit12 == 0 { 0 } else { 1 };
                Some(enc_i(OP_JALR, 0b000, rd, rdrs1, 0))
            } else {
                // c.mv (bit12=0, rs1=x0) or c.add (bit12=1, rs1=rdrs1)
                if rdrs1 == 0 {
                    return None;
                }
                let rs1_enc = if bit12 == 0 { 0 } else { rdrs1 };
                Some(enc_r(OP_OP, 0b000, 0b0000000, rdrs1, rs1_enc, rs2))
            }
        }
        0b110 => {
            // c.swsp -> sw rs2, uimm(x2)
            let imm = (((h >> 9) & 0xF) << 2) | (((h >> 7) & 0x3) << 6);
            Some(enc_s(OP_STORE, 0b010, 2, rs2, imm as i32))
        }
        0b111 => {
            // c.sdsp -> sd rs2, uimm(x2)
            let imm = (((h >> 10) & 0x7) << 3) | (((h >> 7) & 0x7) << 6);
            Some(enc_s(OP_STORE, 0b011, 2, rs2, imm as i32))
        }
        _ => None,
    }
}

/// Map an RV register index to its PVM slot (0..=12).
///
/// Returns `None` for x0 (hardwired zero), x3, x4 (reserved). Callers
/// handle x0 by loading an immediate 0; x3/x4 cause a runtime panic at
/// the offending PC (the transpiler is expected to reject them at
/// deblob, so this is just defence-in-depth).
#[inline]
fn rv_slot(x: u8) -> Option<usize> {
    match RV_SLOT_LUT[(x & 31) as usize] {
        0xFF => None,
        s => Some(s as usize),
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
    /// codegen all happen in one walk over `code`. No `Predecode`
    /// intermediary — that was 57% of the old cold-path compile time
    /// on the large guests (ed25519, ecrecover).
    ///
    /// The returned `CompileResult.valid_pc` is the byte-indexed
    /// "valid branch target" bitmap the runtime BB region needs. A bit
    /// is set iff the PC is a gas-block start (= dispatchable entry in
    /// the gas-block dispatch table). Built incrementally during the
    /// streaming pass — no separate length-only pre-pass.
    pub fn compile(mut self, code: &[u8]) -> CompileResult {
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
                self.compile_rv4(w, inst_pc, 4, rest)
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
    /// `compile_rv4` see a coherent simulator.
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
    /// `Inst` enum constructed. Fusion sites (Ld→Add, Mul-pair) are
    /// inline at their dispatchers.
    /// `inst_len` is the encoded length of the instruction being
    /// compiled (4 for the 4-byte path, 2 for an RVC instruction
    /// expanded by [`compile_rvc`]). It is what jal/jalr use to compute
    /// the return-address `next_pc = pc + inst_len`; a hardcoded `pc + 4`
    /// would mis-set `ra` for `c.jalr` (a 2-byte indirect call).
    fn compile_rv4(&mut self, w: u32, pc: u32, inst_len: u32, rest: &[u8]) -> (bool, bool, usize) {
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
            OP_LUI => self.compile_lui(rd, w, pc, rest),
            OP_AUIPC => self.compile_auipc(rd, w, pc),
            OP_JAL => self.compile_jal(rd, w, pc, inst_len),
            OP_JALR if f3 == 0 => self.compile_jalr(rd, rs1, w, pc, inst_len),
            OP_BRANCH => self.compile_branch(rs1, rs2, f3, w, pc),
            OP_CUSTOM_0 => self.compile_custom_0(rd, rs1, f3, w, pc),
            OP_MISC_MEM => {
                // Fence / FenceI — no-op emit.
                self.feed_gas_rv(RV_KIND_FENCE, 0, 0, 0);
                (false, false, 0)
            }
            // OP_SYSTEM, OP_CUSTOM_1, jalr-with-funct3≠0, etc. — all
            // forbidden in PVM2 and rejected by the linker's validator.
            // Defence in depth: emit a runtime panic if we ever see one.
            _ => {
                self.rv_emit_panic_at(pc);
                self.feed_gas_rv(RV_KIND_RESERVED, 0, 0, 0);
                (true, false, 0)
            }
        }
    }

    /// 2-byte RVC dispatch. Expands the compressed encoding to its
    /// 4-byte equivalent via `expand_rvc` and reuses `compile_rv4` —
    /// all the funct3/funct7 dispatch + fusion logic stays in one
    /// place, and the only RVC-specific code is the bit-shuffling of
    /// the expansion. Forbidden RVC encodings (c.jr, c.jalr, c.ebreak,
    /// c.illegal) return `None` from `expand_rvc` and emit a panic.
    ///
    /// One contract: RVC expansion never produces a JAL with rd != 0
    /// (c.jal is RV32-only and doesn't exist in our target), so
    /// `compile_rv4`'s hardcoded `next_pc = pc + 4` is never consumed
    /// for return-address writes. Branches don't use next_pc either
    /// (the `_fallthrough` parameter on emit_branch_* is unused). The
    /// streaming loop's `pc += base_len + extra` advances by 2 for
    /// RVC regardless of what `compile_rv4` did internally.
    fn compile_rvc(&mut self, h: u16, pc: u32, rest: &[u8]) -> (bool, bool, usize) {
        use javm_exec::gas_cost::*;
        match expand_rvc(h) {
            // RVC instructions are 2 bytes — pass inst_len = 2 so a
            // `c.jalr` writes the correct return address (`pc + 2`).
            Some(w) => self.compile_rv4(w, pc, 2, rest),
            None => {
                self.rv_emit_panic_at(pc);
                self.feed_gas_rv(RV_KIND_RESERVED, 0, 0, 0);
                (true, false, 0)
            }
        }
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
        // Ld→{Add,Xor,Or,And} fusion: only triggers on the 64-bit `ld`
        // (f3 == 0b011). `peek_alu_rr_trailer` handles both 4-byte OP_OP and
        // 2-byte RVC trailing forms — half the code in these guests is RVC,
        // so missing c.add/c.{and,or,xor} would forfeit most of the win.
        if width == 8
            && rd != 0
            && !rv_is_reserved(rd)
            && !rv_is_reserved(rs1)
            && let Some((op, a_rd, a_rs1, a_rs2, consumed)) = peek_alu_rr_trailer(rest)
            && a_rd != 0
            && !rv_is_reserved(a_rd)
            && (a_rs1 == rd || a_rs2 == rd)
            && (a_rs1 == 0 || !rv_is_reserved(a_rs1))
            && (a_rs2 == 0 || !rv_is_reserved(a_rs2))
        {
            self.rv_load(rd, rs1, imm, 8, false, pc);
            self.feed_gas_rv(RV_KIND_LOAD, rs1, 0, rd);
            let next_pc = pc + 4;
            self.rv_alu_rr(a_rd, a_rs1, a_rs2, op, next_pc);
            // ScaledAdd tracking only meaningful for Add.
            if matches!(op, AluOp::Add) && a_rd != a_rs1 && a_rd != a_rs2 {
                self.track_add_scaledadd(a_rd, a_rs1, a_rs2);
            }
            self.feed_gas_rv(RV_KIND_ADD, a_rs1, a_rs2, a_rd);
            // preserve_cf only valid for Add (Sltu fusion consumer).
            let preserve_cf = matches!(op, AluOp::Add);
            return (false, preserve_cf, consumed);
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

    fn compile_lui(&mut self, rd: u8, w: u32, pc: u32, rest: &[u8]) -> (bool, bool, usize) {
        use javm_exec::gas_cost::*;
        let imm = imm_u(w);

        // Lui→Add fusion: `lui rd, imm; add rd, rd, rs2` (4-byte) or the
        // RVC equivalent `c.add rd, rs2` collapses into one `lea rd, [rs2 +
        // imm]`. Only the same-rd Add case is fusable: if the Add writes a
        // different register, the LUI value is still live and we can't skip
        // its materialisation.
        if rd != 0
            && !rv_is_reserved(rd)
            && let Some((op, a_rd, a_rs1, a_rs2, consumed)) = peek_alu_rr_trailer(rest)
            && matches!(op, AluOp::Add)
            && a_rd == rd
        {
            let other = if a_rs1 == rd {
                Some(a_rs2)
            } else if a_rs2 == rd {
                Some(a_rs1)
            } else {
                None
            };
            if let Some(other) = other
                && (other == 0 || !rv_is_reserved(other))
            {
                if let Some(d) = self.rv_dst(a_rd, pc) {
                    if other == 0 {
                        // `add rd, rd, x0` = identity → rd stays as the LUI
                        // constant. Fall back to mov_ri64 + track_const so
                        // subsequent addr-folding still works.
                        self.asm.mov_ri64(d, imm as i64 as u64);
                        self.track_const(a_rd, imm);
                    } else {
                        let base = REG_MAP[rv_slot(other).unwrap()];
                        self.asm.lea(d, base, imm);
                        self.invalidate_reg(rv_slot(a_rd).unwrap());
                    }
                }
                self.feed_gas_rv(RV_KIND_LUI, 0, 0, rd);
                self.feed_gas_rv(RV_KIND_ADD, a_rs1, a_rs2, a_rd);
                // lea preserves CF in x86, but no RV-semantic Add was emitted
                // — clear so downstream Sltu can't fuse against stale CF.
                return (false, false, consumed);
            }
        }

        self.rv_lui(rd, imm, pc);
        self.track_const(rd, imm);
        let term = self.feed_gas_rv(RV_KIND_LUI, 0, 0, rd);
        (term, false, 0)
    }

    fn compile_jal(&mut self, rd: u8, w: u32, pc: u32, inst_len: u32) -> (bool, bool, usize) {
        use javm_exec::gas_cost::*;
        let imm = imm_j(w);
        let next_pc = pc + inst_len;
        self.rv_jal(rd, imm, pc, next_pc);
        let term = self.feed_gas_rv(RV_KIND_JAL, 0, 0, rd);
        (term, false, 0)
    }

    fn compile_auipc(&mut self, rd: u8, w: u32, pc: u32) -> (bool, bool, usize) {
        use javm_exec::gas_cost::*;
        // auipc result is a compile-time constant: code_base + pc + imm.
        let imm = imm_u(w);
        self.rv_auipc(rd, imm, pc);
        // Gas: same kind/cost as LUI (a constant materialise).
        let term = self.feed_gas_rv(RV_KIND_LUI, 0, 0, rd);
        (term, false, 0)
    }

    fn compile_jalr(
        &mut self,
        rd: u8,
        rs1: u8,
        w: u32,
        pc: u32,
        inst_len: u32,
    ) -> (bool, bool, usize) {
        use javm_exec::gas_cost::*;
        let imm = imm_i(w);
        let next_pc = pc + inst_len;
        self.rv_jalr(rd, rs1, imm, pc, next_pc);
        // src = rs1 (target); rd not tracked (terminator).
        let term = self.feed_gas_rv(RV_KIND_JALR, rs1, 0, 0);
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
        _rd: u8,
        _rs1: u8,
        f3: u8,
        w: u32,
        pc: u32,
    ) -> (bool, bool, usize) {
        use javm_exec::gas_cost::*;
        // PVM2 custom-0 encoding:
        //   f3=000 → trap     (other fields ignored)
        //   f3=001 → ecall.jar
        //   f3=010 → ecalli imm
        //   f3=100 → fallthrough (terminator no-op)
        //   f3=011 (was br_table) → reserved; PVM2 uses plain jalr.
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

    /// `auipc rd, imm` — `rd = (code_base + pc) + imm`. Both addends
    /// are compile-time constants, so this materialises a single
    /// constant (mirrors the interpreter's `Auipc` arm exactly). The
    /// value is a guest VA, sign-extended 32→64 like `lui`.
    fn rv_auipc(&mut self, rd: u8, imm: i32, pc: u32) {
        if let Some(d) = self.rv_dst(rd, pc) {
            let va = self.code_base.wrapping_add(pc).wrapping_add(imm as u32);
            self.asm.mov_ri64(d, va as i32 as i64 as u64);
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
    /// Emits a three-op CMOV sequence:
    ///   test r2, r2     ; ZF reflects rs2 == 0
    ///   mov_ri32 _, 0   ; 5-byte mov-imm (no flag effect)
    ///   cmov... ...     ; conditionally swap on ZF
    ///
    /// The two branches below differ only in which register is the cmov
    /// destination vs source, dictated by whether `d` aliases `rs1`
    /// (in which case `d` already holds the "keep" value and we cmov
    /// 0 in on the spec condition) or not (we initialise `d=0` and
    /// cmov `r1` in on the opposite condition). Both paths are 3 ops.
    fn rv_czero(&mut self, rd: u8, rs1: u8, rs2: u8, cond: Cc, pc: u32) {
        let Some(d) = self.rv_dst(rd, pc) else { return };
        if rv_is_reserved(rs1) || rv_is_reserved(rs2) {
            self.rv_emit_panic_at(pc);
            return;
        }
        let slot = rv_slot(rd).unwrap();

        // Static-result short circuits.
        if rs2 == 0 {
            // rs2 hardwired zero: spec condition is statically known.
            //   eqz: rs2==0 always true → d = 0
            //   nez: rs2!=0 always false → d = rs1
            if matches!(cond, Cc::E) {
                self.asm.mov_ri64(d, 0);
            } else {
                self.rv_read(rs1, d, pc);
            }
            self.invalidate_reg(slot);
            return;
        }
        if rs1 == 0 {
            // rs1 hardwired zero: both branches of the conditional yield 0.
            self.asm.mov_ri64(d, 0);
            self.invalidate_reg(slot);
            return;
        }
        if rs1 == rs2 {
            //   eqz: (rs1==0) ? 0 : rs1 == rs1
            //   nez: (rs1!=0) ? 0 : rs1 == 0
            if matches!(cond, Cc::E) {
                self.rv_read(rs1, d, pc);
            } else {
                self.asm.mov_ri64(d, 0);
            }
            self.invalidate_reg(slot);
            return;
        }

        let r1 = REG_MAP[rv_slot(rs1).unwrap()];
        let r2 = REG_MAP[rv_slot(rs2).unwrap()];
        let opposite = match cond {
            Cc::E => Cc::NE,
            Cc::NE => Cc::E,
            _ => unreachable!("rv_czero only accepts E/NE"),
        };

        if d == r1 {
            // d already holds rs1's value. Test rs2, then cmov 0 in
            // when the spec condition holds. We can't cmov from `r1`
            // here — at execution time `r1 == d`, so the source value
            // is whatever d *currently* holds, not the original rs1.
            self.asm.test_rr(r2, r2);
            self.asm.mov_ri32(SCRATCH, 0);
            self.asm.cmovcc(cond, d, SCRATCH);
        } else {
            // d != r1. d may alias r2; that's fine because we test r2
            // BEFORE the mov writes 0 into d.
            self.asm.test_rr(r2, r2);
            self.asm.mov_ri32(d, 0);
            self.asm.cmovcc(opposite, d, r1);
        }
        self.invalidate_reg(slot);
    }

    // ---- Jumps & branches -------------------------------------------

    fn rv_jal(&mut self, rd: u8, imm: i32, pc: u32, next_pc: u32) {
        if rv_is_reserved(rd) {
            self.rv_emit_panic_at(pc);
            return;
        }
        if rd != 0 {
            // The link register holds a guest VA (code_base + offset),
            // matching jalr's return-address contract and the interp.
            let slot = rv_slot(rd).unwrap();
            self.asm
                .mov_ri64(REG_MAP[slot], self.code_base.wrapping_add(next_pc) as u64);
            self.invalidate_reg(slot);
        }
        let target = (pc as i64).wrapping_add(imm as i64) as u32;
        self.emit_static_branch(target, true, next_pc, pc);
    }

    /// Emit `jalr rd, rs1, imm` — indirect jump (return / indirect
    /// call). Strictly simpler than the former br_table (no jump-table
    /// indirection):
    ///   1. `target_va = (rs1 + imm) & 0xFFFFFFFF`   (2³² wrap)
    ///   2. write `rd = code_base + next_pc` if `rd != 0` (return addr)
    ///   3. `offset = target_va - code_base`
    ///   4. bounds: `offset < code_len`  else PANIC
    ///   5. `bb_starts[offset] == 1`?     else PANIC  (security-critical:
    ///      rejects mid-block / mid-instruction targets — gas is
    ///      precharged at block entry)
    ///   6. `native = code_base_native + dispatch_table[offset]; jmp`
    fn rv_jalr(&mut self, rd: u8, rs1: u8, imm: i32, pc: u32, next_pc: u32) {
        use super::asm::Cc;

        if rv_is_reserved(rs1) {
            self.rv_emit_panic_at(pc);
            return;
        }

        // SCRATCH = rs1 (x0 → 0).
        self.rv_read(rs1, SCRATCH, pc);
        if imm != 0 {
            self.asm.add_ri(SCRATCH, imm);
        }
        // 2³² wrap: zero-extend the low 32 bits (shl 32 ; shr 32).
        self.asm.shl_ri64(SCRATCH, 32);
        self.asm.shr_ri64(SCRATCH, 32);

        // Write the return address (a guest VA) — target already in
        // SCRATCH, so this can't clobber it (rd never maps to RDX).
        if rd != 0 {
            let slot = rv_slot(rd).unwrap();
            self.asm
                .mov_ri64(REG_MAP[slot], self.code_base.wrapping_add(next_pc) as u64);
            self.invalidate_reg(slot);
        }

        // offset = target_va - code_base.
        if self.code_base != 0 {
            self.asm.sub_ri(SCRATCH, self.code_base as i32);
        }

        // Record the offset as the paused PC for fault attribution.
        self.asm.mov_store32_rip_rel(CTX_PC, SCRATCH);

        // Bounds: offset < code_len (unsigned) — underflow from a
        // target below code_base wraps huge and fails here.
        self.asm.cmp_ri32(SCRATCH, self.code_len as i32);
        self.asm.jcc_label(Cc::AE, self.panic_label);

        // Validate bb_starts[offset] == 1 (basic-block start).
        self.asm.push(Reg::RAX); // save x14
        self.asm.mov_load64_rip_rel(Reg::RAX, CTX_BB_STARTS);
        // RAX = byte bb_starts[offset] (zero-extended).
        self.asm.movzx_load8_sib(Reg::RAX, Reg::RAX, SCRATCH);
        self.asm.test_rr(Reg::RAX, Reg::RAX);
        self.asm.pop(Reg::RAX); // restore x14 before the conditional branch
        self.asm.jcc_label(Cc::E, self.panic_label);

        // native = code_base_native + dispatch_table[offset]; jmp.
        self.asm.push(Reg::RAX);
        self.asm.mov_load64_rip_rel(Reg::RAX, CTX_DISPATCH_TABLE);
        self.asm.movsxd_load_sib4(Reg::RAX, Reg::RAX, SCRATCH);
        self.asm.add_r64_mem_rip_rel(Reg::RAX, CTX_CODE_BASE);
        self.asm.mov_rr(SCRATCH, Reg::RAX);
        self.asm.pop(Reg::RAX);
        self.asm.jmp_reg(SCRATCH);
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
    // Peephole tracking helpers — called inline from the tracked
    // dispatchers in `compile_rv4`. They replace the old separate
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
