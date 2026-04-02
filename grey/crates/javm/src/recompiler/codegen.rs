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
//! Reserved: R15 = JitContext pointer, RDX = scratch, RSP = native stack.

use super::asm::{Assembler, Cc, Label, Reg};
use crate::args::{self, Args};
use crate::gas_sim::GasSimulator;
use crate::instruction::Opcode;

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
/// Map PVM register index (0..12) to x86-64 register.
/// All 13 PVM registers live in x86 registers.
const REG_MAP: [Reg; 13] = [
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
const SCRATCH: Reg = Reg::RDX;
/// R15 = base of guest memory (flat buffer). JitContext is at negative offset.
const CTX: Reg = Reg::R15;

/// Caller-saved PVM registers that need saving around helper calls.
#[allow(dead_code)]
const CALLER_SAVED: [Reg; 8] = [
    Reg::RSI,
    Reg::RDI,
    Reg::R8,
    Reg::R9,
    Reg::R10,
    Reg::R11,
    Reg::RAX,
    Reg::RCX,
];

/// JitContext field offsets — all NEGATIVE from R15 (guest memory base).
///
/// Memory layout (contiguous mmap):
///   R15 - PERMS_OFFSET .. R15 - CTX_OFFSET:  permission table (1MB)
///   R15 - CTX_OFFSET   .. R15:               JitContext (~208 bytes, padded to page)
///   R15                .. R15 + 4GB:          guest memory (flat buffer)
///
/// CTX_OFFSET is the page-aligned distance from R15 to JitContext start.
pub const CTX_OFFSET: i32 = 4096; // JitContext at R15 - 4096
pub const PERMS_OFFSET: i32 = CTX_OFFSET + (1 << 20); // perms at R15 - 1052672

use super::JitContext;
use memoffset::offset_of;

pub const CTX_REGS: i32 = -CTX_OFFSET + offset_of!(JitContext, regs) as i32;
pub const CTX_GAS: i32 = -CTX_OFFSET + offset_of!(JitContext, gas) as i32;
pub const CTX_EXIT_REASON: i32 = -CTX_OFFSET + offset_of!(JitContext, exit_reason) as i32;
pub const CTX_EXIT_ARG: i32 = -CTX_OFFSET + offset_of!(JitContext, exit_arg) as i32;
pub const CTX_HEAP_BASE: i32 = -CTX_OFFSET + offset_of!(JitContext, heap_base) as i32;
pub const CTX_HEAP_TOP: i32 = -CTX_OFFSET + offset_of!(JitContext, heap_top) as i32;
pub const CTX_JT_PTR: i32 = -CTX_OFFSET + offset_of!(JitContext, jt_ptr) as i32;
pub const CTX_JT_LEN: i32 = -CTX_OFFSET + offset_of!(JitContext, jt_len) as i32;
pub const CTX_BB_STARTS: i32 = -CTX_OFFSET + offset_of!(JitContext, bb_starts) as i32;
pub const CTX_BB_LEN: i32 = -CTX_OFFSET + offset_of!(JitContext, bb_len) as i32;
pub const CTX_ENTRY_PC: i32 = -CTX_OFFSET + offset_of!(JitContext, entry_pc) as i32;
pub const CTX_PC: i32 = -CTX_OFFSET + offset_of!(JitContext, pc) as i32;
pub const CTX_DISPATCH_TABLE: i32 = -CTX_OFFSET + offset_of!(JitContext, dispatch_table) as i32;
pub const CTX_CODE_BASE: i32 = -CTX_OFFSET + offset_of!(JitContext, code_base) as i32;
pub const CTX_FAST_REENTRY: i32 = -CTX_OFFSET + offset_of!(JitContext, fast_reentry) as i32;

/// Exit reason codes (matching ExitReason enum).
pub const EXIT_HALT: u32 = 0;
pub const EXIT_PANIC: u32 = 1;
pub const EXIT_OOG: u32 = 2;
pub const EXIT_PAGE_FAULT: u32 = 3;
pub const EXIT_HOST_CALL: u32 = 4;

/// Result of compilation.
pub struct CompileResult {
    /// Native code bytes (used when mmap_ptr is None).
    pub native_code: Vec<u8>,
    pub dispatch_table: Vec<i32>,
    #[cfg(feature = "signals")]
    pub trap_table: Vec<(u32, u32)>,
    #[cfg(feature = "signals")]
    pub exit_label_offset: u32,
    /// If set, code is already mmap'd and mprotected as PROT_READ|PROT_EXEC.
    /// Skips the copy in NativeCode::new.
    pub mmap_ptr: Option<*mut u8>,
    pub mmap_len: usize,
    pub mmap_cap: usize,
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
enum RegDef {
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
    label_base: u32,
    /// Gas block start PCs discovered during compilation (for dispatch table).
    gas_block_pcs: Vec<u32>,
    /// Label for the exit sequence.
    exit_label: Label,
    /// Label for the shared out-of-gas exit (sets EXIT_OOG + jumps to exit).
    oog_label: Label,
    /// Label for panic exit.
    panic_label: Label,
    /// Label for OOG handler that reads PC from SCRATCH: stores PC, then falls through to oog_label.
    oog_pc_label: Label,
    /// Per-gas-block OOG stubs: (label, pvm_pc) — emitted as cold code after main body.
    oog_stubs: Vec<(Label, u32, u32)>, // (label, pvm_pc, block_cost)
    /// Per-memory-access fault stubs: (label, pvm_pc) — stores PC, jumps to shared handler.
    fault_stubs: Vec<(Label, u32)>,
    /// Helper function addresses.
    helpers: HelperFns,
    /// Bitmask reference (1 = instruction start). Stored as raw pointer for self-referential use.
    bitmask_ptr: *const u8,
    bitmask_len: usize,
    /// Peephole: tracks how each PVM register was last defined.
    reg_defs: [RegDef; 13],
    /// Bitmask of registers that have non-Unknown reg_defs (for fast invalidation).
    reg_defs_active: u16,
    /// Carry flag fusion: after an `add64 D, A, B`, CF = overflow(A+B).
    /// Stores (D, A, B) so that a subsequent `setLtU C, D, A` or `setLtU C, D, B`
    /// can use CF directly instead of emitting a redundant `cmp`.
    /// Cleared by any instruction that clobbers flags (i.e., everything except the
    /// immediately following setLtU).
    last_add_cf: Option<(usize, usize, usize)>,
    /// Trap table for signal-based bounds checking: (native_offset, pvm_pc).
    #[cfg(feature = "signals")]
    trap_entries: Vec<(u32, u32)>,
}

impl Compiler {
    pub fn new(
        bitmask: &[u8],
        _jump_table: &[u32],
        helpers: HelperFns,
        code_len: usize,
        use_mmap: bool,
    ) -> Self {
        // Estimate native code size: ~3x PVM code provides safety margin for
        // direct-write emission (no per-byte capacity checks in hot loop).
        let estimated_native = code_len * 3 + 8192;
        // Labels: one per PC (dense array) + fixed overhead for exit/oog/stubs.
        let estimated_labels = code_len + 1024;
        let mut asm = if use_mmap {
            Assembler::with_mmap(estimated_native, estimated_labels)
                .unwrap_or_else(|_| Assembler::with_capacity(estimated_native, estimated_labels))
        } else {
            Assembler::with_capacity(estimated_native, estimated_labels)
        };
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
            fault_stubs: Vec::with_capacity(256),
            reg_defs: [RegDef::Unknown; 13],
            reg_defs_active: 0,
            last_add_cf: None,
            helpers,
            bitmask_ptr: bitmask.as_ptr(),
            bitmask_len: bitmask.len(),
            #[cfg(feature = "signals")]
            trap_entries: Vec::with_capacity(2048),
        }
    }

    /// Look up the pre-created label for a PVM PC. O(1) arithmetic.
    #[inline]
    fn label_for_pc(&self, pc: u32) -> Label {
        Label(self.label_base + pc)
    }

    fn is_basic_block_start(&self, idx: u32) -> bool {
        let i = idx as usize;
        // SAFETY: bitmask_ptr points to the start of a valid &[u8] slice of length
        // bitmask_len, and i < bitmask_len is checked before the dereference.
        i < self.bitmask_len && unsafe { *self.bitmask_ptr.add(i) } == 1
    }

    /// Compile directly from raw code+bitmask. Streaming single-pass:
    /// gas block discovery + decode + gas sim + codegen in one loop.
    pub fn compile(mut self, code: &[u8], bitmask: &[u8]) -> CompileResult {
        let code_len = code.len();

        // Emit prologue
        self.emit_prologue();

        // True single-pass: no pre-scan. Gas block starts (ϖ) are discovered
        // inline — PC=0 is always a gas block start, and after every terminator
        // instruction the next PC becomes a gas block start.
        let mut gas_sim = GasSimulator::new();
        let mut pending_gas: Option<(Label, u32, usize)> = None;
        // Tracks whether the next instruction starts a new gas block.
        // True initially for PC=0.
        let mut next_is_gas_start = true;

        // Find first instruction start
        let mut pc: usize = 0;
        while pc < code.len() && (pc >= bitmask.len() || bitmask[pc] != 1) {
            pc += 1;
        }

        let code_ptr = code.as_ptr();

        while pc < code.len() {
            self.asm.ensure_capacity(512);

            // SAFETY: pc < code_len is guaranteed by the loop condition.
            let raw_byte = unsafe { *code_ptr.add(pc) };
            let is_gas_start = next_is_gas_start;
            next_is_gas_start = false;

            // Fast skip for Fallthrough/Unlikely: these produce zero native code
            // but ARE terminators, so the next instruction starts a new gas block.
            if raw_byte == 1 || raw_byte == 2 {
                // Fallthrough=1, Unlikely=2
                let skip = crate::vm::skip_for_bitmask(bitmask, pc);
                if is_gas_start {
                    let label = Label(self.label_base + pc as u32);
                    self.asm.bind_label(label);
                    self.gas_block_pcs.push(pc as u32);
                    self.invalidate_all_regs();
                    if let Some((stub_label, block_pc, patch_offset)) = pending_gas.take() {
                        let cost = gas_sim.flush_and_get_cost();
                        self.asm.patch_i32(patch_offset, cost as i32);
                        self.oog_stubs.push((stub_label, block_pc, cost));
                    }
                    gas_sim.reset();
                    let stub_label = self.asm.new_label();
                    self.asm.sub_mem64_imm32(CTX, CTX_GAS, 0);
                    let patch_offset = self.asm.offset() - 4;
                    self.asm.jcc_label(Cc::S, stub_label);
                    pending_gas = Some((stub_label, pc as u32, patch_offset));
                }
                gas_sim.feed(&crate::gas_cost::FastCost {
                    cycles: 2,
                    decode_slots: 1,
                    exec_unit: 0,
                    src_mask: 0,
                    dst_mask: 0,
                    is_terminator: true,
                    is_move_reg: false,
                });
                next_is_gas_start = true; // fallthrough IS a terminator
                pc += 1 + skip;
                continue;
            }

            // Combined opcode validation + category lookup in a single array access.
            let (opcode, category) = match crate::instruction::decode_opcode_fast(raw_byte) {
                Some(oc) => oc,
                None => {
                    self.asm.mov_store32_imm(CTX, CTX_PC, pc as i32);
                    self.emit_exit(EXIT_PANIC, 0);
                    pc += 1;
                    continue;
                }
            };
            let skip = crate::vm::skip_for_bitmask(bitmask, pc);
            let next_pc = (pc + 1 + skip) as u32;

            // Read register bytes once — used by both arg decoding and gas cost.
            // SAFETY: pc < code.len(). pc+1/pc+2 may be out of bounds for
            // instructions at the end, so we bounds-check those.
            let reg_byte1 = if pc + 1 < code.len() {
                unsafe { *code_ptr.add(pc + 1) }
            } else {
                0
            };
            let reg_byte2 = if pc + 2 < code.len() {
                unsafe { *code_ptr.add(pc + 2) }
            } else {
                0
            };
            let raw_ra = reg_byte1 & 0x0F;
            let raw_rb = reg_byte1 >> 4;

            let decoded_args = match category {
                crate::instruction::InstructionCategory::ThreeReg => Args::ThreeReg {
                    ra: raw_ra.min(12) as usize,
                    rb: raw_rb.min(12) as usize,
                    rd: reg_byte2.min(12) as usize,
                },
                crate::instruction::InstructionCategory::TwoReg => Args::TwoReg {
                    rd: raw_ra.min(12) as usize,
                    ra: raw_rb.min(12) as usize,
                },
                crate::instruction::InstructionCategory::TwoRegOneImm => {
                    let ra = raw_ra.min(12) as usize;
                    let rb = raw_rb.min(12) as usize;
                    let lx = if skip > 1 { (skip - 1).min(4) } else { 0 };
                    let imm = args::read_signed_imm(code, pc + 2, lx);
                    Args::TwoRegImm { ra, rb, imm }
                }
                crate::instruction::InstructionCategory::NoArgs => Args::None,
                crate::instruction::InstructionCategory::OneImm => {
                    let lx = skip.min(4);
                    Args::Imm {
                        imm: args::read_signed_imm(code, pc + 1, lx),
                    }
                }
                crate::instruction::InstructionCategory::OneRegOneImm => {
                    let ra = raw_ra.min(12) as usize;
                    let lx = if skip > 1 { (skip - 1).min(4) } else { 0 };
                    Args::RegImm {
                        ra,
                        imm: args::read_signed_imm(code, pc + 2, lx),
                    }
                }
                crate::instruction::InstructionCategory::OneRegExtImm => {
                    let ra = raw_ra.min(12) as usize;
                    Args::RegExtImm {
                        ra,
                        imm: args::read_le_imm(code, pc + 2, 8),
                    }
                }
                crate::instruction::InstructionCategory::TwoImm => {
                    let lx = (reg_byte1 as usize % 8).min(4);
                    let ly = if skip > lx + 1 {
                        (skip - lx - 1).min(4)
                    } else {
                        0
                    };
                    Args::TwoImm {
                        imm_x: args::read_signed_imm(code, pc + 2, lx),
                        imm_y: args::read_signed_imm(code, pc + 2 + lx, ly),
                    }
                }
                crate::instruction::InstructionCategory::OneOffset => {
                    let lx = skip.min(4);
                    let signed_off = args::read_signed_imm(code, pc + 1, lx) as i64;
                    Args::Offset {
                        offset: (pc as i64).wrapping_add(signed_off) as u64,
                    }
                }
                crate::instruction::InstructionCategory::OneRegTwoImm => {
                    let ra = raw_ra.min(12) as usize;
                    let lx = ((reg_byte1 as usize / 16) % 8).min(4);
                    let ly = if skip > lx + 1 {
                        (skip - lx - 1).min(4)
                    } else {
                        0
                    };
                    Args::RegTwoImm {
                        ra,
                        imm_x: args::read_signed_imm(code, pc + 2, lx),
                        imm_y: args::read_signed_imm(code, pc + 2 + lx, ly),
                    }
                }
                crate::instruction::InstructionCategory::OneRegImmOffset => {
                    let ra = raw_ra.min(12) as usize;
                    let lx = ((reg_byte1 as usize / 16) % 8).min(4);
                    let ly = if skip > lx + 1 {
                        (skip - lx - 1).min(4)
                    } else {
                        0
                    };
                    let imm = args::read_signed_imm(code, pc + 2, lx);
                    let signed_off = args::read_signed_imm(code, pc + 2 + lx, ly) as i64;
                    Args::RegImmOffset {
                        ra,
                        imm,
                        offset: (pc as i64).wrapping_add(signed_off) as u64,
                    }
                }
                crate::instruction::InstructionCategory::TwoRegOneOffset => {
                    let ra = raw_ra.min(12) as usize;
                    let rb = raw_rb.min(12) as usize;
                    let lx = if skip > 1 { (skip - 1).min(4) } else { 0 };
                    let signed_off = args::read_signed_imm(code, pc + 2, lx) as i64;
                    Args::TwoRegOffset {
                        ra,
                        rb,
                        offset: (pc as i64).wrapping_add(signed_off) as u64,
                    }
                }
                crate::instruction::InstructionCategory::TwoRegTwoImm => {
                    let ra = raw_ra.min(12) as usize;
                    let rb = raw_rb.min(12) as usize;
                    let lx = (reg_byte2 as usize % 8).min(4);
                    let ly = if skip > lx + 2 {
                        (skip - lx - 2).min(4)
                    } else {
                        0
                    };
                    Args::TwoRegTwoImm {
                        ra,
                        rb,
                        imm_x: args::read_signed_imm(code, pc + 3, lx),
                        imm_y: args::read_signed_imm(code, pc + 3 + lx, ly),
                    }
                }
            };

            // Gas block boundary: discovered inline via next_is_gas_start flag.
            if is_gas_start {
                let label = Label(self.label_base + pc as u32);
                self.asm.bind_label(label);
                self.gas_block_pcs.push(pc as u32);
                self.invalidate_all_regs();
                self.last_add_cf = None; // gas check clobbers flags

                if let Some((stub_label, block_pc, patch_offset)) = pending_gas.take() {
                    let cost = gas_sim.flush_and_get_cost();
                    self.asm.patch_i32(patch_offset, cost as i32);
                    self.oog_stubs.push((stub_label, block_pc, cost));
                }
                gas_sim.reset();

                let stub_label = self.asm.new_label();
                self.asm.sub_mem64_imm32(CTX, CTX_GAS, 0);
                let patch_offset = self.asm.offset() - 4;
                self.asm.jcc_label(Cc::S, stub_label);
                pending_gas = Some((stub_label, pc as u32, patch_offset));
            }

            let is_terminator = {
                // Fast path: feed gas simulator directly from register bytes,
                // skipping FastCost struct construction and bitmask iteration.
                let (term, needs_full) = crate::gas_cost::feed_gas_direct(
                    opcode as u8,
                    raw_ra,
                    raw_rb,
                    reg_byte2 & 0x0F,
                    &mut gas_sim,
                );
                if needs_full {
                    // Slow path for branches/overlap/move: use full FastCost
                    let fc = crate::gas_cost::fast_cost_lut_regs(
                        opcode as u8,
                        &decoded_args,
                        pc,
                        code,
                        bitmask,
                        raw_ra,
                        raw_rb,
                        reg_byte2 & 0x0F,
                    );
                    gas_sim.feed(&fc);
                    fc.is_terminator
                } else {
                    term
                }
            };

            // Peephole fusions
            let fused = match opcode {
                Opcode::Add64 => {
                    self.try_fuse_scaled_index_raw(code, bitmask, pc, &decoded_args, &mut gas_sim)
                }
                // Mul64+MulUpper fusion disabled: corrupts results when φ[11] (RAX)
                // is involved as both source and destination. The push/restore sequence
                // conflicts with rd_hi/rd_lo assignments when they alias RAX.
                // Opcode::Mul64 => {
                //     self.try_fuse_mul_pair_raw(code, bitmask, pc, &decoded_args, &mut gas_sim)
                // }
                _ => None,
            };

            if let Some(advance) = fused {
                self.last_add_cf = None; // fused instruction clobbers flags
                pc += advance;
                continue;
            }

            // Clear carry flag tracking for all opcodes except Add64 (which sets it)
            // and SetLtU (which consumes it inside compile_instruction).
            if !matches!(opcode, Opcode::Add64 | Opcode::SetLtU) {
                self.last_add_cf = None;
            }

            self.compile_instruction(opcode, &decoded_args, pc as u32, next_pc);

            // Fast reg_defs update: for special-case opcodes that produce
            // trackable patterns (Add64→Shifted, LoadImm→Const, etc.), call
            // the full update_reg_defs. For all other opcodes, just invalidate
            // the destination register directly from the decoded args. This
            // avoids the opcode match + Args re-destructuring for ~95% of
            // instructions.
            match opcode {
                Opcode::Add64
                | Opcode::LoadImm
                | Opcode::LoadImm64
                | Opcode::ShloLImm64
                | Opcode::MoveReg => {
                    self.update_reg_defs(opcode, &decoded_args);
                }
                _ => {
                    // Fast path: invalidate dest register based on category.
                    // The destination is the first register field for most categories.
                    match category {
                        crate::instruction::InstructionCategory::ThreeReg => {
                            if let Args::ThreeReg { rd, .. } = decoded_args {
                                self.invalidate_reg(rd);
                            }
                        }
                        crate::instruction::InstructionCategory::TwoReg => {
                            if let Args::TwoReg { rd, .. } = decoded_args {
                                self.invalidate_reg(rd);
                            }
                        }
                        crate::instruction::InstructionCategory::TwoRegOneImm
                        | crate::instruction::InstructionCategory::OneRegOneImm
                        | crate::instruction::InstructionCategory::OneRegExtImm
                        | crate::instruction::InstructionCategory::OneRegTwoImm
                        | crate::instruction::InstructionCategory::OneRegImmOffset => {
                            // Destination = first register (ra in raw byte low nibble)
                            self.invalidate_reg(raw_ra.min(12) as usize);
                        }
                        _ => {
                            // NoArgs, OneImm, OneOffset, TwoRegOneOffset, TwoRegTwoImm:
                            // These either don't write to a register or are terminators
                            // (which invalidate_all_regs at the next gas block boundary).
                            if is_terminator {
                                self.invalidate_all_regs();
                            }
                        }
                    }
                }
            }

            // After a terminator, the next instruction starts a new gas block.
            if is_terminator {
                next_is_gas_start = true;
            }

            pc += 1 + skip;
        }

        // Finalize last gas block
        if let Some((stub_label, block_pc, patch_offset)) = pending_gas.take() {
            let cost = gas_sim.flush_and_get_cost();
            self.asm.patch_i32(patch_offset, cost as i32);
            self.oog_stubs.push((stub_label, block_pc, cost));
        }

        // Emit epilogue and exit sequences
        self.emit_exit_sequences();

        // Build dispatch table: PVM PC → native code offset.
        // gas_block_pcs was populated inline during the single-pass loop.
        let table_len = code_len + 1;
        let mut dispatch_table = vec![0i32; table_len];
        for &pvm_pc in self.gas_block_pcs.iter() {
            let label = Label(self.label_base + pvm_pc);
            if let Some(offset) = self.asm.label_offset(label) {
                dispatch_table[pvm_pc as usize] = offset as i32;
            }
        }
        // PC=0 must always be valid (program start); if not already set, it'll be
        // set by the first basic block at PC 0.

        #[cfg(feature = "signals")]
        let exit_label_offset = self.asm.label_offset(self.exit_label).unwrap_or(0) as u32;
        #[cfg(feature = "signals")]
        let trap_table = self.trap_entries;

        // If the assembler uses mmap, finalize directly to executable memory
        // (no copy). Otherwise fall back to Vec-based finalize.
        match self.asm.finalize_executable() {
            Ok((ptr, code_len, mmap_cap)) => {
                // Wrap in a Vec that will munmap on drop (via NativeCode).
                // We return a CompileResult with a dummy native_code — the caller
                // should use native_mmap_ptr/len/cap instead.
                CompileResult {
                    native_code: Vec::new(), // not used when mmap_ptr is set
                    dispatch_table,
                    #[cfg(feature = "signals")]
                    trap_table,
                    #[cfg(feature = "signals")]
                    exit_label_offset,
                    mmap_ptr: Some(ptr),
                    mmap_len: code_len,
                    mmap_cap,
                }
            }
            Err(_) => CompileResult {
                native_code: self.asm.finalize(),
                dispatch_table,
                #[cfg(feature = "signals")]
                trap_table,
                #[cfg(feature = "signals")]
                exit_label_offset,
                mmap_ptr: None,
                mmap_len: 0,
                mmap_cap: 0,
            },
        }
    }

    /// Save caller-saved registers (PVM registers in caller-saved x86-64 regs).
    #[allow(dead_code)]
    fn save_caller_saved(&mut self) {
        for &reg in &CALLER_SAVED {
            self.asm.push(reg);
        }
    }

    /// Restore caller-saved registers (reverse order).
    #[allow(dead_code)]
    fn restore_caller_saved(&mut self) {
        for &reg in CALLER_SAVED.iter().rev() {
            self.asm.pop(reg);
        }
    }

    /// Load the JitContext pointer (R15 - CTX_OFFSET) into a register.
    #[allow(dead_code)]
    fn emit_ctx_ptr(&mut self, dst: Reg) {
        self.asm.lea(dst, CTX, -CTX_OFFSET);
    }

    /// Peephole: fuse scaled-index from raw code (no pre-decoded array).
    /// Pattern: add64 D,A,A / add64 D,D,D / add64 D2,BASE,D / load/store_ind R,D2,0
    fn try_fuse_scaled_index_raw(
        &mut self,
        code: &[u8],
        bitmask: &[u8],
        pc: usize,
        args: &Args,
        gas_sim: &mut GasSimulator,
    ) -> Option<usize> {
        let Args::ThreeReg {
            ra: a1_ra,
            rb: a1_rb,
            rd: a1_rd,
        } = args
        else {
            return None;
        };
        if a1_ra != a1_rb {
            return None;
        }
        let idx_reg = *a1_ra;
        let d1 = *a1_rd;

        // Peek instruction 2
        let skip1 = compute_skip(pc, bitmask);
        let pc2 = pc + 1 + skip1;
        if pc2 >= code.len() || (pc2 < bitmask.len() && bitmask[pc2] != 1) {
            return None;
        }
        let op2 = Opcode::from_byte(code[pc2])?;
        if op2 != Opcode::Add64 {
            return None;
        }
        let skip2 = compute_skip(pc2, bitmask);
        let args2 = args::decode_args(code, pc2, skip2, op2.category());
        let Args::ThreeReg {
            ra: a2_ra,
            rb: a2_rb,
            rd: a2_rd,
        } = args2
        else {
            return None;
        };
        if a2_ra != d1 || a2_rb != d1 || a2_rd != d1 {
            return None;
        }

        // Peek instruction 3
        let pc3 = pc2 + 1 + skip2;
        if pc3 >= code.len() || (pc3 < bitmask.len() && bitmask[pc3] != 1) {
            return None;
        }
        let op3 = Opcode::from_byte(code[pc3])?;
        if op3 != Opcode::Add64 {
            return None;
        }
        let skip3 = compute_skip(pc3, bitmask);
        let args3 = args::decode_args(code, pc3, skip3, op3.category());
        let Args::ThreeReg {
            ra: a3_ra,
            rb: a3_rb,
            rd: a3_rd,
        } = args3
        else {
            return None;
        };
        let base_reg;
        if a3_rb == d1 && a3_ra != d1 {
            base_reg = a3_ra;
        } else if a3_ra == d1 && a3_rb != d1 {
            base_reg = a3_rb;
        } else {
            return None;
        }
        let addr_reg = a3_rd;

        // Peek instruction 4
        let pc4 = pc3 + 1 + skip3;
        if pc4 >= code.len() || (pc4 < bitmask.len() && bitmask[pc4] != 1) {
            return None;
        }
        let op4 = Opcode::from_byte(code[pc4])?;
        let skip4 = compute_skip(pc4, bitmask);
        let args4 = args::decode_args(code, pc4, skip4, op4.category());

        // Feed instructions 2-4 to gas sim (using decoded args, no redundant decode)
        for &(opc, a, p) in &[(op2, &args2, pc2), (op3, &args3, pc3), (op4, &args4, pc4)] {
            let fc = crate::gas_cost::fast_cost_from_decoded(opc as u8, a, p as u32, code, bitmask);
            gas_sim.feed(&fc);
        }

        // Bind labels for all 4 instructions
        // With post-terminator-only gas blocks, fused instructions (add, mul,
        // load, store) are never terminators, so none of these PCs are gas block
        // starts. No label binding needed.

        match op4 {
            Opcode::LoadIndU8
            | Opcode::LoadIndI8
            | Opcode::LoadIndU16
            | Opcode::LoadIndI16
            | Opcode::LoadIndU32
            | Opcode::LoadIndI32
            | Opcode::LoadIndU64 => {
                let Args::TwoRegImm { ra, rb, imm } = args4 else {
                    return None;
                };
                if rb != addr_reg || imm as i32 != 0 {
                    return None;
                }
                self.asm
                    .lea_sib_scaled_32(SCRATCH, REG_MAP[base_reg], REG_MAP[idx_reg], 2);
                let fn_addr = self.read_fn_for(op4);
                let ra_reg = REG_MAP[ra];
                self.emit_mem_read(ra_reg, SCRATCH, fn_addr, pc4 as u32);
                match op4 {
                    Opcode::LoadIndI8 => self.asm.movsx_8_64(ra_reg, ra_reg),
                    Opcode::LoadIndI16 => self.asm.movsx_16_64(ra_reg, ra_reg),
                    Opcode::LoadIndI32 => self.asm.movsxd(ra_reg, ra_reg),
                    _ => {}
                }
                self.invalidate_all_regs();
                Some(pc4 + 1 + skip4 - pc)
            }
            Opcode::StoreIndU8
            | Opcode::StoreIndU16
            | Opcode::StoreIndU32
            | Opcode::StoreIndU64 => {
                let Args::TwoRegImm { ra, rb, imm } = args4 else {
                    return None;
                };
                if rb != addr_reg || imm as i32 != 0 {
                    return None;
                }
                self.asm
                    .lea_sib_scaled_32(SCRATCH, REG_MAP[base_reg], REG_MAP[idx_reg], 2);
                let fn_addr = self.write_fn_for(op4);
                let ra_reg = REG_MAP[ra];
                self.emit_mem_write(true, ra_reg, fn_addr, pc4 as u32);
                self.invalidate_all_regs();
                Some(pc4 + 1 + skip4 - pc)
            }
            _ => None,
        }
    }

    /// Peephole: fuse Mul64 + MulUpper from raw code.
    /// Currently disabled: corrupts results when φ[11] (RAX) is both source and destination.
    /// Kept for future fix (needs proper RAX aliasing handling in push/pop sequence).
    #[allow(dead_code)]
    fn try_fuse_mul_pair_raw(
        &mut self,
        code: &[u8],
        bitmask: &[u8],
        pc: usize,
        args: &Args,
        gas_sim: &mut GasSimulator,
    ) -> Option<usize> {
        let Args::ThreeReg {
            ra: m_ra,
            rb: m_rb,
            rd: m_rd,
        } = args
        else {
            return None;
        };

        let skip1 = compute_skip(pc, bitmask);
        let pc2 = pc + 1 + skip1;
        if pc2 >= code.len() || (pc2 < bitmask.len() && bitmask[pc2] != 1) {
            return None;
        }
        let op2 = Opcode::from_byte(code[pc2])?;
        let signed = match op2 {
            Opcode::MulUpperSS => true,
            Opcode::MulUpperUU => false,
            _ => return None,
        };
        let skip2 = compute_skip(pc2, bitmask);
        let args2 = args::decode_args(code, pc2, skip2, op2.category());
        let Args::ThreeReg {
            ra: u_ra,
            rb: u_rb,
            rd: u_rd,
        } = args2
        else {
            return None;
        };
        if u_ra != *m_ra || u_rb != *m_rb {
            return None;
        }

        // Feed instruction 2 to gas sim (using decoded args, no redundant decode)
        let fc =
            crate::gas_cost::fast_cost_from_decoded(op2 as u8, &args2, pc2 as u32, code, bitmask);
        gas_sim.feed(&fc);

        // Bind labels
        // Fused mul-pair instructions are never terminators — no gas block binding.

        let (a, b) = (REG_MAP[*m_ra], REG_MAP[*m_rb]);
        let (rd_lo, rd_hi) = (REG_MAP[*m_rd], REG_MAP[u_rd]);

        self.asm.push(Reg::RAX);
        self.asm.push(SCRATCH);
        self.asm.mov_rr(Reg::RAX, a);
        let mul_src = if b == Reg::RAX {
            self.asm.mov_load64(SCRATCH, Reg::RSP, 8);
            SCRATCH
        } else {
            b
        };
        if signed {
            self.asm.imul_rdx_rax(mul_src);
        } else {
            self.asm.mul_rdx_rax(mul_src);
        }
        self.asm.push(SCRATCH);
        self.asm.push(Reg::RAX);
        self.asm.mov_load64(SCRATCH, Reg::RSP, 16);
        self.asm.mov_load64(Reg::RAX, Reg::RSP, 24);
        self.asm.mov_load64(rd_lo, Reg::RSP, 0);
        self.asm.mov_load64(rd_hi, Reg::RSP, 8);
        self.asm.add_ri(Reg::RSP, 32);
        self.invalidate_all_regs();
        Some(pc2 + 1 + skip2 - pc)
    }

    /// Emit memory read. Address in SCRATCH (RDX). Result in dst.
    /// Uses inline flat buffer access with helper fallback for cross-page.
    fn emit_mem_read(&mut self, dst: Reg, _addr_reg: Reg, fn_addr: u64, pvm_pc: u32) {
        self.emit_mem_read_sized(dst, fn_addr, 0, pvm_pc);
    }

    /// Emit memory read with bounds check (cold fault path).
    /// Hot path: cmp + jae + load (2 instructions, no extra stores).
    /// With `signals` feature: no bounds check, just the load (SIGSEGV handles OOB).
    fn emit_mem_read_sized(&mut self, dst: Reg, fn_addr: u64, width_bytes: u32, pvm_pc: u32) {
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

        #[cfg(feature = "signals")]
        {
            // Record trap entry before the load instruction.
            self.trap_entries.push((self.asm.offset() as u32, pvm_pc));
        }
        #[cfg(not(feature = "signals"))]
        {
            let fault_label = self.asm.new_label();
            self.asm.cmp_mem32_r(CTX, CTX_HEAP_TOP, SCRATCH);
            self.asm.jcc_label(Cc::BE, fault_label);
            // Load falls through; fault stub pushed below.
            match w {
                1 => self.asm.movzx_load8_sib(dst, CTX, SCRATCH),
                2 => self.asm.movzx_load16_sib(dst, CTX, SCRATCH),
                4 => self.asm.mov_load32_sib(dst, CTX, SCRATCH),
                8 => self.asm.mov_load64_sib(dst, CTX, SCRATCH),
                _ => unreachable!(),
            }
            self.fault_stubs.push((fault_label, pvm_pc));
            #[allow(clippy::needless_return)]
            return;
        }

        #[cfg(feature = "signals")]
        match w {
            1 => self.asm.movzx_load8_sib(dst, CTX, SCRATCH),
            2 => self.asm.movzx_load16_sib(dst, CTX, SCRATCH),
            4 => self.asm.mov_load32_sib(dst, CTX, SCRATCH),
            8 => self.asm.mov_load64_sib(dst, CTX, SCRATCH),
            _ => unreachable!(),
        }
    }

    /// Emit memory write with bounds check (cold fault path).
    /// With `signals` feature: no bounds check, just the store.
    fn emit_mem_write(&mut self, _addr_in_scratch: bool, val_reg: Reg, fn_addr: u64, pvm_pc: u32) {
        let w = if fn_addr == self.helpers.mem_write_u8 {
            1u32
        } else if fn_addr == self.helpers.mem_write_u16 {
            2
        } else if fn_addr == self.helpers.mem_write_u32 {
            4
        } else {
            8
        };

        #[cfg(feature = "signals")]
        {
            self.trap_entries.push((self.asm.offset() as u32, pvm_pc));
        }
        #[cfg(not(feature = "signals"))]
        {
            let fault_label = self.asm.new_label();
            self.asm.cmp_mem32_r(CTX, CTX_HEAP_TOP, SCRATCH);
            self.asm.jcc_label(Cc::BE, fault_label);
            match w {
                1 => self.asm.mov_store8_sib(CTX, SCRATCH, val_reg),
                2 => self.asm.mov_store16_sib(CTX, SCRATCH, val_reg),
                4 => self.asm.mov_store32_sib(CTX, SCRATCH, val_reg),
                8 => self.asm.mov_store64_sib(CTX, SCRATCH, val_reg),
                _ => unreachable!(),
            }
            self.fault_stubs.push((fault_label, pvm_pc));
            #[allow(clippy::needless_return)]
            return;
        }

        #[cfg(feature = "signals")]
        match w {
            1 => self.asm.mov_store8_sib(CTX, SCRATCH, val_reg),
            2 => self.asm.mov_store16_sib(CTX, SCRATCH, val_reg),
            4 => self.asm.mov_store32_sib(CTX, SCRATCH, val_reg),
            8 => self.asm.mov_store64_sib(CTX, SCRATCH, val_reg),
            _ => unreachable!(),
        }
    }

    /// Emit store-immediate-indirect: store an immediate value to memory.
    /// With `signals` feature: inline SIB store (no function call needed).
    /// Without `signals`: falls back to helper function call.
    fn emit_store_imm_ind(
        &mut self,
        opcode: Opcode,
        ra: usize,
        imm_x: i32,
        imm_y: u64,
        _pvm_pc: u32,
    ) {
        // Compute address into SCRATCH
        self.emit_addr_to_scratch(ra, imm_x);

        #[cfg(feature = "signals")]
        let fits_i32 = {
            let imm_i64 = imm_y as i64;
            imm_i64 >= i32::MIN as i64 && imm_i64 <= i32::MAX as i64
        };

        #[cfg(feature = "signals")]
        {
            self.trap_entries.push((self.asm.offset() as u32, _pvm_pc));

            match opcode {
                Opcode::StoreImmIndU8 => {
                    self.asm.mov_store8_sib_imm(CTX, SCRATCH, imm_y as u8);
                }
                Opcode::StoreImmIndU16 => {
                    self.asm.mov_store16_sib_imm(CTX, SCRATCH, imm_y as u16);
                }
                Opcode::StoreImmIndU32 => {
                    self.asm.mov_store32_sib_imm(CTX, SCRATCH, imm_y as i32);
                }
                Opcode::StoreImmIndU64 if fits_i32 => {
                    // mov qword [CTX + SCRATCH], sign-extended imm32
                    self.asm.mov_store64_sib_imm(CTX, SCRATCH, imm_y as i32);
                }
                Opcode::StoreImmIndU64 => {
                    // Value doesn't fit in sign-extended i32: use a temp register.
                    self.asm.push(Reg::RCX);
                    self.asm.mov_ri64(Reg::RCX, imm_y);
                    self.asm.mov_store64_sib(CTX, SCRATCH, Reg::RCX);
                    self.asm.pop(Reg::RCX);
                }
                _ => unreachable!(),
            }
        }

        #[cfg(not(feature = "signals"))]
        {
            let fn_addr = match opcode {
                Opcode::StoreImmIndU8 => self.helpers.mem_write_u8,
                Opcode::StoreImmIndU16 => self.helpers.mem_write_u16,
                Opcode::StoreImmIndU32 => self.helpers.mem_write_u32,
                Opcode::StoreImmIndU64 => self.helpers.mem_write_u64,
                _ => unreachable!(),
            };
            // Fallback: helper function call
            self.asm.push(SCRATCH);
            self.asm.mov_ri64(SCRATCH, imm_y);
            self.asm.push(SCRATCH);
            self.save_caller_saved();
            self.asm.mov_load64(Reg::RDX, Reg::RSP, 64);
            self.asm.mov_load64(Reg::RSI, Reg::RSP, 72);
            self.emit_ctx_ptr(Reg::RDI);
            self.asm.mov_ri64(Reg::RAX, fn_addr);
            self.asm.call_reg(Reg::RAX);
            self.restore_caller_saved();
            self.asm.pop(SCRATCH);
            self.asm.pop(SCRATCH);
            self.asm.push(SCRATCH);
            self.asm.mov_load32(SCRATCH, CTX, CTX_EXIT_REASON);
            self.asm.cmp_ri(SCRATCH, 0);
            self.asm.pop(SCRATCH);
            self.asm.jcc_label(Cc::NE, self.exit_label);
        }
    }

    /// Compute a memory address into SCRATCH, using peephole optimizations when available.
    fn emit_addr_to_scratch(&mut self, rb: usize, imm: i32) {
        // Peephole: fold known constant address (no register load needed)
        if let RegDef::Const(addr) = self.reg_defs[rb] {
            let effective = addr.wrapping_add(imm as u32);
            self.asm.mov_ri32(SCRATCH, effective);
            return;
        }
        // Peephole: use SIB addressing for scaled-index patterns
        if imm == 0
            && let RegDef::ScaledAdd { base, idx, shift } = self.reg_defs[rb]
        {
            self.asm
                .lea_sib_scaled_32(SCRATCH, REG_MAP[base], REG_MAP[idx], shift);
            return;
        }
        let rb_reg = REG_MAP[rb];
        if imm != 0 {
            // lea r32, [base + disp]: combines truncation to 32-bit and offset
            // addition in one instruction (saves ~2 bytes vs movzx + add).
            self.asm.lea_32(SCRATCH, rb_reg, imm);
        } else {
            self.asm.movzx_32_64(SCRATCH, rb_reg);
        }
    }

    /// Invalidate any reg_defs that depend on `reg`, but NOT reg itself.
    #[inline]
    fn invalidate_dependents(&mut self, reg: usize) {
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
    fn invalidate_reg(&mut self, reg: usize) {
        self.reg_defs[reg] = RegDef::Unknown;
        self.reg_defs_active &= !(1u16 << reg);
        self.invalidate_dependents(reg);
    }

    /// Invalidate all register definitions (on block boundaries, calls, etc.)
    #[inline]
    fn invalidate_all_regs(&mut self) {
        self.reg_defs = [RegDef::Unknown; 13];
        self.reg_defs_active = 0;
    }

    /// Update reg_defs after compiling an instruction.
    /// Opcodes that produce trackable patterns update positively;
    /// all others invalidate the destination register.
    fn update_reg_defs(&mut self, opcode: Opcode, args: &Args) {
        match opcode {
            Opcode::Add64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    if *ra == *rb && *ra == *rd {
                        // add64 D, D, D — doubles again. Shifted{src,s} → Shifted{src,s+1}.
                        if let RegDef::Shifted { src, shift } = self.reg_defs[*rd] {
                            if shift < 3 {
                                self.reg_defs[*rd] = RegDef::Shifted {
                                    src,
                                    shift: shift + 1,
                                };
                                self.reg_defs_active |= 1u16 << *rd;
                            } else {
                                self.reg_defs[*rd] = RegDef::Unknown;
                                self.reg_defs_active &= !(1u16 << *rd);
                            }
                        } else {
                            self.reg_defs[*rd] = RegDef::Unknown;
                            self.reg_defs_active &= !(1u16 << *rd);
                        }
                    } else if *ra == *rb {
                        // add64 D, A, A — D = A * 2 = A << 1
                        self.reg_defs[*rd] = RegDef::Shifted { src: *ra, shift: 1 };
                        self.reg_defs_active |= 1u16 << *rd;
                    } else {
                        // add64 D, A, B — check if one operand is Shifted
                        let def = if let RegDef::Shifted { src, shift } = self.reg_defs[*rb] {
                            Some((*ra, src, shift))
                        } else if let RegDef::Shifted { src, shift } = self.reg_defs[*ra] {
                            Some((*rb, src, shift))
                        } else {
                            None
                        };
                        if let Some((base, idx, shift)) = def {
                            self.reg_defs[*rd] = RegDef::ScaledAdd { base, idx, shift };
                            self.reg_defs_active |= 1u16 << *rd;
                        } else {
                            self.reg_defs[*rd] = RegDef::Unknown;
                            self.reg_defs_active &= !(1u16 << *rd);
                        }
                    }
                    self.invalidate_dependents(*rd);
                }
            }
            Opcode::LoadImm => {
                if let Args::RegImm { ra, imm } = args {
                    self.reg_defs[*ra] = RegDef::Const(*imm as u32);
                    self.reg_defs_active |= 1u16 << *ra;
                    self.invalidate_dependents(*ra);
                }
            }
            Opcode::LoadImm64 => {
                if let Args::RegExtImm { ra, imm } = args {
                    self.reg_defs[*ra] = RegDef::Const(*imm as u32);
                    self.reg_defs_active |= 1u16 << *ra;
                    self.invalidate_dependents(*ra);
                }
            }
            // Track shift-left-immediate as Shifted for LEA-based scaled indexing.
            // sll_imm_64 rd, rb, shift → Shifted{src:rb, shift} if shift ∈ 1..=3.
            // This enables the peephole: sll + add + load → LEA + load with SIB scaling.
            Opcode::ShloLImm64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let shift = (*imm as u32 % 64) as u8;
                    if (1..=3).contains(&shift) {
                        self.reg_defs[*ra] = RegDef::Shifted { src: *rb, shift };
                        self.reg_defs_active |= 1u16 << *ra;
                    } else {
                        self.reg_defs[*ra] = RegDef::Unknown;
                        self.reg_defs_active &= !(1u16 << *ra);
                    }
                    self.invalidate_dependents(*ra);
                }
            }
            Opcode::MoveReg => {
                if let Args::TwoReg { rd, ra } = args
                    && *rd != *ra
                {
                    // Propagate the source's definition to the destination.
                    self.reg_defs[*rd] = self.reg_defs[*ra];
                    if matches!(self.reg_defs[*rd], RegDef::Unknown) {
                        self.reg_defs_active &= !(1u16 << *rd);
                    } else {
                        self.reg_defs_active |= 1u16 << *rd;
                    }
                    self.invalidate_dependents(*rd);
                }
            }
            _ => {
                match args {
                    Args::ThreeReg { rd, .. } => self.invalidate_reg(*rd),
                    Args::TwoReg { rd, .. } => self.invalidate_reg(*rd),
                    Args::TwoRegImm { ra, .. } => self.invalidate_reg(*ra),
                    Args::RegImm { ra, .. } => self.invalidate_reg(*ra),
                    Args::RegExtImm { ra, .. } => self.invalidate_reg(*ra),
                    _ => {}
                }
                if opcode.is_terminator() {
                    self.invalidate_all_regs();
                }
            }
        }
    }

    /// Compile a single PVM instruction.
    /// Caller must ensure the assembler has sufficient capacity (at least 256 bytes).
    #[inline(always)]
    fn compile_instruction(&mut self, opcode: Opcode, args: &Args, pc: u32, next_pc: u32) {
        match opcode {
            // === A.5.1: No arguments ===
            Opcode::Trap => {
                self.asm.mov_store32_imm(CTX, CTX_PC, pc as i32);
                self.emit_exit(EXIT_PANIC, 0);
            }
            Opcode::Fallthrough | Opcode::Unlikely => {
                // Just fall through to next instruction.
                // Note: gas is already charged at basic block start above.
            }

            // === A.5.2: One immediate ===
            Opcode::Ecalli => {
                if let Args::Imm { imm } = args {
                    // Save next_pc for resumption after host call
                    self.asm.mov_store32_imm(CTX, CTX_PC, next_pc as i32);
                    self.emit_exit(EXIT_HOST_CALL, *imm as u32);
                }
            }

            // === A.5.3: One register + extended immediate ===
            Opcode::LoadImm64 => {
                if let Args::RegExtImm { ra, imm } = args {
                    self.asm.mov_ri64(REG_MAP[*ra], *imm);
                }
            }

            // === A.5.4: Two immediates (store_imm) ===
            Opcode::StoreImmU8
            | Opcode::StoreImmU16
            | Opcode::StoreImmU32
            | Opcode::StoreImmU64 => {
                if let Args::TwoImm { imm_x, imm_y } = args {
                    // Reuse StoreImmInd logic: treat as register 0 with the address
                    // replaced by a direct constant load into SCRATCH.
                    let addr = *imm_x as u32;
                    self.asm.mov_ri32(SCRATCH, addr);
                    let imm_val = *imm_y;

                    #[cfg(feature = "signals")]
                    let fits_i32 = {
                        let imm_i64 = imm_val as i64;
                        imm_i64 >= i32::MIN as i64 && imm_i64 <= i32::MAX as i64
                    };

                    #[cfg(feature = "signals")]
                    {
                        self.trap_entries.push((self.asm.offset() as u32, pc));
                        match opcode {
                            Opcode::StoreImmU8 => {
                                self.asm.mov_store8_sib_imm(CTX, SCRATCH, imm_val as u8);
                            }
                            Opcode::StoreImmU16 => {
                                self.asm.mov_store16_sib_imm(CTX, SCRATCH, imm_val as u16);
                            }
                            Opcode::StoreImmU32 => {
                                self.asm.mov_store32_sib_imm(CTX, SCRATCH, imm_val as i32);
                            }
                            Opcode::StoreImmU64 if fits_i32 => {
                                self.asm.mov_store64_sib_imm(CTX, SCRATCH, imm_val as i32);
                            }
                            Opcode::StoreImmU64 => {
                                self.asm.push(Reg::RCX);
                                self.asm.mov_ri64(Reg::RCX, imm_val);
                                self.asm.mov_store64_sib(CTX, SCRATCH, Reg::RCX);
                                self.asm.pop(Reg::RCX);
                            }
                            _ => unreachable!(),
                        }
                    }
                    #[cfg(not(feature = "signals"))]
                    {
                        let fn_addr = match opcode {
                            Opcode::StoreImmU8 => self.helpers.mem_write_u8,
                            Opcode::StoreImmU16 => self.helpers.mem_write_u16,
                            Opcode::StoreImmU32 => self.helpers.mem_write_u32,
                            Opcode::StoreImmU64 => self.helpers.mem_write_u64,
                            _ => unreachable!(),
                        };
                        self.asm.push(SCRATCH);
                        self.asm.mov_ri64(SCRATCH, imm_val);
                        self.asm.push(SCRATCH);
                        self.save_caller_saved();
                        self.asm.mov_load64(Reg::RDX, Reg::RSP, 64);
                        self.asm.mov_load64(Reg::RSI, Reg::RSP, 72);
                        self.emit_ctx_ptr(Reg::RDI);
                        self.asm.mov_ri64(Reg::RAX, fn_addr);
                        self.asm.call_reg(Reg::RAX);
                        self.restore_caller_saved();
                        self.asm.pop(SCRATCH);
                        self.asm.pop(SCRATCH);
                        self.asm.push(SCRATCH);
                        self.asm.mov_load32(SCRATCH, CTX, CTX_EXIT_REASON);
                        self.asm.cmp_ri(SCRATCH, 0);
                        self.asm.pop(SCRATCH);
                        self.asm.jcc_label(Cc::NE, self.exit_label);
                    }
                }
            }

            // === A.5.5: One offset (jump) ===
            Opcode::Jump => {
                if let Args::Offset { offset } = args {
                    self.emit_static_branch(*offset as u32, true, next_pc, pc);
                }
            }

            // === A.5.6: One register + one immediate ===
            Opcode::JumpInd => {
                if let Args::RegImm { ra, imm } = args {
                    self.emit_dynamic_jump(*ra, *imm, pc);
                }
            }
            Opcode::LoadImm => {
                if let Args::RegImm { ra, imm } = args {
                    self.asm.mov_ri64(REG_MAP[*ra], *imm);
                }
            }
            Opcode::LoadU8
            | Opcode::LoadI8
            | Opcode::LoadU16
            | Opcode::LoadI16
            | Opcode::LoadU32
            | Opcode::LoadI32
            | Opcode::LoadU64 => {
                if let Args::RegImm { ra, imm } = args {
                    let addr = *imm as u32;
                    let fn_addr = self.read_fn_for(opcode);
                    self.asm.mov_ri32(SCRATCH, addr);
                    let ra_reg = REG_MAP[*ra];
                    self.emit_mem_read(ra_reg, SCRATCH, fn_addr, pc);
                    // Sign-extend for signed load variants
                    match opcode {
                        Opcode::LoadI8 => self.asm.movsx_8_64(ra_reg, ra_reg),
                        Opcode::LoadI16 => self.asm.movsx_16_64(ra_reg, ra_reg),
                        Opcode::LoadI32 => self.asm.movsxd(ra_reg, ra_reg),
                        _ => {}
                    }
                }
            }
            Opcode::StoreU8 | Opcode::StoreU16 | Opcode::StoreU32 | Opcode::StoreU64 => {
                if let Args::RegImm { ra, imm } = args {
                    let addr = *imm as u32;
                    let ra_reg = REG_MAP[*ra];
                    let fn_addr = self.write_fn_for(opcode);
                    self.asm.mov_ri32(SCRATCH, addr);
                    self.emit_mem_write(true, ra_reg, fn_addr, pc);
                }
            }

            // === A.5.7: One register + two immediates (store_imm_ind) ===
            Opcode::StoreImmIndU8
            | Opcode::StoreImmIndU16
            | Opcode::StoreImmIndU32
            | Opcode::StoreImmIndU64 => {
                if let Args::RegTwoImm { ra, imm_x, imm_y } = args {
                    self.emit_store_imm_ind(opcode, *ra, *imm_x as i32, *imm_y, pc);
                }
            }

            // === A.5.8: One register + immediate + offset ===
            Opcode::LoadImmJump => {
                if let Args::RegImmOffset { ra, imm, offset } = args {
                    self.asm.mov_ri64(REG_MAP[*ra], *imm);
                    self.emit_static_branch(*offset as u32, true, next_pc, pc);
                }
            }
            Opcode::BranchEqImm => {
                if let Args::RegImmOffset { ra, imm, offset } = args {
                    let ra_reg = REG_MAP[*ra];
                    self.emit_branch_imm(ra_reg, *imm, Cc::E, *offset as u32, next_pc, pc);
                }
            }
            Opcode::BranchNeImm => {
                if let Args::RegImmOffset { ra, imm, offset } = args {
                    let ra_reg = REG_MAP[*ra];
                    self.emit_branch_imm(ra_reg, *imm, Cc::NE, *offset as u32, next_pc, pc);
                }
            }
            Opcode::BranchLtUImm => {
                if let Args::RegImmOffset { ra, imm, offset } = args {
                    let ra_reg = REG_MAP[*ra];
                    self.emit_branch_imm(ra_reg, *imm, Cc::B, *offset as u32, next_pc, pc);
                }
            }
            Opcode::BranchLeUImm => {
                if let Args::RegImmOffset { ra, imm, offset } = args {
                    let ra_reg = REG_MAP[*ra];
                    self.emit_branch_imm(ra_reg, *imm, Cc::BE, *offset as u32, next_pc, pc);
                }
            }
            Opcode::BranchGeUImm => {
                if let Args::RegImmOffset { ra, imm, offset } = args {
                    let ra_reg = REG_MAP[*ra];
                    self.emit_branch_imm(ra_reg, *imm, Cc::AE, *offset as u32, next_pc, pc);
                }
            }
            Opcode::BranchGtUImm => {
                if let Args::RegImmOffset { ra, imm, offset } = args {
                    let ra_reg = REG_MAP[*ra];
                    self.emit_branch_imm(ra_reg, *imm, Cc::A, *offset as u32, next_pc, pc);
                }
            }
            Opcode::BranchLtSImm => {
                if let Args::RegImmOffset { ra, imm, offset } = args {
                    let ra_reg = REG_MAP[*ra];
                    self.emit_branch_imm(ra_reg, *imm, Cc::L, *offset as u32, next_pc, pc);
                }
            }
            Opcode::BranchLeSImm => {
                if let Args::RegImmOffset { ra, imm, offset } = args {
                    let ra_reg = REG_MAP[*ra];
                    self.emit_branch_imm(ra_reg, *imm, Cc::LE, *offset as u32, next_pc, pc);
                }
            }
            Opcode::BranchGeSImm => {
                if let Args::RegImmOffset { ra, imm, offset } = args {
                    let ra_reg = REG_MAP[*ra];
                    self.emit_branch_imm(ra_reg, *imm, Cc::GE, *offset as u32, next_pc, pc);
                }
            }
            Opcode::BranchGtSImm => {
                if let Args::RegImmOffset { ra, imm, offset } = args {
                    let ra_reg = REG_MAP[*ra];
                    self.emit_branch_imm(ra_reg, *imm, Cc::G, *offset as u32, next_pc, pc);
                }
            }

            // === A.5.9: Two registers ===
            Opcode::MoveReg => {
                if let Args::TwoReg { rd, ra } = args {
                    let ra_reg = REG_MAP[*ra];
                    self.asm.mov_rr(REG_MAP[*rd], ra_reg);
                }
            }
            Opcode::Sbrk => {
                // JAR v0.8.0: sbrk removed from ISA, replaced by grow_heap hostcall
                self.asm.mov_store32_imm(CTX, CTX_PC, pc as i32);
                self.emit_exit(EXIT_PANIC, 0);
            }
            Opcode::CountSetBits64 => {
                if let Args::TwoReg { rd, ra } = args {
                    let ra_reg = REG_MAP[*ra];
                    self.asm.popcnt64(REG_MAP[*rd], ra_reg);
                }
            }
            Opcode::CountSetBits32 => {
                if let Args::TwoReg { rd, ra } = args {
                    let ra_reg = REG_MAP[*ra];
                    // Zero-extend to 32 bits first, then popcnt
                    self.asm.movzx_32_64(SCRATCH, ra_reg);
                    self.asm.popcnt64(REG_MAP[*rd], SCRATCH);
                }
            }
            Opcode::LeadingZeroBits64 => {
                if let Args::TwoReg { rd, ra } = args {
                    let ra_reg = REG_MAP[*ra];
                    self.asm.lzcnt64(REG_MAP[*rd], ra_reg);
                }
            }
            Opcode::LeadingZeroBits32 => {
                if let Args::TwoReg { rd, ra } = args {
                    let ra_reg = REG_MAP[*ra];
                    self.asm.movzx_32_64(SCRATCH, ra_reg);
                    // lzcnt on 64-bit value then subtract 32
                    self.asm.lzcnt64(REG_MAP[*rd], SCRATCH);
                    self.asm.sub_ri(REG_MAP[*rd], 32);
                }
            }
            Opcode::TrailingZeroBits64 => {
                if let Args::TwoReg { rd, ra } = args {
                    let ra_reg = REG_MAP[*ra];
                    self.asm.tzcnt64(REG_MAP[*rd], ra_reg);
                }
            }
            Opcode::TrailingZeroBits32 => {
                if let Args::TwoReg { rd, ra } = args {
                    let ra_reg = REG_MAP[*ra];
                    // Set bit 32 to ensure tzcnt doesn't return 64 for zero input
                    self.asm.mov_rr(SCRATCH, ra_reg);
                    self.asm.movzx_32_64(SCRATCH, SCRATCH);
                    // OR with (1 << 32) to cap at 32
                    self.asm.push(SCRATCH);
                    self.asm.mov_ri64(SCRATCH, 1u64 << 32);
                    let tmp = SCRATCH;
                    self.asm.pop(REG_MAP[*rd]);
                    self.asm.or_rr(REG_MAP[*rd], tmp);
                    self.asm.tzcnt64(REG_MAP[*rd], REG_MAP[*rd]);
                }
            }
            Opcode::SignExtend8 => {
                if let Args::TwoReg { rd, ra } = args {
                    let ra_reg = REG_MAP[*ra];
                    self.asm.movsx_8_64(REG_MAP[*rd], ra_reg);
                }
            }
            Opcode::SignExtend16 => {
                if let Args::TwoReg { rd, ra } = args {
                    let ra_reg = REG_MAP[*ra];
                    self.asm.movsx_16_64(REG_MAP[*rd], ra_reg);
                }
            }
            Opcode::ZeroExtend16 => {
                if let Args::TwoReg { rd, ra } = args {
                    let ra_reg = REG_MAP[*ra];
                    self.asm.movzx_16_64(REG_MAP[*rd], ra_reg);
                }
            }
            Opcode::ReverseBytes => {
                if let Args::TwoReg { rd, ra } = args {
                    let ra_reg = REG_MAP[*ra];
                    if *rd != *ra {
                        self.asm.mov_rr(REG_MAP[*rd], ra_reg);
                    }
                    self.asm.bswap64(REG_MAP[*rd]);
                }
            }

            // === A.5.10: Two registers + one immediate ===
            Opcode::StoreIndU8
            | Opcode::StoreIndU16
            | Opcode::StoreIndU32
            | Opcode::StoreIndU64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let ra_reg = REG_MAP[*ra];
                    self.emit_addr_to_scratch(*rb, *imm as i32);
                    let fn_addr = self.write_fn_for(opcode);
                    self.emit_mem_write(true, ra_reg, fn_addr, pc);
                }
            }
            Opcode::LoadIndU8
            | Opcode::LoadIndI8
            | Opcode::LoadIndU16
            | Opcode::LoadIndI16
            | Opcode::LoadIndU32
            | Opcode::LoadIndI32
            | Opcode::LoadIndU64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let ra_reg = REG_MAP[*ra];
                    self.emit_addr_to_scratch(*rb, *imm as i32);
                    let fn_addr = self.read_fn_for(opcode);
                    self.emit_mem_read(ra_reg, SCRATCH, fn_addr, pc);
                    // Sign-extend for signed load variants
                    match opcode {
                        Opcode::LoadIndI8 => self.asm.movsx_8_64(ra_reg, ra_reg),
                        Opcode::LoadIndI16 => self.asm.movsx_16_64(ra_reg, ra_reg),
                        Opcode::LoadIndI32 => self.asm.movsxd(ra_reg, ra_reg),
                        _ => {}
                    }
                }
            }
            Opcode::AddImm32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    if *ra != *rb {
                        self.asm.mov_rr(REG_MAP[*ra], rb_reg);
                    }
                    self.asm.add_ri32(REG_MAP[*ra], *imm as i32);
                    self.asm.movsxd(REG_MAP[*ra], REG_MAP[*ra]);
                }
            }
            Opcode::AddImm64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    if *ra != *rb {
                        self.asm.mov_rr(REG_MAP[*ra], rb_reg);
                    }
                    if *imm as i32 == 1 {
                        self.asm.inc64(REG_MAP[*ra]);
                    } else if *imm as i32 == -1 {
                        self.asm.dec64(REG_MAP[*ra]);
                    } else {
                        self.asm.add_ri(REG_MAP[*ra], *imm as i32);
                    }
                }
            }
            Opcode::AndImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    if *ra != *rb {
                        self.asm.mov_rr(REG_MAP[*ra], rb_reg);
                    }
                    self.asm.and_ri(REG_MAP[*ra], *imm as i32);
                }
            }
            Opcode::XorImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    if *ra != *rb {
                        self.asm.mov_rr(REG_MAP[*ra], rb_reg);
                    }
                    self.asm.xor_ri(REG_MAP[*ra], *imm as i32);
                }
            }
            Opcode::OrImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    if *ra != *rb {
                        self.asm.mov_rr(REG_MAP[*ra], rb_reg);
                    }
                    self.asm.or_ri(REG_MAP[*ra], *imm as i32);
                }
            }
            Opcode::MulImm32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    self.asm.imul_rri32(REG_MAP[*ra], rb_reg, *imm as i32);
                    self.asm.movsxd(REG_MAP[*ra], REG_MAP[*ra]);
                }
            }
            Opcode::MulImm64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    self.asm.imul_rri(REG_MAP[*ra], rb_reg, *imm as i32);
                }
            }
            Opcode::SetLtUImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.emit_setcc_imm(*ra, *rb, *imm, Cc::B);
                }
            }
            Opcode::SetLtSImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.emit_setcc_imm(*ra, *rb, *imm, Cc::L);
                }
            }
            Opcode::SetGtUImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.emit_setcc_imm(*ra, *rb, *imm, Cc::A);
                }
            }
            Opcode::SetGtSImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.emit_setcc_imm(*ra, *rb, *imm, Cc::G);
                }
            }
            Opcode::ShloLImm32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    if *ra != *rb {
                        self.asm.mov_rr(REG_MAP[*ra], rb_reg);
                    }
                    self.asm.shl_ri32(REG_MAP[*ra], (*imm as u8) & 31);
                    self.asm.movsxd(REG_MAP[*ra], REG_MAP[*ra]);
                }
            }
            Opcode::ShloRImm32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    if *ra != *rb {
                        self.asm.mov_rr(REG_MAP[*ra], rb_reg);
                    }
                    self.asm.movzx_32_64(REG_MAP[*ra], REG_MAP[*ra]);
                    self.asm.shr_ri32(REG_MAP[*ra], (*imm as u8) & 31);
                    self.asm.movsxd(REG_MAP[*ra], REG_MAP[*ra]);
                }
            }
            Opcode::SharRImm32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    if *ra != *rb {
                        self.asm.mov_rr(REG_MAP[*ra], rb_reg);
                    }
                    self.asm.sar_ri32(REG_MAP[*ra], (*imm as u8) & 31);
                    self.asm.movsxd(REG_MAP[*ra], REG_MAP[*ra]);
                }
            }
            Opcode::ShloLImm64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    if *ra != *rb {
                        self.asm.mov_rr(REG_MAP[*ra], rb_reg);
                    }
                    self.asm.shl_ri64(REG_MAP[*ra], (*imm as u8) & 63);
                }
            }
            Opcode::ShloRImm64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    if *ra != *rb {
                        self.asm.mov_rr(REG_MAP[*ra], rb_reg);
                    }
                    self.asm.shr_ri64(REG_MAP[*ra], (*imm as u8) & 63);
                }
            }
            Opcode::SharRImm64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    if *ra != *rb {
                        self.asm.mov_rr(REG_MAP[*ra], rb_reg);
                    }
                    self.asm.sar_ri64(REG_MAP[*ra], (*imm as u8) & 63);
                }
            }
            Opcode::NegAddImm32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    // rd = imm - rb (32-bit)
                    if *ra == *rb {
                        self.asm.mov_rr(SCRATCH, rb_reg);
                        self.asm.mov_ri64(REG_MAP[*ra], *imm);
                        self.asm.sub_rr32(REG_MAP[*ra], SCRATCH);
                    } else {
                        self.asm.mov_ri64(REG_MAP[*ra], *imm);
                        self.asm.sub_rr32(REG_MAP[*ra], rb_reg);
                    }
                    self.asm.movsxd(REG_MAP[*ra], REG_MAP[*ra]);
                }
            }
            Opcode::NegAddImm64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    if *ra == *rb {
                        self.asm.mov_rr(SCRATCH, rb_reg);
                        self.asm.mov_ri64(REG_MAP[*ra], *imm);
                        self.asm.sub_rr(REG_MAP[*ra], SCRATCH);
                    } else {
                        self.asm.mov_ri64(REG_MAP[*ra], *imm);
                        self.asm.sub_rr(REG_MAP[*ra], rb_reg);
                    }
                }
            }
            // Alt shifts: rd = imm OP rb (operands swapped)
            Opcode::ShloLImmAlt32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    // rd = imm << (rb & 31)
                    let rb_reg = REG_MAP[*rb];
                    let shift_src = if *ra == *rb {
                        self.asm.mov_rr(SCRATCH, rb_reg);
                        SCRATCH
                    } else {
                        rb_reg
                    };
                    self.asm.mov_ri64(REG_MAP[*ra], *imm);
                    self.emit_shift_by_reg32(REG_MAP[*ra], shift_src, 4); // SHL
                    self.asm.movsxd(REG_MAP[*ra], REG_MAP[*ra]);
                }
            }
            Opcode::ShloRImmAlt32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    let shift_src = if *ra == *rb {
                        self.asm.mov_rr(SCRATCH, rb_reg);
                        SCRATCH
                    } else {
                        rb_reg
                    };
                    self.asm.mov_ri64(REG_MAP[*ra], *imm);
                    self.asm.movzx_32_64(REG_MAP[*ra], REG_MAP[*ra]);
                    self.emit_shift_by_reg32(REG_MAP[*ra], shift_src, 5); // SHR
                    self.asm.movsxd(REG_MAP[*ra], REG_MAP[*ra]);
                }
            }
            Opcode::SharRImmAlt32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    let shift_src = if *ra == *rb {
                        self.asm.mov_rr(SCRATCH, rb_reg);
                        SCRATCH
                    } else {
                        rb_reg
                    };
                    self.asm.mov_ri64(REG_MAP[*ra], *imm);
                    self.emit_shift_by_reg32(REG_MAP[*ra], shift_src, 7); // SAR
                    self.asm.movsxd(REG_MAP[*ra], REG_MAP[*ra]);
                }
            }
            Opcode::ShloLImmAlt64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    let shift_src = if *ra == *rb {
                        self.asm.mov_rr(SCRATCH, rb_reg);
                        SCRATCH
                    } else {
                        rb_reg
                    };
                    self.asm.mov_ri64(REG_MAP[*ra], *imm);
                    self.emit_shift_by_reg64(REG_MAP[*ra], shift_src, 4);
                }
            }
            Opcode::ShloRImmAlt64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    let shift_src = if *ra == *rb {
                        self.asm.mov_rr(SCRATCH, rb_reg);
                        SCRATCH
                    } else {
                        rb_reg
                    };
                    self.asm.mov_ri64(REG_MAP[*ra], *imm);
                    self.emit_shift_by_reg64(REG_MAP[*ra], shift_src, 5);
                }
            }
            Opcode::SharRImmAlt64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    let shift_src = if *ra == *rb {
                        self.asm.mov_rr(SCRATCH, rb_reg);
                        SCRATCH
                    } else {
                        rb_reg
                    };
                    self.asm.mov_ri64(REG_MAP[*ra], *imm);
                    self.emit_shift_by_reg64(REG_MAP[*ra], shift_src, 7);
                }
            }
            Opcode::CmovIzImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    // if φ[rb] == 0 then φ[ra] = imm
                    let rb_reg = REG_MAP[*rb];
                    self.asm.test_rr(rb_reg, rb_reg);
                    let skip = self.asm.new_label();
                    self.asm.jcc_label(Cc::NE, skip);
                    self.asm.mov_ri64(REG_MAP[*ra], *imm);

                    self.asm.bind_label(skip);
                }
            }
            Opcode::CmovNzImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    self.asm.test_rr(rb_reg, rb_reg);
                    let skip = self.asm.new_label();
                    self.asm.jcc_label(Cc::E, skip);
                    self.asm.mov_ri64(REG_MAP[*ra], *imm);

                    self.asm.bind_label(skip);
                }
            }
            Opcode::RotR64Imm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    if *ra != *rb {
                        self.asm.mov_rr(REG_MAP[*ra], rb_reg);
                    }
                    self.asm.ror_ri64(REG_MAP[*ra], (*imm as u8) & 63);
                }
            }
            Opcode::RotR64ImmAlt => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    // rd = imm ROR rb
                    let rb_reg = REG_MAP[*rb];
                    let shift_src = if *ra == *rb {
                        self.asm.mov_rr(SCRATCH, rb_reg);
                        SCRATCH
                    } else {
                        rb_reg
                    };
                    self.asm.mov_ri64(REG_MAP[*ra], *imm);
                    self.emit_shift_by_reg64(REG_MAP[*ra], shift_src, 1); // ROR
                }
            }
            Opcode::RotR32Imm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    if *ra != *rb {
                        self.asm.mov_rr(REG_MAP[*ra], rb_reg);
                    }
                    self.asm.movzx_32_64(REG_MAP[*ra], REG_MAP[*ra]);
                    self.asm.ror_ri32(REG_MAP[*ra], (*imm as u8) & 31);
                    self.asm.movsxd(REG_MAP[*ra], REG_MAP[*ra]);
                }
            }
            Opcode::RotR32ImmAlt => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    let shift_src = if *ra == *rb {
                        self.asm.mov_rr(SCRATCH, rb_reg);
                        SCRATCH
                    } else {
                        rb_reg
                    };
                    self.asm.mov_ri64(REG_MAP[*ra], *imm);
                    self.asm.movzx_32_64(REG_MAP[*ra], REG_MAP[*ra]);
                    self.emit_shift_by_reg32(REG_MAP[*ra], shift_src, 1); // ROR
                    self.asm.movsxd(REG_MAP[*ra], REG_MAP[*ra]);
                }
            }

            // === A.5.11: Two registers + one offset ===
            Opcode::BranchEq => {
                if let Args::TwoRegOffset { ra, rb, offset } = args {
                    // Both ra and rb are READ. If one is 12, we need special handling
                    // since both map to RCX. Load spilled first, save to SCRATCH if needed.
                    let (ra_reg, rb_reg) = (REG_MAP[*ra], REG_MAP[*rb]);
                    self.emit_branch_reg(ra_reg, rb_reg, Cc::E, *offset as u32, next_pc, pc);
                }
            }
            Opcode::BranchNe => {
                if let Args::TwoRegOffset { ra, rb, offset } = args {
                    let (ra_reg, rb_reg) = (REG_MAP[*ra], REG_MAP[*rb]);
                    self.emit_branch_reg(ra_reg, rb_reg, Cc::NE, *offset as u32, next_pc, pc);
                }
            }
            Opcode::BranchLtU => {
                if let Args::TwoRegOffset { ra, rb, offset } = args {
                    let (ra_reg, rb_reg) = (REG_MAP[*ra], REG_MAP[*rb]);
                    self.emit_branch_reg(ra_reg, rb_reg, Cc::B, *offset as u32, next_pc, pc);
                }
            }
            Opcode::BranchLtS => {
                if let Args::TwoRegOffset { ra, rb, offset } = args {
                    let (ra_reg, rb_reg) = (REG_MAP[*ra], REG_MAP[*rb]);
                    self.emit_branch_reg(ra_reg, rb_reg, Cc::L, *offset as u32, next_pc, pc);
                }
            }
            Opcode::BranchGeU => {
                if let Args::TwoRegOffset { ra, rb, offset } = args {
                    let (ra_reg, rb_reg) = (REG_MAP[*ra], REG_MAP[*rb]);
                    self.emit_branch_reg(ra_reg, rb_reg, Cc::AE, *offset as u32, next_pc, pc);
                }
            }
            Opcode::BranchGeS => {
                if let Args::TwoRegOffset { ra, rb, offset } = args {
                    let (ra_reg, rb_reg) = (REG_MAP[*ra], REG_MAP[*rb]);
                    self.emit_branch_reg(ra_reg, rb_reg, Cc::GE, *offset as u32, next_pc, pc);
                }
            }

            // === A.5.12: Two registers + two immediates ===
            Opcode::LoadImmJumpInd => {
                if let Args::TwoRegTwoImm {
                    ra,
                    rb,
                    imm_x,
                    imm_y,
                } = args
                {
                    // GP: registers[ra] = imm_x, addr = registers[rb] + imm_y
                    // Per GP semantics, ra is written first, then jump uses the
                    // (possibly updated) rb value.
                    // If ra==rb, the jump target uses imm_x + imm_y.
                    self.asm.mov_ri64(REG_MAP[*ra], *imm_x);
                    self.emit_dynamic_jump(*rb, *imm_y, pc);
                }
            }

            // === A.5.13: Three registers ===
            Opcode::Add32 => {
                self.emit_alu3_32(args, |a, d, s| {
                    a.add_rr32(d, s);
                });
            }
            Opcode::Sub32 => {
                self.emit_alu3_32_sub(args);
            }
            Opcode::Mul32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let (d, a, b) = (REG_MAP[*rd], REG_MAP[*ra], REG_MAP[*rb]);
                    if *rd == *rb && *rd != *ra {
                        self.asm.mov_rr(SCRATCH, b);
                        self.asm.mov_rr(d, a);
                        self.asm.imul_rr32(d, SCRATCH);
                    } else {
                        if *rd != *ra {
                            self.asm.mov_rr(d, a);
                        }
                        self.asm.imul_rr32(d, b);
                    }
                    self.asm.movsxd(d, d);
                }
            }
            Opcode::Add64 => {
                self.emit_alu3_64_comm(args, true, |a, d, s| {
                    a.add_rr(d, s);
                });
                // Track CF: after add64 D, A, B, CF = overflow(A+B).
                // A subsequent setLtU C, D, A (or D, B) can use CF directly.
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.last_add_cf = Some((*rd, *ra, *rb));
                }
                // reg_defs tracking handled by update_reg_defs() in main loop
            }
            Opcode::Sub64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let (d, a, b) = (REG_MAP[*rd], REG_MAP[*ra], REG_MAP[*rb]);
                    if *rd == *rb && *rd != *ra {
                        // d = a - d: neg d; add d, a (6 bytes vs 9 bytes)
                        self.asm.neg64(d);
                        self.asm.add_rr(d, a);
                    } else {
                        if *rd != *ra {
                            self.asm.mov_rr(d, a);
                        }
                        self.asm.sub_rr(d, b);
                    }
                }
            }
            Opcode::Mul64 => {
                self.emit_alu3_64_comm(args, true, |a, d, s| {
                    a.imul_rr(d, s);
                });
            }
            Opcode::And => {
                self.emit_alu3_64_comm(args, true, |a, d, s| {
                    a.and_rr(d, s);
                });
            }
            Opcode::Or => {
                self.emit_alu3_64_comm(args, true, |a, d, s| {
                    a.or_rr(d, s);
                });
            }
            Opcode::Xor => {
                self.emit_alu3_64_comm(args, true, |a, d, s| {
                    a.xor_rr(d, s);
                });
            }

            // Division (32-bit and 64-bit)
            Opcode::DivU32 => {
                self.emit_div(args, false, false, true);
            }
            Opcode::DivS32 => {
                self.emit_div(args, true, false, true);
            }
            Opcode::RemU32 => {
                self.emit_div(args, false, true, true);
            }
            Opcode::RemS32 => {
                self.emit_div(args, true, true, true);
            }
            Opcode::DivU64 => {
                self.emit_div(args, false, false, false);
            }
            Opcode::DivS64 => {
                self.emit_div(args, true, false, false);
            }
            Opcode::RemU64 => {
                self.emit_div(args, false, true, false);
            }
            Opcode::RemS64 => {
                self.emit_div(args, true, true, false);
            }

            // Shifts (three-register)
            // Note: when rd==rb, we must save rb to SCRATCH before mov rd, ra.
            Opcode::ShloL32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let (d, a, b) = (REG_MAP[*rd], REG_MAP[*ra], REG_MAP[*rb]);
                    let shift_src = if *rd == *rb && *rd != *ra {
                        self.asm.mov_rr(SCRATCH, b);
                        SCRATCH
                    } else {
                        b
                    };
                    if *rd != *ra {
                        self.asm.mov_rr(d, a);
                    }
                    self.emit_shift_by_reg32(d, shift_src, 4);
                    self.asm.movsxd(d, d);
                }
            }
            Opcode::ShloR32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let (d, a, b) = (REG_MAP[*rd], REG_MAP[*ra], REG_MAP[*rb]);
                    let shift_src = if *rd == *rb && *rd != *ra {
                        self.asm.mov_rr(SCRATCH, b);
                        SCRATCH
                    } else {
                        b
                    };
                    if *rd != *ra {
                        self.asm.mov_rr(d, a);
                    }
                    self.asm.movzx_32_64(d, d);
                    self.emit_shift_by_reg32(d, shift_src, 5);
                    self.asm.movsxd(d, d);
                }
            }
            Opcode::SharR32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let (d, a, b) = (REG_MAP[*rd], REG_MAP[*ra], REG_MAP[*rb]);
                    let shift_src = if *rd == *rb && *rd != *ra {
                        self.asm.mov_rr(SCRATCH, b);
                        SCRATCH
                    } else {
                        b
                    };
                    if *rd != *ra {
                        self.asm.mov_rr(d, a);
                    }
                    self.emit_shift_by_reg32(d, shift_src, 7);
                    self.asm.movsxd(d, d);
                }
            }
            Opcode::ShloL64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let (d, a, b) = (REG_MAP[*rd], REG_MAP[*ra], REG_MAP[*rb]);
                    let shift_src = if *rd == *rb && *rd != *ra {
                        self.asm.mov_rr(SCRATCH, b);
                        SCRATCH
                    } else {
                        b
                    };
                    if *rd != *ra {
                        self.asm.mov_rr(d, a);
                    }
                    self.emit_shift_by_reg64(d, shift_src, 4);
                }
            }
            Opcode::ShloR64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let (d, a, b) = (REG_MAP[*rd], REG_MAP[*ra], REG_MAP[*rb]);
                    let shift_src = if *rd == *rb && *rd != *ra {
                        self.asm.mov_rr(SCRATCH, b);
                        SCRATCH
                    } else {
                        b
                    };
                    if *rd != *ra {
                        self.asm.mov_rr(d, a);
                    }
                    self.emit_shift_by_reg64(d, shift_src, 5);
                }
            }
            Opcode::SharR64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let (d, a, b) = (REG_MAP[*rd], REG_MAP[*ra], REG_MAP[*rb]);
                    let shift_src = if *rd == *rb && *rd != *ra {
                        self.asm.mov_rr(SCRATCH, b);
                        SCRATCH
                    } else {
                        b
                    };
                    if *rd != *ra {
                        self.asm.mov_rr(d, a);
                    }
                    self.emit_shift_by_reg64(d, shift_src, 7);
                }
            }

            // Multiply upper
            Opcode::MulUpperSS => {
                self.emit_mul_upper(args, true, true);
            }
            Opcode::MulUpperUU => {
                self.emit_mul_upper(args, false, false);
            }
            Opcode::MulUpperSU => {
                self.emit_mul_upper(args, true, false);
            }

            // Set comparisons (three-register)
            Opcode::SetLtU => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    // Carry flag fusion: if the previous instruction was add64 D, A, B,
                    // and this is setLtU where rd = (ra < rb), CF already holds the carry.
                    // Pattern: ra == D (the sum), rb == A or B (one of the addends).
                    // Result goes to rd (the carry register).
                    let fused = if let Some((add_d, add_a, add_b)) = self.last_add_cf {
                        // Carry flag fusion: ra must be the sum register (add_d),
                        // and rb must be an UNMODIFIED original addend (not add_d,
                        // which now holds the sum). If rb == add_d, both sides of
                        // the comparison would be the sum, giving 0 always, but CF
                        // might be 1.
                        if *ra == add_d
                            && *rb != add_d
                            && (*rb == add_a || *rb == add_b)
                            && *rd != *rb
                        {
                            let d = REG_MAP[*rd];
                            // CF is valid from the add — use setb directly (no cmp needed).
                            // Cannot use xor to clear upper bits (it would clobber CF).
                            // Instead: setb + movzx (2 insns vs xor+cmp+setb = 3 insns).
                            self.asm.setcc(Cc::B, d);
                            self.asm.movzx_8_64(d, d);
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    };
                    if !fused {
                        self.emit_setcc_3reg(*ra, *rb, *rd, Cc::B);
                    }
                }
            }
            Opcode::SetLtS => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.emit_setcc_3reg(*ra, *rb, *rd, Cc::L);
                }
            }

            // Conditional moves
            Opcode::CmovIz => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    // if φ[rb] == 0 then φ[rd] = φ[ra]
                    self.asm.test_rr(REG_MAP[*rb], REG_MAP[*rb]);
                    self.asm.cmovcc(Cc::E, REG_MAP[*rd], REG_MAP[*ra]);
                }
            }
            Opcode::CmovNz => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.asm.test_rr(REG_MAP[*rb], REG_MAP[*rb]);
                    self.asm.cmovcc(Cc::NE, REG_MAP[*rd], REG_MAP[*ra]);
                }
            }

            // Rotates (three-register)
            Opcode::RotL64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let (d, a, b) = (REG_MAP[*rd], REG_MAP[*ra], REG_MAP[*rb]);
                    let shift_src = if *rd == *rb && *rd != *ra {
                        self.asm.mov_rr(SCRATCH, b);
                        SCRATCH
                    } else {
                        b
                    };
                    if *rd != *ra {
                        self.asm.mov_rr(d, a);
                    }
                    self.emit_shift_by_reg64(d, shift_src, 0); // ROL
                }
            }
            Opcode::RotL32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let (d, a, b) = (REG_MAP[*rd], REG_MAP[*ra], REG_MAP[*rb]);
                    let shift_src = if *rd == *rb && *rd != *ra {
                        self.asm.mov_rr(SCRATCH, b);
                        SCRATCH
                    } else {
                        b
                    };
                    if *rd != *ra {
                        self.asm.mov_rr(d, a);
                    }
                    self.asm.movzx_32_64(d, d);
                    self.emit_shift_by_reg32(d, shift_src, 0);
                    self.asm.movsxd(d, d);
                }
            }
            Opcode::RotR64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let (d, a, b) = (REG_MAP[*rd], REG_MAP[*ra], REG_MAP[*rb]);
                    let shift_src = if *rd == *rb && *rd != *ra {
                        self.asm.mov_rr(SCRATCH, b);
                        SCRATCH
                    } else {
                        b
                    };
                    if *rd != *ra {
                        self.asm.mov_rr(d, a);
                    }
                    self.emit_shift_by_reg64(d, shift_src, 1); // ROR
                }
            }
            Opcode::RotR32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let (d, a, b) = (REG_MAP[*rd], REG_MAP[*ra], REG_MAP[*rb]);
                    let shift_src = if *rd == *rb && *rd != *ra {
                        self.asm.mov_rr(SCRATCH, b);
                        SCRATCH
                    } else {
                        b
                    };
                    if *rd != *ra {
                        self.asm.mov_rr(d, a);
                    }
                    self.asm.movzx_32_64(d, d);
                    self.emit_shift_by_reg32(d, shift_src, 1);
                    self.asm.movsxd(d, d);
                }
            }

            // Logical with invert
            Opcode::AndInv => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    // rd = ra & ~rb
                    self.asm.mov_rr(SCRATCH, REG_MAP[*rb]);
                    self.asm.not64(SCRATCH);
                    self.asm.mov_rr(REG_MAP[*rd], REG_MAP[*ra]);
                    self.asm.and_rr(REG_MAP[*rd], SCRATCH);
                }
            }
            Opcode::OrInv => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    // rd = ra | ~rb
                    self.asm.mov_rr(SCRATCH, REG_MAP[*rb]);
                    self.asm.not64(SCRATCH);
                    self.asm.mov_rr(REG_MAP[*rd], REG_MAP[*ra]);
                    self.asm.or_rr(REG_MAP[*rd], SCRATCH);
                }
            }
            Opcode::Xnor => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    // rd = ~(ra ^ rb)
                    let (d, a, b) = (REG_MAP[*rd], REG_MAP[*ra], REG_MAP[*rb]);
                    if *rd == *rb && *rd != *ra {
                        self.asm.mov_rr(SCRATCH, b);
                        self.asm.mov_rr(d, a);
                        self.asm.xor_rr(d, SCRATCH);
                    } else {
                        if *rd != *ra {
                            self.asm.mov_rr(d, a);
                        }
                        self.asm.xor_rr(d, b);
                    }
                    self.asm.not64(REG_MAP[*rd]);
                }
            }

            // Min/Max
            Opcode::Max => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let (d, a, b) = (REG_MAP[*rd], REG_MAP[*ra], REG_MAP[*rb]);
                    self.asm.cmp_rr(a, b);
                    if *rd == *rb && *rd != *ra {
                        self.asm.mov_rr(SCRATCH, b);
                        self.asm.mov_rr(d, a);
                        self.asm.cmovcc(Cc::L, d, SCRATCH);
                    } else {
                        if *rd != *ra {
                            self.asm.mov_rr(d, a);
                        }
                        self.asm.cmovcc(Cc::L, d, b);
                    }
                }
            }
            Opcode::MaxU => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let (d, a, b) = (REG_MAP[*rd], REG_MAP[*ra], REG_MAP[*rb]);
                    self.asm.cmp_rr(a, b);
                    if *rd == *rb && *rd != *ra {
                        self.asm.mov_rr(SCRATCH, b);
                        self.asm.mov_rr(d, a);
                        self.asm.cmovcc(Cc::B, d, SCRATCH);
                    } else {
                        if *rd != *ra {
                            self.asm.mov_rr(d, a);
                        }
                        self.asm.cmovcc(Cc::B, d, b);
                    }
                }
            }
            Opcode::Min => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let (d, a, b) = (REG_MAP[*rd], REG_MAP[*ra], REG_MAP[*rb]);
                    self.asm.cmp_rr(a, b);
                    if *rd == *rb && *rd != *ra {
                        self.asm.mov_rr(SCRATCH, b);
                        self.asm.mov_rr(d, a);
                        self.asm.cmovcc(Cc::G, d, SCRATCH);
                    } else {
                        if *rd != *ra {
                            self.asm.mov_rr(d, a);
                        }
                        self.asm.cmovcc(Cc::G, d, b);
                    }
                }
            }
            Opcode::MinU => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let (d, a, b) = (REG_MAP[*rd], REG_MAP[*ra], REG_MAP[*rb]);
                    self.asm.cmp_rr(a, b);
                    if *rd == *rb && *rd != *ra {
                        self.asm.mov_rr(SCRATCH, b);
                        self.asm.mov_rr(d, a);
                        self.asm.cmovcc(Cc::A, d, SCRATCH);
                    } else {
                        if *rd != *ra {
                            self.asm.mov_rr(d, a);
                        }
                        self.asm.cmovcc(Cc::A, d, b);
                    }
                }
            }
        }
    }

    // === Helper emission methods ===

    /// Emit a static branch (validated at compile time).
    fn emit_static_branch(&mut self, target: u32, condition: bool, _fallthrough: u32, pc: u32) {
        if !condition {
            return;
        }
        if !self.is_basic_block_start(target) {
            self.asm.mov_store32_imm(CTX, CTX_PC, pc as i32);
            self.emit_exit(EXIT_PANIC, 0);
            return;
        }
        let label = self.label_for_pc(target);
        self.asm.jmp_label(label);
    }

    /// Emit a dynamic jump (through jump table).
    fn emit_dynamic_jump(&mut self, ra: usize, imm: u64, pc: u32) {
        // Store PC for any exit path in the dynamic jump sequence
        self.asm.mov_store32_imm(CTX, CTX_PC, pc as i32);
        // addr = (φ[ra] + imm) % 2^32
        self.asm.mov_rr(SCRATCH, REG_MAP[ra]);
        if imm as i32 != 0 {
            self.asm.add_ri(SCRATCH, imm as i32);
        }
        self.asm.movzx_32_64(SCRATCH, SCRATCH); // truncate to 32-bit

        // Check halt address: 2^32 - 2^16 = 0xFFFF0000
        // SCRATCH already has the 32-bit zero-extended address.
        // Use a 32-bit CMP (without REX.W) so the immediate is not sign-extended to 64 bits.
        self.asm.cmp_ri32(SCRATCH, 0xFFFF0000u32 as i32);
        let not_halt = self.asm.new_label();
        self.asm.jcc_label(Cc::NE, not_halt);
        self.emit_exit(EXIT_HALT, 0);
        self.asm.bind_label(not_halt);

        // For dynamic jumps, we save state and return to the host to handle
        // (the host will validate and dispatch). This is simpler than inlining
        // the full jump table lookup. Exit with a special "dynamic jump" that
        // stores the target address.
        // We use EXIT_PANIC as default and let the caller handle djump.
        // Actually, let's inline it for performance:

        // Check alignment: addr must be even and non-zero
        // addr == 0 → panic
        self.asm.test_rr(SCRATCH, SCRATCH);
        self.asm.jcc_label(Cc::E, self.panic_label);

        // idx = addr/2 - 1 (also checks alignment: bit 0 goes to CF via SHR)
        self.asm.shr_ri64(SCRATCH, 1); // CF = bit 0 (alignment)
        self.asm.jcc_label(Cc::B, self.panic_label); // odd addr → panic (B = carry set)
        self.asm.sub_ri(SCRATCH, 1);

        // Inline djump resolution: idx is in SCRATCH (RDX).
        // Bounds check: idx < jt_len
        self.asm.cmp_mem32_r(CTX, CTX_JT_LEN, SCRATCH);
        self.asm.jcc_label(Cc::BE, self.panic_label); // jt_len <= idx → panic

        // target_pc = jt_ptr[idx] (u32 array, need idx*4)
        self.asm.push(Reg::RAX); // save φ[11]
        self.asm.shl_ri64(SCRATCH, 2); // idx *= 4
        self.asm.mov_load64(Reg::RAX, CTX, CTX_JT_PTR);
        self.asm.add_rr(Reg::RAX, SCRATCH);
        self.asm.mov_load32(SCRATCH, Reg::RAX, 0); // SCRATCH = jt_ptr[idx]

        // Validate: target_pc < bb_len && bb_starts[target_pc] == 1
        let djump_panic = self.asm.new_label();
        self.asm.cmp_mem32_r(CTX, CTX_BB_LEN, SCRATCH);
        self.asm.jcc_label(Cc::BE, djump_panic); // bb_len <= target → panic
        self.asm.mov_load64(Reg::RAX, CTX, CTX_BB_STARTS);
        self.asm.movzx_load8_sib(Reg::RAX, Reg::RAX, SCRATCH);
        self.asm.cmp_ri32(Reg::RAX, 1);
        self.asm.jcc_label(Cc::NE, djump_panic);

        // Dispatch: native_addr = code_base + dispatch_table[target_pc]
        self.asm.mov_load64(Reg::RAX, CTX, CTX_DISPATCH_TABLE);
        self.asm.movsxd_load_sib4(Reg::RAX, Reg::RAX, SCRATCH);
        self.asm.add_r64_mem(Reg::RAX, CTX, CTX_CODE_BASE);
        // Store target PC for gas block tracking
        self.asm.mov_store32(CTX, CTX_PC, SCRATCH);
        // RAX = native addr, [rsp] = saved φ[11].
        // Use SCRATCH (which we no longer need) to swap.
        self.asm.mov_rr(SCRATCH, Reg::RAX); // SCRATCH = native addr
        self.asm.pop(Reg::RAX); // restore φ[11]
        self.asm.jmp_reg(SCRATCH); // jump to native addr

        self.asm.bind_label(djump_panic);
        self.asm.pop(Reg::RAX); // restore φ[11] before panicking
        self.asm.jmp_label(self.panic_label);
    }

    /// Emit setcc for three-register comparisons: rd = (ra CMP rb) ? 1 : 0.
    /// When rd != ra and rd != rb, uses xor+cmp+setcc (eliminates movzx).
    fn emit_setcc_3reg(&mut self, ra: usize, rb: usize, rd: usize, cc: Cc) {
        let (a, b, d) = (REG_MAP[ra], REG_MAP[rb], REG_MAP[rd]);
        if rd != ra && rd != rb {
            // xor clears upper bits; setcc writes only the low byte.
            self.asm.mov_ri64(d, 0); // xor r32,r32 (via mov_ri64 zero optimization)
            self.asm.cmp_rr(a, b);
            self.asm.setcc(cc, d);
        } else {
            self.asm.cmp_rr(a, b);
            self.asm.setcc(cc, d);
            self.asm.movzx_8_64(d, d);
        }
    }

    /// Emit setcc for immediate comparisons: ra = (rb CMP imm) ? 1 : 0.
    /// When ra != rb, uses xor+cmp+setcc (eliminates movzx).
    fn emit_setcc_imm(&mut self, ra: usize, rb: usize, imm: u64, cc: Cc) {
        let (a, b) = (REG_MAP[ra], REG_MAP[rb]);
        if ra != rb {
            self.asm.mov_ri64(a, 0); // xor r32,r32
            self.emit_cmp_imm(b, imm);
            self.asm.setcc(cc, a);
        } else {
            self.emit_cmp_imm(b, imm);
            self.asm.setcc(cc, a);
            self.asm.movzx_8_64(a, a);
        }
    }

    /// Compare register against immediate, using cmp_ri for i32-range values.
    fn emit_cmp_imm(&mut self, reg: Reg, imm: u64) {
        let imm_i64 = imm as i64;
        if imm_i64 >= i32::MIN as i64 && imm_i64 <= i32::MAX as i64 {
            self.asm.cmp_ri(reg, imm_i64 as i32);
        } else {
            self.asm.mov_ri64(SCRATCH, imm);
            self.asm.cmp_rr(reg, SCRATCH);
        }
    }

    /// Emit a branch comparing register against immediate.
    fn emit_branch_imm(
        &mut self,
        reg: Reg,
        imm: u64,
        cc: Cc,
        target: u32,
        _fallthrough: u32,
        pc: u32,
    ) {
        if !self.is_basic_block_start(target) {
            // Target not valid → store PC and panic if condition true (cold path)
            self.asm.mov_store32_imm(CTX, CTX_PC, pc as i32);
            self.asm.mov_ri64(SCRATCH, imm);
            self.asm.cmp_rr(reg, SCRATCH);
            self.asm.jcc_label(cc, self.panic_label);
            return;
        }
        self.emit_cmp_imm(reg, imm);
        let label = self.label_for_pc(target);
        self.asm.jcc_label(cc, label);
    }

    /// Emit a branch comparing two registers.
    fn emit_branch_reg(&mut self, a: Reg, b: Reg, cc: Cc, target: u32, _fallthrough: u32, pc: u32) {
        if !self.is_basic_block_start(target) {
            self.asm.mov_store32_imm(CTX, CTX_PC, pc as i32);
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
    fn emit_shift_by_reg32(&mut self, dst: Reg, shift_reg: Reg, shift_op: u8) {
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

    fn emit_shift_by_reg64(&mut self, dst: Reg, shift_reg: Reg, shift_op: u8) {
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

    /// Three-register 64-bit ALU: rd = ra OP rb
    #[allow(dead_code)]
    fn emit_alu3_64(&mut self, args: &Args, op: impl FnOnce(&mut Assembler, Reg, Reg)) {
        self.emit_alu3_64_comm(args, false, op);
    }

    /// Three-register 64-bit ALU with optional commutativity optimization.
    /// When `commutative` is true and rd == rb, emit `op(d, a)` directly
    /// instead of saving/restoring via SCRATCH.
    fn emit_alu3_64_comm(
        &mut self,
        args: &Args,
        commutative: bool,
        op: impl FnOnce(&mut Assembler, Reg, Reg),
    ) {
        if let Args::ThreeReg { ra, rb, rd } = args {
            let d = REG_MAP[*rd];
            let a = REG_MAP[*ra];
            let b = REG_MAP[*rb];
            if *rd == *ra {
                op(&mut self.asm, d, b);
            } else if *rd == *rb && commutative {
                // Commutative: rd = rb OP ra = ra OP rb — just op(d, a)
                op(&mut self.asm, d, a);
            } else if *rd == *rb {
                self.asm.mov_rr(SCRATCH, b);
                self.asm.mov_rr(d, a);
                op(&mut self.asm, d, SCRATCH);
            } else {
                self.asm.mov_rr(d, a);
                op(&mut self.asm, d, b);
            }
        }
    }

    /// Three-register 32-bit ALU with sign extension: rd = sx32(ra OP rb)
    fn emit_alu3_32(&mut self, args: &Args, op: impl FnOnce(&mut Assembler, Reg, Reg)) {
        if let Args::ThreeReg { ra, rb, rd } = args {
            let d = REG_MAP[*rd];
            let a = REG_MAP[*ra];
            let b = REG_MAP[*rb];
            if *rd == *ra {
                op(&mut self.asm, d, b);
            } else if *rd == *rb {
                self.asm.mov_rr(SCRATCH, b);
                self.asm.mov_rr(d, a);
                op(&mut self.asm, d, SCRATCH);
            } else {
                self.asm.mov_rr(d, a);
                op(&mut self.asm, d, b);
            }
            self.asm.movsxd(d, d);
        }
    }

    fn emit_alu3_32_sub(&mut self, args: &Args) {
        if let Args::ThreeReg { ra, rb, rd } = args {
            let d = REG_MAP[*rd];
            let a = REG_MAP[*ra];
            let b = REG_MAP[*rb];
            if *rd == *ra {
                self.asm.sub_rr32(d, b);
            } else if *rd == *rb {
                // d = a - d: neg32 d; add32 d, a (6 bytes vs 9 bytes)
                self.asm.neg32(d);
                self.asm.add_rr32(d, a);
            } else {
                self.asm.mov_rr(d, a);
                self.asm.sub_rr32(d, b);
            }
            self.asm.movsxd(d, d);
        }
    }

    /// Division/remainder.
    ///
    /// x86 DIV/IDIV: dividend in RDX:RAX, divisor in any GPR except RAX/RDX.
    /// Quotient → RAX, remainder → RDX. Only RAX and RDX are clobbered.
    ///
    /// Key insight: RDX = SCRATCH (not mapped to any PVM register), so it never
    /// needs saving/restoring. When b_reg != RAX (~92% of cases), we use b_reg
    /// directly as the divisor — DIV/IDIV does not clobber the operand register,
    /// so no save of RCX (φ[12]) is needed either. Only RAX (φ[11]) must be
    /// preserved (unless d_reg == RAX).
    fn emit_div(&mut self, args: &Args, signed: bool, remainder: bool, is_32bit: bool) {
        if let Args::ThreeReg { ra, rb, rd } = args {
            let a_reg = REG_MAP[*ra];
            let b_reg = REG_MAP[*rb];
            let d_reg = REG_MAP[*rd];

            // Check divisor == 0
            self.asm.test_rr(b_reg, b_reg);
            let nonzero = self.asm.new_label();
            let done = self.asm.new_label();
            self.asm.jcc_label(Cc::NE, nonzero);

            // Division by zero: quotient = 2^64-1, remainder = dividend
            if remainder {
                self.asm.mov_rr(d_reg, a_reg);
            } else {
                self.asm.mov_ri64(d_reg, u64::MAX);
                if is_32bit {
                    self.asm.movsxd(d_reg, d_reg);
                }
            }
            self.asm.jmp_label(done);

            self.asm.bind_label(nonzero);

            if b_reg != Reg::RAX {
                // Fast path: use b_reg directly as divisor (no extra register needed).
                // Only save RAX (φ[11]) if the result doesn't go there.
                self.emit_div_fast(a_reg, b_reg, d_reg, signed, remainder, is_32bit);
            } else {
                // b_reg == RAX: divisor is in RAX, but we need RAX for the dividend.
                // Move divisor to RCX; save both RAX (φ[11]) and RCX (φ[12]).
                self.emit_div_b_is_rax(a_reg, d_reg, signed, remainder, is_32bit);
            }

            if is_32bit {
                self.asm.movsxd(d_reg, d_reg);
            }

            self.asm.bind_label(done);
        }
    }

    /// Division fast path: b_reg is not RAX, so we use it directly as the divisor.
    /// DIV/IDIV does not clobber the operand register, so only RAX needs saving.
    fn emit_div_fast(
        &mut self,
        a_reg: Reg,
        b_reg: Reg,
        d_reg: Reg,
        signed: bool,
        remainder: bool,
        is_32bit: bool,
    ) {
        let save_rax = d_reg != Reg::RAX;

        if save_rax {
            self.asm.push(Reg::RAX);
        }

        // Load dividend into RAX (push doesn't modify RAX, so a_reg==RAX is fine).
        if a_reg != Reg::RAX {
            self.asm.mov_rr(Reg::RAX, a_reg);
        }

        // Set up RDX and divide.
        self.emit_div_setup_and_exec(signed, is_32bit, b_reg);

        if save_rax {
            // d_reg != RAX: move result, then restore φ[11].
            let result_reg = if remainder { SCRATCH } else { Reg::RAX };
            self.asm.mov_rr(d_reg, result_reg);
            self.asm.pop(Reg::RAX);
        } else {
            // d_reg == RAX: quotient is already there; for remainder, move RDX → RAX.
            if remainder {
                self.asm.mov_rr(Reg::RAX, SCRATCH);
            }
        }
    }

    /// Division slow path: b_reg == RAX (divisor is φ[11]).
    /// We must move the divisor to RCX before loading the dividend into RAX.
    fn emit_div_b_is_rax(
        &mut self,
        a_reg: Reg,
        d_reg: Reg,
        signed: bool,
        remainder: bool,
        is_32bit: bool,
    ) {
        // Always save RAX and RCX so we can restore both PVM registers.
        self.asm.push(Reg::RAX); // save φ[11]
        self.asm.push(Reg::RCX); // save φ[12]
        // Stack: [RSP+0]=old_RCX, [RSP+8]=old_RAX

        // Move divisor (currently in RAX) to RCX.
        // (push doesn't modify RAX, so it still holds the divisor.)
        self.asm.mov_rr(Reg::RCX, Reg::RAX);

        // Load dividend into RAX.
        if a_reg == Reg::RAX {
            // Dividend is also φ[11] — RAX still holds it (mov_rr above
            // copied RAX→RCX but didn't change RAX). Nothing to do.
        } else if a_reg == Reg::RCX {
            // We just overwrote RCX with the divisor; load original φ[12] from stack.
            self.asm.mov_load64(Reg::RAX, Reg::RSP, 0); // old_RCX
        } else {
            self.asm.mov_rr(Reg::RAX, a_reg);
        }

        // Set up RDX and divide.
        self.emit_div_setup_and_exec(signed, is_32bit, Reg::RCX);

        // Place result and restore saved registers.
        let result_reg = if remainder { SCRATCH } else { Reg::RAX };

        if d_reg == Reg::RAX {
            if remainder {
                self.asm.mov_rr(Reg::RAX, SCRATCH);
            }
            self.asm.pop(Reg::RCX); // restore φ[12]
            self.asm.pop(SCRATCH); // discard saved RAX (d_reg overwrites φ[11])
        } else if d_reg == Reg::RCX {
            self.asm.mov_rr(Reg::RCX, result_reg);
            self.asm.pop(SCRATCH); // discard saved RCX (d_reg overwrites φ[12])
            self.asm.pop(Reg::RAX); // restore φ[11]
        } else {
            self.asm.mov_rr(d_reg, result_reg);
            self.asm.pop(Reg::RCX); // restore φ[12]
            self.asm.pop(Reg::RAX); // restore φ[11]
        }
    }

    /// Emit RDX setup (sign-extend or zero) and the DIV/IDIV instruction.
    fn emit_div_setup_and_exec(&mut self, signed: bool, is_32bit: bool, divisor: Reg) {
        if is_32bit {
            if signed {
                self.asm.movsxd(Reg::RAX, Reg::RAX);
                self.asm.cdq();
                self.asm.idiv32(divisor);
            } else {
                self.asm.movzx_32_64(Reg::RAX, Reg::RAX);
                self.asm.mov_ri64(SCRATCH, 0);
                self.asm.div32(divisor);
            }
        } else if signed {
            self.asm.cqo();
            self.asm.idiv64(divisor);
        } else {
            self.asm.mov_ri64(SCRATCH, 0);
            self.asm.div64(divisor);
        }
    }

    /// Multiply upper (128-bit product, take high 64 bits).
    ///
    /// MUL/IMUL uses RAX (φ[11]) and RDX (SCRATCH) implicitly.
    /// RDX = SCRATCH is not a PVM register, so only RAX needs saving.
    fn emit_mul_upper(&mut self, args: &Args, a_signed: bool, b_signed: bool) {
        if let Args::ThreeReg { ra, rb, rd } = args {
            let d_reg = REG_MAP[*rd];
            let rb_is_rax = REG_MAP[*rb] == Reg::RAX;
            // We need to preserve φ[11] (RAX) unless d_reg is RAX AND rb != RAX
            // (if rb == RAX, we always push so we can recover the original value).
            let save_rax = d_reg != Reg::RAX || rb_is_rax;

            if save_rax {
                self.asm.push(Reg::RAX); // save φ[11]
            }

            // Load ra into RAX (push doesn't modify RAX).
            if REG_MAP[*ra] != Reg::RAX {
                self.asm.mov_rr(Reg::RAX, REG_MAP[*ra]);
            }

            // Determine mul_src: the register holding rb's value.
            let mul_src = if rb_is_rax {
                // rb is φ[11] = RAX; original value is on stack.
                self.asm.mov_load64(SCRATCH, Reg::RSP, 0);
                SCRATCH
            } else {
                REG_MAP[*rb]
            };

            if a_signed && b_signed {
                self.asm.imul_rdx_rax(mul_src);
            } else if !a_signed && !b_signed {
                self.asm.mul_rdx_rax(mul_src);
            } else {
                // MulUpperSU: ra is signed, rb is unsigned
                // result_hi = unsigned_mul_hi(ra, rb) - (ra < 0 ? rb : 0)
                self.asm.push(mul_src); // save rb
                self.asm.push(Reg::RAX); // save ra (for sign check)
                if rb_is_rax {
                    // mul_src was SCRATCH (loaded from stack); reload after pushes.
                    // orig_RAX is now at [RSP + 16] (ra push + rb push above it).
                    self.asm.mov_load64(SCRATCH, Reg::RSP, 16);
                    self.asm.mul_rdx_rax(SCRATCH);
                } else {
                    self.asm.mul_rdx_rax(mul_src);
                }
                // RDX = high bits. Check if original ra was negative.
                self.asm.pop(Reg::RAX); // pop saved ra
                let skip = self.asm.new_label();
                self.asm.test_rr(Reg::RAX, Reg::RAX);
                self.asm.jcc_label(Cc::NS, skip);
                // ra was negative: subtract rb from high word (RDX)
                self.asm.pop(Reg::RAX); // pop saved rb
                self.asm.sub_rr(SCRATCH, Reg::RAX);
                let done = self.asm.new_label();
                self.asm.jmp_label(done);
                self.asm.bind_label(skip);
                self.asm.add_ri(Reg::RSP, 8); // discard saved rb
                self.asm.bind_label(done);
            }

            // High 64 bits are in RDX (SCRATCH).
            if save_rax {
                if d_reg == Reg::RAX {
                    // rb_is_rax case: we saved RAX for rb recovery but d_reg is also RAX.
                    // Discard the saved value and put result in RAX.
                    self.asm.add_ri(Reg::RSP, 8);
                    self.asm.mov_rr(Reg::RAX, SCRATCH);
                } else {
                    self.asm.mov_rr(d_reg, SCRATCH);
                    self.asm.pop(Reg::RAX); // restore φ[11]
                }
            } else {
                // d_reg == RAX and !rb_is_rax → didn't save RAX.
                self.asm.mov_rr(Reg::RAX, SCRATCH);
            }
        }
    }

    /// Emit an exit sequence that sets exit_reason and exit_arg.
    fn emit_exit(&mut self, reason: u32, arg: u32) {
        self.asm
            .mov_store32_imm(CTX, CTX_EXIT_REASON, reason as i32);
        self.asm.mov_store32_imm(CTX, CTX_EXIT_ARG, arg as i32);
        self.asm.jmp_label(self.exit_label);
    }

    /// Emit prologue: save callee-saved, load PVM registers from context,
    /// then dispatch to the correct basic block based on entry_pc.
    fn emit_prologue(&mut self) {
        self.asm.ensure_capacity(512); // prologue needs ~200 bytes
        // Save callee-saved registers
        self.asm.push(Reg::RBX);
        self.asm.push(Reg::RBP);
        self.asm.push(Reg::R12);
        self.asm.push(Reg::R13);
        self.asm.push(Reg::R14);
        self.asm.push(Reg::R15);

        // Stack alignment: after 6 callee-saved pushes + return address (7 * 8 = 56),
        // RSP mod 16 = 8. With save_caller_saved (8 pushes = 64 bytes), total
        // displacement = 56 + 64 = 120, RSP mod 16 = 8. Push extra 8 bytes for
        // alignment so that save_caller_saved leaves RSP mod 16 = 0 for CALL.
        self.asm.push(SCRATCH); // alignment padding

        // RDI = JitContext pointer. R15 = guest memory base = RDI + CTX_OFFSET.
        self.asm.lea(CTX, Reg::RDI, CTX_OFFSET);

        // Clear exit reason
        self.asm.mov_store32_imm(CTX, CTX_EXIT_REASON, 0);

        // --- O(1) dispatch via table lookup (before loading PVM regs) ---
        self.asm.mov_load32(SCRATCH, CTX, CTX_ENTRY_PC);
        self.asm.mov_load64(Reg::RAX, CTX, CTX_DISPATCH_TABLE);
        self.asm.movsxd_load_sib4(Reg::RAX, Reg::RAX, SCRATCH);
        self.asm.mov_load64(SCRATCH, CTX, CTX_CODE_BASE);
        self.asm.add_rr(Reg::RAX, SCRATCH);
        self.asm.push(Reg::RAX);

        // Load all 13 PVM registers from context
        for (i, &reg) in REG_MAP.iter().enumerate() {
            self.asm.mov_load64(reg, CTX, CTX_REGS + (i as i32) * 8);
        }

        // Jump to the dispatch target (pop into SCRATCH, then indirect jump)
        self.asm.pop(SCRATCH);
        self.asm.jmp_reg(SCRATCH);
    }

    /// Emit exit sequences and epilogue.
    fn emit_exit_sequences(&mut self) {
        // Reserve capacity for exit sequences + all OOG/fault stubs.
        // Each OOG stub is ~12 bytes, each fault stub is ~10 bytes.
        let needed = 512 + self.oog_stubs.len() * 16 + self.fault_stubs.len() * 16;
        self.asm.ensure_capacity(needed);
        // Shared OOG handler that reads PC from SCRATCH — emitted BEFORE OOG
        // stubs so backward jumps from stubs can use jmp rel8 (2 bytes).
        self.asm.bind_label(self.oog_pc_label);
        self.asm.mov_store32(CTX, CTX_PC, SCRATCH);
        // fall through to oog_label:
        self.asm.bind_label(self.oog_label);
        self.asm
            .mov_store32_imm(CTX, CTX_EXIT_REASON, EXIT_OOG as i32);
        self.asm.jmp_label(self.exit_label);

        // Per-gas-block OOG stubs: compact format — load PC into SCRATCH,
        // jump to shared handler. Saves ~6 bytes per stub vs inline PC store.
        let stubs = std::mem::take(&mut self.oog_stubs);
        for (label, pvm_pc, _cost) in &stubs {
            self.asm.bind_label(*label);
            self.asm.mov_ri32(SCRATCH, *pvm_pc);
            self.asm.jmp_label(self.oog_pc_label);
        }

        // Shared page fault handler with PC from stack — emitted BEFORE
        // per-stub code so backward jumps from stubs can use jmp rel8.
        //
        // Each stub pushes its PVM PC onto the stack, then jumps here.
        // SCRATCH still holds the faulting address from the bounds check.
        // Handler: save fault addr, pop PC, save PC, set exit reason, exit.
        let fault_pc_label = self.asm.new_label();
        self.asm.bind_label(fault_pc_label);
        self.asm.mov_store32(CTX, CTX_EXIT_ARG, SCRATCH);
        self.asm.pop(SCRATCH);
        self.asm.mov_store32(CTX, CTX_PC, SCRATCH);
        self.asm
            .mov_store32_imm(CTX, CTX_EXIT_REASON, EXIT_PAGE_FAULT as i32);
        self.asm.jmp_label(self.exit_label);

        // Per-memory-access fault stubs: compact format — push PC, jump
        // to shared handler. Saves ~7 bytes per stub vs inline PC store.
        let fault_stubs = std::mem::take(&mut self.fault_stubs);
        for (label, pvm_pc) in &fault_stubs {
            self.asm.bind_label(*label);
            self.asm.push_imm32(*pvm_pc as i32);
            self.asm.jmp_label(fault_pc_label);
        }

        // Panic exit
        self.asm.bind_label(self.panic_label);
        self.asm
            .mov_store32_imm(CTX, CTX_EXIT_REASON, EXIT_PANIC as i32);
        // fall through to exit_label

        // Common exit: save all 13 PVM registers to context, restore callee-saved, return
        self.asm.bind_label(self.exit_label);
        for (i, &reg) in REG_MAP.iter().enumerate() {
            self.asm.mov_store64(CTX, CTX_REGS + (i as i32) * 8, reg);
        }

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

    /// Get the memory read helper for a load opcode.
    fn read_fn_for(&self, opcode: Opcode) -> u64 {
        match opcode {
            Opcode::LoadU8 | Opcode::LoadI8 | Opcode::LoadIndU8 | Opcode::LoadIndI8 => {
                self.helpers.mem_read_u8
            }
            Opcode::LoadU16 | Opcode::LoadI16 | Opcode::LoadIndU16 | Opcode::LoadIndI16 => {
                self.helpers.mem_read_u16
            }
            Opcode::LoadU32 | Opcode::LoadI32 | Opcode::LoadIndU32 | Opcode::LoadIndI32 => {
                self.helpers.mem_read_u32
            }
            Opcode::LoadU64 | Opcode::LoadIndU64 => self.helpers.mem_read_u64,
            _ => self.helpers.mem_read_u8,
        }
    }

    /// Get the memory write helper for a store opcode.
    fn write_fn_for(&self, opcode: Opcode) -> u64 {
        match opcode {
            Opcode::StoreU8 | Opcode::StoreIndU8 => self.helpers.mem_write_u8,
            Opcode::StoreU16 | Opcode::StoreIndU16 => self.helpers.mem_write_u16,
            Opcode::StoreU32 | Opcode::StoreIndU32 => self.helpers.mem_write_u32,
            Opcode::StoreU64 | Opcode::StoreIndU64 => self.helpers.mem_write_u64,
            _ => self.helpers.mem_write_u8,
        }
    }
}
