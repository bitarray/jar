//! PVM-to-x86-64 code generation.
//!
//! Compiles PVM bytecode into native x86-64 machine code. Each PVM basic block
//! becomes a native basic block with gas metering at entry. PVM registers are
//! mapped to x86-64 registers for the duration of execution.
//!
//! Register mapping (PVM φ[i] → x86-64):
//!   φ[0]  → RBP   (callee-saved) — RA, rarely used as memory base
//!   φ[1]  → RBX   (callee-saved) — SP, avoids RBP encoding penalty
//!   φ[2]  → R12   (callee-saved)
//!   φ[3]  → R13   (callee-saved)
//!   φ[4]  → R14   (callee-saved)
//!   φ[5]  → RSI   (caller-saved)
//!   φ[6]  → RDI   (caller-saved)
//!   φ[7]  → R8    (caller-saved)
//!   φ[8]  → R9    (caller-saved)
//!   φ[9]  → R10   (caller-saved)
//!   φ[10] → R11   (caller-saved)
//!   φ[11] → RAX   (caller-saved)
//!   φ[12] → RCX   (caller-saved)
//!
//! Reserved: R15 = JitContext pointer, RDX = scratch, RSP = native stack.

use super::asm::{Assembler, Cc, Label, Reg};
use crate::gas_sim::GasSimulator;
use crate::args::{self, Args};
use crate::instruction::Opcode;

/// Extract flat (ra, rb, rd) from Args enum.
fn extract_regs(args: &Args) -> (u8, u8, u8) {
    match args {
        Args::ThreeReg { ra, rb, rd } => (*ra as u8, *rb as u8, *rd as u8),
        Args::TwoReg { rd: d, ra: a } => (*a as u8, 0xFF, *d as u8),
        Args::TwoRegImm { ra, rb, .. } | Args::TwoRegOffset { ra, rb, .. }
        | Args::TwoRegTwoImm { ra, rb, .. } => (*ra as u8, *rb as u8, 0xFF),
        Args::RegImm { ra, .. } | Args::RegExtImm { ra, .. }
        | Args::RegTwoImm { ra, .. } | Args::RegImmOffset { ra, .. } => (*ra as u8, 0xFF, 0xFF),
        _ => (0xFF, 0xFF, 0xFF),
    }
}

/// Compute skip(i) — distance to next instruction start.
fn compute_skip(pc: usize, bitmask: &[u8]) -> usize {
    for j in 0..25 {
        let idx = pc + 1 + j;
        let bit = if idx < bitmask.len() { bitmask[idx] } else { 1 };
        if bit == 1 { return j; }
    }
    24
}
/// Map PVM register index (0..12) to x86-64 register.
/// All 13 PVM registers live in x86 registers.
const REG_MAP: [Reg; 13] = [
    Reg::RBP,  // φ[0] — RA (rarely used as memory base, so RBP encoding penalty is acceptable)
    Reg::RBX,  // φ[1] — SP (frequently used as memory base, RBX avoids RBP disp8 penalty)
    Reg::R12,  // φ[2]
    Reg::R13,  // φ[3]
    Reg::R14,  // φ[4]
    Reg::RSI,  // φ[5]
    Reg::RDI,  // φ[6]
    Reg::R8,   // φ[7]
    Reg::R9,   // φ[8]
    Reg::R10,  // φ[9]
    Reg::R11,  // φ[10]
    Reg::RAX,  // φ[11]
    Reg::RCX,  // φ[12]
];

/// Scratch register (not mapped to any PVM register).
const SCRATCH: Reg = Reg::RDX;
/// R15 = base of guest memory (flat buffer). JitContext is at negative offset.
const CTX: Reg = Reg::R15;

/// Caller-saved PVM registers that need saving around helper calls.
const CALLER_SAVED: [Reg; 8] = [
    Reg::RSI, Reg::RDI, Reg::R8, Reg::R9, Reg::R10, Reg::R11, Reg::RAX, Reg::RCX,
];

/// JitContext field offsets — all NEGATIVE from R15 (guest memory base).
///
/// Memory layout (contiguous mmap):
///   R15 - PERMS_OFFSET .. R15 - CTX_OFFSET:  permission table (1MB)
///   R15 - CTX_OFFSET   .. R15:               JitContext (~208 bytes, padded to page)
///   R15                .. R15 + 4GB:          guest memory (flat buffer)
///
/// CTX_OFFSET is the page-aligned distance from R15 to JitContext start.
pub const CTX_OFFSET: i32 = 4096;         // JitContext at R15 - 4096
pub const PERMS_OFFSET: i32 = CTX_OFFSET + (1 << 20); // perms at R15 - 1052672

use memoffset::offset_of;
use super::JitContext;

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
    pub native_code: Vec<u8>,
    pub dispatch_table: Vec<i32>,
    #[cfg(feature = "signals")]
    pub trap_table: Vec<(u32, u32)>,
    #[cfg(feature = "signals")]
    pub exit_label_offset: u32,
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
    /// PVM PC → native code label (Label(0) = invalid/unset).
    block_labels: Vec<Label>,
    /// Label for the exit sequence.
    exit_label: Label,
    /// Label for the shared out-of-gas exit (sets EXIT_OOG + jumps to exit).
    oog_label: Label,
    /// Label for panic exit.
    panic_label: Label,
    /// Label for shared page fault exit (sets PAGE_FAULT + jumps to exit).
    fault_exit_label: Label,
    /// Per-gas-block OOG stubs: (label, pvm_pc) — emitted as cold code after main body.
    oog_stubs: Vec<(Label, u32, u32)>,  // (label, pvm_pc, block_cost)
    /// Per-memory-access fault stubs: (label, pvm_pc) — stores PC, jumps to shared handler.
    fault_stubs: Vec<(Label, u32)>,
    /// Helper function addresses.
    helpers: HelperFns,
    /// Jump table.
    jump_table: Vec<u32>,
    /// Bitmask reference (1 = instruction start). Stored as raw pointer for self-referential use.
    bitmask_ptr: *const u8,
    bitmask_len: usize,
    /// Peephole: tracks how each PVM register was last defined.
    reg_defs: [RegDef; 13],
    /// Bitmask of registers that have non-Unknown reg_defs (for fast invalidation).
    reg_defs_active: u16,
    /// Trap table for signal-based bounds checking: (native_offset, pvm_pc).
    #[cfg(feature = "signals")]
    trap_entries: Vec<(u32, u32)>,
}

/// Sentinel label meaning "no label assigned for this PC".
const NO_LABEL: Label = Label(u32::MAX);

impl Compiler {
    pub fn new(
        bitmask: &[u8],
        jump_table: Vec<u32>,
        helpers: HelperFns,
        code_len: usize,
    ) -> Self {
        // Estimate native code size: ~8 bytes per PVM code byte (empirically ~5-6x).
        let estimated_native = code_len * 8;
        // Labels: estimate ~1 label per 3 code bytes + overhead.
        let estimated_labels = code_len / 3 + 256;
        let mut asm = Assembler::with_capacity(estimated_native, estimated_labels);
        let exit_label = asm.new_label();
        let oog_label = asm.new_label();
        let panic_label = asm.new_label();
        let fault_exit_label = asm.new_label();
        Self {
            block_labels: vec![NO_LABEL; code_len + 1],
            asm,
            exit_label,
            oog_label,
            panic_label,
            fault_exit_label,
            oog_stubs: Vec::new(),
            fault_stubs: Vec::with_capacity(256),
            reg_defs: [RegDef::Unknown; 13],
            reg_defs_active: 0,
            helpers,
            jump_table,
            bitmask_ptr: bitmask.as_ptr(),
            bitmask_len: bitmask.len(),
            #[cfg(feature = "signals")]
            trap_entries: Vec::new(),
        }
    }

    /// Get or create a label for a PVM PC offset.
    fn label_for_pc(&mut self, pc: u32) -> Label {
        let idx = pc as usize;
        let l = self.block_labels[idx];
        if l != NO_LABEL {
            l
        } else {
            let l = self.asm.new_label();
            self.block_labels[idx] = l;
            l
        }
    }

    fn is_basic_block_start(&self, idx: u32) -> bool {
        let i = idx as usize;
        i < self.bitmask_len && unsafe { *self.bitmask_ptr.add(i) } == 1
    }

    /// Compile directly from raw code+bitmask. Streaming single-pass:
    /// gas block discovery + decode + gas sim + codegen in one loop.
    pub fn compile(mut self, code: &[u8], bitmask: &[u8]) -> CompileResult {
        let code_len = code.len();

        // Emit prologue
        self.emit_prologue();

        // Gas block starts: use the same basic block analysis as the interpreter.
        // This ensures gas charging matches exactly. The inline discovery missed
        // forward-reference targets (e.g., a branch at PC=664 targeting PC=604
        // wouldn't be discovered before PC=604 is compiled).
        let mut gas_starts = crate::vm::compute_basic_block_starts(code, bitmask);

        // Single streaming pass: decode + gas blocks + codegen
        let mut gas_sim = GasSimulator::new();
        let mut pending_gas: Option<(Label, u32, usize)> = None;

        // Find first instruction start
        let mut pc: usize = 0;
        while pc < code.len() && (pc >= bitmask.len() || bitmask[pc] != 1) { pc += 1; }

        while pc < code.len() {

            // Decode instruction inline
            let opcode = match Opcode::from_byte(code[pc]) {
                Some(op) => op,
                None => {
                    self.asm.mov_store32_imm(CTX, CTX_PC as i32, pc as i32);
                    self.emit_exit(EXIT_PANIC, 0);
                    pc += 1;
                    continue;
                }
            };
            let skip = compute_skip(pc, bitmask);
            let next_pc = (pc + 1 + skip) as u32;

            // Extract raw register fields (for gas sim)
            let raw_ra = if pc + 1 < code.len() { code[pc + 1] & 0x0F } else { 0xFF };
            let raw_rb = if pc + 1 < code.len() { (code[pc + 1] >> 4) & 0x0F } else { 0xFF };
            let raw_rd = if pc + 2 < code.len() { code[pc + 2] & 0x0F } else { 0xFF };

            // Bind label (on-demand creation — no pre-pass needed)
            let label = self.label_for_pc(pc as u32);
            self.asm.bind_label(label);

            // Full decode
            let category = opcode.category();
            let decoded_args = args::decode_args(code, pc, skip, category);

            // Discover gas block boundaries inline (reuses decoded_args):
            // - Branch/jump targets mark future gas block starts
            // - Post-terminator/ecalli mark next instruction as gas block start
            let target = match decoded_args {
                Args::Offset { offset } => Some(offset as usize),
                Args::RegImmOffset { offset, .. } => Some(offset as usize),
                Args::TwoRegOffset { offset, .. } => Some(offset as usize),
                _ => None,
            };
            // Note: gas_starts is pre-computed by compute_basic_block_starts()
            // which already includes all branch/jump targets and post-terminators.
            // Post-ecalli boundaries need to be added here since they're not
            // basic block boundaries per se but must be gas block boundaries.
            if matches!(opcode, Opcode::Ecalli) && (next_pc as usize) < code_len {
                gas_starts[next_pc as usize] = true;
            }

            // Gas block boundary check
            if gas_starts[pc] {
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

            // Feed gas simulator
            let fc = crate::gas_cost::fast_cost_from_raw(
                opcode as u8, raw_ra, raw_rb, raw_rd, pc as u32, code, bitmask,
            );
            gas_sim.feed(&fc);

            // Peephole fusions
            let fused = match opcode {
                Opcode::Add64 => self.try_fuse_scaled_index_raw(code, bitmask, pc, &decoded_args, &mut gas_sim),
                Opcode::Mul64 => self.try_fuse_mul_pair_raw(code, bitmask, pc, &decoded_args, &mut gas_sim),
                _ => None,
            };

            if let Some(advance) = fused {
                pc += advance;
                continue;
            }

            self.compile_instruction(opcode, &decoded_args, pc as u32, next_pc);
            self.update_reg_defs(opcode, &decoded_args);

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

        // Build dispatch table: PVM PC → native code offset
        let table_len = code_len + 1; // +1 so PC=code.len() is valid (maps to panic)
        let mut dispatch_table = vec![-1i32; table_len];
        for (pvm_pc, &label) in self.block_labels.iter().enumerate() {
            if label != NO_LABEL {
                if let Some(offset) = self.asm.label_offset(label) {
                    dispatch_table[pvm_pc] = offset as i32;
                }
            }
        }
        // PC=0 must always be valid (program start); if not already set, it'll be
        // set by the first basic block at PC 0.

        #[cfg(feature = "signals")]
        let exit_label_offset = self.asm.label_offset(self.exit_label).unwrap_or(0) as u32;
        #[cfg(feature = "signals")]
        let trap_table = self.trap_entries;

        CompileResult {
            native_code: self.asm.finalize(),
            dispatch_table,
            #[cfg(feature = "signals")]
            trap_table,
            #[cfg(feature = "signals")]
            exit_label_offset,
        }
    }

    /// Save caller-saved registers (PVM registers in caller-saved x86-64 regs).
    fn save_caller_saved(&mut self) {
        for &reg in &CALLER_SAVED {
            self.asm.push(reg);
        }
    }

    /// Restore caller-saved registers (reverse order).
    fn restore_caller_saved(&mut self) {
        for &reg in CALLER_SAVED.iter().rev() {
            self.asm.pop(reg);
        }
    }

/// Load the JitContext pointer (R15 - CTX_OFFSET) into a register.
    fn emit_ctx_ptr(&mut self, dst: Reg) {
        self.asm.lea(dst, CTX, -CTX_OFFSET);
    }

    /// Peephole: fuse scaled-index from raw code (no pre-decoded array).
    /// Pattern: add64 D,A,A / add64 D,D,D / add64 D2,BASE,D / load/store_ind R,D2,0
    fn try_fuse_scaled_index_raw(&mut self, code: &[u8], bitmask: &[u8], pc: usize,
        args: &Args, gas_sim: &mut GasSimulator) -> Option<usize>
    {
        let Args::ThreeReg { ra: a1_ra, rb: a1_rb, rd: a1_rd } = args else { return None; };
        if a1_ra != a1_rb { return None; }
        let idx_reg = *a1_ra;
        let d1 = *a1_rd;

        // Peek instruction 2
        let skip1 = compute_skip(pc, bitmask);
        let pc2 = pc + 1 + skip1;
        if pc2 >= code.len() || (pc2 < bitmask.len() && bitmask[pc2] != 1) { return None; }
        let op2 = Opcode::from_byte(code[pc2])?;
        if op2 != Opcode::Add64 { return None; }
        let skip2 = compute_skip(pc2, bitmask);
        let args2 = args::decode_args(code, pc2, skip2, op2.category());
        let Args::ThreeReg { ra: a2_ra, rb: a2_rb, rd: a2_rd } = args2 else { return None; };
        if a2_ra != d1 || a2_rb != d1 || a2_rd != d1 { return None; }

        // Peek instruction 3
        let pc3 = pc2 + 1 + skip2;
        if pc3 >= code.len() || (pc3 < bitmask.len() && bitmask[pc3] != 1) { return None; }
        let op3 = Opcode::from_byte(code[pc3])?;
        if op3 != Opcode::Add64 { return None; }
        let skip3 = compute_skip(pc3, bitmask);
        let args3 = args::decode_args(code, pc3, skip3, op3.category());
        let Args::ThreeReg { ra: a3_ra, rb: a3_rb, rd: a3_rd } = args3 else { return None; };
        let base_reg;
        if a3_rb == d1 && a3_ra != d1 { base_reg = a3_ra; }
        else if a3_ra == d1 && a3_rb != d1 { base_reg = a3_rb; }
        else { return None; }
        let addr_reg = a3_rd;

        // Peek instruction 4
        let pc4 = pc3 + 1 + skip3;
        if pc4 >= code.len() || (pc4 < bitmask.len() && bitmask[pc4] != 1) { return None; }
        let op4 = Opcode::from_byte(code[pc4])?;
        let skip4 = compute_skip(pc4, bitmask);
        let args4 = args::decode_args(code, pc4, skip4, op4.category());

        // Feed instructions 2-4 to gas sim
        for &(opc, ref a, p) in &[(op2, &args2, pc2), (op3, &args3, pc3), (op4, &args4, pc4)] {
            let (ra, rb, rd) = extract_regs(a);
            let fc = crate::gas_cost::fast_cost_from_raw(opc as u8, ra, rb, rd, p as u32, code, bitmask);
            gas_sim.feed(&fc);
        }

        // Bind labels for all 4 instructions
        for &ipc in &[pc, pc2, pc3, pc4] {
            let label = self.block_labels[ipc];
            if label != NO_LABEL { self.asm.bind_label(label); }
        }

        match op4 {
            Opcode::LoadIndU8 | Opcode::LoadIndI8 | Opcode::LoadIndU16 | Opcode::LoadIndI16 |
            Opcode::LoadIndU32 | Opcode::LoadIndI32 | Opcode::LoadIndU64 => {
                let Args::TwoRegImm { ra, rb, imm } = args4 else { return None; };
                if rb != addr_reg || imm as i32 != 0 { return None; }
                self.asm.lea_sib_scaled_32(SCRATCH, REG_MAP[base_reg], REG_MAP[idx_reg], 2);
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
            Opcode::StoreIndU8 | Opcode::StoreIndU16 | Opcode::StoreIndU32 | Opcode::StoreIndU64 => {
                let Args::TwoRegImm { ra, rb, imm } = args4 else { return None; };
                if rb != addr_reg || imm as i32 != 0 { return None; }
                self.asm.lea_sib_scaled_32(SCRATCH, REG_MAP[base_reg], REG_MAP[idx_reg], 2);
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
    fn try_fuse_mul_pair_raw(&mut self, code: &[u8], bitmask: &[u8], pc: usize,
        args: &Args, gas_sim: &mut GasSimulator) -> Option<usize>
    {
        let Args::ThreeReg { ra: m_ra, rb: m_rb, rd: m_rd } = args else { return None; };

        let skip1 = compute_skip(pc, bitmask);
        let pc2 = pc + 1 + skip1;
        if pc2 >= code.len() || (pc2 < bitmask.len() && bitmask[pc2] != 1) { return None; }
        let op2 = Opcode::from_byte(code[pc2])?;
        let signed = match op2 {
            Opcode::MulUpperSS => true,
            Opcode::MulUpperUU => false,
            _ => return None,
        };
        let skip2 = compute_skip(pc2, bitmask);
        let args2 = args::decode_args(code, pc2, skip2, op2.category());
        let Args::ThreeReg { ra: u_ra, rb: u_rb, rd: u_rd } = args2 else { return None; };
        if u_ra != *m_ra || u_rb != *m_rb { return None; }

        // Feed instruction 2 to gas sim
        let (ra2, rb2, rd2) = extract_regs(&args2);
        let fc = crate::gas_cost::fast_cost_from_raw(op2 as u8, ra2, rb2, rd2, pc2 as u32, code, bitmask);
        gas_sim.feed(&fc);

        // Bind labels
        for &ipc in &[pc, pc2] {
            let label = self.block_labels[ipc];
            if label != NO_LABEL { self.asm.bind_label(label); }
        }

        let (a, b) = (REG_MAP[*m_ra], REG_MAP[*m_rb]);
        let (rd_lo, rd_hi) = (REG_MAP[*m_rd], REG_MAP[u_rd]);

        self.asm.push(Reg::RAX);
        self.asm.push(SCRATCH);
        self.asm.mov_rr(Reg::RAX, a);
        let mul_src = if b == Reg::RAX {
            self.asm.mov_load64(SCRATCH, Reg::RSP, 8);
            SCRATCH
        } else { b };
        if signed { self.asm.imul_rdx_rax(mul_src); } else { self.asm.mul_rdx_rax(mul_src); }
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
        let w = if width_bytes > 0 { width_bytes } else {
            if fn_addr == self.helpers.mem_read_u8 { 1 }
            else if fn_addr == self.helpers.mem_read_u16 { 2 }
            else if fn_addr == self.helpers.mem_read_u32 { 4 }
            else { 8 }
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
        let w = if fn_addr == self.helpers.mem_write_u8 { 1u32 }
            else if fn_addr == self.helpers.mem_write_u16 { 2 }
            else if fn_addr == self.helpers.mem_write_u32 { 4 }
            else { 8 };

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

    /// Compute a memory address into SCRATCH, using peephole optimizations when available.
    fn emit_addr_to_scratch(&mut self, rb: usize, imm: i32) {
        // Peephole: fold known constant address (no register load needed)
        if let RegDef::Const(addr) = self.reg_defs[rb] {
            let effective = addr.wrapping_add(imm as u32);
            self.asm.mov_ri32(SCRATCH, effective);
            return;
        }
        // Peephole: use SIB addressing for scaled-index patterns
        if imm == 0 {
            if let RegDef::ScaledAdd { base, idx, shift } = self.reg_defs[rb] {
                self.asm.lea_sib_scaled_32(SCRATCH, REG_MAP[base], REG_MAP[idx], shift);
                return;
            }
        }
        let rb_reg = REG_MAP[rb];
        self.asm.movzx_32_64(SCRATCH, rb_reg);
        if imm != 0 {
            self.asm.add_ri32(SCRATCH, imm);
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
                                self.reg_defs[*rd] = RegDef::Shifted { src, shift: shift + 1 };
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
            Opcode::MoveReg => {
                if let Args::TwoReg { rd, ra } = args {
                    if *rd != *ra {
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
    fn compile_instruction(&mut self, opcode: Opcode, args: &Args, pc: u32, next_pc: u32) {
        match opcode {
            // === A.5.1: No arguments ===
            Opcode::Trap => {
                self.asm.mov_store32_imm(CTX, CTX_PC as i32, pc as i32);
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
                    self.asm.mov_store32_imm(CTX, CTX_PC as i32, next_pc as i32);
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
            Opcode::StoreImmU8 | Opcode::StoreImmU16 | Opcode::StoreImmU32 | Opcode::StoreImmU64 => {
                if let Args::TwoImm { imm_x, imm_y } = args {
                    let addr = *imm_x as u32;
                    let fn_addr = match opcode {
                        Opcode::StoreImmU8 => self.helpers.mem_write_u8,
                        Opcode::StoreImmU16 => self.helpers.mem_write_u16,
                        Opcode::StoreImmU32 => self.helpers.mem_write_u32,
                        Opcode::StoreImmU64 => self.helpers.mem_write_u64,
                        _ => unreachable!(),
                    };
                    // addr in SCRATCH, value in a temp
                    self.asm.mov_ri64(SCRATCH, addr as u64);
                    // For the value, use a push-based approach
                    let val = *imm_y;
                    // We need val_reg - use a temp approach: push SCRATCH (addr), load val
                    self.asm.push(SCRATCH); // save addr
                    self.asm.mov_ri64(SCRATCH, val); // SCRATCH = value
                    self.asm.push(SCRATCH); // push value

                    self.save_caller_saved();
                    // Stack: [8 caller-saved (64)] [value (8)] [addr (8)]
                    self.asm.mov_load64(Reg::RDX, Reg::RSP, 64); // value
                    self.asm.mov_load64(Reg::RSI, Reg::RSP, 72); // addr
                    self.emit_ctx_ptr(Reg::RDI);                 // ctx = R15 - CTX_OFFSET
                    self.asm.mov_ri64(Reg::RAX, fn_addr);
                    self.asm.call_reg(Reg::RAX);
                    self.restore_caller_saved();
                    self.asm.pop(SCRATCH);
                    self.asm.pop(SCRATCH);
                    // fault check
                    self.asm.push(SCRATCH);
                    self.asm.mov_load32(SCRATCH, CTX, CTX_EXIT_REASON);
                    self.asm.cmp_ri(SCRATCH, 0);
                    self.asm.pop(SCRATCH);
                    self.asm.jcc_label(Cc::NE, self.exit_label);
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
            Opcode::LoadU8 | Opcode::LoadI8 | Opcode::LoadU16 | Opcode::LoadI16 |
            Opcode::LoadU32 | Opcode::LoadI32 | Opcode::LoadU64 => {
                if let Args::RegImm { ra, imm } = args {
                    let addr = *imm as u32;
                    let fn_addr = self.read_fn_for(opcode);
                    self.asm.mov_ri64(SCRATCH, addr as u64);
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
                    self.asm.mov_ri64(SCRATCH, addr as u64);
                    self.emit_mem_write(true, ra_reg, fn_addr, pc);
                }
            }

            // === A.5.7: One register + two immediates (store_imm_ind) ===
            Opcode::StoreImmIndU8 | Opcode::StoreImmIndU16 | Opcode::StoreImmIndU32 | Opcode::StoreImmIndU64 => {
                if let Args::RegTwoImm { ra, imm_x, imm_y } = args {
                    // addr = φ[ra] + imm_x
                    let ra_reg = REG_MAP[*ra];
                    self.asm.mov_rr(SCRATCH, ra_reg);
                    if *imm_x as i32 != 0 {
                        self.asm.add_ri(SCRATCH, *imm_x as i32);
                    }
                    // Truncate to 32-bit
                    self.asm.movzx_32_64(SCRATCH, SCRATCH);

                    let fn_addr = match opcode {
                        Opcode::StoreImmIndU8 => self.helpers.mem_write_u8,
                        Opcode::StoreImmIndU16 => self.helpers.mem_write_u16,
                        Opcode::StoreImmIndU32 => self.helpers.mem_write_u32,
                        Opcode::StoreImmIndU64 => self.helpers.mem_write_u64,
                        _ => unreachable!(),
                    };
                    // Push addr and imm_y value
                    self.asm.push(SCRATCH);
                    self.asm.mov_ri64(SCRATCH, *imm_y);
                    self.asm.push(SCRATCH);
                    self.save_caller_saved();
                    // Stack: [8 caller-saved (64)] [value (8)] [addr (8)]
                    self.asm.mov_load64(Reg::RDX, Reg::RSP, 64); // value
                    self.asm.mov_load64(Reg::RSI, Reg::RSP, 72); // addr
                    self.emit_ctx_ptr(Reg::RDI);                 // ctx = R15 - CTX_OFFSET
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
                self.asm.mov_store32_imm(CTX, CTX_PC as i32, pc as i32);
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
            Opcode::StoreIndU8 | Opcode::StoreIndU16 | Opcode::StoreIndU32 | Opcode::StoreIndU64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let ra_reg = REG_MAP[*ra];
                    self.emit_addr_to_scratch(*rb, *imm as i32);
                    let fn_addr = self.write_fn_for(opcode);
                    self.emit_mem_write(true, ra_reg, fn_addr, pc);
                }
            }
            Opcode::LoadIndU8 | Opcode::LoadIndI8 | Opcode::LoadIndU16 | Opcode::LoadIndI16 |
            Opcode::LoadIndU32 | Opcode::LoadIndI32 | Opcode::LoadIndU64 => {
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
                    if *ra != *rb { self.asm.mov_rr(REG_MAP[*ra], rb_reg); }
                    self.asm.add_ri32(REG_MAP[*ra], *imm as i32);
                    self.asm.movsxd(REG_MAP[*ra], REG_MAP[*ra]);

                }
            }
            Opcode::AddImm64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    if *ra != *rb { self.asm.mov_rr(REG_MAP[*ra], rb_reg); }
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
                    if *ra != *rb { self.asm.mov_rr(REG_MAP[*ra], rb_reg); }
                    self.asm.and_ri(REG_MAP[*ra], *imm as i32);

                }
            }
            Opcode::XorImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    if *ra != *rb { self.asm.mov_rr(REG_MAP[*ra], rb_reg); }
                    self.asm.xor_ri(REG_MAP[*ra], *imm as i32);

                }
            }
            Opcode::OrImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    if *ra != *rb { self.asm.mov_rr(REG_MAP[*ra], rb_reg); }
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
                    let rb_reg = REG_MAP[*rb];
                    self.asm.mov_ri64(SCRATCH, *imm);
                    self.asm.cmp_rr(rb_reg, SCRATCH);
                    self.asm.setcc(Cc::B, REG_MAP[*ra]);
                    self.asm.movzx_8_64(REG_MAP[*ra], REG_MAP[*ra]);

                }
            }
            Opcode::SetLtSImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    self.asm.mov_ri64(SCRATCH, *imm);
                    self.asm.cmp_rr(rb_reg, SCRATCH);
                    self.asm.setcc(Cc::L, REG_MAP[*ra]);
                    self.asm.movzx_8_64(REG_MAP[*ra], REG_MAP[*ra]);

                }
            }
            Opcode::SetGtUImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    self.asm.mov_ri64(SCRATCH, *imm);
                    self.asm.cmp_rr(rb_reg, SCRATCH);
                    self.asm.setcc(Cc::A, REG_MAP[*ra]);
                    self.asm.movzx_8_64(REG_MAP[*ra], REG_MAP[*ra]);

                }
            }
            Opcode::SetGtSImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    self.asm.mov_ri64(SCRATCH, *imm);
                    self.asm.cmp_rr(rb_reg, SCRATCH);
                    self.asm.setcc(Cc::G, REG_MAP[*ra]);
                    self.asm.movzx_8_64(REG_MAP[*ra], REG_MAP[*ra]);

                }
            }
            Opcode::ShloLImm32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    if *ra != *rb { self.asm.mov_rr(REG_MAP[*ra], rb_reg); }
                    self.asm.shl_ri32(REG_MAP[*ra], (*imm as u8) & 31);
                    self.asm.movsxd(REG_MAP[*ra], REG_MAP[*ra]);

                }
            }
            Opcode::ShloRImm32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    if *ra != *rb { self.asm.mov_rr(REG_MAP[*ra], rb_reg); }
                    self.asm.movzx_32_64(REG_MAP[*ra], REG_MAP[*ra]);
                    self.asm.shr_ri32(REG_MAP[*ra], (*imm as u8) & 31);
                    self.asm.movsxd(REG_MAP[*ra], REG_MAP[*ra]);

                }
            }
            Opcode::SharRImm32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    if *ra != *rb { self.asm.mov_rr(REG_MAP[*ra], rb_reg); }
                    self.asm.sar_ri32(REG_MAP[*ra], (*imm as u8) & 31);
                    self.asm.movsxd(REG_MAP[*ra], REG_MAP[*ra]);

                }
            }
            Opcode::ShloLImm64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    if *ra != *rb { self.asm.mov_rr(REG_MAP[*ra], rb_reg); }
                    self.asm.shl_ri64(REG_MAP[*ra], (*imm as u8) & 63);

                }
            }
            Opcode::ShloRImm64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    if *ra != *rb { self.asm.mov_rr(REG_MAP[*ra], rb_reg); }
                    self.asm.shr_ri64(REG_MAP[*ra], (*imm as u8) & 63);

                }
            }
            Opcode::SharRImm64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    if *ra != *rb { self.asm.mov_rr(REG_MAP[*ra], rb_reg); }
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
                    let shift_src = if *ra == *rb { self.asm.mov_rr(SCRATCH, rb_reg); SCRATCH } else { rb_reg };
                    self.asm.mov_ri64(REG_MAP[*ra], *imm);
                    self.emit_shift_by_reg32(REG_MAP[*ra], shift_src, 4); // SHL
                    self.asm.movsxd(REG_MAP[*ra], REG_MAP[*ra]);

                }
            }
            Opcode::ShloRImmAlt32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    let shift_src = if *ra == *rb { self.asm.mov_rr(SCRATCH, rb_reg); SCRATCH } else { rb_reg };
                    self.asm.mov_ri64(REG_MAP[*ra], *imm);
                    self.asm.movzx_32_64(REG_MAP[*ra], REG_MAP[*ra]);
                    self.emit_shift_by_reg32(REG_MAP[*ra], shift_src, 5); // SHR
                    self.asm.movsxd(REG_MAP[*ra], REG_MAP[*ra]);

                }
            }
            Opcode::SharRImmAlt32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    let shift_src = if *ra == *rb { self.asm.mov_rr(SCRATCH, rb_reg); SCRATCH } else { rb_reg };
                    self.asm.mov_ri64(REG_MAP[*ra], *imm);
                    self.emit_shift_by_reg32(REG_MAP[*ra], shift_src, 7); // SAR
                    self.asm.movsxd(REG_MAP[*ra], REG_MAP[*ra]);

                }
            }
            Opcode::ShloLImmAlt64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    let shift_src = if *ra == *rb { self.asm.mov_rr(SCRATCH, rb_reg); SCRATCH } else { rb_reg };
                    self.asm.mov_ri64(REG_MAP[*ra], *imm);
                    self.emit_shift_by_reg64(REG_MAP[*ra], shift_src, 4);

                }
            }
            Opcode::ShloRImmAlt64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    let shift_src = if *ra == *rb { self.asm.mov_rr(SCRATCH, rb_reg); SCRATCH } else { rb_reg };
                    self.asm.mov_ri64(REG_MAP[*ra], *imm);
                    self.emit_shift_by_reg64(REG_MAP[*ra], shift_src, 5);

                }
            }
            Opcode::SharRImmAlt64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    let shift_src = if *ra == *rb { self.asm.mov_rr(SCRATCH, rb_reg); SCRATCH } else { rb_reg };
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
                    if *ra != *rb { self.asm.mov_rr(REG_MAP[*ra], rb_reg); }
                    self.asm.ror_ri64(REG_MAP[*ra], (*imm as u8) & 63);

                }
            }
            Opcode::RotR64ImmAlt => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    // rd = imm ROR rb
                    let rb_reg = REG_MAP[*rb];
                    let shift_src = if *ra == *rb { self.asm.mov_rr(SCRATCH, rb_reg); SCRATCH } else { rb_reg };
                    self.asm.mov_ri64(REG_MAP[*ra], *imm);
                    self.emit_shift_by_reg64(REG_MAP[*ra], shift_src, 1); // ROR

                }
            }
            Opcode::RotR32Imm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    if *ra != *rb { self.asm.mov_rr(REG_MAP[*ra], rb_reg); }
                    self.asm.movzx_32_64(REG_MAP[*ra], REG_MAP[*ra]);
                    self.asm.ror_ri32(REG_MAP[*ra], (*imm as u8) & 31);
                    self.asm.movsxd(REG_MAP[*ra], REG_MAP[*ra]);

                }
            }
            Opcode::RotR32ImmAlt => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let rb_reg = REG_MAP[*rb];
                    let shift_src = if *ra == *rb { self.asm.mov_rr(SCRATCH, rb_reg); SCRATCH } else { rb_reg };
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
                if let Args::TwoRegTwoImm { ra, rb, imm_x, imm_y } = args {
                    // GP: registers[ra] = imm_x, addr = registers[rb] + imm_y
                    // Per GP semantics, ra is written first, then jump uses the
                    // (possibly updated) rb value.
                    // If ra==rb, the jump target uses imm_x + imm_y.
                    self.asm.mov_ri64(REG_MAP[*ra], *imm_x);
                    self.emit_dynamic_jump(*rb, *imm_y, pc);
                }
            }

            // === A.5.13: Three registers ===
            Opcode::Add32 => { self.emit_alu3_32(args, |a, d, s| { a.add_rr32(d, s); }); }
            Opcode::Sub32 => { self.emit_alu3_32_sub(args); }
            Opcode::Mul32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {

                    let (d, a, b) = (REG_MAP[*rd], REG_MAP[*ra], REG_MAP[*rb]);
                    if *rd == *rb && *rd != *ra {
                        self.asm.mov_rr(SCRATCH, b);
                        self.asm.mov_rr(d, a);
                        self.asm.imul_rr32(d, SCRATCH);
                    } else {
                        if *rd != *ra { self.asm.mov_rr(d, a); }
                        self.asm.imul_rr32(d, b);
                    }
                    self.asm.movsxd(d, d);

                }
            }
            Opcode::Add64 => {
                self.emit_alu3_64(args, |a, d, s| { a.add_rr(d, s); });
                // reg_defs tracking handled by update_reg_defs() in main loop
            }
            Opcode::Sub64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {

                    let (d, a, b) = (REG_MAP[*rd], REG_MAP[*ra], REG_MAP[*rb]);
                    if *rd == *rb && *rd != *ra {
                        self.asm.mov_rr(SCRATCH, b);
                        self.asm.mov_rr(d, a);
                        self.asm.sub_rr(d, SCRATCH);
                    } else {
                        if *rd != *ra { self.asm.mov_rr(d, a); }
                        self.asm.sub_rr(d, b);
                    }

                }
            }
            Opcode::Mul64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {

                    let (d, a, b) = (REG_MAP[*rd], REG_MAP[*ra], REG_MAP[*rb]);
                    if *rd == *rb && *rd != *ra {
                        self.asm.mov_rr(SCRATCH, b);
                        self.asm.mov_rr(d, a);
                        self.asm.imul_rr(d, SCRATCH);
                    } else {
                        if *rd != *ra { self.asm.mov_rr(d, a); }
                        self.asm.imul_rr(d, b);
                    }

                }
            }
            Opcode::And => { self.emit_alu3_64(args, |a, d, s| { a.and_rr(d, s); }); }
            Opcode::Or => { self.emit_alu3_64(args, |a, d, s| { a.or_rr(d, s); }); }
            Opcode::Xor => { self.emit_alu3_64(args, |a, d, s| { a.xor_rr(d, s); }); }

            // Division (32-bit and 64-bit)
            Opcode::DivU32 => { self.emit_div(args, false, false, true); }
            Opcode::DivS32 => { self.emit_div(args, true, false, true); }
            Opcode::RemU32 => { self.emit_div(args, false, true, true); }
            Opcode::RemS32 => { self.emit_div(args, true, true, true); }
            Opcode::DivU64 => { self.emit_div(args, false, false, false); }
            Opcode::DivS64 => { self.emit_div(args, true, false, false); }
            Opcode::RemU64 => { self.emit_div(args, false, true, false); }
            Opcode::RemS64 => { self.emit_div(args, true, true, false); }

            // Shifts (three-register)
            // Note: when rd==rb, we must save rb to SCRATCH before mov rd, ra.
            Opcode::ShloL32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {

                    let (d, a, b) = (REG_MAP[*rd], REG_MAP[*ra], REG_MAP[*rb]);
                    let shift_src = if *rd == *rb && *rd != *ra { self.asm.mov_rr(SCRATCH, b); SCRATCH } else { b };
                    if *rd != *ra { self.asm.mov_rr(d, a); }
                    self.emit_shift_by_reg32(d, shift_src, 4);
                    self.asm.movsxd(d, d);

                }
            }
            Opcode::ShloR32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {

                    let (d, a, b) = (REG_MAP[*rd], REG_MAP[*ra], REG_MAP[*rb]);
                    let shift_src = if *rd == *rb && *rd != *ra { self.asm.mov_rr(SCRATCH, b); SCRATCH } else { b };
                    if *rd != *ra { self.asm.mov_rr(d, a); }
                    self.asm.movzx_32_64(d, d);
                    self.emit_shift_by_reg32(d, shift_src, 5);
                    self.asm.movsxd(d, d);

                }
            }
            Opcode::SharR32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {

                    let (d, a, b) = (REG_MAP[*rd], REG_MAP[*ra], REG_MAP[*rb]);
                    let shift_src = if *rd == *rb && *rd != *ra { self.asm.mov_rr(SCRATCH, b); SCRATCH } else { b };
                    if *rd != *ra { self.asm.mov_rr(d, a); }
                    self.emit_shift_by_reg32(d, shift_src, 7);
                    self.asm.movsxd(d, d);

                }
            }
            Opcode::ShloL64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {

                    let (d, a, b) = (REG_MAP[*rd], REG_MAP[*ra], REG_MAP[*rb]);
                    let shift_src = if *rd == *rb && *rd != *ra { self.asm.mov_rr(SCRATCH, b); SCRATCH } else { b };
                    if *rd != *ra { self.asm.mov_rr(d, a); }
                    self.emit_shift_by_reg64(d, shift_src, 4);

                }
            }
            Opcode::ShloR64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {

                    let (d, a, b) = (REG_MAP[*rd], REG_MAP[*ra], REG_MAP[*rb]);
                    let shift_src = if *rd == *rb && *rd != *ra { self.asm.mov_rr(SCRATCH, b); SCRATCH } else { b };
                    if *rd != *ra { self.asm.mov_rr(d, a); }
                    self.emit_shift_by_reg64(d, shift_src, 5);

                }
            }
            Opcode::SharR64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {

                    let (d, a, b) = (REG_MAP[*rd], REG_MAP[*ra], REG_MAP[*rb]);
                    let shift_src = if *rd == *rb && *rd != *ra { self.asm.mov_rr(SCRATCH, b); SCRATCH } else { b };
                    if *rd != *ra { self.asm.mov_rr(d, a); }
                    self.emit_shift_by_reg64(d, shift_src, 7);

                }
            }

            // Multiply upper
            Opcode::MulUpperSS => { self.emit_mul_upper(args, true, true); }
            Opcode::MulUpperUU => { self.emit_mul_upper(args, false, false); }
            Opcode::MulUpperSU => { self.emit_mul_upper(args, true, false); }

            // Set comparisons (three-register)
            Opcode::SetLtU => {
                if let Args::ThreeReg { ra, rb, rd } = args {

                    self.asm.cmp_rr(REG_MAP[*ra], REG_MAP[*rb]);
                    self.asm.setcc(Cc::B, REG_MAP[*rd]);
                    self.asm.movzx_8_64(REG_MAP[*rd], REG_MAP[*rd]);

                }
            }
            Opcode::SetLtS => {
                if let Args::ThreeReg { ra, rb, rd } = args {

                    self.asm.cmp_rr(REG_MAP[*ra], REG_MAP[*rb]);
                    self.asm.setcc(Cc::L, REG_MAP[*rd]);
                    self.asm.movzx_8_64(REG_MAP[*rd], REG_MAP[*rd]);

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
                    let shift_src = if *rd == *rb && *rd != *ra { self.asm.mov_rr(SCRATCH, b); SCRATCH } else { b };
                    if *rd != *ra { self.asm.mov_rr(d, a); }
                    self.emit_shift_by_reg64(d, shift_src, 0); // ROL

                }
            }
            Opcode::RotL32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {

                    let (d, a, b) = (REG_MAP[*rd], REG_MAP[*ra], REG_MAP[*rb]);
                    let shift_src = if *rd == *rb && *rd != *ra { self.asm.mov_rr(SCRATCH, b); SCRATCH } else { b };
                    if *rd != *ra { self.asm.mov_rr(d, a); }
                    self.asm.movzx_32_64(d, d);
                    self.emit_shift_by_reg32(d, shift_src, 0);
                    self.asm.movsxd(d, d);

                }
            }
            Opcode::RotR64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {

                    let (d, a, b) = (REG_MAP[*rd], REG_MAP[*ra], REG_MAP[*rb]);
                    let shift_src = if *rd == *rb && *rd != *ra { self.asm.mov_rr(SCRATCH, b); SCRATCH } else { b };
                    if *rd != *ra { self.asm.mov_rr(d, a); }
                    self.emit_shift_by_reg64(d, shift_src, 1); // ROR

                }
            }
            Opcode::RotR32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {

                    let (d, a, b) = (REG_MAP[*rd], REG_MAP[*ra], REG_MAP[*rb]);
                    let shift_src = if *rd == *rb && *rd != *ra { self.asm.mov_rr(SCRATCH, b); SCRATCH } else { b };
                    if *rd != *ra { self.asm.mov_rr(d, a); }
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
                        if *rd != *ra { self.asm.mov_rr(d, a); }
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
                        if *rd != *ra { self.asm.mov_rr(d, a); }
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
                        if *rd != *ra { self.asm.mov_rr(d, a); }
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
                        if *rd != *ra { self.asm.mov_rr(d, a); }
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
                        if *rd != *ra { self.asm.mov_rr(d, a); }
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
            self.asm.mov_store32_imm(CTX, CTX_PC as i32, pc as i32);
            self.emit_exit(EXIT_PANIC, 0);
            return;
        }
        let label = self.label_for_pc(target);
        self.asm.jmp_label(label);
    }

    /// Emit a dynamic jump (through jump table).
    fn emit_dynamic_jump(&mut self, ra: usize, imm: u64, pc: u32) {
        // Store PC for any exit path in the dynamic jump sequence
        self.asm.mov_store32_imm(CTX, CTX_PC as i32, pc as i32);
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

        // addr % 2 != 0 → panic (test bit 0)
        self.asm.push(SCRATCH);
        self.asm.and_ri(SCRATCH, 1);
        self.asm.test_rr(SCRATCH, SCRATCH);
        self.asm.pop(SCRATCH);
        self.asm.jcc_label(Cc::NE, self.panic_label);

        // idx = addr/2 - 1
        self.asm.shr_ri64(SCRATCH, 1);
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
        self.asm.mov_store32(CTX, CTX_PC as i32, SCRATCH);
        // RAX = native addr, [rsp] = saved φ[11].
        // Use SCRATCH (which we no longer need) to swap.
        self.asm.mov_rr(SCRATCH, Reg::RAX);  // SCRATCH = native addr
        self.asm.pop(Reg::RAX);               // restore φ[11]
        self.asm.jmp_reg(SCRATCH);            // jump to native addr

        self.asm.bind_label(djump_panic);
        self.asm.pop(Reg::RAX); // restore φ[11] before panicking
        self.asm.jmp_label(self.panic_label);
    }

    /// Emit a branch comparing register against immediate.
    fn emit_branch_imm(&mut self, reg: Reg, imm: u64, cc: Cc, target: u32, _fallthrough: u32, pc: u32) {
        if !self.is_basic_block_start(target) {
            // Target not valid → store PC and panic if condition true (cold path)
            self.asm.mov_store32_imm(CTX, CTX_PC as i32, pc as i32);
            self.asm.mov_ri64(SCRATCH, imm);
            self.asm.cmp_rr(reg, SCRATCH);
            self.asm.jcc_label(cc, self.panic_label);
            return;
        }
        self.asm.mov_ri64(SCRATCH, imm);
        self.asm.cmp_rr(reg, SCRATCH);
        let label = self.label_for_pc(target);
        self.asm.jcc_label(cc, label);
    }

    /// Emit a branch comparing two registers.
    fn emit_branch_reg(&mut self, a: Reg, b: Reg, cc: Cc, target: u32, _fallthrough: u32, pc: u32) {
        if !self.is_basic_block_start(target) {
            self.asm.mov_store32_imm(CTX, CTX_PC as i32, pc as i32);
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
    fn emit_alu3_64(&mut self, args: &Args, op: impl FnOnce(&mut Assembler, Reg, Reg)) {
        if let Args::ThreeReg { ra, rb, rd } = args {

            let d = REG_MAP[*rd];
            let a = REG_MAP[*ra];
            let b = REG_MAP[*rb];
            if *rd == *ra {
                // d is already a, just apply op with b
                op(&mut self.asm, d, b);
            } else if *rd == *rb {
                // d is b — save b to SCRATCH before overwriting d
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
                self.asm.mov_rr(SCRATCH, b);
                self.asm.mov_rr(d, a);
                self.asm.sub_rr32(d, SCRATCH);
            } else {
                self.asm.mov_rr(d, a);
                self.asm.sub_rr32(d, b);
            }
            self.asm.movsxd(d, d);

        }
    }

    /// Division/remainder.
    fn emit_div(&mut self, args: &Args, signed: bool, remainder: bool, is_32bit: bool) {
        if let Args::ThreeReg { ra, rb, rd } = args {
            // Division uses RAX and RDX implicitly.
            // RAX = φ[11], RDX = SCRATCH (not a PVM reg)
            // We need to save φ[11] (RAX) around the operation.

            // Load spilled register if ra or rb is phi[12]

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

            // x86 DIV/IDIV: dividend in RDX:RAX, divisor in any GPR except RAX/RDX.
            // Quotient → RAX, remainder → RDX. Both are always clobbered.
            // RCX is used as divisor register and must be saved/restored (it's phi[12]).
            //
            // Strategy: save RAX, RDX, and RCX to stack, load operands from saved
            // values if needed, perform division, then push result, restore all three,
            // and load result into d_reg last.

            // Save RAX, RDX, and RCX.
            self.asm.push(Reg::RAX);
            self.asm.push(SCRATCH); // SCRATCH = RDX
            self.asm.push(Reg::RCX);
            // Stack: [RSP+0]=old_RCX, [RSP+8]=old_RDX, [RSP+16]=old_RAX

            // Load divisor into RCX.
            if b_reg == Reg::RAX {
                self.asm.mov_load64(Reg::RCX, Reg::RSP, 16); // original RAX
            } else if b_reg == SCRATCH {
                self.asm.mov_load64(Reg::RCX, Reg::RSP, 8); // original RDX
            } else if b_reg == Reg::RCX {
                self.asm.mov_load64(Reg::RCX, Reg::RSP, 0); // original RCX
            } else {
                self.asm.mov_rr(Reg::RCX, b_reg);
            }

            // Load dividend into RAX.
            if a_reg == Reg::RAX {
                self.asm.mov_load64(Reg::RAX, Reg::RSP, 16); // original RAX
            } else if a_reg == SCRATCH {
                self.asm.mov_load64(Reg::RAX, Reg::RSP, 8); // original RDX
            } else if a_reg == Reg::RCX {
                self.asm.mov_load64(Reg::RAX, Reg::RSP, 0); // original RCX
            } else {
                self.asm.mov_rr(Reg::RAX, a_reg);
            }

            // Perform the division.
            if is_32bit {
                if signed {
                    self.asm.movsxd(Reg::RAX, Reg::RAX);
                    self.asm.cdq();
                    self.asm.idiv32(Reg::RCX);
                } else {
                    self.asm.movzx_32_64(Reg::RAX, Reg::RAX);
                    self.asm.mov_ri64(SCRATCH, 0);
                    self.asm.div32(Reg::RCX);
                }
            } else {
                if signed {
                    self.asm.cqo();
                    self.asm.idiv64(Reg::RCX);
                } else {
                    self.asm.mov_ri64(SCRATCH, 0);
                    self.asm.div64(Reg::RCX);
                }
            }

            // Result: quotient in RAX, remainder in RDX (SCRATCH).
            let result_reg = if remainder { SCRATCH } else { Reg::RAX };

            // Push result, restore RAX/RDX/RCX, then load result into d_reg.
            // This ordering ensures d_reg gets the correct value even when
            // d_reg is RAX, RDX, or RCX (the load happens after the restore).
            self.asm.push(result_reg);
            // Stack: [RSP+0]=result, [RSP+8]=old_RCX, [RSP+16]=old_RDX, [RSP+24]=old_RAX
            self.asm.mov_load64(Reg::RAX, Reg::RSP, 24); // restore original RAX
            self.asm.mov_load64(SCRATCH, Reg::RSP, 16);   // restore original RDX
            self.asm.mov_load64(Reg::RCX, Reg::RSP, 8);   // restore original RCX
            self.asm.mov_load64(d_reg, Reg::RSP, 0);      // load result (last!)
            self.asm.add_ri(Reg::RSP, 32);                 // clean up 4 stack slots

            if is_32bit {
                self.asm.movsxd(d_reg, d_reg);
            }

            self.asm.bind_label(done);

        }
    }

    /// Multiply upper (128-bit product, take high 64 bits).
    fn emit_mul_upper(&mut self, args: &Args, a_signed: bool, b_signed: bool) {
        if let Args::ThreeReg { ra, rb, rd } = args {
            // MUL/IMUL uses RAX (φ[11]) and RDX (SCRATCH) implicitly.
            // Save original RAX and RDX.
            self.asm.push(Reg::RAX);  // save φ[11]
            self.asm.push(SCRATCH);   // save RDX
            // Stack: [RSP+0]=orig_RDX, [RSP+8]=orig_RAX

            // Load ra into RAX
            self.asm.mov_rr(Reg::RAX, REG_MAP[*ra]);

            // Handle rb being RAX (φ[11], which we've overwritten with ra).
            let mul_src = if REG_MAP[*rb] == Reg::RAX {
                // rb is φ[11] = RAX; original value is on stack at [RSP+8]
                self.asm.mov_load64(SCRATCH, Reg::RSP, 8);
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
                // Save rb and ra's sign for post-multiply adjustment
                self.asm.push(mul_src); // save rb
                self.asm.push(Reg::RAX); // save ra (for sign check)
                // Now do unsigned multiply. mul_src might be SCRATCH which is
                // clobbered by the pushes. Reload from stack if needed.
                if REG_MAP[*rb] == Reg::RAX {
                    // rb was in SCRATCH (loaded from stack). It's saved at [RSP+8].
                    self.asm.mov_load64(SCRATCH, Reg::RSP, 8);
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
            // Save result, restore original RAX and RDX, put result in rd.
            self.asm.push(SCRATCH); // push result_hi
            // Stack: [RSP+0]=result_hi, [RSP+8]=orig_RDX, [RSP+16]=orig_RAX
            self.asm.mov_load64(SCRATCH, Reg::RSP, 8);  // restore original RDX
            self.asm.mov_load64(Reg::RAX, Reg::RSP, 16); // restore original RAX
            self.asm.pop(REG_MAP[*rd]); // rd = result_hi
            self.asm.add_ri(Reg::RSP, 16); // discard orig_RDX and orig_RAX

        }
    }

/// Emit an exit sequence that sets exit_reason and exit_arg.
    fn emit_exit(&mut self, reason: u32, arg: u32) {
        self.asm.mov_store32_imm(CTX, CTX_EXIT_REASON as i32, reason as i32);
        self.asm.mov_store32_imm(CTX, CTX_EXIT_ARG as i32, arg as i32);
        self.asm.jmp_label(self.exit_label);
    }

    /// Emit prologue: save callee-saved, load PVM registers from context,
    /// then dispatch to the correct basic block based on entry_pc.
    fn emit_prologue(&mut self) {
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
        self.asm.mov_store32_imm(CTX, CTX_EXIT_REASON as i32, 0);

        // --- O(1) dispatch via table lookup (before loading PVM regs) ---
        self.asm.mov_load32(SCRATCH, CTX, CTX_ENTRY_PC);
        self.asm.mov_load64(Reg::RAX, CTX, CTX_DISPATCH_TABLE);
        self.asm.movsxd_load_sib4(Reg::RAX, Reg::RAX, SCRATCH);
        self.asm.mov_load64(SCRATCH, CTX, CTX_CODE_BASE);
        self.asm.add_rr(Reg::RAX, SCRATCH);
        self.asm.push(Reg::RAX);

        // Load all 13 PVM registers from context
        for i in 0..13 {
            self.asm.mov_load64(REG_MAP[i], CTX, CTX_REGS + (i as i32) * 8);
        }

        // Jump to the dispatch target (pop into SCRATCH, then indirect jump)
        self.asm.pop(SCRATCH);
        self.asm.jmp_reg(SCRATCH);
    }

    /// Emit exit sequences and epilogue.
    fn emit_exit_sequences(&mut self) {
        // Per-gas-block OOG stubs: store PC, jump to shared OOG handler.
        // JAR v0.8.0 pipeline gas: the full block cost is always the correct
        // charge, so we let the subtraction stand (no gas restore needed).
        let stubs = std::mem::take(&mut self.oog_stubs);
        for (label, pvm_pc, _cost) in &stubs {
            self.asm.bind_label(*label);
            self.asm.mov_store32_imm(CTX, CTX_PC as i32, *pvm_pc as i32);
            self.asm.jmp_label(self.oog_label);
        }

        // Per-memory-access fault stubs: store PC, jump to shared fault handler.
        // Each stub is ~16 bytes (vs old ~35 bytes) thanks to shared handler.
        let fault_stubs = std::mem::take(&mut self.fault_stubs);
        for (label, pvm_pc) in &fault_stubs {
            self.asm.bind_label(*label);
            self.asm.mov_store32_imm(CTX, CTX_PC as i32, *pvm_pc as i32);
            self.asm.jmp_label(self.fault_exit_label);
        }

        // Shared page fault handler: set exit reason, store fault addr, exit.
        self.asm.bind_label(self.fault_exit_label);
        self.asm.mov_store32_imm(CTX, CTX_EXIT_REASON, EXIT_PAGE_FAULT as i32);
        self.asm.mov_store32(CTX, CTX_EXIT_ARG, SCRATCH);
        self.asm.jmp_label(self.exit_label);

        // Shared out-of-gas exit
        self.asm.bind_label(self.oog_label);
        self.asm.mov_store32_imm(CTX, CTX_EXIT_REASON as i32, EXIT_OOG as i32);
        self.asm.jmp_label(self.exit_label);

        // Panic exit
        self.asm.bind_label(self.panic_label);
        self.asm.mov_store32_imm(CTX, CTX_EXIT_REASON as i32, EXIT_PANIC as i32);
        // fall through to exit_label

        // Common exit: save all 13 PVM registers to context, restore callee-saved, return
        self.asm.bind_label(self.exit_label);
        for i in 0..13 {
            self.asm.mov_store64(CTX, CTX_REGS + (i as i32) * 8, REG_MAP[i]);
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
            Opcode::LoadU8 | Opcode::LoadI8 | Opcode::LoadIndU8 | Opcode::LoadIndI8 => self.helpers.mem_read_u8,
            Opcode::LoadU16 | Opcode::LoadI16 | Opcode::LoadIndU16 | Opcode::LoadIndI16 => self.helpers.mem_read_u16,
            Opcode::LoadU32 | Opcode::LoadI32 | Opcode::LoadIndU32 | Opcode::LoadIndI32 => self.helpers.mem_read_u32,
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

