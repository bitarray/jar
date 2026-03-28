//! PVM execution engine (Appendix A of the Gray Paper v0.7.2).
//!
//! Implements the single-step state transition Ψ₁ and the full PVM Ψ.

use alloc::{vec, vec::Vec};

use crate::args::{self, Args};
use crate::instruction::Opcode;
use crate::{Gas, PVM_REGISTER_COUNT};

/// Exit reason for PVM execution (ε values, eq A.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExitReason {
    /// ∎: Normal halt.
    Halt,
    /// ☇: Panic / unexpected termination.
    Panic,
    /// ∞: Out of gas.
    OutOfGas,
    /// ×: Page fault at the given page address.
    PageFault(u32),
    /// h̵: Host-call with the given identifier.
    HostCall(u32),
}

/// Pre-decoded instruction for the fast interpreter path.
///
/// Flattened representation: all operands stored directly (no enum discrimination
/// needed at runtime). This avoids the Args pattern-matching overhead.
#[derive(Clone, Copy, Debug)]
pub struct DecodedInst {
    pub opcode: Opcode,
    /// Register A (first register operand, context-dependent).
    pub ra: u8,
    /// Register B (second register operand, context-dependent).
    pub rb: u8,
    /// Register D (destination register, context-dependent).
    pub rd: u8,
    /// First immediate / offset value.
    pub imm1: u64,
    /// Second immediate / offset value.
    pub imm2: u64,
    /// Byte offset of this instruction in the code.
    pub pc: u32,
    /// Byte offset of the next sequential instruction.
    pub next_pc: u32,
    /// Pre-resolved instruction index for the next sequential instruction.
    pub next_idx: u32,
    /// Pre-resolved instruction index for the branch/jump target (u32::MAX = invalid).
    pub target_idx: u32,
    /// Gas cost to charge at gas-block entry (0 for non-gas-block-start instructions).
    /// Gas blocks are {PC=0} ∪ {post-terminator PCs} — branch targets are NOT gas block starts.
    pub bb_gas_cost: u64,
}

/// PVM instance state (eq A.6).
#[derive(Clone, Debug)]
pub struct Pvm {
    /// ϱ: Gas counter (remaining gas).
    pub gas: Gas,
    /// φ: 13 general-purpose 64-bit registers.
    pub registers: [u64; PVM_REGISTER_COUNT],
    /// µ: Memory state (flat linear buffer).
    pub flat_mem: Vec<u8>,
    /// ı: Instruction counter (program counter), indexes into code bytes.
    pub pc: u32,
    /// c: Instruction bytecode.
    pub code: Vec<u8>,
    /// k: Opcode bitmask (1 = start of instruction).
    pub bitmask: Vec<u8>,
    /// j: Dynamic jump table (indices into code).
    pub jump_table: Vec<u32>,
    /// Heap base address (h) for sbrk.
    pub heap_base: u32,
    /// Current heap top pointer for sbrk (heap_base + total_allocated).
    pub heap_top: u32,
    /// Set of valid branch/jump landing targets (post-terminator PCs + static branch targets).
    /// Used for branch validation, not for gas block boundaries.
    pub(crate) basic_block_starts: Vec<bool>,
    /// Gas cost for each gas block (indexed by block start PC).
    /// Only entries at gas block starts are meaningful. Gas blocks are
    /// {PC=0} ∪ {post-terminator PCs}, NOT branch targets.
    pub block_gas_costs: Vec<u64>,
    /// JAR v0.8.0: true when the next instruction should be charged block gas.
    /// Set at initialization and after every terminator instruction.
    pub need_gas_charge: bool,
    /// When true, collect instruction trace in `pc_trace`.
    pub tracing_enabled: bool,
    /// Collected instruction trace: (PC, opcode_byte) pairs.
    pub pc_trace: Vec<(u32, u8)>,
    /// Pre-decoded instruction stream (indexed by instruction number).
    pub(crate) decoded_insts: Vec<DecodedInst>,
    /// Mapping from PC byte offset → instruction index. u32::MAX = invalid.
    pub(crate) pc_to_idx: Vec<u32>,
}

impl Pvm {
    /// Create a new PVM from parsed program components.
    pub fn new(
        code: Vec<u8>,
        bitmask: Vec<u8>,
        jump_table: Vec<u32>,
        registers: [u64; PVM_REGISTER_COUNT],
        flat_mem: Vec<u8>,
        gas: Gas,
    ) -> Self {
        let basic_block_starts = compute_basic_block_starts(&code, &bitmask);
        let gas_block_starts = compute_gas_block_starts(&code, &bitmask);
        let block_gas_costs = compute_block_gas_costs(&code, &bitmask, &gas_block_starts);
        let (decoded_insts, pc_to_idx) =
            predecode_instructions(&code, &bitmask, &basic_block_starts, &gas_block_starts, &block_gas_costs);
        Self {
            gas,
            registers,
            flat_mem,
            pc: 0,
            code,
            bitmask,
            jump_table,
            heap_base: 0,
            heap_top: 0,
            basic_block_starts,
            block_gas_costs,
            need_gas_charge: true,
            tracing_enabled: false,
            pc_trace: Vec::new(),
            decoded_insts,
            pc_to_idx,
        }
    }

    /// Create a simple PVM for testing (code only, trivial bitmask).
    pub fn new_simple(code: Vec<u8>, registers: [u64; PVM_REGISTER_COUNT], flat_mem: Vec<u8>, gas: Gas) -> Self {
        // Build a bitmask where every byte is marked as an instruction start
        // This is a simplified mode; real programs use deblob.
        let bitmask = vec![1u8; code.len()];
        Self::new(code, bitmask, vec![], registers, flat_mem, gas)
    }

    // --- Flat memory accessors ---
    //
    // Use direct pointer access with a single bounds check for the hot path.
    // On little-endian x86, read_unaligned/write_unaligned compile to single
    // MOV instructions. The bounds check is a single comparison (no slice ops).

    #[inline(always)]
    pub fn read_u8(&self, addr: u32) -> Option<u8> {
        let a = addr as usize;
        if a < self.flat_mem.len() {
            Some(unsafe { *self.flat_mem.get_unchecked(a) })
        } else {
            None
        }
    }

    #[inline(always)]
    fn read_u16_le(&self, addr: u32) -> Option<u16> {
        let a = addr as usize;
        if a + 2 <= self.flat_mem.len() {
            Some(unsafe { self.flat_mem.as_ptr().add(a).cast::<u16>().read_unaligned() })
        } else {
            None
        }
    }

    #[inline(always)]
    fn read_u32_le(&self, addr: u32) -> Option<u32> {
        let a = addr as usize;
        if a + 4 <= self.flat_mem.len() {
            Some(unsafe { self.flat_mem.as_ptr().add(a).cast::<u32>().read_unaligned() })
        } else {
            None
        }
    }

    #[inline(always)]
    fn read_u64_le(&self, addr: u32) -> Option<u64> {
        let a = addr as usize;
        if a + 8 <= self.flat_mem.len() {
            Some(unsafe { self.flat_mem.as_ptr().add(a).cast::<u64>().read_unaligned() })
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn write_u8(&mut self, addr: u32, val: u8) -> bool {
        let a = addr as usize;
        if a < self.flat_mem.len() {
            unsafe { *self.flat_mem.get_unchecked_mut(a) = val; }
            true
        } else {
            false
        }
    }

    #[inline(always)]
    fn write_u16_le(&mut self, addr: u32, val: u16) -> bool {
        let a = addr as usize;
        if a + 2 <= self.flat_mem.len() {
            unsafe { self.flat_mem.as_mut_ptr().add(a).cast::<u16>().write_unaligned(val); }
            true
        } else {
            false
        }
    }

    #[inline(always)]
    fn write_u32_le(&mut self, addr: u32, val: u32) -> bool {
        let a = addr as usize;
        if a + 4 <= self.flat_mem.len() {
            unsafe { self.flat_mem.as_mut_ptr().add(a).cast::<u32>().write_unaligned(val); }
            true
        } else {
            false
        }
    }

    #[inline(always)]
    fn write_u64_le(&mut self, addr: u32, val: u64) -> bool {
        let a = addr as usize;
        if a + 8 <= self.flat_mem.len() {
            unsafe { self.flat_mem.as_mut_ptr().add(a).cast::<u64>().write_unaligned(val); }
            true
        } else {
            false
        }
    }

    /// Compute skip(i) — distance to next instruction minus one (eq A.3).
    fn skip(&self, i: usize) -> usize {
        // skip(i) = min(24, first j where (k ++ [1,1,...])_{i+1+j} = 1)
        for j in 0..25 {
            let idx = i + 1 + j;
            let bit = if idx < self.bitmask.len() {
                self.bitmask[idx]
            } else {
                1 // infinite 1s appended
            };
            if bit == 1 {
                return j;
            }
        }
        24
    }

    /// Read from ζ (code with implicit zero extension, eq A.4).
    fn zeta(&self, i: usize) -> u8 {
        if i < self.code.len() { self.code[i] } else { 0 }
    }

    /// Check if a code index is a valid basic block start (public accessor).
    pub fn is_basic_block_start(&self, idx: u64) -> bool {
        let i = idx as usize;
        if i < self.basic_block_starts.len() {
            self.basic_block_starts[i]
        } else {
            false
        }
    }

    /// Handle static branch (eq A.17).
    /// Returns (exit_reason, new_pc) where exit_reason is None for continue.
    fn branch(&self, target: u64, condition: bool, next_pc: u32) -> (Option<ExitReason>, u32) {
        if !condition {
            (None, next_pc)
        } else if !self.is_basic_block_start(target) {
            (Some(ExitReason::Panic), self.pc)
        } else {
            (None, target as u32)
        }
    }

    /// Handle dynamic jump (eq A.18).
    fn djump(&self, a: u64) -> (Option<ExitReason>, u32) {
        const ZA: u64 = 2; // Jump alignment factor
        let halt_addr = (1u64 << 32) - (1u64 << 16);

        if a == halt_addr {
            return (Some(ExitReason::Halt), self.pc);
        }
        if a == 0 || a > self.jump_table.len() as u64 * ZA || a % ZA != 0 {
            return (Some(ExitReason::Panic), self.pc);
        }
        let idx = (a / ZA) as usize - 1;
        let target = self.jump_table[idx];
        if !self.is_basic_block_start(target as u64) {
            return (Some(ExitReason::Panic), self.pc);
        }
        (None, target)
    }

    /// Execute a single instruction step Ψ₁ (eq A.6-A.9).
    ///
    /// Gas is charged per gas block: the entire block's cost is deducted
    /// when entering the block. Gas block starts are {PC=0} ∪ {post-terminator PCs};
    /// branch targets are NOT gas block starts (they are validation-only).
    ///
    /// Returns the exit reason if the machine should stop, or None to continue.
    pub fn step(&mut self) -> Option<ExitReason> {
        let pc = self.pc as usize;

        // Fetch and validate opcode (eq A.19)
        let opcode_byte = self.zeta(pc);
        let bitmask_valid = pc < self.bitmask.len() && self.bitmask[pc] == 1;

        let opcode = if bitmask_valid {
            Opcode::from_byte(opcode_byte)
        } else {
            None
        };

        let opcode = match opcode {
            Some(op) => op,
            None => {
                return Some(ExitReason::Panic);
            }
        };

        // Per-gas-block metering (JAR v0.8.0).
        // Gas is charged at gas block entries: initial entry (PC=0) and after
        // terminators. Branch/jump targets are NOT gas block starts per spec
        // (Lean Interpreter.lean:130, GP PR #508).
        if self.need_gas_charge {
            let block_cost = self.block_gas_costs[pc];
            if self.gas < block_cost {
                return Some(ExitReason::OutOfGas);
            }
            self.gas -= block_cost;
            self.need_gas_charge = false;
        }

        // Collect trace if enabled
        if self.tracing_enabled {
            self.pc_trace.push((self.pc, opcode_byte));
        }

        // Compute skip length ℓ (eq A.20)
        let skip = self.skip(pc);

        // Default next PC: ı + 1 + skip(ı) (eq A.9)
        let next_pc = (pc + 1 + skip) as u32;

        // Decode arguments
        let category = opcode.category();
        let args = args::decode_args(&self.code, pc, skip, category);

        // Per-instruction trace
        tracing::trace!(pc, ?opcode, gas = self.gas, "pvm-inst");

        // Execute instruction inline
        match opcode {
            // === A.5.1: No arguments ===
            Opcode::Trap => return Some(ExitReason::Panic),
            Opcode::Fallthrough | Opcode::Unlikely => { self.pc = next_pc; }

            // === A.5.2: One immediate ===
            Opcode::Ecalli => {
                if let Args::Imm { imm } = args {
                    // Advance PC to next instruction before returning (eq A.9)
                    self.pc = next_pc;
                    return Some(ExitReason::HostCall(imm as u32));
                }
            }

            // === A.5.3: One register + extended immediate ===
            Opcode::LoadImm64 => {
                if let Args::RegExtImm { ra, imm } = args {
                    self.registers[ra] = imm;
                    self.pc = next_pc;
                }
            }

            // === A.5.4: Two immediates (store_imm) ===
            Opcode::StoreImmU8 => {
                if let Args::TwoImm { imm_x, imm_y } = args {
                    let addr = imm_x as u32;

                    if self.write_u8(addr, imm_y as u8) { self.pc = next_pc; }
                    else { return Some(ExitReason::PageFault(addr & !0xFFF)); }
                }
            }
            Opcode::StoreImmU16 => {
                if let Args::TwoImm { imm_x, imm_y } = args {
                    let addr = imm_x as u32;

                    if self.write_u16_le(addr, imm_y as u16) { self.pc = next_pc; }
                    else { return Some(ExitReason::PageFault(addr & !0xFFF)); }
                }
            }
            Opcode::StoreImmU32 => {
                if let Args::TwoImm { imm_x, imm_y } = args {
                    let addr = imm_x as u32;

                    if self.write_u32_le(addr, imm_y as u32) { self.pc = next_pc; }
                    else { return Some(ExitReason::PageFault(addr & !0xFFF)); }
                }
            }
            Opcode::StoreImmU64 => {
                if let Args::TwoImm { imm_x, imm_y } = args {
                    let addr = imm_x as u32;

                    if self.write_u64_le(addr, imm_y) { self.pc = next_pc; }
                    else { return Some(ExitReason::PageFault(addr & !0xFFF)); }
                }
            }

            // === A.5.5: One offset (jump) ===
            Opcode::Jump => {
                if let Args::Offset { offset } = args {
                    let (exit, new_pc) = self.branch(offset, true, next_pc);
                    if let Some(e) = exit { return Some(e); }
                    self.pc = new_pc;
                }
            }

            // === A.5.6: One register + one immediate ===
            Opcode::JumpInd => {
                if let Args::RegImm { ra, imm } = args {
                    let addr = self.registers[ra].wrapping_add(imm) % (1u64 << 32);
                    let (exit, new_pc) = self.djump(addr);
                    if let Some(e) = exit { return Some(e); }
                    self.pc = new_pc;
                }
            }
            Opcode::LoadImm => {
                if let Args::RegImm { ra, imm } = args {
                    self.registers[ra] = imm;
                    self.pc = next_pc;
                }
            }
            Opcode::LoadU8 => {
                if let Args::RegImm { ra, imm } = args {
                    let addr = imm as u32;

                    match self.read_u8(addr) {
                        Some(v) => { self.registers[ra] = v as u64; self.pc = next_pc; }
                        None => return Some(ExitReason::PageFault(addr & !0xFFF)),
                    }
                }
            }
            Opcode::LoadI8 => {
                if let Args::RegImm { ra, imm } = args {
                    let addr = imm as u32;

                    match self.read_u8(addr) {
                        Some(v) => { self.registers[ra] = v as i8 as i64 as u64; self.pc = next_pc; }
                        None => return Some(ExitReason::PageFault(addr & !0xFFF)),
                    }
                }
            }
            Opcode::LoadU16 => {
                if let Args::RegImm { ra, imm } = args {
                    let addr = imm as u32;

                    match self.read_u16_le(addr) {
                        Some(v) => { self.registers[ra] = v as u64; self.pc = next_pc; }
                        None => return Some(ExitReason::PageFault(addr & !0xFFF)),
                    }
                }
            }
            Opcode::LoadI16 => {
                if let Args::RegImm { ra, imm } = args {
                    let addr = imm as u32;

                    match self.read_u16_le(addr) {
                        Some(v) => { self.registers[ra] = v as i16 as i64 as u64; self.pc = next_pc; }
                        None => return Some(ExitReason::PageFault(addr & !0xFFF)),
                    }
                }
            }
            Opcode::LoadU32 => {
                if let Args::RegImm { ra, imm } = args {
                    let addr = imm as u32;

                    match self.read_u32_le(addr) {
                        Some(v) => { self.registers[ra] = v as u64; self.pc = next_pc; }
                        None => return Some(ExitReason::PageFault(addr & !0xFFF)),
                    }
                }
            }
            Opcode::LoadI32 => {
                if let Args::RegImm { ra, imm } = args {
                    let addr = imm as u32;

                    match self.read_u32_le(addr) {
                        Some(v) => { self.registers[ra] = v as i32 as i64 as u64; self.pc = next_pc; }
                        None => return Some(ExitReason::PageFault(addr & !0xFFF)),
                    }
                }
            }
            Opcode::LoadU64 => {
                if let Args::RegImm { ra, imm } = args {
                    let addr = imm as u32;

                    match self.read_u64_le(addr) {
                        Some(v) => { self.registers[ra] = v; self.pc = next_pc; }
                        None => return Some(ExitReason::PageFault(addr & !0xFFF)),
                    }
                }
            }
            Opcode::StoreU8 => {
                if let Args::RegImm { ra, imm } = args {
                    let addr = imm as u32;

                    if self.write_u8(addr, self.registers[ra] as u8) { self.pc = next_pc; }
                    else { return Some(ExitReason::PageFault(addr & !0xFFF)); }
                }
            }
            Opcode::StoreU16 => {
                if let Args::RegImm { ra, imm } = args {
                    let addr = imm as u32;

                    if self.write_u16_le(addr, self.registers[ra] as u16) { self.pc = next_pc; }
                    else { return Some(ExitReason::PageFault(addr & !0xFFF)); }
                }
            }
            Opcode::StoreU32 => {
                if let Args::RegImm { ra, imm } = args {
                    let addr = imm as u32;

                    if self.write_u32_le(addr, self.registers[ra] as u32) { self.pc = next_pc; }
                    else { return Some(ExitReason::PageFault(addr & !0xFFF)); }
                }
            }
            Opcode::StoreU64 => {
                if let Args::RegImm { ra, imm } = args {
                    let addr = imm as u32;

                    if self.write_u64_le(addr, self.registers[ra]) { self.pc = next_pc; }
                    else { return Some(ExitReason::PageFault(addr & !0xFFF)); }
                }
            }

            // === A.5.7: One register + two immediates (store_imm_ind) ===
            Opcode::StoreImmIndU8 => {
                if let Args::RegTwoImm { ra, imm_x, imm_y } = args {
                    let addr = self.registers[ra].wrapping_add(imm_x) as u32;

                    if self.write_u8(addr, imm_y as u8) { self.pc = next_pc; }
                    else { return Some(ExitReason::PageFault(addr & !0xFFF)); }
                }
            }
            Opcode::StoreImmIndU16 => {
                if let Args::RegTwoImm { ra, imm_x, imm_y } = args {
                    let addr = self.registers[ra].wrapping_add(imm_x) as u32;

                    if self.write_u16_le(addr, imm_y as u16) { self.pc = next_pc; }
                    else { return Some(ExitReason::PageFault(addr & !0xFFF)); }
                }
            }
            Opcode::StoreImmIndU32 => {
                if let Args::RegTwoImm { ra, imm_x, imm_y } = args {
                    let addr = self.registers[ra].wrapping_add(imm_x) as u32;

                    if self.write_u32_le(addr, imm_y as u32) { self.pc = next_pc; }
                    else { return Some(ExitReason::PageFault(addr & !0xFFF)); }
                }
            }
            Opcode::StoreImmIndU64 => {
                if let Args::RegTwoImm { ra, imm_x, imm_y } = args {
                    let addr = self.registers[ra].wrapping_add(imm_x) as u32;

                    if self.write_u64_le(addr, imm_y) { self.pc = next_pc; }
                    else { return Some(ExitReason::PageFault(addr & !0xFFF)); }
                }
            }

            // === A.5.8: One register + immediate + offset ===
            Opcode::LoadImmJump => {
                if let Args::RegImmOffset { ra, imm, offset } = args {
                    self.registers[ra] = imm;
                    let (exit, new_pc) = self.branch(offset, true, next_pc);
                    if let Some(e) = exit { return Some(e); }
                    self.pc = new_pc;
                }
            }
            Opcode::BranchEqImm => {
                if let Args::RegImmOffset { ra, imm, offset } = args {
                    let cond = self.registers[ra] == imm;
                    let (exit, new_pc) = self.branch(offset, cond, next_pc);
                    if let Some(e) = exit { return Some(e); }
                    self.pc = new_pc;
                }
            }
            Opcode::BranchNeImm => {
                if let Args::RegImmOffset { ra, imm, offset } = args {
                    let cond = self.registers[ra] != imm;
                    let (exit, new_pc) = self.branch(offset, cond, next_pc);
                    if let Some(e) = exit { return Some(e); }
                    self.pc = new_pc;
                }
            }
            Opcode::BranchLtUImm => {
                if let Args::RegImmOffset { ra, imm, offset } = args {
                    let cond = self.registers[ra] < imm;
                    let (exit, new_pc) = self.branch(offset, cond, next_pc);
                    if let Some(e) = exit { return Some(e); }
                    self.pc = new_pc;
                }
            }
            Opcode::BranchLeUImm => {
                if let Args::RegImmOffset { ra, imm, offset } = args {
                    let cond = self.registers[ra] <= imm;
                    let (exit, new_pc) = self.branch(offset, cond, next_pc);
                    if let Some(e) = exit { return Some(e); }
                    self.pc = new_pc;
                }
            }
            Opcode::BranchGeUImm => {
                if let Args::RegImmOffset { ra, imm, offset } = args {
                    let cond = self.registers[ra] >= imm;
                    let (exit, new_pc) = self.branch(offset, cond, next_pc);
                    if let Some(e) = exit { return Some(e); }
                    self.pc = new_pc;
                }
            }
            Opcode::BranchGtUImm => {
                if let Args::RegImmOffset { ra, imm, offset } = args {
                    let cond = self.registers[ra] > imm;
                    let (exit, new_pc) = self.branch(offset, cond, next_pc);
                    if let Some(e) = exit { return Some(e); }
                    self.pc = new_pc;
                }
            }
            Opcode::BranchLtSImm => {
                if let Args::RegImmOffset { ra, imm, offset } = args {
                    let cond = (self.registers[ra] as i64) < (imm as i64);
                    let (exit, new_pc) = self.branch(offset, cond, next_pc);
                    if let Some(e) = exit { return Some(e); }
                    self.pc = new_pc;
                }
            }
            Opcode::BranchLeSImm => {
                if let Args::RegImmOffset { ra, imm, offset } = args {
                    let cond = (self.registers[ra] as i64) <= (imm as i64);
                    let (exit, new_pc) = self.branch(offset, cond, next_pc);
                    if let Some(e) = exit { return Some(e); }
                    self.pc = new_pc;
                }
            }
            Opcode::BranchGeSImm => {
                if let Args::RegImmOffset { ra, imm, offset } = args {
                    let cond = (self.registers[ra] as i64) >= (imm as i64);
                    let (exit, new_pc) = self.branch(offset, cond, next_pc);
                    if let Some(e) = exit { return Some(e); }
                    self.pc = new_pc;
                }
            }
            Opcode::BranchGtSImm => {
                if let Args::RegImmOffset { ra, imm, offset } = args {
                    let cond = (self.registers[ra] as i64) > (imm as i64);
                    let (exit, new_pc) = self.branch(offset, cond, next_pc);
                    if let Some(e) = exit { return Some(e); }
                    self.pc = new_pc;
                }
            }

            // === A.5.9: Two registers ===
            Opcode::MoveReg => {
                if let Args::TwoReg { rd, ra } = args {
                    self.registers[rd] = self.registers[ra];
                    self.pc = next_pc;
                }
            }
            Opcode::Sbrk => {
                // JAR v0.8.0: sbrk removed from ISA, replaced by grow_heap hostcall
                return Some(ExitReason::Panic);
            }
            Opcode::CountSetBits64 => {
                if let Args::TwoReg { rd, ra } = args {
                    self.registers[rd] = self.registers[ra].count_ones() as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::CountSetBits32 => {
                if let Args::TwoReg { rd, ra } = args {
                    self.registers[rd] = (self.registers[ra] as u32).count_ones() as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::LeadingZeroBits64 => {
                if let Args::TwoReg { rd, ra } = args {
                    self.registers[rd] = self.registers[ra].leading_zeros() as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::LeadingZeroBits32 => {
                if let Args::TwoReg { rd, ra } = args {
                    self.registers[rd] = (self.registers[ra] as u32).leading_zeros() as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::TrailingZeroBits64 => {
                if let Args::TwoReg { rd, ra } = args {
                    self.registers[rd] = self.registers[ra].trailing_zeros() as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::TrailingZeroBits32 => {
                if let Args::TwoReg { rd, ra } = args {
                    self.registers[rd] = (self.registers[ra] as u32).trailing_zeros() as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::SignExtend8 => {
                if let Args::TwoReg { rd, ra } = args {
                    self.registers[rd] = (self.registers[ra] as u8) as i8 as i64 as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::SignExtend16 => {
                if let Args::TwoReg { rd, ra } = args {
                    self.registers[rd] = (self.registers[ra] as u16) as i16 as i64 as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::ZeroExtend16 => {
                if let Args::TwoReg { rd, ra } = args {
                    self.registers[rd] = self.registers[ra] % (1 << 16);
                    self.pc = next_pc;
                }
            }
            Opcode::ReverseBytes => {
                if let Args::TwoReg { rd, ra } = args {
                    self.registers[rd] = self.registers[ra].swap_bytes();
                    self.pc = next_pc;
                }
            }

            // === A.5.10: Two registers + one immediate ===
            Opcode::StoreIndU8 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let addr = self.registers[rb].wrapping_add(imm) as u32;

                    if self.write_u8(addr, self.registers[ra] as u8) { self.pc = next_pc; }
                    else { return Some(ExitReason::PageFault(addr & !0xFFF)); }
                }
            }
            Opcode::StoreIndU16 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let addr = self.registers[rb].wrapping_add(imm) as u32;

                    if self.write_u16_le(addr, self.registers[ra] as u16) { self.pc = next_pc; }
                    else { return Some(ExitReason::PageFault(addr & !0xFFF)); }
                }
            }
            Opcode::StoreIndU32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let addr = self.registers[rb].wrapping_add(imm) as u32;

                    if self.write_u32_le(addr, self.registers[ra] as u32) { self.pc = next_pc; }
                    else { return Some(ExitReason::PageFault(addr & !0xFFF)); }
                }
            }
            Opcode::StoreIndU64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let addr = self.registers[rb].wrapping_add(imm) as u32;

                    if self.write_u64_le(addr, self.registers[ra]) { self.pc = next_pc; }
                    else { return Some(ExitReason::PageFault(addr & !0xFFF)); }
                }
            }
            Opcode::LoadIndU8 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let addr = self.registers[rb].wrapping_add(imm) as u32;

                    match self.read_u8(addr) {
                        Some(v) => { self.registers[ra] = v as u64; self.pc = next_pc; }
                        None => return Some(ExitReason::PageFault(addr & !0xFFF)),
                    }
                }
            }
            Opcode::LoadIndI8 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let addr = self.registers[rb].wrapping_add(imm) as u32;

                    match self.read_u8(addr) {
                        Some(v) => { self.registers[ra] = v as i8 as i64 as u64; self.pc = next_pc; }
                        None => return Some(ExitReason::PageFault(addr & !0xFFF)),
                    }
                }
            }
            Opcode::LoadIndU16 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let addr = self.registers[rb].wrapping_add(imm) as u32;

                    match self.read_u16_le(addr) {
                        Some(v) => { self.registers[ra] = v as u64; self.pc = next_pc; }
                        None => return Some(ExitReason::PageFault(addr & !0xFFF)),
                    }
                }
            }
            Opcode::LoadIndI16 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let addr = self.registers[rb].wrapping_add(imm) as u32;

                    match self.read_u16_le(addr) {
                        Some(v) => { self.registers[ra] = v as i16 as i64 as u64; self.pc = next_pc; }
                        None => return Some(ExitReason::PageFault(addr & !0xFFF)),
                    }
                }
            }
            Opcode::LoadIndU32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let addr = self.registers[rb].wrapping_add(imm) as u32;

                    match self.read_u32_le(addr) {
                        Some(v) => { self.registers[ra] = v as u64; self.pc = next_pc; }
                        None => return Some(ExitReason::PageFault(addr & !0xFFF)),
                    }
                }
            }
            Opcode::LoadIndI32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let addr = self.registers[rb].wrapping_add(imm) as u32;

                    match self.read_u32_le(addr) {
                        Some(v) => { self.registers[ra] = v as i32 as i64 as u64; self.pc = next_pc; }
                        None => return Some(ExitReason::PageFault(addr & !0xFFF)),
                    }
                }
            }
            Opcode::LoadIndU64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let addr = self.registers[rb].wrapping_add(imm) as u32;

                    match self.read_u64_le(addr) {
                        Some(v) => { self.registers[ra] = v; self.pc = next_pc; }
                        None => return Some(ExitReason::PageFault(addr & !0xFFF)),
                    }
                }
            }
            Opcode::AddImm32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.registers[ra] = args::sign_extend_32(self.registers[rb].wrapping_add(imm));
                    self.pc = next_pc;
                }
            }
            Opcode::AndImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.registers[ra] = self.registers[rb] & imm;
                    self.pc = next_pc;
                }
            }
            Opcode::XorImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.registers[ra] = self.registers[rb] ^ imm;
                    self.pc = next_pc;
                }
            }
            Opcode::OrImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.registers[ra] = self.registers[rb] | imm;
                    self.pc = next_pc;
                }
            }
            Opcode::MulImm32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.registers[ra] = args::sign_extend_32(self.registers[rb].wrapping_mul(imm));
                    self.pc = next_pc;
                }
            }
            Opcode::SetLtUImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.registers[ra] = (self.registers[rb] < imm) as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::SetLtSImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.registers[ra] = ((self.registers[rb] as i64) < (imm as i64)) as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::ShloLImm32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let shift = (imm % 32) as u32;
                    self.registers[ra] = args::sign_extend_32((self.registers[rb] as u32).wrapping_shl(shift) as u64);
                    self.pc = next_pc;
                }
            }
            Opcode::ShloRImm32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let shift = (imm % 32) as u32;
                    self.registers[ra] = args::sign_extend_32((self.registers[rb] as u32).wrapping_shr(shift) as u64);
                    self.pc = next_pc;
                }
            }
            Opcode::SharRImm32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let shift = (imm % 32) as u32;
                    let val = (self.registers[rb] as u32) as i32;
                    self.registers[ra] = val.wrapping_shr(shift) as i64 as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::NegAddImm32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    // νX + 2^32 - φB, all mod 2^32, then sign-extend
                    let result = imm.wrapping_add((1u64 << 32).wrapping_sub(self.registers[rb]));
                    self.registers[ra] = args::sign_extend_32(result);
                    self.pc = next_pc;
                }
            }
            Opcode::SetGtUImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.registers[ra] = (self.registers[rb] > imm) as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::SetGtSImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.registers[ra] = ((self.registers[rb] as i64) > (imm as i64)) as u64;
                    self.pc = next_pc;
                }
            }
            // Alt shifts: operands swapped (νX as the value being shifted by φB)
            Opcode::ShloLImmAlt32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let shift = (self.registers[rb] % 32) as u32;
                    self.registers[ra] = args::sign_extend_32((imm as u32).wrapping_shl(shift) as u64);
                    self.pc = next_pc;
                }
            }
            Opcode::ShloRImmAlt32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let shift = (self.registers[rb] % 32) as u32;
                    self.registers[ra] = args::sign_extend_32((imm as u32).wrapping_shr(shift) as u64);
                    self.pc = next_pc;
                }
            }
            Opcode::SharRImmAlt32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let shift = (self.registers[rb] % 32) as u32;
                    let val = (imm as u32) as i32;
                    self.registers[ra] = val.wrapping_shr(shift) as i64 as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::CmovIzImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    if self.registers[rb] == 0 {
                        self.registers[ra] = imm;
                    }
                    self.pc = next_pc;
                }
            }
            Opcode::CmovNzImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    if self.registers[rb] != 0 {
                        self.registers[ra] = imm;
                    }
                    self.pc = next_pc;
                }
            }
            Opcode::AddImm64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.registers[ra] = self.registers[rb].wrapping_add(imm);
                    self.pc = next_pc;
                }
            }
            Opcode::MulImm64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.registers[ra] = self.registers[rb].wrapping_mul(imm);
                    self.pc = next_pc;
                }
            }
            Opcode::ShloLImm64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let shift = (imm % 64) as u32;
                    self.registers[ra] = self.registers[rb].wrapping_shl(shift);
                    self.pc = next_pc;
                }
            }
            Opcode::ShloRImm64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let shift = (imm % 64) as u32;
                    self.registers[ra] = self.registers[rb].wrapping_shr(shift);
                    self.pc = next_pc;
                }
            }
            Opcode::SharRImm64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let shift = (imm % 64) as u32;
                    self.registers[ra] = (self.registers[rb] as i64).wrapping_shr(shift) as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::NegAddImm64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.registers[ra] = imm.wrapping_sub(self.registers[rb]);
                    self.pc = next_pc;
                }
            }
            Opcode::ShloLImmAlt64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let shift = (self.registers[rb] % 64) as u32;
                    self.registers[ra] = imm.wrapping_shl(shift);
                    self.pc = next_pc;
                }
            }
            Opcode::ShloRImmAlt64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let shift = (self.registers[rb] % 64) as u32;
                    self.registers[ra] = imm.wrapping_shr(shift);
                    self.pc = next_pc;
                }
            }
            Opcode::SharRImmAlt64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let shift = (self.registers[rb] % 64) as u32;
                    self.registers[ra] = (imm as i64).wrapping_shr(shift) as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::RotR64Imm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.registers[ra] = self.registers[rb].rotate_right((imm % 64) as u32);
                    self.pc = next_pc;
                }
            }
            Opcode::RotR64ImmAlt => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.registers[ra] = imm.rotate_right((self.registers[rb] % 64) as u32);
                    self.pc = next_pc;
                }
            }
            Opcode::RotR32Imm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let val = self.registers[rb] as u32;
                    let result = val.rotate_right((imm % 32) as u32);
                    self.registers[ra] = args::sign_extend_32(result as u64);
                    self.pc = next_pc;
                }
            }
            Opcode::RotR32ImmAlt => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let val = imm as u32;
                    let result = val.rotate_right((self.registers[rb] % 32) as u32);
                    self.registers[ra] = args::sign_extend_32(result as u64);
                    self.pc = next_pc;
                }
            }

            // === A.5.11: Two registers + one offset ===
            Opcode::BranchEq => {
                if let Args::TwoRegOffset { ra, rb, offset } = args {
                    let cond = self.registers[ra] == self.registers[rb];
                    let (exit, new_pc) = self.branch(offset, cond, next_pc);
                    if let Some(e) = exit { return Some(e); }
                    self.pc = new_pc;
                }
            }
            Opcode::BranchNe => {
                if let Args::TwoRegOffset { ra, rb, offset } = args {
                    let cond = self.registers[ra] != self.registers[rb];
                    let (exit, new_pc) = self.branch(offset, cond, next_pc);
                    if let Some(e) = exit { return Some(e); }
                    self.pc = new_pc;
                }
            }
            Opcode::BranchLtU => {
                if let Args::TwoRegOffset { ra, rb, offset } = args {
                    let cond = self.registers[ra] < self.registers[rb];
                    let (exit, new_pc) = self.branch(offset, cond, next_pc);
                    if let Some(e) = exit { return Some(e); }
                    self.pc = new_pc;
                }
            }
            Opcode::BranchLtS => {
                if let Args::TwoRegOffset { ra, rb, offset } = args {
                    let cond = (self.registers[ra] as i64) < (self.registers[rb] as i64);
                    let (exit, new_pc) = self.branch(offset, cond, next_pc);
                    if let Some(e) = exit { return Some(e); }
                    self.pc = new_pc;
                }
            }
            Opcode::BranchGeU => {
                if let Args::TwoRegOffset { ra, rb, offset } = args {
                    let cond = self.registers[ra] >= self.registers[rb];
                    let (exit, new_pc) = self.branch(offset, cond, next_pc);
                    if let Some(e) = exit { return Some(e); }
                    self.pc = new_pc;
                }
            }
            Opcode::BranchGeS => {
                if let Args::TwoRegOffset { ra, rb, offset } = args {
                    let cond = (self.registers[ra] as i64) >= (self.registers[rb] as i64);
                    let (exit, new_pc) = self.branch(offset, cond, next_pc);
                    if let Some(e) = exit { return Some(e); }
                    self.pc = new_pc;
                }
            }

            // === A.5.12: Two registers + two immediates ===
            Opcode::LoadImmJumpInd => {
                if let Args::TwoRegTwoImm { ra, rb, imm_x, imm_y } = args {
                    self.registers[ra] = imm_x;
                    let addr = self.registers[rb].wrapping_add(imm_y) % (1u64 << 32);
                    let (exit, new_pc) = self.djump(addr);
                    if let Some(e) = exit { return Some(e); }
                    self.pc = new_pc;
                }
            }

            // === A.5.13: Three registers ===
            Opcode::Add32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] = args::sign_extend_32(self.registers[ra].wrapping_add(self.registers[rb]));
                    self.pc = next_pc;
                }
            }
            Opcode::Sub32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let a = self.registers[ra] as u32;
                    let b = self.registers[rb] as u32;
                    self.registers[rd] = args::sign_extend_32(a.wrapping_sub(b) as u64);
                    self.pc = next_pc;
                }
            }
            Opcode::Mul32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] = args::sign_extend_32(self.registers[ra].wrapping_mul(self.registers[rb]));
                    self.pc = next_pc;
                }
            }
            Opcode::DivU32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let a = self.registers[ra] as u32;
                    let b = self.registers[rb] as u32;
                    self.registers[rd] = if b == 0 {
                        u64::MAX
                    } else {
                        args::sign_extend_32((a / b) as u64)
                    };
                    self.pc = next_pc;
                }
            }
            Opcode::DivS32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let a = self.registers[ra] as u32 as i32;
                    let b = self.registers[rb] as u32 as i32;
                    self.registers[rd] = if b == 0 {
                        u64::MAX
                    } else if a == i32::MIN && b == -1 {
                        a as i64 as u64 // Z8^-1(Z4(a))
                    } else {
                        let q = if (a < 0) != (b < 0) && a % b != 0 {
                            a / b // rtz rounds toward zero, which Rust does
                        } else {
                            a / b
                        };
                        q as i64 as u64
                    };
                    self.pc = next_pc;
                }
            }
            Opcode::RemU32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let a = self.registers[ra] as u32;
                    let b = self.registers[rb] as u32;
                    self.registers[rd] = if b == 0 {
                        args::sign_extend_32(a as u64)
                    } else {
                        args::sign_extend_32((a % b) as u64)
                    };
                    self.pc = next_pc;
                }
            }
            Opcode::RemS32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let a = self.registers[ra] as u32 as i32;
                    let b = self.registers[rb] as u32 as i32;
                    self.registers[rd] = if a == i32::MIN && b == -1 {
                        0
                    } else if b == 0 {
                        a as i64 as u64
                    } else {
                        // smod: sign of numerator, mod of absolutes
                        let r = smod_i64(a as i64, b as i64);
                        r as u64
                    };
                    self.pc = next_pc;
                }
            }
            Opcode::ShloL32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let shift = (self.registers[rb] % 32) as u32;
                    self.registers[rd] = args::sign_extend_32((self.registers[ra] as u32).wrapping_shl(shift) as u64);
                    self.pc = next_pc;
                }
            }
            Opcode::ShloR32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let shift = (self.registers[rb] % 32) as u32;
                    self.registers[rd] = args::sign_extend_32((self.registers[ra] as u32).wrapping_shr(shift) as u64);
                    self.pc = next_pc;
                }
            }
            Opcode::SharR32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let shift = (self.registers[rb] % 32) as u32;
                    let val = self.registers[ra] as u32 as i32;
                    self.registers[rd] = val.wrapping_shr(shift) as i64 as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::Add64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] = self.registers[ra].wrapping_add(self.registers[rb]);
                    self.pc = next_pc;
                }
            }
            Opcode::Sub64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] = self.registers[ra].wrapping_sub(self.registers[rb]);
                    self.pc = next_pc;
                }
            }
            Opcode::Mul64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] = self.registers[ra].wrapping_mul(self.registers[rb]);
                    self.pc = next_pc;
                }
            }
            Opcode::DivU64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] = if self.registers[rb] == 0 {
                        u64::MAX
                    } else {
                        self.registers[ra] / self.registers[rb]
                    };
                    self.pc = next_pc;
                }
            }
            Opcode::DivS64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let a = self.registers[ra] as i64;
                    let b = self.registers[rb] as i64;
                    self.registers[rd] = if b == 0 {
                        u64::MAX
                    } else if a == i64::MIN && b == -1 {
                        a as u64
                    } else {
                        (a / b) as u64 // Rust truncates toward zero
                    };
                    self.pc = next_pc;
                }
            }
            Opcode::RemU64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] = if self.registers[rb] == 0 {
                        self.registers[ra]
                    } else {
                        self.registers[ra] % self.registers[rb]
                    };
                    self.pc = next_pc;
                }
            }
            Opcode::RemS64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let a = self.registers[ra] as i64;
                    let b = self.registers[rb] as i64;
                    self.registers[rd] = if a == i64::MIN && b == -1 {
                        0
                    } else if b == 0 {
                        a as u64
                    } else {
                        smod_i64(a, b) as u64
                    };
                    self.pc = next_pc;
                }
            }
            Opcode::ShloL64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let shift = (self.registers[rb] % 64) as u32;
                    self.registers[rd] = self.registers[ra].wrapping_shl(shift);
                    self.pc = next_pc;
                }
            }
            Opcode::ShloR64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let shift = (self.registers[rb] % 64) as u32;
                    self.registers[rd] = self.registers[ra].wrapping_shr(shift);
                    self.pc = next_pc;
                }
            }
            Opcode::SharR64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let shift = (self.registers[rb] % 64) as u32;
                    self.registers[rd] = (self.registers[ra] as i64).wrapping_shr(shift) as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::And => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] = self.registers[ra] & self.registers[rb];
                    self.pc = next_pc;
                }
            }
            Opcode::Xor => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] = self.registers[ra] ^ self.registers[rb];
                    self.pc = next_pc;
                }
            }
            Opcode::Or => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] = self.registers[ra] | self.registers[rb];
                    self.pc = next_pc;
                }
            }
            Opcode::MulUpperSS => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let a = self.registers[ra] as i64 as i128;
                    let b = self.registers[rb] as i64 as i128;
                    self.registers[rd] = ((a * b) >> 64) as i64 as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::MulUpperUU => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let a = self.registers[ra] as u128;
                    let b = self.registers[rb] as u128;
                    self.registers[rd] = ((a * b) >> 64) as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::MulUpperSU => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let a = self.registers[ra] as i64 as i128;
                    let b = self.registers[rb] as u128;
                    // Z8(φA) * φB, signed * unsigned
                    let result = (a * b as i128) >> 64;
                    self.registers[rd] = result as i64 as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::SetLtU => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] = (self.registers[ra] < self.registers[rb]) as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::SetLtS => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] = ((self.registers[ra] as i64) < (self.registers[rb] as i64)) as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::CmovIz => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    if self.registers[rb] == 0 {
                        self.registers[rd] = self.registers[ra];
                    }
                    self.pc = next_pc;
                }
            }
            Opcode::CmovNz => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    if self.registers[rb] != 0 {
                        self.registers[rd] = self.registers[ra];
                    }
                    self.pc = next_pc;
                }
            }
            Opcode::RotL64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] = self.registers[ra].rotate_left((self.registers[rb] % 64) as u32);
                    self.pc = next_pc;
                }
            }
            Opcode::RotL32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let val = self.registers[ra] as u32;
                    let result = val.rotate_left((self.registers[rb] % 32) as u32);
                    self.registers[rd] = args::sign_extend_32(result as u64);
                    self.pc = next_pc;
                }
            }
            Opcode::RotR64 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] = self.registers[ra].rotate_right((self.registers[rb] % 64) as u32);
                    self.pc = next_pc;
                }
            }
            Opcode::RotR32 => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let val = self.registers[ra] as u32;
                    let result = val.rotate_right((self.registers[rb] % 32) as u32);
                    self.registers[rd] = args::sign_extend_32(result as u64);
                    self.pc = next_pc;
                }
            }
            Opcode::AndInv => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] = self.registers[ra] & !self.registers[rb];
                    self.pc = next_pc;
                }
            }
            Opcode::OrInv => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] = self.registers[ra] | !self.registers[rb];
                    self.pc = next_pc;
                }
            }
            Opcode::Xnor => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] = !(self.registers[ra] ^ self.registers[rb]);
                    self.pc = next_pc;
                }
            }
            Opcode::Max => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let a = self.registers[ra] as i64;
                    let b = self.registers[rb] as i64;
                    self.registers[rd] = a.max(b) as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::MaxU => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] = self.registers[ra].max(self.registers[rb]);
                    self.pc = next_pc;
                }
            }
            Opcode::Min => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    let a = self.registers[ra] as i64;
                    let b = self.registers[rb] as i64;
                    self.registers[rd] = a.min(b) as u64;
                    self.pc = next_pc;
                }
            }
            Opcode::MinU => {
                if let Args::ThreeReg { ra, rb, rd } = args {
                    self.registers[rd] = self.registers[ra].min(self.registers[rb]);
                    self.pc = next_pc;
                }
            }
        }

        // After execution: if this instruction is a terminator, the next
        // instruction starts a new basic block and needs gas charging.
        if opcode.is_terminator() {
            self.need_gas_charge = true;
        }

        None
    }

    /// Run the machine until it exits (eq A.1).
    ///
    /// Uses pre-decoded instructions for speed (avoids per-instruction decode overhead).
    /// Gas is charged per-instruction (1 gas each, matching the stepping path exactly).
    /// Returns (exit_reason, gas_used).
    pub fn run(&mut self) -> (ExitReason, Gas) {
        let initial_gas = self.gas;

        // If tracing is enabled, fall back to the slow step-by-step path
        if self.tracing_enabled {
            return self.run_stepping(initial_gas);
        }

        // Resolve starting PC to instruction index
        let mut idx = if (self.pc as usize) < self.pc_to_idx.len() {
            self.pc_to_idx[self.pc as usize]
        } else {
            u32::MAX
        };

        if idx == u32::MAX {
            // Invalid starting PC
            self.gas = self.gas.saturating_sub(1);
            return (ExitReason::Panic, initial_gas - self.gas);
        }

        loop {
            // Copy the decoded instruction (avoids borrow conflict with &mut self)
            let inst = *unsafe { self.decoded_insts.get_unchecked(idx as usize) };

            // Per-gas-block charging (JAR v0.8.0): only at PC=0 and post-terminator starts
            if inst.bb_gas_cost > 0 {
                if self.gas < inst.bb_gas_cost {
                    self.pc = inst.pc;
                    return (ExitReason::OutOfGas, initial_gas - self.gas);
                }
                self.gas -= inst.bb_gas_cost;
            }

            // Fast-path execution using flat operands (no Args enum matching).
            let ra = inst.ra as usize;
            let rb = inst.rb as usize;
            let rd = inst.rd as usize;
            let imm1 = inst.imm1;
            let next_pc = inst.next_pc;

            // Most instructions advance sequentially. Branches/jumps set
            // branch_idx to the pre-resolved instruction index.
            let mut branch_idx: u32 = u32::MAX; // sentinel: means sequential
            let mut exit: Option<ExitReason> = None;

            match inst.opcode {
                // === No arguments ===
                Opcode::Trap => { exit = Some(ExitReason::Panic); }
                Opcode::Fallthrough | Opcode::Unlikely => {}

                // === One immediate ===
                Opcode::Ecalli => {
                    self.pc = next_pc;
                    return (ExitReason::HostCall(imm1 as u32), initial_gas - self.gas);
                }

                // === One register + extended immediate ===
                Opcode::LoadImm64 => { self.registers[ra] = imm1; }

                // === One offset (jump) ===
                Opcode::Jump => {
                    if inst.target_idx != u32::MAX {
                        branch_idx = inst.target_idx;
                    } else {
                        exit = Some(ExitReason::Panic);
                    }
                }

                // === One register + one immediate ===
                Opcode::JumpInd => {
                    let addr = self.registers[ra].wrapping_add(imm1) % (1u64 << 32);
                    let (e, target_pc) = self.djump(addr);
                    if let Some(reason) = e {
                        exit = Some(reason);
                    } else {
                        let t = target_pc as usize;
                        if t < self.pc_to_idx.len() {
                            let tidx = self.pc_to_idx[t];
                            if tidx != u32::MAX { branch_idx = tidx; }
                            else { exit = Some(ExitReason::Panic); }
                        } else { exit = Some(ExitReason::Panic); }
                    }
                }
                Opcode::LoadImm => { self.registers[ra] = imm1; }

                // === Two registers ===
                Opcode::MoveReg => { self.registers[rd] = self.registers[ra]; }
                Opcode::Sbrk => {
                    // JAR v0.8.0: sbrk removed
                    exit = Some(ExitReason::Panic);
                }
                Opcode::CountSetBits64 => { self.registers[rd] = self.registers[ra].count_ones() as u64; }
                Opcode::CountSetBits32 => { self.registers[rd] = (self.registers[ra] as u32).count_ones() as u64; }
                Opcode::LeadingZeroBits64 => { self.registers[rd] = self.registers[ra].leading_zeros() as u64; }
                Opcode::LeadingZeroBits32 => { self.registers[rd] = (self.registers[ra] as u32).leading_zeros() as u64; }
                Opcode::TrailingZeroBits64 => { self.registers[rd] = self.registers[ra].trailing_zeros() as u64; }
                Opcode::TrailingZeroBits32 => { self.registers[rd] = (self.registers[ra] as u32).trailing_zeros() as u64; }
                Opcode::SignExtend8 => { self.registers[rd] = self.registers[ra] as u8 as i8 as i64 as u64; }
                Opcode::SignExtend16 => { self.registers[rd] = self.registers[ra] as u16 as i16 as i64 as u64; }
                Opcode::ZeroExtend16 => { self.registers[rd] = self.registers[ra] as u16 as u64; }
                Opcode::ReverseBytes => { self.registers[rd] = self.registers[ra].swap_bytes(); }

                // === Two registers + one immediate ===
                Opcode::AddImm32 => { self.registers[ra] = args::sign_extend_32(self.registers[rb].wrapping_add(imm1)); }
                Opcode::AddImm64 => { self.registers[ra] = self.registers[rb].wrapping_add(imm1); }
                Opcode::MulImm32 => { self.registers[ra] = args::sign_extend_32((self.registers[rb] as u32).wrapping_mul(imm1 as u32) as u64); }
                Opcode::MulImm64 => { self.registers[ra] = self.registers[rb].wrapping_mul(imm1); }
                Opcode::AndImm => { self.registers[ra] = self.registers[rb] & imm1; }
                Opcode::XorImm => { self.registers[ra] = self.registers[rb] ^ imm1; }
                Opcode::OrImm => { self.registers[ra] = self.registers[rb] | imm1; }
                Opcode::SetLtUImm => { self.registers[ra] = if self.registers[rb] < imm1 { 1 } else { 0 }; }
                Opcode::SetLtSImm => { self.registers[ra] = if (self.registers[rb] as i64) < (imm1 as i64) { 1 } else { 0 }; }
                Opcode::SetGtUImm => { self.registers[ra] = if self.registers[rb] > imm1 { 1 } else { 0 }; }
                Opcode::SetGtSImm => { self.registers[ra] = if (self.registers[rb] as i64) > (imm1 as i64) { 1 } else { 0 }; }
                Opcode::ShloLImm32 => { self.registers[ra] = args::sign_extend_32((self.registers[rb] as u32).wrapping_shl((imm1 % 32) as u32) as u64); }
                Opcode::ShloRImm32 => { self.registers[ra] = args::sign_extend_32((self.registers[rb] as u32).wrapping_shr((imm1 % 32) as u32) as u64); }
                Opcode::SharRImm32 => { self.registers[ra] = (self.registers[rb] as u32 as i32).wrapping_shr((imm1 % 32) as u32) as i64 as u64; }
                Opcode::ShloLImm64 => { self.registers[ra] = self.registers[rb].wrapping_shl((imm1 % 64) as u32); }
                Opcode::ShloRImm64 => { self.registers[ra] = self.registers[rb].wrapping_shr((imm1 % 64) as u32); }
                Opcode::SharRImm64 => { self.registers[ra] = (self.registers[rb] as i64).wrapping_shr((imm1 % 64) as u32) as u64; }
                Opcode::NegAddImm32 => { self.registers[ra] = args::sign_extend_32(imm1.wrapping_sub(self.registers[rb]) as u32 as u64); }
                Opcode::NegAddImm64 => { self.registers[ra] = imm1.wrapping_sub(self.registers[rb]); }
                Opcode::CmovIzImm => { if self.registers[rb] == 0 { self.registers[ra] = imm1; } }
                Opcode::CmovNzImm => { if self.registers[rb] != 0 { self.registers[ra] = imm1; } }
                Opcode::RotR64Imm => { self.registers[ra] = self.registers[rb].rotate_right((imm1 % 64) as u32); }
                Opcode::RotR32Imm => { self.registers[ra] = args::sign_extend_32((self.registers[rb] as u32).rotate_right((imm1 % 32) as u32) as u64); }

                // ImmAlt variants: op ra, imm, rb (imm is the "left" operand)
                Opcode::ShloLImmAlt32 => { self.registers[ra] = args::sign_extend_32((imm1 as u32).wrapping_shl((self.registers[rb] % 32) as u32) as u64); }
                Opcode::ShloRImmAlt32 => { self.registers[ra] = args::sign_extend_32((imm1 as u32).wrapping_shr((self.registers[rb] % 32) as u32) as u64); }
                Opcode::SharRImmAlt32 => { self.registers[ra] = ((imm1 as u32) as i32).wrapping_shr((self.registers[rb] % 32) as u32) as i64 as u64; }
                Opcode::ShloLImmAlt64 => { self.registers[ra] = imm1.wrapping_shl((self.registers[rb] % 64) as u32); }
                Opcode::ShloRImmAlt64 => { self.registers[ra] = imm1.wrapping_shr((self.registers[rb] % 64) as u32); }
                Opcode::SharRImmAlt64 => { self.registers[ra] = (imm1 as i64).wrapping_shr((self.registers[rb] % 64) as u32) as u64; }
                Opcode::RotR64ImmAlt => { self.registers[ra] = imm1.rotate_right((self.registers[rb] % 64) as u32); }
                Opcode::RotR32ImmAlt => { self.registers[ra] = args::sign_extend_32((imm1 as u32).rotate_right((self.registers[rb] % 32) as u32) as u64); }

                // === Two registers + one offset (branches) ===
                Opcode::BranchEq => {
                    if self.registers[ra] == self.registers[rb] {
                        if inst.target_idx != u32::MAX { branch_idx = inst.target_idx; }
                        else { exit = Some(ExitReason::Panic); }
                    }
                }
                Opcode::BranchNe => {
                    if self.registers[ra] != self.registers[rb] {
                        if inst.target_idx != u32::MAX { branch_idx = inst.target_idx; }
                        else { exit = Some(ExitReason::Panic); }
                    }
                }
                Opcode::BranchLtU => {
                    if self.registers[ra] < self.registers[rb] {
                        if inst.target_idx != u32::MAX { branch_idx = inst.target_idx; }
                        else { exit = Some(ExitReason::Panic); }
                    }
                }
                Opcode::BranchLtS => {
                    if (self.registers[ra] as i64) < (self.registers[rb] as i64) {
                        if inst.target_idx != u32::MAX { branch_idx = inst.target_idx; }
                        else { exit = Some(ExitReason::Panic); }
                    }
                }
                Opcode::BranchGeU => {
                    if self.registers[ra] >= self.registers[rb] {
                        if inst.target_idx != u32::MAX { branch_idx = inst.target_idx; }
                        else { exit = Some(ExitReason::Panic); }
                    }
                }
                Opcode::BranchGeS => {
                    if (self.registers[ra] as i64) >= (self.registers[rb] as i64) {
                        if inst.target_idx != u32::MAX { branch_idx = inst.target_idx; }
                        else { exit = Some(ExitReason::Panic); }
                    }
                }

                // === Three register ALU ===
                Opcode::Add32 => { self.registers[rd] = args::sign_extend_32(self.registers[ra].wrapping_add(self.registers[rb])); }
                Opcode::Sub32 => { self.registers[rd] = args::sign_extend_32(self.registers[ra].wrapping_sub(self.registers[rb])); }
                Opcode::Add64 => { self.registers[rd] = self.registers[ra].wrapping_add(self.registers[rb]); }
                Opcode::Sub64 => { self.registers[rd] = self.registers[ra].wrapping_sub(self.registers[rb]); }
                Opcode::Mul32 => { self.registers[rd] = args::sign_extend_32((self.registers[ra] as u32).wrapping_mul(self.registers[rb] as u32) as u64); }
                Opcode::Mul64 => { self.registers[rd] = self.registers[ra].wrapping_mul(self.registers[rb]); }
                Opcode::And => { self.registers[rd] = self.registers[ra] & self.registers[rb]; }
                Opcode::Or => { self.registers[rd] = self.registers[ra] | self.registers[rb]; }
                Opcode::Xor => { self.registers[rd] = self.registers[ra] ^ self.registers[rb]; }
                Opcode::SetLtU => { self.registers[rd] = if self.registers[ra] < self.registers[rb] { 1 } else { 0 }; }
                Opcode::SetLtS => { self.registers[rd] = if (self.registers[ra] as i64) < (self.registers[rb] as i64) { 1 } else { 0 }; }
                Opcode::CmovIz => { if self.registers[rb] == 0 { self.registers[rd] = self.registers[ra]; } }
                Opcode::CmovNz => { if self.registers[rb] != 0 { self.registers[rd] = self.registers[ra]; } }
                Opcode::ShloL32 => { self.registers[rd] = args::sign_extend_32((self.registers[ra] as u32).wrapping_shl((self.registers[rb] % 32) as u32) as u64); }
                Opcode::ShloR32 => { self.registers[rd] = args::sign_extend_32((self.registers[ra] as u32).wrapping_shr((self.registers[rb] % 32) as u32) as u64); }
                Opcode::SharR32 => { self.registers[rd] = (self.registers[ra] as u32 as i32).wrapping_shr((self.registers[rb] % 32) as u32) as i64 as u64; }
                Opcode::ShloL64 => { self.registers[rd] = self.registers[ra].wrapping_shl((self.registers[rb] % 64) as u32); }
                Opcode::ShloR64 => { self.registers[rd] = self.registers[ra].wrapping_shr((self.registers[rb] % 64) as u32); }
                Opcode::SharR64 => { self.registers[rd] = (self.registers[ra] as i64).wrapping_shr((self.registers[rb] % 64) as u32) as u64; }
                Opcode::RotL64 => { self.registers[rd] = self.registers[ra].rotate_left((self.registers[rb] % 64) as u32); }
                Opcode::RotR64 => { self.registers[rd] = self.registers[ra].rotate_right((self.registers[rb] % 64) as u32); }
                Opcode::RotL32 => { self.registers[rd] = args::sign_extend_32((self.registers[ra] as u32).rotate_left((self.registers[rb] % 32) as u32) as u64); }
                Opcode::RotR32 => { self.registers[rd] = args::sign_extend_32((self.registers[ra] as u32).rotate_right((self.registers[rb] % 32) as u32) as u64); }
                Opcode::AndInv => { self.registers[rd] = self.registers[ra] & !self.registers[rb]; }
                Opcode::OrInv => { self.registers[rd] = self.registers[ra] | !self.registers[rb]; }
                Opcode::Xnor => { self.registers[rd] = !(self.registers[ra] ^ self.registers[rb]); }
                Opcode::Max => { self.registers[rd] = core::cmp::max(self.registers[ra] as i64, self.registers[rb] as i64) as u64; }
                Opcode::MaxU => { self.registers[rd] = core::cmp::max(self.registers[ra], self.registers[rb]); }
                Opcode::Min => { self.registers[rd] = core::cmp::min(self.registers[ra] as i64, self.registers[rb] as i64) as u64; }
                Opcode::MinU => { self.registers[rd] = core::cmp::min(self.registers[ra], self.registers[rb]); }

                // === Indirect loads (two reg + imm) ===
                Opcode::LoadIndU8 => {
                    let addr = self.registers[rb].wrapping_add(imm1) as u32;
                    match self.read_u8(addr) {
                        Some(v) => { self.registers[ra] = v as u64; }
                        None => { exit = Some(ExitReason::PageFault(addr & !0xFFF)); }
                    }
                }
                Opcode::LoadIndI8 => {
                    let addr = self.registers[rb].wrapping_add(imm1) as u32;
                    match self.read_u8(addr) {
                        Some(v) => { self.registers[ra] = v as i8 as i64 as u64; }
                        None => { exit = Some(ExitReason::PageFault(addr & !0xFFF)); }
                    }
                }
                Opcode::LoadIndU16 => {
                    let addr = self.registers[rb].wrapping_add(imm1) as u32;
                    match self.read_u16_le(addr) {
                        Some(v) => { self.registers[ra] = v as u64; }
                        None => { exit = Some(ExitReason::PageFault(addr & !0xFFF)); }
                    }
                }
                Opcode::LoadIndI16 => {
                    let addr = self.registers[rb].wrapping_add(imm1) as u32;
                    match self.read_u16_le(addr) {
                        Some(v) => { self.registers[ra] = v as i16 as i64 as u64; }
                        None => { exit = Some(ExitReason::PageFault(addr & !0xFFF)); }
                    }
                }
                Opcode::LoadIndU32 => {
                    let addr = self.registers[rb].wrapping_add(imm1) as u32;
                    match self.read_u32_le(addr) {
                        Some(v) => { self.registers[ra] = v as u64; }
                        None => { exit = Some(ExitReason::PageFault(addr & !0xFFF)); }
                    }
                }
                Opcode::LoadIndI32 => {
                    let addr = self.registers[rb].wrapping_add(imm1) as u32;
                    match self.read_u32_le(addr) {
                        Some(v) => { self.registers[ra] = v as i32 as i64 as u64; }
                        None => { exit = Some(ExitReason::PageFault(addr & !0xFFF)); }
                    }
                }
                Opcode::LoadIndU64 => {
                    let addr = self.registers[rb].wrapping_add(imm1) as u32;
                    match self.read_u64_le(addr) {
                        Some(v) => { self.registers[ra] = v; }
                        None => { exit = Some(ExitReason::PageFault(addr & !0xFFF)); }
                    }
                }

                // === Indirect stores (two reg + imm) ===
                Opcode::StoreIndU8 => {
                    let addr = self.registers[rb].wrapping_add(imm1) as u32;
                    if !self.write_u8(addr, self.registers[ra] as u8) {
                        exit = Some(ExitReason::PageFault(addr & !0xFFF));
                    }
                }
                Opcode::StoreIndU16 => {
                    let addr = self.registers[rb].wrapping_add(imm1) as u32;
                    if !self.write_u16_le(addr, self.registers[ra] as u16) {
                        exit = Some(ExitReason::PageFault(addr & !0xFFF));
                    }
                }
                Opcode::StoreIndU32 => {
                    let addr = self.registers[rb].wrapping_add(imm1) as u32;
                    if !self.write_u32_le(addr, self.registers[ra] as u32) {
                        exit = Some(ExitReason::PageFault(addr & !0xFFF));
                    }
                }
                Opcode::StoreIndU64 => {
                    let addr = self.registers[rb].wrapping_add(imm1) as u32;
                    if !self.write_u64_le(addr, self.registers[ra]) {
                        exit = Some(ExitReason::PageFault(addr & !0xFFF));
                    }
                }

                // === Div/Rem (three reg, common in crypto) ===
                Opcode::DivU32 => {
                    let b = self.registers[rb] as u32;
                    self.registers[rd] = if b == 0 { u64::MAX } else { args::sign_extend_32((self.registers[ra] as u32 / b) as u64) };
                }
                Opcode::DivU64 => {
                    let b = self.registers[rb];
                    self.registers[rd] = if b == 0 { u64::MAX } else { self.registers[ra] / b };
                }
                Opcode::DivS32 => {
                    let a = self.registers[ra] as i32;
                    let b = self.registers[rb] as i32;
                    self.registers[rd] = if b == 0 { u64::MAX } else if a == i32::MIN && b == -1 { a as u64 } else { args::sign_extend_32((a / b) as i64 as u64) };
                }
                Opcode::DivS64 => {
                    let a = self.registers[ra] as i64;
                    let b = self.registers[rb] as i64;
                    self.registers[rd] = if b == 0 { u64::MAX } else if a == i64::MIN && b == -1 { a as u64 } else { (a / b) as u64 };
                }
                Opcode::RemU32 => {
                    let b = self.registers[rb] as u32;
                    self.registers[rd] = if b == 0 { args::sign_extend_32(self.registers[ra] as u32 as u64) } else { args::sign_extend_32((self.registers[ra] as u32 % b) as u64) };
                }
                Opcode::RemU64 => {
                    let b = self.registers[rb];
                    self.registers[rd] = if b == 0 { self.registers[ra] } else { self.registers[ra] % b };
                }
                Opcode::RemS32 => {
                    let a = self.registers[ra] as i32;
                    let b = self.registers[rb] as i32;
                    self.registers[rd] = if b == 0 { a as u64 } else if a == i32::MIN && b == -1 { 0 } else { args::sign_extend_32((a % b) as i64 as u64) };
                }
                Opcode::RemS64 => {
                    let a = self.registers[ra] as i64;
                    let b = self.registers[rb] as i64;
                    self.registers[rd] = if b == 0 { a as u64 } else if a == i64::MIN && b == -1 { 0 } else { (a % b) as u64 };
                }
                Opcode::MulUpperSS => {
                    self.registers[rd] = ((self.registers[ra] as i64 as i128).wrapping_mul(self.registers[rb] as i64 as i128) >> 64) as u64;
                }
                Opcode::MulUpperUU => {
                    self.registers[rd] = ((self.registers[ra] as u128).wrapping_mul(self.registers[rb] as u128) >> 64) as u64;
                }
                Opcode::MulUpperSU => {
                    self.registers[rd] = ((self.registers[ra] as i64 as i128).wrapping_mul(self.registers[rb] as u128 as i128) >> 64) as u64;
                }

                // === Two immediates (store_imm: addr = imm1, value = imm2) ===
                Opcode::StoreImmU8 => {
                    let addr = imm1 as u32;
                    if !self.write_u8(addr, inst.imm2 as u8) { exit = Some(ExitReason::PageFault(addr & !0xFFF)); }
                }
                Opcode::StoreImmU16 => {
                    let addr = imm1 as u32;
                    if !self.write_u16_le(addr, inst.imm2 as u16) { exit = Some(ExitReason::PageFault(addr & !0xFFF)); }
                }
                Opcode::StoreImmU32 => {
                    let addr = imm1 as u32;
                    if !self.write_u32_le(addr, inst.imm2 as u32) { exit = Some(ExitReason::PageFault(addr & !0xFFF)); }
                }
                Opcode::StoreImmU64 => {
                    let addr = imm1 as u32;
                    if !self.write_u64_le(addr, inst.imm2) { exit = Some(ExitReason::PageFault(addr & !0xFFF)); }
                }

                // === Absolute address loads (addr = imm1) ===
                Opcode::LoadU8 => {
                    let addr = imm1 as u32;
                    match self.read_u8(addr) {
                        Some(v) => { self.registers[ra] = v as u64; }
                        None => { exit = Some(ExitReason::PageFault(addr & !0xFFF)); }
                    }
                }
                Opcode::LoadI8 => {
                    let addr = imm1 as u32;
                    match self.read_u8(addr) {
                        Some(v) => { self.registers[ra] = v as i8 as i64 as u64; }
                        None => { exit = Some(ExitReason::PageFault(addr & !0xFFF)); }
                    }
                }
                Opcode::LoadU16 => {
                    let addr = imm1 as u32;
                    match self.read_u16_le(addr) {
                        Some(v) => { self.registers[ra] = v as u64; }
                        None => { exit = Some(ExitReason::PageFault(addr & !0xFFF)); }
                    }
                }
                Opcode::LoadI16 => {
                    let addr = imm1 as u32;
                    match self.read_u16_le(addr) {
                        Some(v) => { self.registers[ra] = v as i16 as i64 as u64; }
                        None => { exit = Some(ExitReason::PageFault(addr & !0xFFF)); }
                    }
                }
                Opcode::LoadU32 => {
                    let addr = imm1 as u32;
                    match self.read_u32_le(addr) {
                        Some(v) => { self.registers[ra] = v as u64; }
                        None => { exit = Some(ExitReason::PageFault(addr & !0xFFF)); }
                    }
                }
                Opcode::LoadI32 => {
                    let addr = imm1 as u32;
                    match self.read_u32_le(addr) {
                        Some(v) => { self.registers[ra] = v as i32 as i64 as u64; }
                        None => { exit = Some(ExitReason::PageFault(addr & !0xFFF)); }
                    }
                }
                Opcode::LoadU64 => {
                    let addr = imm1 as u32;
                    match self.read_u64_le(addr) {
                        Some(v) => { self.registers[ra] = v; }
                        None => { exit = Some(ExitReason::PageFault(addr & !0xFFF)); }
                    }
                }

                // === Absolute address stores (addr = imm1, value = reg[ra]) ===
                Opcode::StoreU8 => {
                    let addr = imm1 as u32;
                    if !self.write_u8(addr, self.registers[ra] as u8) { exit = Some(ExitReason::PageFault(addr & !0xFFF)); }
                }
                Opcode::StoreU16 => {
                    let addr = imm1 as u32;
                    if !self.write_u16_le(addr, self.registers[ra] as u16) { exit = Some(ExitReason::PageFault(addr & !0xFFF)); }
                }
                Opcode::StoreU32 => {
                    let addr = imm1 as u32;
                    if !self.write_u32_le(addr, self.registers[ra] as u32) { exit = Some(ExitReason::PageFault(addr & !0xFFF)); }
                }
                Opcode::StoreU64 => {
                    let addr = imm1 as u32;
                    if !self.write_u64_le(addr, self.registers[ra]) { exit = Some(ExitReason::PageFault(addr & !0xFFF)); }
                }

                // === Store imm indirect (addr = reg[ra] + imm1, value = imm2) ===
                Opcode::StoreImmIndU8 => {
                    let addr = self.registers[ra].wrapping_add(imm1) as u32;
                    if !self.write_u8(addr, inst.imm2 as u8) { exit = Some(ExitReason::PageFault(addr & !0xFFF)); }
                }
                Opcode::StoreImmIndU16 => {
                    let addr = self.registers[ra].wrapping_add(imm1) as u32;
                    if !self.write_u16_le(addr, inst.imm2 as u16) { exit = Some(ExitReason::PageFault(addr & !0xFFF)); }
                }
                Opcode::StoreImmIndU32 => {
                    let addr = self.registers[ra].wrapping_add(imm1) as u32;
                    if !self.write_u32_le(addr, inst.imm2 as u32) { exit = Some(ExitReason::PageFault(addr & !0xFFF)); }
                }
                Opcode::StoreImmIndU64 => {
                    let addr = self.registers[ra].wrapping_add(imm1) as u32;
                    if !self.write_u64_le(addr, inst.imm2) { exit = Some(ExitReason::PageFault(addr & !0xFFF)); }
                }

                // === LoadImmJump (reg[ra] = imm1, branch to target) ===
                Opcode::LoadImmJump => {
                    self.registers[ra] = imm1;
                    if inst.target_idx != u32::MAX { branch_idx = inst.target_idx; }
                    else { exit = Some(ExitReason::Panic); }
                }

                // === BranchImm variants (cond on reg[ra] vs imm1, target = target_idx) ===
                Opcode::BranchEqImm => {
                    if self.registers[ra] == imm1 {
                        if inst.target_idx != u32::MAX { branch_idx = inst.target_idx; }
                        else { exit = Some(ExitReason::Panic); }
                    }
                }
                Opcode::BranchNeImm => {
                    if self.registers[ra] != imm1 {
                        if inst.target_idx != u32::MAX { branch_idx = inst.target_idx; }
                        else { exit = Some(ExitReason::Panic); }
                    }
                }
                Opcode::BranchLtUImm => {
                    if self.registers[ra] < imm1 {
                        if inst.target_idx != u32::MAX { branch_idx = inst.target_idx; }
                        else { exit = Some(ExitReason::Panic); }
                    }
                }
                Opcode::BranchLeUImm => {
                    if self.registers[ra] <= imm1 {
                        if inst.target_idx != u32::MAX { branch_idx = inst.target_idx; }
                        else { exit = Some(ExitReason::Panic); }
                    }
                }
                Opcode::BranchGeUImm => {
                    if self.registers[ra] >= imm1 {
                        if inst.target_idx != u32::MAX { branch_idx = inst.target_idx; }
                        else { exit = Some(ExitReason::Panic); }
                    }
                }
                Opcode::BranchGtUImm => {
                    if self.registers[ra] > imm1 {
                        if inst.target_idx != u32::MAX { branch_idx = inst.target_idx; }
                        else { exit = Some(ExitReason::Panic); }
                    }
                }
                Opcode::BranchLtSImm => {
                    if (self.registers[ra] as i64) < (imm1 as i64) {
                        if inst.target_idx != u32::MAX { branch_idx = inst.target_idx; }
                        else { exit = Some(ExitReason::Panic); }
                    }
                }
                Opcode::BranchLeSImm => {
                    if (self.registers[ra] as i64) <= (imm1 as i64) {
                        if inst.target_idx != u32::MAX { branch_idx = inst.target_idx; }
                        else { exit = Some(ExitReason::Panic); }
                    }
                }
                Opcode::BranchGeSImm => {
                    if (self.registers[ra] as i64) >= (imm1 as i64) {
                        if inst.target_idx != u32::MAX { branch_idx = inst.target_idx; }
                        else { exit = Some(ExitReason::Panic); }
                    }
                }
                Opcode::BranchGtSImm => {
                    if (self.registers[ra] as i64) > (imm1 as i64) {
                        if inst.target_idx != u32::MAX { branch_idx = inst.target_idx; }
                        else { exit = Some(ExitReason::Panic); }
                    }
                }

                // === Two registers + two immediates ===
                Opcode::LoadImmJumpInd => {
                    self.registers[ra] = imm1;
                    let addr = self.registers[rb].wrapping_add(inst.imm2) % (1u64 << 32);
                    let (e, target_pc) = self.djump(addr);
                    if let Some(reason) = e {
                        exit = Some(reason);
                    } else {
                        let t = target_pc as usize;
                        if t < self.pc_to_idx.len() {
                            let tidx = self.pc_to_idx[t];
                            if tidx != u32::MAX { branch_idx = tidx; }
                            else { exit = Some(ExitReason::Panic); }
                        } else { exit = Some(ExitReason::Panic); }
                    }
                }
            }

            if let Some(reason) = exit {
                self.pc = inst.pc;
                return (reason, initial_gas - self.gas);
            }

            if branch_idx == u32::MAX {
                // Sequential advance
                idx += 1;
            } else {
                idx = branch_idx;
            }
        }
    }

    /// Slow run path for tracing/stepping mode — uses step() with per-instruction gas.
    fn run_stepping(&mut self, initial_gas: Gas) -> (ExitReason, Gas) {
        loop {
            match self.step() {
                Some(exit) => {
                    let gas_used = initial_gas - self.gas;
                    return (exit, gas_used);
                }
                None => continue,
            }
        }
    }
}

/// Signed modulo: sign of numerator, mod of absolute values (eq A.33).
fn smod_i64(a: i64, b: i64) -> i64 {
    if b == 0 {
        a
    } else {
        let sign = if a < 0 { -1i64 } else { 1 };
        sign * ((a.unsigned_abs() % b.unsigned_abs()) as i64)
    }
}

/// Compute the set of basic block start indices (ϖ, eq A.5).
/// Compact bitset: 1 bit per code byte, stored as Vec<u64>.
/// 64x more cache-friendly than Vec<bool> for the compilation hot loop.
pub struct BitSet {
    pub words: Vec<u64>,
}

impl BitSet {
    /// Create a bitset with `n` bits, all cleared.
    pub fn new(n: usize) -> Self {
        Self { words: vec![0u64; (n + 63) / 64] }
    }

    /// Set bit at index `i`.
    #[inline(always)]
    pub fn set(&mut self, i: usize) {
        self.words[i / 64] |= 1u64 << (i % 64);
    }

    /// Test bit at index `i`.
    #[inline(always)]
    pub fn get(&self, i: usize) -> bool {
        (self.words[i / 64] >> (i % 64)) & 1 != 0
    }

    /// Build a rank index for O(1) rank queries.
    /// rank_index[i] = number of set bits in words[0..i] (prefix popcount sum).
    pub fn build_rank_index(&self) -> Vec<u32> {
        let mut idx = Vec::with_capacity(self.words.len());
        let mut sum = 0u32;
        for &w in &self.words {
            idx.push(sum);
            sum += w.count_ones();
        }
        idx
    }

    /// Count set bits before position `pos` using the pre-built rank index.
    /// This is the rank(pos) operation: number of 1-bits at positions 0..pos.
    #[inline(always)]
    pub fn rank(&self, rank_index: &[u32], pos: usize) -> usize {
        let word_idx = pos / 64;
        let bit_idx = pos % 64;
        let prefix = rank_index[word_idx] as usize;
        let mask = if bit_idx == 0 { 0 } else { (1u64 << bit_idx) - 1 };
        prefix + (self.words[word_idx] & mask).count_ones() as usize
    }

    /// Collect all set bit positions into a Vec.
    pub fn collect_set_positions(&self) -> Vec<u32> {
        let mut positions = Vec::new();
        for (word_idx, &word) in self.words.iter().enumerate() {
            let mut bits = word;
            while bits != 0 {
                let bit = bits.trailing_zeros() as usize;
                positions.push((word_idx * 64 + bit) as u32);
                bits &= bits - 1;
            }
        }
        positions
    }
}

/// Compute basic block starts as a compact bitset + precomputed skip table.
/// The bitset is 64x smaller than Vec<bool>, improving L1 cache utilization
/// during the hot compilation loop (~1.75KB vs ~112KB for ecrecover).
/// Compute the skip (number of argument bytes) for instruction at `pc` by
/// scanning the bitmask for the next instruction start.
///
/// Uses u64 word-at-a-time scanning when possible. The bitmask has value 1
/// at instruction starts and 0 for argument bytes. We find the first 1 after
/// pc+1 by loading 8 bytes at a time and using trailing-zero count.
#[inline(always)]
pub fn skip_for_bitmask(bitmask: &[u8], pc: usize) -> usize {
    let start = pc + 1;
    let bm_len = bitmask.len();

    // Fast path: if we have at least 8 bytes, use a u64 scan.
    // Most instructions are 1-6 bytes, so the first word usually suffices.
    if start + 8 <= bm_len {
        let word = unsafe {
            std::ptr::read_unaligned(bitmask.as_ptr().add(start) as *const u64)
        };
        // Each byte is 0 or 1. A byte with value 1 means "instruction start".
        // We want the position of the first non-zero byte.
        if word != 0 {
            // The first non-zero byte position (little-endian: trailing zeros / 8)
            return (word.trailing_zeros() / 8) as usize;
        }
        // All 8 bytes are 0 — continue with scalar scan from start+8
        let mut j = 8;
        while j < 25 {
            let idx = start + j;
            if idx >= bm_len || bitmask[idx] == 1 { return j; }
            j += 1;
        }
        return 0;
    }

    // Scalar fallback for near end of bitmask
    let mut s = 0;
    for j in 0..25 {
        let idx = start + j;
        let bit = if idx < bm_len { bitmask[idx] } else { 1 };
        if bit == 1 { s = j; break; }
    }
    s
}

/// Compute basic block starts AND a precomputed skip table in a single pass.
/// skip_table[pc] = number of bytes to skip after the opcode byte (instruction size - 1).
/// Only valid at instruction-start PCs (where bitmask[pc] == 1).
pub fn compute_basic_block_starts_with_skips(code: &[u8], bitmask: &[u8]) -> (Vec<bool>, Vec<u8>) {
    let (starts, skip_table) = compute_bb_starts_inner(code, bitmask);
    (starts, skip_table)
}

pub fn compute_basic_block_starts(code: &[u8], bitmask: &[u8]) -> Vec<bool> {
    compute_bb_starts_inner(code, bitmask).0
}

/// Compute gas block starts per the JAM spec: {PC=0} ∪ {post-terminator PCs}.
///
/// Unlike `compute_basic_block_starts`, this does NOT include branch targets.
/// Gas blocks are defined solely by terminator boundaries (Lean `Interpreter.lean:130`,
/// GP PR #508). This aligns the interpreter with the recompiler (PR #154).
pub fn compute_gas_block_starts(code: &[u8], bitmask: &[u8]) -> Vec<bool> {
    let len = code.len();
    if len == 0 {
        return vec![];
    }

    let mut starts = vec![false; len];

    // Index 0 is always a gas block start if it's a valid instruction
    if !bitmask.is_empty() && bitmask[0] == 1 {
        if Opcode::from_byte(code[0]).is_some() {
            starts[0] = true;
        }
    }

    let mut i = 0;
    while i < len {
        if i >= bitmask.len() || bitmask[i] != 1 { i += 1; continue; }
        let Some(op) = Opcode::from_byte(code[i]) else { i += 1; continue; };

        let skip = {
            let mut s = 0;
            for j in 0..25 {
                let idx = i + 1 + j;
                let bit = if idx < bitmask.len() { bitmask[idx] } else { 1 };
                if bit == 1 { s = j; break; }
            }
            s
        };

        if op.is_terminator() {
            let next = i + 1 + skip;
            if next < len && next < bitmask.len() && bitmask[next] == 1 {
                starts[next] = true;
            }
        }

        // No branch target marking — gas blocks are terminator-only.

        i += 1 + skip;
    }

    starts
}

fn compute_bb_starts_inner(code: &[u8], bitmask: &[u8]) -> (Vec<bool>, Vec<u8>) {
    let len = code.len();
    if len == 0 {
        return (vec![], vec![]);
    }

    let mut starts = vec![false; len];
    let mut skip_table = vec![0u8; len];

    // Index 0 is always a basic block start if it's a valid instruction
    if !bitmask.is_empty() && bitmask[0] == 1 {
        if Opcode::from_byte(code[0]).is_some() {
            starts[0] = true;
        }
    }

    // Iterate only over instruction starts (skip non-instruction bytes).
    let mut i = 0;
    while i < len {
        if i >= bitmask.len() || bitmask[i] != 1 { i += 1; continue; }
        let Some(op) = Opcode::from_byte(code[i]) else { i += 1; continue; };

        let skip = {
            let mut s = 0;
            for j in 0..25 {
                let idx = i + 1 + j;
                let bit = if idx < bitmask.len() { bitmask[idx] } else { 1 };
                if bit == 1 { s = j; break; }
            }
            s
        };
        skip_table[i] = skip as u8;

        if op.is_terminator() {
            // The instruction after a terminator starts a new block
            let next = i + 1 + skip;
            if next < len && next < bitmask.len() && bitmask[next] == 1 {
                starts[next] = true;
            }
        }

        // For branch/jump instructions, mark the target as a basic block start
        let cat = op.category();
        match cat {
            crate::instruction::InstructionCategory::OneOffset => {
                // Jump: opcode + 4-byte offset
                if i + 5 <= len {
                    let off = i32::from_le_bytes([code[i+1], code[i+2], code[i+3], code[i+4]]);
                    let target = (i as i64 + off as i64) as usize;
                    if target < len && target < bitmask.len() && bitmask[target] == 1 {
                        starts[target] = true;
                    }
                }
            }
            crate::instruction::InstructionCategory::TwoRegOneOffset => {
                // Branch: opcode + 1-byte regs + 4-byte offset
                if i + 6 <= len {
                    let off = i32::from_le_bytes([code[i+2], code[i+3], code[i+4], code[i+5]]);
                    let target = (i as i64 + off as i64) as usize;
                    if target < len && target < bitmask.len() && bitmask[target] == 1 {
                        starts[target] = true;
                    }
                }
            }
            crate::instruction::InstructionCategory::OneRegImmOffset => {
                // BranchImm: opcode(1) + reg|lx(1) + imm(lx bytes) + offset(ly bytes)
                // lx is variable (0-4), so compute the actual offset position.
                if i + 2 <= len {
                    let reg_byte = code[i + 1];
                    let lx = ((reg_byte as usize / 16) % 8).min(4);
                    let ly = if skip > lx + 1 { (skip - lx - 1).min(4) } else { 0 };
                    let off_start = i + 2 + lx;
                    if ly > 0 && off_start + ly <= len {
                        let mut buf = [0u8; 4];
                        buf[..ly].copy_from_slice(&code[off_start..off_start + ly]);
                        // Sign-extend from ly bytes
                        if ly < 4 && buf[ly - 1] & 0x80 != 0 {
                            for b in &mut buf[ly..4] { *b = 0xFF; }
                        }
                        let off = i32::from_le_bytes(buf);
                        let target = (i as i64 + off as i64) as usize;
                        if target < len && target < bitmask.len() && bitmask[target] == 1 {
                            starts[target] = true;
                        }
                    }
                }
            }
            _ => {}
        }

        i += 1 + skip; // advance to next instruction start
    }

    (starts, skip_table)
}

/// Compute the gas cost for each basic block using single-pass gas model (JAR v0.8.0).
///
/// Uses the same GasSimulator as the recompiler — single code path.
/// Gas is charged per basic block at block entry: max(max_done - 3, 1).
fn compute_block_gas_costs(code: &[u8], bitmask: &[u8], basic_block_starts: &[bool]) -> Vec<u64> {
    use crate::gas_cost::{fast_cost_from_raw, skip_distance};
    use crate::gas_sim::GasSimulator;

    let len = code.len();
    let mut costs = vec![0u64; len];
    let mut sim = GasSimulator::new();
    let mut block_start: usize = 0;
    let mut in_block = false;

    let mut pc = 0;
    while pc < len {
        if !basic_block_starts[pc] && !in_block {
            pc += 1;
            continue;
        }

        if basic_block_starts[pc] {
            if in_block {
                // Finalize previous block
                costs[block_start] = sim.flush_and_get_cost() as u64;
                sim.reset();
            }
            block_start = pc;
            in_block = true;
        }

        // Extract raw register nibbles (same as codegen.rs)
        let opcode_byte = code[pc];
        let raw_ra = if pc + 1 < len { code[pc + 1] & 0x0F } else { 0xFF };
        let raw_rb = if pc + 1 < len { (code[pc + 1] >> 4) & 0x0F } else { 0xFF };
        let raw_rd = if pc + 2 < len { code[pc + 2] & 0x0F } else { 0xFF };

        let fc = fast_cost_from_raw(opcode_byte, raw_ra, raw_rb, raw_rd, pc as u32, code, bitmask);
        sim.feed(&fc);

        // Advance to next instruction
        let skip = skip_distance(bitmask, pc);
        pc += 1 + skip;
    }

    // Finalize last block
    if in_block {
        costs[block_start] = sim.flush_and_get_cost() as u64;
    }

    costs
}

/// Extract flat operands (ra, rb, rd, imm1, imm2) from a decoded Args enum.
fn flatten_args(args: &Args) -> (u8, u8, u8, u64, u64) {
    match *args {
        Args::None => (0, 0, 0, 0, 0),
        Args::Imm { imm } => (0, 0, 0, imm, 0),
        Args::RegExtImm { ra, imm } => (ra as u8, 0, 0, imm, 0),
        Args::TwoImm { imm_x, imm_y } => (0, 0, 0, imm_x, imm_y),
        Args::Offset { offset } => (0, 0, 0, offset, 0),
        Args::RegImm { ra, imm } => (ra as u8, 0, 0, imm, 0),
        Args::RegTwoImm { ra, imm_x, imm_y } => (ra as u8, 0, 0, imm_x, imm_y),
        Args::RegImmOffset { ra, imm, offset } => (ra as u8, 0, 0, imm, offset),
        Args::TwoReg { rd, ra } => (ra as u8, 0, rd as u8, 0, 0),
        Args::TwoRegImm { ra, rb, imm } => (ra as u8, rb as u8, 0, imm, 0),
        Args::TwoRegOffset { ra, rb, offset } => (ra as u8, rb as u8, 0, offset, 0),
        Args::TwoRegTwoImm { ra, rb, imm_x, imm_y } => (ra as u8, rb as u8, 0, imm_x, imm_y),
        Args::ThreeReg { ra, rb, rd } => (ra as u8, rb as u8, rd as u8, 0, 0),
    }
}

/// Pre-decode all instructions into a flat array for fast execution.
///
/// Returns (decoded_insts, pc_to_idx) where:
/// - decoded_insts[i] is the i-th instruction with pre-decoded opcode, args, and gas
/// - pc_to_idx[pc] maps a byte offset to instruction index (u32::MAX = invalid)
fn predecode_instructions(
    code: &[u8],
    bitmask: &[u8],
    basic_block_starts: &[bool],
    gas_block_starts: &[bool],
    block_gas_costs: &[u64],
) -> (Vec<DecodedInst>, Vec<u32>) {
    let len = code.len();
    let mut insts = Vec::new();
    let mut pc_to_idx = vec![u32::MAX; len + 1]; // +1 for sentinel

    let skip_at = |i: usize| -> usize {
        for j in 0..25 {
            let idx = i + 1 + j;
            let bit = if idx < bitmask.len() { bitmask[idx] } else { 1 };
            if bit == 1 {
                return j;
            }
        }
        24
    };

    let mut pc = 0;
    while pc < len {
        if pc < bitmask.len() && bitmask[pc] == 1 {
            if let Some(opcode) = Opcode::from_byte(code[pc]) {
                let skip = skip_at(pc);
                let next_pc = (pc + 1 + skip) as u32;
                let category = opcode.category();
                let args = args::decode_args(code, pc, skip, category);
                let bb_gas_cost = if pc < gas_block_starts.len() && gas_block_starts[pc] {
                    block_gas_costs[pc]
                } else {
                    0
                };

                // Extract flat operands from decoded args
                let (ra, rb, rd, imm1, imm2) = flatten_args(&args);

                let idx = insts.len() as u32;
                pc_to_idx[pc] = idx;
                insts.push(DecodedInst {
                    opcode,
                    ra, rb, rd, imm1, imm2,
                    pc: pc as u32,
                    next_pc,
                    next_idx: u32::MAX, // resolved in second pass
                    target_idx: u32::MAX, // resolved in second pass
                    bb_gas_cost,
                });

                pc = next_pc as usize;
                continue;
            }
        }
        pc += 1;
    }

    let sentinel_idx = insts.len() as u32;

    // Add a sentinel instruction at the end (trap) so sequential advance past
    // the last instruction doesn't index out of bounds.
    insts.push(DecodedInst {
        opcode: Opcode::Trap,
        ra: 0, rb: 0, rd: 0, imm1: 0, imm2: 0,
        pc: len as u32,
        next_pc: len as u32 + 1,
        next_idx: sentinel_idx, // self-loop (will trap anyway)
        target_idx: u32::MAX,
        bb_gas_cost: 1, // charge 1 gas for the trap
    });

    // Second pass: resolve next_idx and target_idx for all instructions.
    for i in 0..insts.len() {
        let inst = &insts[i];
        // Resolve next sequential instruction index
        let np = inst.next_pc as usize;
        let next_idx = if np < pc_to_idx.len() {
            let ni = pc_to_idx[np];
            if ni != u32::MAX { ni } else { sentinel_idx }
        } else {
            sentinel_idx
        };

        // Resolve branch/jump target index.
        // For Jump/BranchEq/Ne/LtU/LtS/GeU/GeS: target PC is in imm1.
        // For BranchEqImm/NeImm/.../GtSImm and LoadImmJump: target PC is in imm2.
        let target_idx = {
            let op = inst.opcode;
            let target_from_imm1 = matches!(op,
                Opcode::Jump | Opcode::BranchEq | Opcode::BranchNe |
                Opcode::BranchLtU | Opcode::BranchLtS | Opcode::BranchGeU | Opcode::BranchGeS
            );
            let target_from_imm2 = matches!(op,
                Opcode::LoadImmJump |
                Opcode::BranchEqImm | Opcode::BranchNeImm |
                Opcode::BranchLtUImm | Opcode::BranchLeUImm |
                Opcode::BranchGeUImm | Opcode::BranchGtUImm |
                Opcode::BranchLtSImm | Opcode::BranchLeSImm |
                Opcode::BranchGeSImm | Opcode::BranchGtSImm
            );
            let target_pc_opt = if target_from_imm1 {
                Some(inst.imm1 as usize)
            } else if target_from_imm2 {
                Some(inst.imm2 as usize)
            } else {
                None
            };
            if let Some(target_pc) = target_pc_opt {
                if target_pc < basic_block_starts.len() && basic_block_starts[target_pc]
                    && target_pc < pc_to_idx.len()
                {
                    pc_to_idx[target_pc]
                } else {
                    u32::MAX
                }
            } else {
                u32::MAX
            }
        };

        // Can't borrow mutably with the immutable reference, so use indexing
        insts[i].next_idx = next_idx;
        insts[i].target_idx = target_idx;
    }

    (insts, pc_to_idx)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a VM with simple bitmask (every byte is instruction start).
    fn simple_vm(code: Vec<u8>, gas: Gas) -> Pvm {
        Pvm::new_simple(code, [0; 13], Vec::new(), gas)
    }

    #[test]
    fn test_trap_instruction() {
        let mut vm = simple_vm(vec![0], 100); // trap = opcode 0
        let (exit, _) = vm.run();
        assert_eq!(exit, ExitReason::Panic);
    }

    #[test]
    fn test_fallthrough_instruction() {
        // fallthrough (1) then trap (0)
        let mut vm = simple_vm(vec![1, 0], 100);
        let (exit, gas_used) = vm.run();
        assert_eq!(exit, ExitReason::Panic);
        assert_eq!(gas_used, 2); // 1 for fallthrough + 1 for trap
    }

    #[test]
    fn test_out_of_gas() {
        // Many fallthroughs
        let mut vm = simple_vm(vec![1; 100], 5);
        let (exit, gas_used) = vm.run();
        assert_eq!(exit, ExitReason::OutOfGas);
        assert_eq!(gas_used, 5);
    }

    #[test]
    fn test_empty_program() {
        let mut vm = simple_vm(vec![], 100);
        // PC=0, code is empty, zeta(0)=0 which is trap
        let (exit, _) = vm.run();
        assert_eq!(exit, ExitReason::Panic);
    }

    #[test]
    fn test_load_imm() {
        // load_imm (51), reg_byte (reg 0), immediate 42 (4 bytes LE)
        // Bitmask: [1, 0, 0, 0, 0, 0, 1] for the load_imm (6 bytes) + trap
        let code = vec![51, 0x00, 42, 0, 0, 0, 0]; // opcode + reg + 4-byte imm + trap
        let bitmask = vec![1, 0, 0, 0, 0, 0, 1];
        let mut vm = Pvm::new(code, bitmask, vec![], [0; 13], Vec::new(), 100);
        vm.step();
        assert_eq!(vm.registers[0], 42);
    }

    #[test]
    fn test_add_imm_64() {
        // add_imm_64 (149), reg_byte (rA=0, rB=1 => 0x10), immediate 10
        let code = vec![149, 0x10, 10, 0, 0, 0, 0]; // trap at end
        let bitmask = vec![1, 0, 0, 0, 0, 0, 1];
        let mut regs = [0u64; 13];
        regs[1] = 32;
        let mut vm = Pvm::new(code, bitmask, vec![], regs, Vec::new(), 100);
        vm.step();
        assert_eq!(vm.registers[0], 42);
    }

    #[test]
    fn test_add64_three_reg() {
        // add_64 (200), reg_byte (rA=0, rB=1 => 0x10), rD=2
        let code = vec![200, 0x10, 2, 0]; // trap at end
        let bitmask = vec![1, 0, 0, 1];
        let mut regs = [0u64; 13];
        regs[0] = 100;
        regs[1] = 200;
        let mut vm = Pvm::new(code, bitmask, vec![], regs, Vec::new(), 100);
        vm.step();
        assert_eq!(vm.registers[2], 300);
    }

    #[test]
    fn test_sub64() {
        let code = vec![201, 0x10, 2, 0];
        let bitmask = vec![1, 0, 0, 1];
        let mut regs = [0u64; 13];
        regs[0] = 300;
        regs[1] = 100;
        let mut vm = Pvm::new(code, bitmask, vec![], regs, Vec::new(), 100);
        vm.step();
        assert_eq!(vm.registers[2], 200);
    }

    #[test]
    fn test_and_xor_or() {
        // AND(210): 0xFF00 & 0x0FF0 = 0x0F00
        let code = vec![210, 0x10, 2, 0];
        let bitmask = vec![1, 0, 0, 1];
        let mut regs = [0u64; 13];
        regs[0] = 0xFF00;
        regs[1] = 0x0FF0;
        let mut vm = Pvm::new(code, bitmask, vec![], regs, Vec::new(), 100);
        vm.step();
        assert_eq!(vm.registers[2], 0x0F00);
    }

    #[test]
    fn test_set_lt_u() {
        let code = vec![216, 0x10, 2, 0];
        let bitmask = vec![1, 0, 0, 1];
        let mut regs = [0u64; 13];
        regs[0] = 5;
        regs[1] = 10;
        let mut vm = Pvm::new(code, bitmask, vec![], regs, Vec::new(), 100);
        vm.step();
        assert_eq!(vm.registers[2], 1);
    }

    #[test]
    fn test_ecalli() {
        // ecalli (10), immediate = 7 (1 byte)
        let code = vec![10, 7];
        let bitmask = vec![1, 0];
        let mut vm = Pvm::new(code, bitmask, vec![], [0; 13], Vec::new(), 100);
        let exit = vm.step();
        assert_eq!(exit, Some(ExitReason::HostCall(7)));
    }

    #[test]
    fn test_move_reg() {
        let code = vec![100, 0x10, 0]; // move_reg rD=0, rA=1, then trap
        let bitmask = vec![1, 0, 1];
        let mut regs = [0u64; 13];
        regs[1] = 42;
        let mut vm = Pvm::new(code, bitmask, vec![], regs, Vec::new(), 100);
        vm.step();
        assert_eq!(vm.registers[0], 42);
    }

    #[test]
    fn test_count_set_bits() {
        let code = vec![102, 0x10, 0]; // count_set_bits_64 rD=0, rA=1
        let bitmask = vec![1, 0, 1];
        let mut regs = [0u64; 13];
        regs[1] = 0xFF; // 8 bits set
        let mut vm = Pvm::new(code, bitmask, vec![], regs, Vec::new(), 100);
        vm.step();
        assert_eq!(vm.registers[0], 8);
    }

    #[test]
    fn test_div_u64_by_zero() {
        let code = vec![203, 0x10, 2, 0];
        let bitmask = vec![1, 0, 0, 1];
        let mut regs = [0u64; 13];
        regs[0] = 100;
        regs[1] = 0; // divide by zero
        let mut vm = Pvm::new(code, bitmask, vec![], regs, Vec::new(), 100);
        vm.step();
        assert_eq!(vm.registers[2], u64::MAX);
    }

    #[test]
    fn test_sign_extend_8() {
        let code = vec![108, 0x10, 0]; // sign_extend_8 rD=0, rA=1
        let bitmask = vec![1, 0, 1];
        let mut regs = [0u64; 13];
        regs[1] = 0x80; // -128 as i8
        let mut vm = Pvm::new(code, bitmask, vec![], regs, Vec::new(), 100);
        vm.step();
        assert_eq!(vm.registers[0] as i64, -128);
    }

    #[test]
    fn test_reverse_bytes() {
        let code = vec![111, 0x10, 0]; // reverse_bytes rD=0, rA=1
        let bitmask = vec![1, 0, 1];
        let mut regs = [0u64; 13];
        regs[1] = 0x0123456789ABCDEF;
        let mut vm = Pvm::new(code, bitmask, vec![], regs, Vec::new(), 100);
        vm.step();
        assert_eq!(vm.registers[0], 0xEFCDAB8967452301);
    }

    // ========================================================================
    // Issue #155 regression tests: gas block starts vs branch target validation
    // ========================================================================
    //
    // These tests verify that gas block boundaries and branch-target validation
    // are correctly separated per the JAM spec. Gas blocks are defined as
    // {PC=0} ∪ {post-terminator PCs}. Branch targets are valid landing sites
    // but must NOT affect gas block boundaries.

    /// Build a program with a branch target that is NOT post-terminator.
    ///
    /// Layout (bitmask all-1s, so skip=0 for each byte):
    ///   PC 0: Fallthrough (1)   — terminator, so PC 1 is a gas block start
    ///   PC 1: Fallthrough (1)   — terminator, so PC 2 is a gas block start
    ///   PC 2: Fallthrough (1)   — terminator, so PC 3 is a gas block start
    ///   PC 3: MoveReg (100)     — NOT a terminator
    ///   PC 4: Jump (40)         — terminator, offset = 0 bytes (skip=0)
    ///                             target = PC 4 + 0 = PC 4 (self-loop, but
    ///                             compute_bb_starts_inner reads code[i+1..i+5])
    ///
    /// For a cleaner branch target, use explicit bitmask to give Jump a 4-byte
    /// offset field pointing at a non-post-terminator PC.
    fn branch_target_mid_block_program() -> (Vec<u8>, Vec<u8>) {
        // Layout:
        //   PC 0: Fallthrough (1)  — terminator
        //   PC 1: MoveReg (100)    — NOT terminator, bitmask [1,0]
        //   PC 3: MoveReg (100)    — NOT terminator, bitmask [1,0]
        //   PC 5: Jump (40)        — terminator, offset = 4 bytes LE
        //                            bitmask [1,0,0,0,0]
        //                            offset = -2 as i32 → target = 5 + (-2) = 3
        //   PC 10: Trap (0)        — catches fallthrough
        //
        // Gas block starts (spec-correct): PC 0, 1 (post-Fallthrough), 10 (post-Jump)
        // Branch targets (validation):     PC 3 (Jump target)
        // basic_block_starts (old):        PC 0, 1, 3, 10
        // gas_block_starts (new):          PC 0, 1, 10
        let code = vec![
            1,          // PC 0: Fallthrough
            100, 0x10,  // PC 1: MoveReg rD=0, rA=1 (2 bytes)
            100, 0x10,  // PC 3: MoveReg rD=0, rA=1 (2 bytes)
            // PC 5: Jump, offset = -2 as i32 LE = [0xFE, 0xFF, 0xFF, 0xFF]
            40, 0xFE, 0xFF, 0xFF, 0xFF,
            0,          // PC 10: Trap
        ];
        let bitmask = vec![
            1,    // PC 0: Fallthrough
            1, 0, // PC 1-2: MoveReg (skip=1)
            1, 0, // PC 3-4: MoveReg (skip=1)
            1, 0, 0, 0, 0, // PC 5-9: Jump (skip=4)
            1,    // PC 10: Trap
        ];
        (code, bitmask)
    }

    #[test]
    fn test_gas_block_starts_exclude_branch_targets() {
        let (code, bitmask) = branch_target_mid_block_program();
        let bb_starts = compute_basic_block_starts(&code, &bitmask);
        let gas_starts = compute_gas_block_starts(&code, &bitmask);

        // basic_block_starts includes branch targets
        assert!(bb_starts[0],  "PC 0 should be a basic block start");
        assert!(bb_starts[1],  "PC 1 should be a basic block start (post-Fallthrough)");
        assert!(bb_starts[3],  "PC 3 should be a basic block start (branch target)");
        assert!(bb_starts[10], "PC 10 should be a basic block start (post-Jump)");

        // gas_block_starts does NOT include branch targets
        assert!(gas_starts[0],  "PC 0 should be a gas block start");
        assert!(gas_starts[1],  "PC 1 should be a gas block start (post-Fallthrough)");
        assert!(!gas_starts[3], "PC 3 should NOT be a gas block start (branch target only)");
        assert!(gas_starts[10], "PC 10 should be a gas block start (post-Jump)");
    }

    #[test]
    fn test_block_gas_costs_only_at_gas_block_starts() {
        let (code, bitmask) = branch_target_mid_block_program();
        let gas_starts = compute_gas_block_starts(&code, &bitmask);
        let costs = compute_block_gas_costs(&code, &bitmask, &gas_starts);

        // Gas costs should be nonzero only at gas block starts
        assert!(costs[0] > 0,  "PC 0 (gas block start) should have nonzero cost");
        assert!(costs[1] > 0,  "PC 1 (gas block start) should have nonzero cost");
        assert_eq!(costs[3], 0, "PC 3 (branch target, NOT gas start) should have zero cost");
        assert!(costs[10] > 0, "PC 10 (gas block start) should have nonzero cost");
    }

    #[test]
    fn test_step_and_run_same_gas_on_linear_program() {
        // Verify that step() and run() consume the same gas on a simple
        // linear program. This is a generic parity check between the two
        // execution paths (step uses need_gas_charge + block_gas_costs,
        // run uses predecoded bb_gas_cost).
        // Layout:
        //   PC 0: Fallthrough (1)  — terminator
        //   PC 1: MoveReg (100)    — NOT terminator
        //   PC 3: Trap (0)
        let code = vec![1, 100, 0x10, 0];
        let bitmask = vec![1, 1, 0, 1];

        // Run via step()
        let mut vm_step = Pvm::new(code.clone(), bitmask.clone(), vec![], [0; 13], Vec::new(), 1000);
        let initial_gas = vm_step.gas;
        loop {
            if vm_step.step().is_some() { break; }
        }
        let gas_used_step = initial_gas - vm_step.gas;

        // Run via run()
        let mut vm_run = Pvm::new(code, bitmask, vec![], [0; 13], Vec::new(), 1000);
        let (_, gas_used_run) = vm_run.run();

        assert_eq!(gas_used_step, gas_used_run,
            "step() and run() must consume the same gas");
    }

    #[test]
    fn test_branch_target_accepted_even_if_not_gas_start() {
        // A branch target that is NOT a gas block start must still be accepted
        // as a valid landing site for branch validation.
        let (code, bitmask) = branch_target_mid_block_program();

        // PC 3 is a branch target but NOT a gas start.
        // Verify is_basic_block_start accepts it (branch validation).
        let vm = Pvm::new(code, bitmask, vec![], [0; 13], Vec::new(), 1000);
        assert!(vm.is_basic_block_start(3),
            "branch target at PC 3 must be a valid basic block start for validation");

        // But the gas cost at PC 3 should be zero (it's not a gas block start).
        assert_eq!(vm.block_gas_costs[3], 0,
            "PC 3 should not carry gas cost (not a gas block start)");
    }
}
