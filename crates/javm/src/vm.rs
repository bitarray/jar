//! PVM execution engine (Appendix A of the Gray Paper v0.7.2).
//!
//! Implements the single-step state transition Ψ₁ and the full PVM Ψ.

use crate::args::{self, Args};
use crate::instruction::Opcode;
use crate::memory::{Memory, MemoryAccess};
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
    pub args: Args,
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
    /// Gas cost to charge at basic-block entry (0 for non-BB-start instructions).
    pub bb_gas_cost: u64,
}

/// PVM instance state (eq A.6).
#[derive(Clone, Debug)]
pub struct Pvm {
    /// ϱ: Gas counter (remaining gas).
    pub gas: Gas,
    /// φ: 13 general-purpose 64-bit registers.
    pub registers: [u64; PVM_REGISTER_COUNT],
    /// µ: Memory state.
    pub memory: Memory,
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
    /// Set of basic block start indices (ϖ).
    basic_block_starts: Vec<bool>,
    /// Gas cost for each basic block (indexed by block start PC).
    /// Only entries at basic_block_starts[i]==true are meaningful.
    pub block_gas_costs: Vec<u64>,
    /// When true, collect instruction trace in `pc_trace`.
    pub tracing_enabled: bool,
    /// Collected instruction trace: (PC, opcode_byte) pairs.
    pub pc_trace: Vec<(u32, u8)>,
    /// Pre-decoded instruction stream (indexed by instruction number).
    decoded_insts: Vec<DecodedInst>,
    /// Mapping from PC byte offset → instruction index. u32::MAX = invalid.
    pc_to_idx: Vec<u32>,
}

impl Pvm {
    /// Create a new PVM from parsed program components.
    pub fn new(
        code: Vec<u8>,
        bitmask: Vec<u8>,
        jump_table: Vec<u32>,
        registers: [u64; PVM_REGISTER_COUNT],
        memory: Memory,
        gas: Gas,
    ) -> Self {
        let basic_block_starts = compute_basic_block_starts(&code, &bitmask);
        let block_gas_costs = compute_block_gas_costs(&code, &bitmask, &basic_block_starts);
        let (decoded_insts, pc_to_idx) =
            predecode_instructions(&code, &bitmask, &basic_block_starts, &block_gas_costs);
        Self {
            gas,
            registers,
            memory,
            pc: 0,
            code,
            bitmask,
            jump_table,
            heap_base: 0,
            heap_top: 0,
            basic_block_starts,
            block_gas_costs,
            tracing_enabled: false,
            pc_trace: Vec::new(),
            decoded_insts,
            pc_to_idx,
        }
    }

    /// Create a simple PVM for testing (code only, trivial bitmask).
    pub fn new_simple(code: Vec<u8>, registers: [u64; PVM_REGISTER_COUNT], memory: Memory, gas: Gas) -> Self {
        // Build a bitmask where every byte is marked as an instruction start
        // This is a simplified mode; real programs use deblob.
        let bitmask = vec![1u8; code.len()];
        Self::new(code, bitmask, vec![], registers, memory, gas)
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
    /// Gas is charged per basic block: the entire block's cost is deducted
    /// when entering the block (at a basic block start). This matches the
    /// reference polkavm implementation and enables JIT compilation.
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
                // Invalid opcode or bitmask: treat as trap
                self.gas = self.gas.saturating_sub(1);
                return Some(ExitReason::Panic);
            }
        };

        // Per-instruction gas metering (v0.7.2: ϱ' = ϱ - ϱ_Δ where ϱ_Δ = 1).
        // All instructions cost ϱΔ = 1 gas per GP instruction table (including ecalli).
        // The host-call handler additionally charges g = 10 for ecalli.
        let gas_cost: u64 = 1;
        if self.gas < gas_cost {
            return Some(ExitReason::OutOfGas);
        }
        self.gas -= gas_cost;

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

        // Execute instruction
        self.execute(opcode, args, next_pc)
    }

    /// Execute a decoded instruction. Returns exit reason if halting.
    fn execute(&mut self, opcode: Opcode, args: Args, next_pc: u32) -> Option<ExitReason> {
        match opcode {
            // === A.5.1: No arguments ===
            Opcode::Trap => return Some(ExitReason::Panic),
            Opcode::Fallthrough => { self.pc = next_pc; }

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
                    if let Some(exit) = self.check_write_low(addr) { return Some(exit); }
                    match self.memory.write_u8(addr, imm_y as u8) {
                        MemoryAccess::Ok => self.pc = next_pc,
                        MemoryAccess::PageFault(a) => return Some(ExitReason::PageFault(a)),
                    }
                }
            }
            Opcode::StoreImmU16 => {
                if let Args::TwoImm { imm_x, imm_y } = args {
                    let addr = imm_x as u32;
                    if let Some(exit) = self.check_write_low(addr) { return Some(exit); }
                    match self.memory.write_u16_le(addr, imm_y as u16) {
                        MemoryAccess::Ok => self.pc = next_pc,
                        MemoryAccess::PageFault(a) => return Some(ExitReason::PageFault(a)),
                    }
                }
            }
            Opcode::StoreImmU32 => {
                if let Args::TwoImm { imm_x, imm_y } = args {
                    let addr = imm_x as u32;
                    if let Some(exit) = self.check_write_low(addr) { return Some(exit); }
                    match self.memory.write_u32_le(addr, imm_y as u32) {
                        MemoryAccess::Ok => self.pc = next_pc,
                        MemoryAccess::PageFault(a) => return Some(ExitReason::PageFault(a)),
                    }
                }
            }
            Opcode::StoreImmU64 => {
                if let Args::TwoImm { imm_x, imm_y } = args {
                    let addr = imm_x as u32;
                    if let Some(exit) = self.check_write_low(addr) { return Some(exit); }
                    match self.memory.write_u64_le(addr, imm_y) {
                        MemoryAccess::Ok => self.pc = next_pc,
                        MemoryAccess::PageFault(a) => return Some(ExitReason::PageFault(a)),
                    }
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
                    if let Some(exit) = self.check_read_low(addr) { return Some(exit); }
                    match self.memory.read_u8(addr) {
                        Some(v) => { self.registers[ra] = v as u64; self.pc = next_pc; }
                        None => return Some(ExitReason::PageFault(addr & !0xFFF)),
                    }
                }
            }
            Opcode::LoadI8 => {
                if let Args::RegImm { ra, imm } = args {
                    let addr = imm as u32;
                    if let Some(exit) = self.check_read_low(addr) { return Some(exit); }
                    match self.memory.read_u8(addr) {
                        Some(v) => { self.registers[ra] = v as i8 as i64 as u64; self.pc = next_pc; }
                        None => return Some(ExitReason::PageFault(addr & !0xFFF)),
                    }
                }
            }
            Opcode::LoadU16 => {
                if let Args::RegImm { ra, imm } = args {
                    let addr = imm as u32;
                    if let Some(exit) = self.check_read_low(addr) { return Some(exit); }
                    match self.memory.read_u16_le(addr) {
                        Some(v) => { self.registers[ra] = v as u64; self.pc = next_pc; }
                        None => return Some(ExitReason::PageFault(addr & !0xFFF)),
                    }
                }
            }
            Opcode::LoadI16 => {
                if let Args::RegImm { ra, imm } = args {
                    let addr = imm as u32;
                    if let Some(exit) = self.check_read_low(addr) { return Some(exit); }
                    match self.memory.read_u16_le(addr) {
                        Some(v) => { self.registers[ra] = v as i16 as i64 as u64; self.pc = next_pc; }
                        None => return Some(ExitReason::PageFault(addr & !0xFFF)),
                    }
                }
            }
            Opcode::LoadU32 => {
                if let Args::RegImm { ra, imm } = args {
                    let addr = imm as u32;
                    if let Some(exit) = self.check_read_low(addr) { return Some(exit); }
                    match self.memory.read_u32_le(addr) {
                        Some(v) => { self.registers[ra] = v as u64; self.pc = next_pc; }
                        None => return Some(ExitReason::PageFault(addr & !0xFFF)),
                    }
                }
            }
            Opcode::LoadI32 => {
                if let Args::RegImm { ra, imm } = args {
                    let addr = imm as u32;
                    if let Some(exit) = self.check_read_low(addr) { return Some(exit); }
                    match self.memory.read_u32_le(addr) {
                        Some(v) => { self.registers[ra] = v as i32 as i64 as u64; self.pc = next_pc; }
                        None => return Some(ExitReason::PageFault(addr & !0xFFF)),
                    }
                }
            }
            Opcode::LoadU64 => {
                if let Args::RegImm { ra, imm } = args {
                    let addr = imm as u32;
                    if let Some(exit) = self.check_read_low(addr) { return Some(exit); }
                    match self.memory.read_u64_le(addr) {
                        Some(v) => { self.registers[ra] = v; self.pc = next_pc; }
                        None => return Some(ExitReason::PageFault(addr & !0xFFF)),
                    }
                }
            }
            Opcode::StoreU8 => {
                if let Args::RegImm { ra, imm } = args {
                    let addr = imm as u32;
                    if let Some(exit) = self.check_write_low(addr) { return Some(exit); }
                    match self.memory.write_u8(addr, self.registers[ra] as u8) {
                        MemoryAccess::Ok => self.pc = next_pc,
                        MemoryAccess::PageFault(a) => return Some(ExitReason::PageFault(a)),
                    }
                }
            }
            Opcode::StoreU16 => {
                if let Args::RegImm { ra, imm } = args {
                    let addr = imm as u32;
                    if let Some(exit) = self.check_write_low(addr) { return Some(exit); }
                    match self.memory.write_u16_le(addr, self.registers[ra] as u16) {
                        MemoryAccess::Ok => self.pc = next_pc,
                        MemoryAccess::PageFault(a) => return Some(ExitReason::PageFault(a)),
                    }
                }
            }
            Opcode::StoreU32 => {
                if let Args::RegImm { ra, imm } = args {
                    let addr = imm as u32;
                    if let Some(exit) = self.check_write_low(addr) { return Some(exit); }
                    match self.memory.write_u32_le(addr, self.registers[ra] as u32) {
                        MemoryAccess::Ok => self.pc = next_pc,
                        MemoryAccess::PageFault(a) => return Some(ExitReason::PageFault(a)),
                    }
                }
            }
            Opcode::StoreU64 => {
                if let Args::RegImm { ra, imm } = args {
                    let addr = imm as u32;
                    if let Some(exit) = self.check_write_low(addr) { return Some(exit); }
                    match self.memory.write_u64_le(addr, self.registers[ra]) {
                        MemoryAccess::Ok => self.pc = next_pc,
                        MemoryAccess::PageFault(a) => return Some(ExitReason::PageFault(a)),
                    }
                }
            }

            // === A.5.7: One register + two immediates (store_imm_ind) ===
            Opcode::StoreImmIndU8 => {
                if let Args::RegTwoImm { ra, imm_x, imm_y } = args {
                    let addr = self.registers[ra].wrapping_add(imm_x) as u32;
                    if let Some(exit) = self.check_write_low(addr) { return Some(exit); }
                    match self.memory.write_u8(addr, imm_y as u8) {
                        MemoryAccess::Ok => self.pc = next_pc,
                        MemoryAccess::PageFault(a) => return Some(ExitReason::PageFault(a)),
                    }
                }
            }
            Opcode::StoreImmIndU16 => {
                if let Args::RegTwoImm { ra, imm_x, imm_y } = args {
                    let addr = self.registers[ra].wrapping_add(imm_x) as u32;
                    if let Some(exit) = self.check_write_low(addr) { return Some(exit); }
                    match self.memory.write_u16_le(addr, imm_y as u16) {
                        MemoryAccess::Ok => self.pc = next_pc,
                        MemoryAccess::PageFault(a) => return Some(ExitReason::PageFault(a)),
                    }
                }
            }
            Opcode::StoreImmIndU32 => {
                if let Args::RegTwoImm { ra, imm_x, imm_y } = args {
                    let addr = self.registers[ra].wrapping_add(imm_x) as u32;
                    if let Some(exit) = self.check_write_low(addr) { return Some(exit); }
                    match self.memory.write_u32_le(addr, imm_y as u32) {
                        MemoryAccess::Ok => self.pc = next_pc,
                        MemoryAccess::PageFault(a) => return Some(ExitReason::PageFault(a)),
                    }
                }
            }
            Opcode::StoreImmIndU64 => {
                if let Args::RegTwoImm { ra, imm_x, imm_y } = args {
                    let addr = self.registers[ra].wrapping_add(imm_x) as u32;
                    if let Some(exit) = self.check_write_low(addr) { return Some(exit); }
                    match self.memory.write_u64_le(addr, imm_y) {
                        MemoryAccess::Ok => self.pc = next_pc,
                        MemoryAccess::PageFault(a) => return Some(ExitReason::PageFault(a)),
                    }
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
                if let Args::TwoReg { rd, ra } = args {
                    // sbrk: GP eq A.5, opcode 101
                    // Heap-pointer tracking model (matching polkavm reference):
                    // - heap_top tracks the current end of the allocated heap
                    // - sbrk(0) returns heap_top (query mode)
                    // - sbrk(n) returns old heap_top and advances heap_top by n,
                    //   mapping any needed pages along the way
                    let size = self.registers[ra];
                    let ps = crate::PVM_PAGE_SIZE;

                    if size > u32::MAX as u64 {
                        self.registers[rd] = 0;
                    } else if size == 0 {
                        // Query mode: return current heap top
                        self.registers[rd] = self.heap_top as u64;
                    } else {
                        let size_u32 = size as u32;
                        let old_top = self.heap_top;
                        let new_top = (old_top as u64) + (size_u32 as u64);

                        if new_top > (u32::MAX as u64) + 1 {
                            self.registers[rd] = 0;
                        } else {
                            let new_top_u32 = new_top as u32;
                            // Map any pages in [old_top, new_top) that aren't mapped yet
                            let start_page = old_top / ps;
                            let end_page = if new_top_u32 == 0 { u32::MAX / ps } else { (new_top_u32 - 1) / ps };
                            for p in start_page..=end_page {
                                if !self.memory.is_page_mapped(p) {
                                    self.memory.map_page(p, crate::memory::PageAccess::ReadWrite);
                                }
                            }
                            self.registers[rd] = old_top as u64;
                            self.heap_top = new_top_u32;
                        }
                    }
                    self.pc = next_pc;
                }
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
                    if let Some(exit) = self.check_write_low(addr) { return Some(exit); }
                    match self.memory.write_u8(addr, self.registers[ra] as u8) {
                        MemoryAccess::Ok => self.pc = next_pc,
                        MemoryAccess::PageFault(a) => return Some(ExitReason::PageFault(a)),
                    }
                }
            }
            Opcode::StoreIndU16 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let addr = self.registers[rb].wrapping_add(imm) as u32;
                    if let Some(exit) = self.check_write_low(addr) { return Some(exit); }
                    match self.memory.write_u16_le(addr, self.registers[ra] as u16) {
                        MemoryAccess::Ok => self.pc = next_pc,
                        MemoryAccess::PageFault(a) => return Some(ExitReason::PageFault(a)),
                    }
                }
            }
            Opcode::StoreIndU32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let addr = self.registers[rb].wrapping_add(imm) as u32;
                    if let Some(exit) = self.check_write_low(addr) { return Some(exit); }
                    match self.memory.write_u32_le(addr, self.registers[ra] as u32) {
                        MemoryAccess::Ok => self.pc = next_pc,
                        MemoryAccess::PageFault(a) => return Some(ExitReason::PageFault(a)),
                    }
                }
            }
            Opcode::StoreIndU64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let addr = self.registers[rb].wrapping_add(imm) as u32;
                    if let Some(exit) = self.check_write_low(addr) { return Some(exit); }
                    match self.memory.write_u64_le(addr, self.registers[ra]) {
                        MemoryAccess::Ok => self.pc = next_pc,
                        MemoryAccess::PageFault(a) => return Some(ExitReason::PageFault(a)),
                    }
                }
            }
            Opcode::LoadIndU8 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let addr = self.registers[rb].wrapping_add(imm) as u32;
                    if let Some(exit) = self.check_read_low(addr) { return Some(exit); }
                    match self.memory.read_u8(addr) {
                        Some(v) => { self.registers[ra] = v as u64; self.pc = next_pc; }
                        None => return Some(ExitReason::PageFault(addr & !0xFFF)),
                    }
                }
            }
            Opcode::LoadIndI8 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let addr = self.registers[rb].wrapping_add(imm) as u32;
                    if let Some(exit) = self.check_read_low(addr) { return Some(exit); }
                    match self.memory.read_u8(addr) {
                        Some(v) => { self.registers[ra] = v as i8 as i64 as u64; self.pc = next_pc; }
                        None => return Some(ExitReason::PageFault(addr & !0xFFF)),
                    }
                }
            }
            Opcode::LoadIndU16 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let addr = self.registers[rb].wrapping_add(imm) as u32;
                    if let Some(exit) = self.check_read_low(addr) { return Some(exit); }
                    match self.memory.read_u16_le(addr) {
                        Some(v) => { self.registers[ra] = v as u64; self.pc = next_pc; }
                        None => return Some(ExitReason::PageFault(addr & !0xFFF)),
                    }
                }
            }
            Opcode::LoadIndI16 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let addr = self.registers[rb].wrapping_add(imm) as u32;
                    if let Some(exit) = self.check_read_low(addr) { return Some(exit); }
                    match self.memory.read_u16_le(addr) {
                        Some(v) => { self.registers[ra] = v as i16 as i64 as u64; self.pc = next_pc; }
                        None => return Some(ExitReason::PageFault(addr & !0xFFF)),
                    }
                }
            }
            Opcode::LoadIndU32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let addr = self.registers[rb].wrapping_add(imm) as u32;
                    if let Some(exit) = self.check_read_low(addr) { return Some(exit); }
                    match self.memory.read_u32_le(addr) {
                        Some(v) => { self.registers[ra] = v as u64; self.pc = next_pc; }
                        None => return Some(ExitReason::PageFault(addr & !0xFFF)),
                    }
                }
            }
            Opcode::LoadIndI32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let addr = self.registers[rb].wrapping_add(imm) as u32;
                    if let Some(exit) = self.check_read_low(addr) { return Some(exit); }
                    match self.memory.read_u32_le(addr) {
                        Some(v) => { self.registers[ra] = v as i32 as i64 as u64; self.pc = next_pc; }
                        None => return Some(ExitReason::PageFault(addr & !0xFFF)),
                    }
                }
            }
            Opcode::LoadIndU64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let addr = self.registers[rb].wrapping_add(imm) as u32;
                    if let Some(exit) = self.check_read_low(addr) { return Some(exit); }
                    match self.memory.read_u64_le(addr) {
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

        None
    }

    /// Check that a memory address is not in the low 2^16 range (eq A.7-A.8).
    fn check_read_low(&self, addr: u32) -> Option<ExitReason> {
        if addr < (1 << 16) {
            Some(ExitReason::Panic)
        } else {
            None
        }
    }

    /// Check that a write address is not in the low 2^16 range.
    fn check_write_low(&self, addr: u32) -> Option<ExitReason> {
        if addr < (1 << 16) {
            Some(ExitReason::Panic)
        } else {
            None
        }
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

            // Per-instruction gas charging (ϱΔ = 1 per instruction)
            if self.gas == 0 {
                self.pc = inst.pc;
                return (ExitReason::OutOfGas, initial_gas);
            }
            self.gas -= 1;

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
                Opcode::Fallthrough => {}

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
                    self.pc = inst.pc;
                    if let Some(e) = self.execute(inst.opcode, inst.args, next_pc) {
                        return (e, initial_gas - self.gas);
                    }
                    if self.pc != next_pc {
                        // sbrk changed PC — resolve dynamically
                        let t = self.pc as usize;
                        if t < self.pc_to_idx.len() {
                            let ti = self.pc_to_idx[t];
                            if ti != u32::MAX { branch_idx = ti; }
                            else { exit = Some(ExitReason::Panic); }
                        } else { exit = Some(ExitReason::Panic); }
                    }
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
                Opcode::Max => { self.registers[rd] = std::cmp::max(self.registers[ra] as i64, self.registers[rb] as i64) as u64; }
                Opcode::MaxU => { self.registers[rd] = std::cmp::max(self.registers[ra], self.registers[rb]); }
                Opcode::Min => { self.registers[rd] = std::cmp::min(self.registers[ra] as i64, self.registers[rb] as i64) as u64; }
                Opcode::MinU => { self.registers[rd] = std::cmp::min(self.registers[ra], self.registers[rb]); }

                // === All other instructions: delegate to execute() ===
                _ => {
                    self.pc = inst.pc;
                    if let Some(e) = self.execute(inst.opcode, inst.args, next_pc) {
                        return (e, initial_gas - self.gas);
                    }
                    if self.pc != next_pc {
                        // execute() changed PC — resolve dynamically
                        let t = self.pc as usize;
                        if t < self.pc_to_idx.len() {
                            let ti = self.pc_to_idx[t];
                            if ti != u32::MAX { branch_idx = ti; }
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
pub fn compute_basic_block_starts(code: &[u8], bitmask: &[u8]) -> Vec<bool> {
    let len = code.len();
    if len == 0 {
        return vec![];
    }

    let mut starts = vec![false; len];

    // Index 0 is always a basic block start if it's a valid instruction
    if !bitmask.is_empty() && bitmask[0] == 1 {
        if Opcode::from_byte(code[0]).is_some() {
            starts[0] = true;
        }
    }

    // For each terminator instruction, the next instruction starts a new block
    for i in 0..len {
        if i < bitmask.len() && bitmask[i] == 1 {
            if let Some(op) = Opcode::from_byte(code[i]) {
                if op.is_terminator() {
                    // Compute skip for this instruction
                    let skip = {
                        let mut s = 0;
                        for j in 0..25 {
                            let idx = i + 1 + j;
                            let bit = if idx < bitmask.len() { bitmask[idx] } else { 1 };
                            if bit == 1 {
                                s = j;
                                break;
                            }
                        }
                        s
                    };
                    let next = i + 1 + skip;
                    if next < len && next < bitmask.len() && bitmask[next] == 1 {
                        if let Some(next_op) = Opcode::from_byte(code[next]) {
                            let _ = next_op; // valid opcode
                            starts[next] = true;
                        }
                    }
                }
            }
        }
    }

    starts
}

/// Compute the gas cost for each basic block.
///
/// Gas is charged per basic block at block entry. The cost of a block is
/// the sum of all instruction gas costs within it (each instruction costs 1).
/// Returns a vector indexed by code offset; only entries where
/// basic_block_starts[i]==true are meaningful.
fn compute_block_gas_costs(code: &[u8], bitmask: &[u8], basic_block_starts: &[bool]) -> Vec<u64> {
    let len = code.len();
    let mut costs = vec![0u64; len];

    if len == 0 {
        return costs;
    }

    // Helper to compute skip(i) for a given position
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

    // For each basic block start, count instructions until the next block start
    // (or end of code). Each instruction costs 1 gas.
    let mut i = 0;
    while i < len {
        if basic_block_starts[i] {
            // Count instructions in this block
            let block_start = i;
            let mut count = 0u64;
            let mut pos = i;
            loop {
                if pos >= len {
                    break;
                }
                if pos < bitmask.len() && bitmask[pos] == 1 {
                    // This is an instruction start
                    if pos != block_start && basic_block_starts[pos] {
                        // Reached next basic block
                        break;
                    }
                    count += 1;
                    let s = skip_at(pos);
                    pos = pos + 1 + s;
                } else {
                    pos += 1;
                }
            }
            costs[block_start] = count;
            i = pos;
        } else {
            i += 1;
        }
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
                let bb_gas_cost = if pc < basic_block_starts.len() && basic_block_starts[pc] {
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
                    args,
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
        args: Args::None,
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

        // Resolve branch/jump target index for instructions where imm1 is the target PC:
        // Jump (OneOffset) and BranchEq/Ne/LtU/LtS/GeU/GeS (TwoRegOneOffset)
        let target_idx = {
            let op = inst.opcode;
            let has_imm1_target = matches!(op,
                Opcode::Jump | Opcode::BranchEq | Opcode::BranchNe |
                Opcode::BranchLtU | Opcode::BranchLtS | Opcode::BranchGeU | Opcode::BranchGeS
            );
            if has_imm1_target {
                let target_pc = inst.imm1 as usize;
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
    use crate::memory::Memory;

    /// Helper to create a VM with simple bitmask (every byte is instruction start).
    fn simple_vm(code: Vec<u8>, gas: Gas) -> Pvm {
        Pvm::new_simple(code, [0; 13], Memory::new(), gas)
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
        let mut vm = Pvm::new(code, bitmask, vec![], [0; 13], Memory::new(), 100);
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
        let mut vm = Pvm::new(code, bitmask, vec![], regs, Memory::new(), 100);
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
        let mut vm = Pvm::new(code, bitmask, vec![], regs, Memory::new(), 100);
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
        let mut vm = Pvm::new(code, bitmask, vec![], regs, Memory::new(), 100);
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
        let mut vm = Pvm::new(code, bitmask, vec![], regs, Memory::new(), 100);
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
        let mut vm = Pvm::new(code, bitmask, vec![], regs, Memory::new(), 100);
        vm.step();
        assert_eq!(vm.registers[2], 1);
    }

    #[test]
    fn test_ecalli() {
        // ecalli (10), immediate = 7 (1 byte)
        let code = vec![10, 7];
        let bitmask = vec![1, 0];
        let mut vm = Pvm::new(code, bitmask, vec![], [0; 13], Memory::new(), 100);
        let exit = vm.step();
        assert_eq!(exit, Some(ExitReason::HostCall(7)));
    }

    #[test]
    fn test_move_reg() {
        let code = vec![100, 0x10, 0]; // move_reg rD=0, rA=1, then trap
        let bitmask = vec![1, 0, 1];
        let mut regs = [0u64; 13];
        regs[1] = 42;
        let mut vm = Pvm::new(code, bitmask, vec![], regs, Memory::new(), 100);
        vm.step();
        assert_eq!(vm.registers[0], 42);
    }

    #[test]
    fn test_count_set_bits() {
        let code = vec![102, 0x10, 0]; // count_set_bits_64 rD=0, rA=1
        let bitmask = vec![1, 0, 1];
        let mut regs = [0u64; 13];
        regs[1] = 0xFF; // 8 bits set
        let mut vm = Pvm::new(code, bitmask, vec![], regs, Memory::new(), 100);
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
        let mut vm = Pvm::new(code, bitmask, vec![], regs, Memory::new(), 100);
        vm.step();
        assert_eq!(vm.registers[2], u64::MAX);
    }

    #[test]
    fn test_sign_extend_8() {
        let code = vec![108, 0x10, 0]; // sign_extend_8 rD=0, rA=1
        let bitmask = vec![1, 0, 1];
        let mut regs = [0u64; 13];
        regs[1] = 0x80; // -128 as i8
        let mut vm = Pvm::new(code, bitmask, vec![], regs, Memory::new(), 100);
        vm.step();
        assert_eq!(vm.registers[0] as i64, -128);
    }

    #[test]
    fn test_reverse_bytes() {
        let code = vec![111, 0x10, 0]; // reverse_bytes rD=0, rA=1
        let bitmask = vec![1, 0, 1];
        let mut regs = [0u64; 13];
        regs[1] = 0x0123456789ABCDEF;
        let mut vm = Pvm::new(code, bitmask, vec![], regs, Memory::new(), 100);
        vm.step();
        assert_eq!(vm.registers[0], 0xEFCDAB8967452301);
    }
}
