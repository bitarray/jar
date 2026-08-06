//! Lazy Pre-decode Implementation for JAVM Interpreter
//!
//! This module implements on-demand pre-decoding of basic blocks.
//! Instead of pre-decoding all instructions upfront, we decode blocks
//! when they are first executed.
//!
//! # Architecture
//!
//! - `get_decoded(pc)` - Main lazy access point
//! - `lazy_decode_block(start_pc)` - Decode single block on-demand
//! - `should_eager_decode()` - Check if we should switch to eager mode
//! - `switch_to_eager_mode()` - Migrate to full pre-decode
//!
//! # Usage
//!
//! ```rust
//! let program = InterpreterProgram::new(
//!     code,
//!     bitmask,
//!     jump_table,
//!     mem_cycles,
//!     true, // enable lazy mode
//! );
//!
//! let mut interpreter = Interpreter::new_with_program(program);
//! interpreter.run_segment(start_pc)?;
//! ```

use crate::backend::InterpreterProgram;
use crate::interpreter::{DecodedInst, Opcode};

/// Sentinel value for "no register"
const NO_REG: u8 = 0xFF;

/// Maximum percentage of blocks before switching to eager mode
const EAGER_SWITCH_THRESHOLD: f32 = 0.5;

impl InterpreterProgram {
    /// Create a new InterpreterProgram with optional lazy pre-decode
    ///
    /// # Arguments
    ///
    /// * `code` - Raw bytecode
    /// * `bitmask` - Opcode bitmask
    /// * `jump_table` - Dynamic jump table
    /// * `mem_cycles` - Memory tier cycles (25/50/75/100)
    /// * `lazy_enabled` - Enable lazy pre-decode (recommended for short programs)
    pub fn new(
        code: Vec<u8>,
        bitmask: Vec<u8>,
        jump_table: Vec<u32>,
        mem_cycles: u8,
        lazy_enabled: bool,
    ) -> Self {
        // Compute block structure (but don't pre-decode instructions)
        let basic_block_starts = compute_basic_block_starts(&code, &bitmask);
        let gas_block_starts = compute_gas_block_starts(&code, &bitmask);
        let block_gas_costs =
            compute_block_gas_costs(&code, &bitmask, &gas_block_starts, mem_cycles);

        // Initialize pc_to_idx (structure only, no instruction decoding)
        let pc_to_idx = compute_pc_to_idx(&code, &bitmask, &basic_block_starts);

        // Count total blocks
        let total_block_count = basic_block_starts.iter().filter(|&&x| x).count() as u32;

        // Pre-allocate cache (don't fill yet)
        let decoded_cache = vec![None; code.len()];
        let cache_valid_until = vec![0; code.len()];

        Self {
            decoded_insts: Vec::new(), // Lazy mode: starts empty
            pc_to_idx,
            basic_block_starts,
            block_gas_costs,
            code,
            bitmask,
            jump_table,
            mem_cycles,
            decoded_cache,
            cache_valid_until,
            decoded_block_count: 0,
            total_block_count,
            lazy_enabled,
        }
    }

    /// Check if we should switch to eager pre-decode mode
    ///
    /// When more than 50% of blocks have been decoded, eager mode
    /// becomes more efficient than continuing with lazy decoding.
    pub fn should_eager_decode(&self) -> bool {
        if self.total_block_count == 0 {
            return true;
        }
        self.decoded_block_count as f32 / self.total_block_count as f32
            > EAGER_SWITCH_THRESHOLD
    }

    /// Check if decoded instruction is cached
    #[inline]
    pub fn is_cached(&self, idx: u32) -> bool {
        idx as usize < self.decoded_cache.len()
            && self.decoded_cache[idx as usize].is_some()
    }

    /// Get cached decoded instruction
    #[inline]
    pub fn get_cached(&self, idx: u32) -> Option<&DecodedInst> {
        self.decoded_cache
            .get(idx as usize)
            .and_then(|opt| opt.as_ref())
    }

    /// Set cached decoded instruction
    #[inline]
    pub fn set_cached(&mut self, idx: u32, inst: DecodedInst) {
        if idx as usize >= self.decoded_cache.len() {
            self.decoded_cache.resize(idx as usize + 1, None);
            self.cache_valid_until.resize(idx as usize + 1, 0);
        }
        self.decoded_cache[idx as usize] = Some(inst);
    }

    /// Increment decoded block counter
    #[inline]
    pub fn increment_decoded_blocks(&mut self) {
        self.decoded_block_count += 1;
    }

    /// Check if lazy mode is enabled
    #[inline]
    pub fn is_lazy_enabled(&self) -> bool {
        self.lazy_enabled
    }

    /// Drain the cache and return decoded instructions
    /// Used when switching to eager mode
    pub fn drain_cache(&mut self) -> Vec<DecodedInst> {
        let mut result = Vec::with_capacity(self.decoded_cache.len());
        for opt in self.decoded_cache.drain(..) {
            if let Some(inst) = opt {
                result.push(inst);
            }
        }
        result
    }
}

impl Interpreter {
    /// On-demand get decoded instruction
    ///
    /// If the instruction is already cached, return it directly.
    /// Otherwise, decode the entire basic block and cache all instructions.
    #[inline]
    pub fn get_decoded(&mut self, pc: u32) -> &DecodedInst {
        let idx = self.program.pc_to_idx[pc as usize];

        if self.program.lazy_enabled {
            // Lazy mode
            if !self.program.is_cached(idx) {
                // First access to this block - decode lazily
                self.lazy_decode_block(pc);
            }
            self.program
                .get_cached(idx)
                .expect("lazy_decode_block should have populated cache")
        } else {
            // Eager mode (original behavior)
            &self.program.decoded_insts[idx as usize]
        }
    }

    /// Lazily decode a single basic block
    ///
    /// Decodes all instructions within the basic block starting at `start_pc`.
    /// Results are stored in `decoded_cache`.
    fn lazy_decode_block(&mut self, start_pc: u32) {
        let mem_cycles = self.program.mem_cycles;
        let code = &self.program.code;
        let bitmask = &self.program.bitmask;

        // Find block boundaries
        let block_end = self.find_block_end(start_pc);

        // Decode all instructions in the block
        let mut pc = start_pc;
        while pc < block_end {
            let idx = self.program.pc_to_idx[pc as usize];

            // Skip if already decoded
            if !self.program.is_cached(idx) {
                // Decode single instruction
                let inst = self.decode_single_instruction(pc);

                // Cache it
                self.program.set_cached(idx, inst);
            }

            // Move to next instruction
            pc = self.get_next_pc(pc);

            // Safety check to prevent infinite loops
            if pc <= start_pc && pc != block_end {
                break;
            }
        }

        // Update statistics
        self.program.increment_decoded_blocks();

        // Check if we should switch to eager mode
        if self.program.should_eager_decode() {
            self.switch_to_eager_mode();
        }
    }

    /// Decode a single instruction at the given PC
    ///
    /// This is a simplified version that only decodes what's needed
    /// for execution, without full pre-decoding optimization.
    fn decode_single_instruction(&self, pc: u32) -> DecodedInst {
        let code = &self.program.code;
        let bitmask = &self.program.bitmask;
        let mem_cycles = self.program.mem_cycles;

        let opcode_byte = code[pc as usize];
        let raw_ra = bitmask_get(bitmask, pc, 0).unwrap_or(NO_REG);
        let raw_rb = bitmask_get(bitmask, pc, 1).unwrap_or(NO_REG);
        let raw_rd = bitmask_get(bitmask, pc, 2).unwrap_or(NO_REG);

        // Compute gas cost at block entry
        let bb_gas_cost = self.compute_gas_cost_for_block(pc);

        // Parse immediates based on opcode
        let (imm1, imm2) = self.parse_immediates(pc, opcode_byte);

        // Calculate next/target indices
        let next_pc = self.get_next_pc(pc);
        let next_idx = if next_pc < code.len() as u32 {
            self.program.pc_to_idx[next_pc as usize]
        } else {
            0
        };

        let target_idx = if is_branch(opcode_byte) {
            self.resolve_branch_target_idx(pc, raw_ra, raw_rb)
        } else {
            0
        };

        DecodedInst {
            opcode: Opcode::from(opcode_byte),
            ra: raw_ra,
            rb: raw_rb,
            rd: raw_rd,
            imm1,
            imm2,
            pc,
            next_pc,
            next_idx,
            target_idx,
            bb_gas_cost,
        }
    }

    /// Compute gas cost for the block containing the given PC
    fn compute_gas_cost_for_block(&self, pc: u32) -> u32 {
        // Find the gas block that contains this PC
        for (i, &is_start) in self.program.basic_block_starts.iter().enumerate() {
            if is_start {
                let block_pc = i as u32;
                if block_pc <= pc {
                    // This is the containing block
                    if let Some(&cost) = self.program.block_gas_costs.get(i) {
                        return cost;
                    }
                }
            }
        }
        0 // Non-gas-block-start PC
    }

    /// Parse immediates for an instruction
    fn parse_immediates(&self, pc: u32, opcode: u8) -> (u64, u64) {
        let code = &self.program.code;

        match opcode {
            // load_imm: immediate in next 8 bytes
            20 | 51 => {
                let imm_bytes = &code[(pc as usize + 1)..(pc as usize + 9)];
                let imm = u64::from_le_bytes(imm_bytes.try_into().unwrap());
                (imm, 0)
            }
            // Branch with immediate: offset in next 4 bytes
            181..=255 => {
                let offset_bytes = &code[(pc as usize + 1)..(pc as usize + 5)];
                let offset = u32::from_le_bytes(offset_bytes.try_into().unwrap()) as i32;
                (offset as u64, 0)
            }
            // Default: no immediates
            _ => (0, 0),
        }
    }

    /// Find the end of a basic block starting at `start_pc`
    fn find_block_end(&self, start_pc: u32) -> u32 {
        let code = &self.program.code;
        let code_len = code.len() as u32;
        let mut pc = start_pc;

        while pc < code_len {
            let opcode = code[pc as usize];

            // Terminator instructions end the basic block
            if is_terminator(opcode) {
                return pc + instruction_length(opcode) as u32;
            }

            pc = self.get_next_pc(pc);
        }

        code_len
    }

    /// Get the PC of the next instruction after the one at `pc`
    #[inline]
    fn get_next_pc(&self, pc: u32) -> u32 {
        let opcode = self.program.code[pc as usize];
        pc + instruction_length(opcode) as u32
    }

    /// Resolve a branch target to an instruction index
    fn resolve_branch_target_idx(&self, pc: u32, _ra: u8, _rb: u8) -> u32 {
        let code = &self.program.code;

        // Branch offset is in next 4 bytes
        let offset_bytes = &code[(pc as usize + 1)..(pc as usize + 5)];
        let offset = i32::from_le_bytes(offset_bytes.try_into().unwrap());

        // Calculate target PC
        let target_pc = (pc as i32 + offset + instruction_length(code[pc as usize]) as i32) as u32;

        // Bounds check
        if target_pc >= code.len() as u32 {
            return 0;
        }

        self.program.pc_to_idx[target_pc as usize]
    }

    /// Switch to eager pre-decode mode
    ///
    /// This is called when we've decoded enough blocks that eager mode
    /// would be more efficient.
    fn switch_to_eager_mode(&mut self) {
        // Full pre-decode all blocks
        let gas_block_starts = compute_gas_block_starts(
            &self.program.code,
            &self.program.bitmask,
        );

        let (decoded_insts, pc_to_idx) = predecode_instructions(
            &self.program.code,
            &self.program.bitmask,
            &self.program.basic_block_starts,
            &gas_block_starts,
            &self.program.block_gas_costs,
        );

        self.program.decoded_insts = decoded_insts;
        self.program.pc_to_idx = pc_to_idx;
        self.program.lazy_enabled = false;

        // Release cache memory
        let _ = self.program.drain_cache();
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Compute PC to instruction index mapping
fn compute_pc_to_idx(
    code: &[u8],
    bitmask: &[u8],
    basic_block_starts: &[bool],
) -> Vec<u32> {
    let mut pc_to_idx = vec![0u32; code.len()];
    let mut current_idx = 0u32;
    let mut pc = 0u32;

    while pc < code.len() as u32 {
        pc_to_idx[pc as usize] = current_idx;

        // If this is a basic block start, increment the index
        if pc < basic_block_starts.len() as u32 && basic_block_starts[pc as usize] {
            current_idx += 1;
        }

        pc += instruction_length(code[pc as usize]) as u32;
    }

    pc_to_idx
}

/// Check if opcode is a terminator (ends basic block)
fn is_terminator(opcode: u8) -> bool {
    matches!(
        opcode,
        0 | 1 | // trap, fallthrough
        40 | 50 | // jump, jump_ind
        180 | // load_imm_jump
        181..=255 // conditional branches
    )
}

/// Check if opcode is a branch
fn is_branch(opcode: u8) -> bool {
    matches!(opcode, 181..=255)
}

/// Get bitmask value at position
fn bitmask_get(bitmask: &[u8], pc: u32, index: u8) -> Option<u8> {
    if pc >= bitmask.len() as u32 * 8 {
        return None;
    }

    let byte_idx = pc as usize / 8;
    let bit_offset = pc as usize % 8;

    let byte = bitmask.get(byte_idx)?;

    // Check if this bit is set
    if byte & (1 << bit_offset) == 0 {
        return None;
    }

    // Count set bits before this position to get the index
    let mut count = 0u8;
    for i in 0..bit_offset {
        if byte & (1 << i) != 0 {
            count += 1;
        }
    }

    // Check previous bytes
    for &prev_byte in &bitmask[..byte_idx] {
        count += prev_byte.count_ones() as u8;
    }

    if count == index {
        Some(0) // Placeholder - actual value from code
    } else {
        None
    }
}

/// Get instruction length
fn instruction_length(opcode: u8) -> u8 {
    match opcode {
        0..=39 => 1,   // Most single-byte opcodes
        40..=49 => 1,  // Jump instructions
        50 => 1,       // jump_ind
        51 => 9,       // load_imm (1 + 8 byte immediate)
        52..=69 => 1,  // Memory operations
        70..=73 => 3,  // store_imm_ind (1 + 2 byte offset)
        74..=79 => 1,
        80 => 9,       // load_imm_jump
        81..=89 => 1,
        90..=99 => 1, // ALU three-register
        100 => 1,     // move_reg
        101..=119 => 1,
        120..=123 => 3, // store_imm (1 + 2 byte immediate)
        124..=130 => 1,
        131..=179 => 3, // ALU reg+imm (1 + 2 byte immediate)
        180 => 9,       // load_imm_jump_ind
        181..=255 => 5, // Branch (1 + 4 byte offset)
    }
}

// Placeholder for compute_basic_block_starts
fn compute_basic_block_starts(_code: &[u8], _bitmask: &[u8]) -> Vec<bool> {
    vec![true]
}

// Placeholder for compute_gas_block_starts
fn compute_gas_block_starts(_code: &[u8], _bitmask: &[u8]) -> Vec<bool> {
    vec![true]
}

// Placeholder for compute_block_gas_costs
fn compute_block_gas_costs(
    _code: &[u8],
    _bitmask: &[u8],
    _gas_block_starts: &[bool],
    _mem_cycles: u8,
) -> Vec<u32> {
    vec![1]
}

// Placeholder for predecode_instructions
fn predecode_instructions(
    _code: &[u8],
    _bitmask: &[u8],
    _basic_block_starts: &[bool],
    _gas_block_starts: &[bool],
    _block_gas_costs: &[u32],
) -> (Vec<DecodedInst>, Vec<u32>) {
    (vec![], vec![])
}

#[cfg(test)]
mod lazy_decode_tests {
    use super::*;

    #[test]
    fn test_instruction_length() {
        assert_eq!(instruction_length(0), 1); // trap
        assert_eq!(instruction_length(51), 9); // load_imm
        assert_eq!(instruction_length(181), 5); // branch
    }

    #[test]
    fn test_is_terminator() {
        assert!(is_terminator(0)); // trap
        assert!(is_terminator(40)); // jump
        assert!(is_terminator(200)); // conditional branch
        assert!(!is_terminator(52)); // load
    }

    #[test]
    fn test_is_branch() {
        assert!(is_branch(181));
        assert!(is_branch(200));
        assert!(is_branch(255));
        assert!(!is_branch(52));
    }
}
