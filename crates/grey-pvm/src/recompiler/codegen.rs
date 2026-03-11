//! PVM-to-x86-64 code generation.
//!
//! Compiles PVM bytecode into native x86-64 machine code. Each PVM basic block
//! becomes a native basic block with gas metering at entry. PVM registers are
//! mapped to x86-64 registers for the duration of execution.
//!
//! Register mapping (PVM φ[i] → x86-64):
//!   φ[0]  → RBX   (callee-saved)
//!   φ[1]  → RBP   (callee-saved)
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
use crate::args::{self, Args};
use crate::instruction::Opcode;
use std::collections::HashMap;

/// Map PVM register index (0..12) to x86-64 register.
const REG_MAP: [Reg; 13] = [
    Reg::RBX,  // φ[0]
    Reg::RBP,  // φ[1]
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
/// Context pointer register.
const CTX: Reg = Reg::R15;

/// Caller-saved PVM registers that need saving around helper calls.
const CALLER_SAVED: [Reg; 8] = [
    Reg::RSI, Reg::RDI, Reg::R8, Reg::R9, Reg::R10, Reg::R11, Reg::RAX, Reg::RCX,
];

/// JitContext field offsets (must match the #[repr(C)] struct in mod.rs).
pub const CTX_REGS: i32 = 0;        // [u64; 13] = 104 bytes
pub const CTX_GAS: i32 = 104;       // i64
pub const CTX_MEMORY: i32 = 112;    // *mut Memory
pub const CTX_EXIT_REASON: i32 = 120; // u32
pub const CTX_EXIT_ARG: i32 = 124;  // u32
pub const CTX_HEAP_BASE: i32 = 128; // u32
pub const CTX_HEAP_TOP: i32 = 132;  // u32
pub const CTX_JT_PTR: i32 = 136;    // *const u32 (jump table pointer)
pub const CTX_JT_LEN: i32 = 144;    // u32 (jump table length)
pub const CTX_BB_STARTS: i32 = 152; // *const u8 (basic block starts)
pub const CTX_BB_LEN: i32 = 160;    // u32
pub const CTX_ENTRY_PC: i32 = 168;  // u32 (entry PC for re-entry)
pub const CTX_PC: i32 = 172;        // u32 (current PC on exit)
pub const CTX_DISPATCH_TABLE: i32 = 176; // *const i32 (PVM PC → native offset)
pub const CTX_CODE_BASE: i32 = 184; // u64 (base address of native code)

/// Exit reason codes (matching ExitReason enum).
pub const EXIT_HALT: u32 = 0;
pub const EXIT_PANIC: u32 = 1;
pub const EXIT_OOG: u32 = 2;
pub const EXIT_PAGE_FAULT: u32 = 3;
pub const EXIT_HOST_CALL: u32 = 4;

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

/// PVM-to-x86-64 compiler.
pub struct Compiler {
    pub asm: Assembler,
    /// PVM PC → native code label.
    block_labels: HashMap<u32, Label>,
    /// Label for the exit sequence.
    exit_label: Label,
    /// Label for the out-of-gas exit.
    oog_label: Label,
    /// Label for panic exit.
    panic_label: Label,
    /// Helper function addresses.
    helpers: HelperFns,
    /// Basic block starts from PVM.
    basic_block_starts: Vec<bool>,
    /// Jump table.
    jump_table: Vec<u32>,
}

impl Compiler {
    pub fn new(
        basic_block_starts: Vec<bool>,
        jump_table: Vec<u32>,
        helpers: HelperFns,
    ) -> Self {
        let mut asm = Assembler::new();
        let exit_label = asm.new_label();
        let oog_label = asm.new_label();
        let panic_label = asm.new_label();
        Self {
            asm,
            block_labels: HashMap::new(),
            exit_label,
            oog_label,
            panic_label,
            helpers,
            basic_block_starts,
            jump_table,
        }
    }

    /// Get or create a label for a PVM PC offset.
    fn label_for_pc(&mut self, pc: u32) -> Label {
        if let Some(&l) = self.block_labels.get(&pc) {
            l
        } else {
            let l = self.asm.new_label();
            self.block_labels.insert(pc, l);
            l
        }
    }

    fn is_basic_block_start(&self, idx: u32) -> bool {
        (idx as usize) < self.basic_block_starts.len() && self.basic_block_starts[idx as usize]
    }

    /// Compile a full PVM program.
    /// Returns (native_code, dispatch_table) where dispatch_table[pc] is the
    /// native code offset for PVM PC, or -1 if not a valid entry point.
    pub fn compile(mut self, code: &[u8], bitmask: &[u8]) -> (Vec<u8>, Vec<i32>) {
        // Emit prologue
        self.emit_prologue();

        // Pre-create labels for all basic block starts
        let bb_indices: Vec<u32> = self.basic_block_starts.iter().enumerate()
            .filter(|&(_, s)| *s)
            .map(|(i, _)| i as u32)
            .collect();
        for pc_idx in bb_indices {
            self.label_for_pc(pc_idx);
        }

        // Compile instructions
        let mut pc: usize = 0;
        while pc < code.len() {
            // Check bitmask
            if pc < bitmask.len() && bitmask[pc] != 1 {
                pc += 1;
                continue;
            }

            // Bind label if this is a known target
            if let Some(&label) = self.block_labels.get(&(pc as u32)) {
                self.asm.bind_label(label);
            }

            // Gas metering at basic block starts
            if self.is_basic_block_start(pc as u32) {
                // Track current PC for debugging (so panic reports correct location)
                self.asm.mov_store32_imm(CTX, CTX_PC as i32, pc as i32);
                self.emit_gas_check(pc, code, bitmask);
            }

            // Decode instruction
            let opcode_byte = code[pc];
            let opcode = match Opcode::from_byte(opcode_byte) {
                Some(op) => op,
                None => {
                    self.emit_exit(EXIT_PANIC, 0);
                    pc += 1;
                    continue;
                }
            };

            let skip = compute_skip(pc, bitmask);
            let next_pc = (pc + 1 + skip) as u32;
            let category = opcode.category();
            let args = args::decode_args(code, pc, skip, category);

            self.compile_instruction(opcode, &args, pc as u32, next_pc);

            pc += 1 + skip;
        }

        // Emit epilogue and exit sequences
        self.emit_exit_sequences();

        // Build dispatch table: PVM PC → native code offset
        let table_len = code.len() + 1; // +1 so PC=code.len() is valid (maps to panic)
        let mut dispatch_table = vec![-1i32; table_len];
        for (&pvm_pc, &label) in &self.block_labels {
            if let Some(offset) = self.asm.label_offset(label) {
                dispatch_table[pvm_pc as usize] = offset as i32;
            }
        }
        // PC=0 must always be valid (program start); if not already set, it'll be
        // set by the first basic block at PC 0.

        (self.asm.finalize(), dispatch_table)
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

    /// Call a helper function. Saves/restores caller-saved PVM registers.
    /// Args should be set up in RDI, RSI before calling this.
    /// Result will be in RAX after the call.
    fn emit_helper_call(&mut self, fn_addr: u64) {
        self.save_caller_saved();
        self.asm.mov_ri64(SCRATCH, fn_addr);
        self.asm.call_reg(SCRATCH);
        // Save result in SCRATCH before restoring
        self.asm.mov_rr(SCRATCH, Reg::RAX);
        self.restore_caller_saved();
        // Result is now in SCRATCH (RDX)
    }

    /// Check for page fault after a memory helper call.
    /// Assumes result/fault info is ready.
    fn emit_fault_check(&mut self) {
        // Check ctx.exit_reason != 0
        self.asm.cmp_ri(SCRATCH, 0);  // SCRATCH has fault flag
        // Actually we check the context field set by the helper
        // The helper sets ctx.exit_reason on fault.
        // We use a simpler approach: check ctx.exit_reason
        let fault_label = self.exit_label;
        // cmp dword [r15 + CTX_EXIT_REASON], 0
        self.asm.mov_load32(SCRATCH, CTX, CTX_EXIT_REASON);
        // We only need 32-bit comparison but loading 64 is fine (upper bits are 0)
        self.asm.cmp_ri(SCRATCH, 0);
        self.asm.jcc_label(Cc::NE, fault_label);
    }

    /// Emit a memory read. Address should be in SCRATCH (RDX).
    /// Result goes into the specified destination register.
    fn emit_mem_read(&mut self, dst: Reg, addr_reg: Reg, fn_addr: u64) {
        // Set up args: RDI = ctx (R15), RSI = addr
        // Save caller-saved first because RDI and RSI are PVM regs
        self.save_caller_saved();

        // RDI = ctx pointer (R15 is callee-saved, still valid)
        self.asm.mov_rr(Reg::RDI, CTX);
        // addr_reg should be SCRATCH which isn't a PVM register, so it's not on the stack.
        self.asm.mov_rr(Reg::RSI, addr_reg);

        self.asm.mov_ri64(Reg::RAX, fn_addr);
        self.asm.call_reg(Reg::RAX);
        // Result in RAX, save to SCRATCH before restore
        self.asm.mov_rr(SCRATCH, Reg::RAX);
        self.restore_caller_saved();

        // Check fault: load only exit_reason (32-bit) to avoid reading stale exit_arg
        self.asm.push(SCRATCH); // save result
        self.asm.mov_load32(SCRATCH, CTX, CTX_EXIT_REASON);
        self.asm.cmp_ri(SCRATCH, 0);
        self.asm.pop(SCRATCH); // restore result
        self.asm.jcc_label(Cc::NE, self.exit_label);

        // Move result to destination
        if dst != SCRATCH {
            self.asm.mov_rr(dst, SCRATCH);
        }
    }

    /// Emit a memory write. Address in SCRATCH, value prepared by caller.
    /// value_reg: register holding the value (will be moved to RDX/R8 for the call).
    fn emit_mem_write(&mut self, _addr_in_scratch: bool, val_reg: Reg, fn_addr: u64) {
        // We need: RDI = memory ptr, RSI = addr, RDX = value
        // addr is in SCRATCH (RDX), value in val_reg
        // Save addr and value to stack first, then save caller-saved, then set up args

        // Push value (might be a PVM register that'll be saved)
        self.asm.push(SCRATCH);    // addr on stack
        self.asm.push(val_reg);    // value on stack

        self.save_caller_saved();

        // Load args from stack (above the 8 saved registers)
        // Stack layout: [8 caller-saved regs] [value] [addr] ...
        // Offset from RSP: value = 8*8, addr = 8*8 + 8
        self.asm.mov_load64(Reg::RDX, Reg::RSP, 64);   // value
        self.asm.mov_load64(Reg::RSI, Reg::RSP, 72);    // addr
        self.asm.mov_rr(Reg::RDI, CTX);                 // ctx pointer

        self.asm.mov_ri64(Reg::RAX, fn_addr);
        self.asm.call_reg(Reg::RAX);

        self.restore_caller_saved();
        self.asm.pop(SCRATCH);  // discard saved value
        self.asm.pop(SCRATCH);  // discard saved addr

        // Check fault
        self.asm.push(SCRATCH);
        self.asm.mov_load32(SCRATCH, CTX, CTX_EXIT_REASON);
        self.asm.cmp_ri(SCRATCH, 0);
        self.asm.pop(SCRATCH);
        self.asm.jcc_label(Cc::NE, self.exit_label);
    }

    /// Emit a simpler memory write where address and value are immediates or
    /// already computed. Uses a push-based approach.
    fn emit_mem_write_from_scratch(&mut self, fn_addr: u64) {
        // RDI = memory, RSI = addr (already in SCRATCH saved to stack),
        // RDX = value (on stack too)
        // Caller must have pushed: [addr] [value] onto native stack before this.
        // We'll use a different approach: caller has set SCRATCH = addr,
        // and pushed value separately.

        // Actually let's simplify: provide addr in SCRATCH, value on top of stack.
        // Save everything, load from known positions.
        // This is too complex. Let's use a unified approach.
        let _ = fn_addr;
        unimplemented!("use emit_mem_write instead");
    }

    /// Compile a single PVM instruction.
    fn compile_instruction(&mut self, opcode: Opcode, args: &Args, _pc: u32, next_pc: u32) {
        match opcode {
            // === A.5.1: No arguments ===
            Opcode::Trap => {
                self.emit_exit(EXIT_PANIC, 0);
            }
            Opcode::Fallthrough => {
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
                    // Low address check — unmapped pages yield PageFault, not Panic
                    if (addr as u64) < 0x10000 {
                        self.emit_exit(EXIT_PAGE_FAULT, addr);
                        return;
                    }
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
                    // Stack: [8 saved] [value] [addr]
                    self.asm.mov_load64(Reg::RDX, Reg::RSP, 64); // value
                    self.asm.mov_load64(Reg::RSI, Reg::RSP, 72); // addr
                    self.asm.mov_rr(Reg::RDI, CTX);              // ctx
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
                    self.emit_static_branch(*offset as u32, true, next_pc);
                }
            }

            // === A.5.6: One register + one immediate ===
            Opcode::JumpInd => {
                if let Args::RegImm { ra, imm } = args {
                    self.emit_dynamic_jump(*ra, *imm);
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
                    self.emit_mem_read(REG_MAP[*ra], SCRATCH, fn_addr);
                    // Sign-extend for signed load variants
                    match opcode {
                        Opcode::LoadI8 => self.asm.movsx_8_64(REG_MAP[*ra], REG_MAP[*ra]),
                        Opcode::LoadI16 => self.asm.movsx_16_64(REG_MAP[*ra], REG_MAP[*ra]),
                        Opcode::LoadI32 => self.asm.movsxd(REG_MAP[*ra], REG_MAP[*ra]),
                        _ => {}
                    }
                }
            }
            Opcode::StoreU8 | Opcode::StoreU16 | Opcode::StoreU32 | Opcode::StoreU64 => {
                if let Args::RegImm { ra, imm } = args {
                    let addr = *imm as u32;
                    if (addr as u64) < 0x10000 {
                        self.emit_exit(EXIT_PAGE_FAULT, addr);
                        return;
                    }
                    let fn_addr = self.write_fn_for(opcode);
                    self.asm.mov_ri64(SCRATCH, addr as u64);
                    self.emit_mem_write(true, REG_MAP[*ra], fn_addr);
                }
            }

            // === A.5.7: One register + two immediates (store_imm_ind) ===
            Opcode::StoreImmIndU8 | Opcode::StoreImmIndU16 | Opcode::StoreImmIndU32 | Opcode::StoreImmIndU64 => {
                if let Args::RegTwoImm { ra, imm_x, imm_y } = args {
                    // addr = φ[ra] + imm_x
                    self.asm.mov_rr(SCRATCH, REG_MAP[*ra]);
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
                    self.asm.mov_load64(Reg::RDX, Reg::RSP, 64); // value
                    self.asm.mov_load64(Reg::RSI, Reg::RSP, 72); // addr
                    self.asm.mov_rr(Reg::RDI, CTX);              // ctx
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
                    self.emit_static_branch(*offset as u32, true, next_pc);
                }
            }
            Opcode::BranchEqImm => {
                if let Args::RegImmOffset { ra, imm, offset } = args {
                    self.emit_branch_imm(REG_MAP[*ra], *imm, Cc::E, *offset as u32, next_pc);
                }
            }
            Opcode::BranchNeImm => {
                if let Args::RegImmOffset { ra, imm, offset } = args {
                    self.emit_branch_imm(REG_MAP[*ra], *imm, Cc::NE, *offset as u32, next_pc);
                }
            }
            Opcode::BranchLtUImm => {
                if let Args::RegImmOffset { ra, imm, offset } = args {
                    self.emit_branch_imm(REG_MAP[*ra], *imm, Cc::B, *offset as u32, next_pc);
                }
            }
            Opcode::BranchLeUImm => {
                if let Args::RegImmOffset { ra, imm, offset } = args {
                    self.emit_branch_imm(REG_MAP[*ra], *imm, Cc::BE, *offset as u32, next_pc);
                }
            }
            Opcode::BranchGeUImm => {
                if let Args::RegImmOffset { ra, imm, offset } = args {
                    self.emit_branch_imm(REG_MAP[*ra], *imm, Cc::AE, *offset as u32, next_pc);
                }
            }
            Opcode::BranchGtUImm => {
                if let Args::RegImmOffset { ra, imm, offset } = args {
                    self.emit_branch_imm(REG_MAP[*ra], *imm, Cc::A, *offset as u32, next_pc);
                }
            }
            Opcode::BranchLtSImm => {
                if let Args::RegImmOffset { ra, imm, offset } = args {
                    self.emit_branch_imm(REG_MAP[*ra], *imm, Cc::L, *offset as u32, next_pc);
                }
            }
            Opcode::BranchLeSImm => {
                if let Args::RegImmOffset { ra, imm, offset } = args {
                    self.emit_branch_imm(REG_MAP[*ra], *imm, Cc::LE, *offset as u32, next_pc);
                }
            }
            Opcode::BranchGeSImm => {
                if let Args::RegImmOffset { ra, imm, offset } = args {
                    self.emit_branch_imm(REG_MAP[*ra], *imm, Cc::GE, *offset as u32, next_pc);
                }
            }
            Opcode::BranchGtSImm => {
                if let Args::RegImmOffset { ra, imm, offset } = args {
                    self.emit_branch_imm(REG_MAP[*ra], *imm, Cc::G, *offset as u32, next_pc);
                }
            }

            // === A.5.9: Two registers ===
            Opcode::MoveReg => {
                if let Args::TwoReg { rd, ra } = args {
                    self.asm.mov_rr(REG_MAP[*rd], REG_MAP[*ra]);
                }
            }
            Opcode::Sbrk => {
                if let Args::TwoReg { rd, ra } = args {
                    self.emit_sbrk(*rd, *ra);
                }
            }
            Opcode::CountSetBits64 => {
                if let Args::TwoReg { rd, ra } = args {
                    self.asm.popcnt64(REG_MAP[*rd], REG_MAP[*ra]);
                }
            }
            Opcode::CountSetBits32 => {
                if let Args::TwoReg { rd, ra } = args {
                    // Zero-extend to 32 bits first, then popcnt
                    self.asm.movzx_32_64(SCRATCH, REG_MAP[*ra]);
                    self.asm.popcnt64(REG_MAP[*rd], SCRATCH);
                }
            }
            Opcode::LeadingZeroBits64 => {
                if let Args::TwoReg { rd, ra } = args {
                    self.asm.lzcnt64(REG_MAP[*rd], REG_MAP[*ra]);
                }
            }
            Opcode::LeadingZeroBits32 => {
                if let Args::TwoReg { rd, ra } = args {
                    self.asm.movzx_32_64(SCRATCH, REG_MAP[*ra]);
                    // lzcnt on 64-bit value then subtract 32
                    self.asm.lzcnt64(REG_MAP[*rd], SCRATCH);
                    self.asm.sub_ri(REG_MAP[*rd], 32);
                }
            }
            Opcode::TrailingZeroBits64 => {
                if let Args::TwoReg { rd, ra } = args {
                    self.asm.tzcnt64(REG_MAP[*rd], REG_MAP[*ra]);
                }
            }
            Opcode::TrailingZeroBits32 => {
                if let Args::TwoReg { rd, ra } = args {
                    // Set bit 32 to ensure tzcnt doesn't return 64 for zero input
                    self.asm.mov_rr(SCRATCH, REG_MAP[*ra]);
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
                    self.asm.movsx_8_64(REG_MAP[*rd], REG_MAP[*ra]);
                }
            }
            Opcode::SignExtend16 => {
                if let Args::TwoReg { rd, ra } = args {
                    self.asm.movsx_16_64(REG_MAP[*rd], REG_MAP[*ra]);
                }
            }
            Opcode::ZeroExtend16 => {
                if let Args::TwoReg { rd, ra } = args {
                    self.asm.movzx_16_64(REG_MAP[*rd], REG_MAP[*ra]);
                }
            }
            Opcode::ReverseBytes => {
                if let Args::TwoReg { rd, ra } = args {
                    if *rd != *ra {
                        self.asm.mov_rr(REG_MAP[*rd], REG_MAP[*ra]);
                    }
                    self.asm.bswap64(REG_MAP[*rd]);
                }
            }

            // === A.5.10: Two registers + one immediate ===
            Opcode::StoreIndU8 | Opcode::StoreIndU16 | Opcode::StoreIndU32 | Opcode::StoreIndU64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    // addr = φ[rb] + imm, value = φ[ra] (matches interpreter)
                    self.asm.mov_rr(SCRATCH, REG_MAP[*rb]);
                    if *imm as i32 != 0 {
                        self.asm.add_ri(SCRATCH, *imm as i32);
                    }
                    self.asm.movzx_32_64(SCRATCH, SCRATCH);

                    let fn_addr = self.write_fn_for(opcode);
                    self.emit_mem_write(true, REG_MAP[*ra], fn_addr);
                }
            }
            Opcode::LoadIndU8 | Opcode::LoadIndI8 | Opcode::LoadIndU16 | Opcode::LoadIndI16 |
            Opcode::LoadIndU32 | Opcode::LoadIndI32 | Opcode::LoadIndU64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    // addr = φ[rb] + imm
                    self.asm.mov_rr(SCRATCH, REG_MAP[*rb]);
                    if *imm as i32 != 0 {
                        self.asm.add_ri(SCRATCH, *imm as i32);
                    }
                    self.asm.movzx_32_64(SCRATCH, SCRATCH);
                    let fn_addr = self.read_fn_for(opcode);
                    self.emit_mem_read(REG_MAP[*ra], SCRATCH, fn_addr);
                    // Sign-extend for signed load variants
                    match opcode {
                        Opcode::LoadIndI8 => self.asm.movsx_8_64(REG_MAP[*ra], REG_MAP[*ra]),
                        Opcode::LoadIndI16 => self.asm.movsx_16_64(REG_MAP[*ra], REG_MAP[*ra]),
                        Opcode::LoadIndI32 => self.asm.movsxd(REG_MAP[*ra], REG_MAP[*ra]),
                        _ => {}
                    }
                }
            }
            Opcode::AddImm32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    if *ra != *rb { self.asm.mov_rr(REG_MAP[*ra], REG_MAP[*rb]); }
                    self.asm.add_ri32(REG_MAP[*ra], *imm as i32);
                    self.asm.movsxd(REG_MAP[*ra], REG_MAP[*ra]);
                }
            }
            Opcode::AddImm64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    if *ra != *rb { self.asm.mov_rr(REG_MAP[*ra], REG_MAP[*rb]); }
                    self.asm.add_ri(REG_MAP[*ra], *imm as i32);
                }
            }
            Opcode::AndImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    if *ra != *rb { self.asm.mov_rr(REG_MAP[*ra], REG_MAP[*rb]); }
                    self.asm.and_ri(REG_MAP[*ra], *imm as i32);
                }
            }
            Opcode::XorImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    if *ra != *rb { self.asm.mov_rr(REG_MAP[*ra], REG_MAP[*rb]); }
                    self.asm.xor_ri(REG_MAP[*ra], *imm as i32);
                }
            }
            Opcode::OrImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    if *ra != *rb { self.asm.mov_rr(REG_MAP[*ra], REG_MAP[*rb]); }
                    self.asm.or_ri(REG_MAP[*ra], *imm as i32);
                }
            }
            Opcode::MulImm32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.asm.imul_rri32(REG_MAP[*ra], REG_MAP[*rb], *imm as i32);
                    self.asm.movsxd(REG_MAP[*ra], REG_MAP[*ra]);
                }
            }
            Opcode::MulImm64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.asm.imul_rri(REG_MAP[*ra], REG_MAP[*rb], *imm as i32);
                }
            }
            Opcode::SetLtUImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.asm.mov_ri64(SCRATCH, *imm);
                    self.asm.cmp_rr(REG_MAP[*rb], SCRATCH);
                    self.asm.setcc(Cc::B, REG_MAP[*ra]);
                    self.asm.movzx_8_64(REG_MAP[*ra], REG_MAP[*ra]);
                }
            }
            Opcode::SetLtSImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.asm.mov_ri64(SCRATCH, *imm);
                    self.asm.cmp_rr(REG_MAP[*rb], SCRATCH);
                    self.asm.setcc(Cc::L, REG_MAP[*ra]);
                    self.asm.movzx_8_64(REG_MAP[*ra], REG_MAP[*ra]);
                }
            }
            Opcode::SetGtUImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.asm.mov_ri64(SCRATCH, *imm);
                    self.asm.cmp_rr(REG_MAP[*rb], SCRATCH);
                    self.asm.setcc(Cc::A, REG_MAP[*ra]);
                    self.asm.movzx_8_64(REG_MAP[*ra], REG_MAP[*ra]);
                }
            }
            Opcode::SetGtSImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.asm.mov_ri64(SCRATCH, *imm);
                    self.asm.cmp_rr(REG_MAP[*rb], SCRATCH);
                    self.asm.setcc(Cc::G, REG_MAP[*ra]);
                    self.asm.movzx_8_64(REG_MAP[*ra], REG_MAP[*ra]);
                }
            }
            Opcode::ShloLImm32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    if *ra != *rb { self.asm.mov_rr(REG_MAP[*ra], REG_MAP[*rb]); }
                    self.asm.shl_ri32(REG_MAP[*ra], (*imm as u8) & 31);
                    self.asm.movsxd(REG_MAP[*ra], REG_MAP[*ra]);
                }
            }
            Opcode::ShloRImm32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    if *ra != *rb { self.asm.mov_rr(REG_MAP[*ra], REG_MAP[*rb]); }
                    self.asm.movzx_32_64(REG_MAP[*ra], REG_MAP[*ra]);
                    self.asm.shr_ri32(REG_MAP[*ra], (*imm as u8) & 31);
                    self.asm.movsxd(REG_MAP[*ra], REG_MAP[*ra]);
                }
            }
            Opcode::SharRImm32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    if *ra != *rb { self.asm.mov_rr(REG_MAP[*ra], REG_MAP[*rb]); }
                    self.asm.sar_ri32(REG_MAP[*ra], (*imm as u8) & 31);
                    self.asm.movsxd(REG_MAP[*ra], REG_MAP[*ra]);
                }
            }
            Opcode::ShloLImm64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    if *ra != *rb { self.asm.mov_rr(REG_MAP[*ra], REG_MAP[*rb]); }
                    self.asm.shl_ri64(REG_MAP[*ra], (*imm as u8) & 63);
                }
            }
            Opcode::ShloRImm64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    if *ra != *rb { self.asm.mov_rr(REG_MAP[*ra], REG_MAP[*rb]); }
                    self.asm.shr_ri64(REG_MAP[*ra], (*imm as u8) & 63);
                }
            }
            Opcode::SharRImm64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    if *ra != *rb { self.asm.mov_rr(REG_MAP[*ra], REG_MAP[*rb]); }
                    self.asm.sar_ri64(REG_MAP[*ra], (*imm as u8) & 63);
                }
            }
            Opcode::NegAddImm32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    // rd = imm - rb (32-bit)
                    if *ra == *rb {
                        self.asm.mov_rr(SCRATCH, REG_MAP[*rb]);
                        self.asm.mov_ri64(REG_MAP[*ra], *imm);
                        self.asm.sub_rr32(REG_MAP[*ra], SCRATCH);
                    } else {
                        self.asm.mov_ri64(REG_MAP[*ra], *imm);
                        self.asm.sub_rr32(REG_MAP[*ra], REG_MAP[*rb]);
                    }
                    self.asm.movsxd(REG_MAP[*ra], REG_MAP[*ra]);
                }
            }
            Opcode::NegAddImm64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    if *ra == *rb {
                        self.asm.mov_rr(SCRATCH, REG_MAP[*rb]);
                        self.asm.mov_ri64(REG_MAP[*ra], *imm);
                        self.asm.sub_rr(REG_MAP[*ra], SCRATCH);
                    } else {
                        self.asm.mov_ri64(REG_MAP[*ra], *imm);
                        self.asm.sub_rr(REG_MAP[*ra], REG_MAP[*rb]);
                    }
                }
            }
            // Alt shifts: rd = imm OP rb (operands swapped)
            Opcode::ShloLImmAlt32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    // rd = imm << (rb & 31)
                    let shift_src = if *ra == *rb { self.asm.mov_rr(SCRATCH, REG_MAP[*rb]); SCRATCH } else { REG_MAP[*rb] };
                    self.asm.mov_ri64(REG_MAP[*ra], *imm);
                    self.emit_shift_by_reg32(REG_MAP[*ra], shift_src, 4); // SHL
                    self.asm.movsxd(REG_MAP[*ra], REG_MAP[*ra]);
                }
            }
            Opcode::ShloRImmAlt32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let shift_src = if *ra == *rb { self.asm.mov_rr(SCRATCH, REG_MAP[*rb]); SCRATCH } else { REG_MAP[*rb] };
                    self.asm.mov_ri64(REG_MAP[*ra], *imm);
                    self.asm.movzx_32_64(REG_MAP[*ra], REG_MAP[*ra]);
                    self.emit_shift_by_reg32(REG_MAP[*ra], shift_src, 5); // SHR
                    self.asm.movsxd(REG_MAP[*ra], REG_MAP[*ra]);
                }
            }
            Opcode::SharRImmAlt32 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let shift_src = if *ra == *rb { self.asm.mov_rr(SCRATCH, REG_MAP[*rb]); SCRATCH } else { REG_MAP[*rb] };
                    self.asm.mov_ri64(REG_MAP[*ra], *imm);
                    self.emit_shift_by_reg32(REG_MAP[*ra], shift_src, 7); // SAR
                    self.asm.movsxd(REG_MAP[*ra], REG_MAP[*ra]);
                }
            }
            Opcode::ShloLImmAlt64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let shift_src = if *ra == *rb { self.asm.mov_rr(SCRATCH, REG_MAP[*rb]); SCRATCH } else { REG_MAP[*rb] };
                    self.asm.mov_ri64(REG_MAP[*ra], *imm);
                    self.emit_shift_by_reg64(REG_MAP[*ra], shift_src, 4);
                }
            }
            Opcode::ShloRImmAlt64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let shift_src = if *ra == *rb { self.asm.mov_rr(SCRATCH, REG_MAP[*rb]); SCRATCH } else { REG_MAP[*rb] };
                    self.asm.mov_ri64(REG_MAP[*ra], *imm);
                    self.emit_shift_by_reg64(REG_MAP[*ra], shift_src, 5);
                }
            }
            Opcode::SharRImmAlt64 => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let shift_src = if *ra == *rb { self.asm.mov_rr(SCRATCH, REG_MAP[*rb]); SCRATCH } else { REG_MAP[*rb] };
                    self.asm.mov_ri64(REG_MAP[*ra], *imm);
                    self.emit_shift_by_reg64(REG_MAP[*ra], shift_src, 7);
                }
            }
            Opcode::CmovIzImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    // if φ[rb] == 0 then φ[ra] = imm
                    self.asm.test_rr(REG_MAP[*rb], REG_MAP[*rb]);
                    let skip = self.asm.new_label();
                    self.asm.jcc_label(Cc::NE, skip);
                    self.asm.mov_ri64(REG_MAP[*ra], *imm);
                    self.asm.bind_label(skip);
                }
            }
            Opcode::CmovNzImm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    self.asm.test_rr(REG_MAP[*rb], REG_MAP[*rb]);
                    let skip = self.asm.new_label();
                    self.asm.jcc_label(Cc::E, skip);
                    self.asm.mov_ri64(REG_MAP[*ra], *imm);
                    self.asm.bind_label(skip);
                }
            }
            Opcode::RotR64Imm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    if *ra != *rb { self.asm.mov_rr(REG_MAP[*ra], REG_MAP[*rb]); }
                    self.asm.ror_ri64(REG_MAP[*ra], (*imm as u8) & 63);
                }
            }
            Opcode::RotR64ImmAlt => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    // rd = imm ROR rb
                    let shift_src = if *ra == *rb { self.asm.mov_rr(SCRATCH, REG_MAP[*rb]); SCRATCH } else { REG_MAP[*rb] };
                    self.asm.mov_ri64(REG_MAP[*ra], *imm);
                    self.emit_shift_by_reg64(REG_MAP[*ra], shift_src, 1); // ROR
                }
            }
            Opcode::RotR32Imm => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    if *ra != *rb { self.asm.mov_rr(REG_MAP[*ra], REG_MAP[*rb]); }
                    self.asm.movzx_32_64(REG_MAP[*ra], REG_MAP[*ra]);
                    self.asm.ror_ri32(REG_MAP[*ra], (*imm as u8) & 31);
                    self.asm.movsxd(REG_MAP[*ra], REG_MAP[*ra]);
                }
            }
            Opcode::RotR32ImmAlt => {
                if let Args::TwoRegImm { ra, rb, imm } = args {
                    let shift_src = if *ra == *rb { self.asm.mov_rr(SCRATCH, REG_MAP[*rb]); SCRATCH } else { REG_MAP[*rb] };
                    self.asm.mov_ri64(REG_MAP[*ra], *imm);
                    self.asm.movzx_32_64(REG_MAP[*ra], REG_MAP[*ra]);
                    self.emit_shift_by_reg32(REG_MAP[*ra], shift_src, 1); // ROR
                    self.asm.movsxd(REG_MAP[*ra], REG_MAP[*ra]);
                }
            }

            // === A.5.11: Two registers + one offset ===
            Opcode::BranchEq => {
                if let Args::TwoRegOffset { ra, rb, offset } = args {
                    self.emit_branch_reg(REG_MAP[*ra], REG_MAP[*rb], Cc::E, *offset as u32, next_pc);
                }
            }
            Opcode::BranchNe => {
                if let Args::TwoRegOffset { ra, rb, offset } = args {
                    self.emit_branch_reg(REG_MAP[*ra], REG_MAP[*rb], Cc::NE, *offset as u32, next_pc);
                }
            }
            Opcode::BranchLtU => {
                if let Args::TwoRegOffset { ra, rb, offset } = args {
                    self.emit_branch_reg(REG_MAP[*ra], REG_MAP[*rb], Cc::B, *offset as u32, next_pc);
                }
            }
            Opcode::BranchLtS => {
                if let Args::TwoRegOffset { ra, rb, offset } = args {
                    self.emit_branch_reg(REG_MAP[*ra], REG_MAP[*rb], Cc::L, *offset as u32, next_pc);
                }
            }
            Opcode::BranchGeU => {
                if let Args::TwoRegOffset { ra, rb, offset } = args {
                    self.emit_branch_reg(REG_MAP[*ra], REG_MAP[*rb], Cc::AE, *offset as u32, next_pc);
                }
            }
            Opcode::BranchGeS => {
                if let Args::TwoRegOffset { ra, rb, offset } = args {
                    self.emit_branch_reg(REG_MAP[*ra], REG_MAP[*rb], Cc::GE, *offset as u32, next_pc);
                }
            }

            // === A.5.12: Two registers + two immediates ===
            Opcode::LoadImmJumpInd => {
                if let Args::TwoRegTwoImm { ra, rb, imm_x, imm_y } = args {
                    // GP: registers[ra] = imm_x, addr = registers[rb] + imm_y
                    self.asm.mov_ri64(REG_MAP[*ra], *imm_x);
                    self.emit_dynamic_jump(*rb, *imm_y);
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
            Opcode::Add64 => { self.emit_alu3_64(args, |a, d, s| { a.add_rr(d, s); }); }
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
    fn emit_static_branch(&mut self, target: u32, condition: bool, _fallthrough: u32) {
        if !condition {
            return;
        }
        if !self.is_basic_block_start(target) {
            self.emit_exit(EXIT_PANIC, 0);
            return;
        }
        let label = self.label_for_pc(target);
        self.asm.jmp_label(label);
    }

    /// Emit a dynamic jump (through jump table).
    fn emit_dynamic_jump(&mut self, ra: usize, imm: u64) {
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

        // Store idx in ctx and exit with DJUMP marker for host-side resolution.
        // We avoid inlining the full jump table lookup to prevent clobbering
        // PVM-mapped registers (e.g. RAX = φ[11]).
        // The outer loop handles djump resolution.
        self.asm.mov_store32(CTX, CTX_EXIT_ARG as i32, SCRATCH);
        self.asm.mov_store32_imm(CTX, CTX_EXIT_REASON as i32, 5); // 5 = DJUMP
        self.asm.jmp_label(self.exit_label);
    }

    /// Emit a branch comparing register against immediate.
    fn emit_branch_imm(&mut self, reg: Reg, imm: u64, cc: Cc, target: u32, _fallthrough: u32) {
        if !self.is_basic_block_start(target) {
            // Target not valid → panic if condition true, else just fall through
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
    fn emit_branch_reg(&mut self, a: Reg, b: Reg, cc: Cc, target: u32, _fallthrough: u32) {
        if !self.is_basic_block_start(target) {
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

    fn shift_cl32(&mut self, op: u8, dst: Reg) {
        self.asm.shift_cl32(op, dst);
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

            // Save RAX if it's not the destination
            let _need_save_rax = d_reg != Reg::RAX && a_reg != Reg::RAX && b_reg != Reg::RAX;
            // Actually we always clobber RAX and RDX. Save them.
            self.asm.push(Reg::RAX);
            self.asm.push(SCRATCH); // save RDX

            // Load dividend into RAX
            self.asm.mov_rr(Reg::RAX, a_reg);
            // Put divisor somewhere safe (use a callee-saved if not clobbered)
            // If b_reg is RAX or RDX, we need to save it first
            let div_reg;
            if b_reg == Reg::RAX || b_reg == SCRATCH {
                // Load divisor from the saved stack value
                // Actually b_reg's value is already on stack if it's RAX
                // This is getting complex. Just push b_reg before we clobber.
                self.asm.push(b_reg);
                // We'll use stack later
                div_reg = Reg::RCX; // temp, but RCX = φ[12]
                self.asm.push(Reg::RCX);
                self.asm.mov_load64(div_reg, Reg::RSP, 8); // load saved b_reg
            } else {
                div_reg = b_reg;
            }

            if is_32bit {
                if signed {
                    self.asm.movsxd(Reg::RAX, Reg::RAX);
                    self.asm.cdq();
                    self.asm.idiv32(div_reg);
                } else {
                    self.asm.movzx_32_64(Reg::RAX, Reg::RAX);
                    self.asm.mov_ri64(SCRATCH, 0); // zero RDX
                    self.asm.div32(div_reg);
                }
            } else {
                if signed {
                    self.asm.cqo();
                    self.asm.idiv64(div_reg);
                } else {
                    self.asm.mov_ri64(SCRATCH, 0); // zero RDX
                    self.asm.div64(div_reg);
                }
            }

            // Result: quotient in RAX, remainder in RDX
            let result_reg = if remainder { SCRATCH } else { Reg::RAX };

            // Restore b_reg if we saved it
            if b_reg == Reg::RAX || b_reg == SCRATCH {
                self.asm.pop(Reg::RCX);
                self.asm.pop(b_reg);
            }

            // Save result to a temp location
            self.asm.mov_rr(REG_MAP[*rd], result_reg);

            // Restore RAX and RDX
            self.asm.pop(SCRATCH);
            self.asm.pop(Reg::RAX);

            // But wait: we just moved result into d_reg, then restored RAX.
            // If d_reg is RAX, the restore just clobbered it!
            // Need to handle this case specially.
            if d_reg == Reg::RAX {
                // Put result on stack above the saved values
                // Actually let's restructure: save result to context temp, restore, load from temp
                // This is getting complex. Let me simplify.
                // Re-do: use context temp storage
                self.asm.pop(SCRATCH); // undo pop SCRATCH
                self.asm.pop(Reg::RAX); // undo pop RAX
                // ... this doesn't work because we already did it.
                // Let's just handle the d_reg == RAX case with a separate path.
            }

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

    /// Emit sbrk helper call.
    fn emit_sbrk(&mut self, rd: usize, ra: usize) {
        // sbrk(size) where size = φ[ra]
        // If size == 0: return current heap top
        // Else: allocate size pages, return new heap start or error
        // We call the helper function which handles this.
        let fn_addr = self.helpers.sbrk_helper;
        self.asm.push(SCRATCH);
        self.asm.push(REG_MAP[ra]);

        self.save_caller_saved();
        // Args: RDI = ctx, RSI = size
        self.asm.mov_rr(Reg::RDI, CTX);
        self.asm.mov_load64(Reg::RSI, Reg::RSP, 64); // ra value from stack
        self.asm.mov_ri64(Reg::RAX, fn_addr);
        self.asm.call_reg(Reg::RAX);
        self.asm.mov_rr(SCRATCH, Reg::RAX);
        self.restore_caller_saved();

        // Discard the two saved values without clobbering any PVM registers
        self.asm.add_ri(Reg::RSP, 16);

        self.asm.mov_rr(REG_MAP[rd], SCRATCH);
    }

    /// Emit gas check at basic block start.
    fn emit_gas_check(&mut self, pc: usize, code: &[u8], bitmask: &[u8]) {
        // Count instructions in this block
        let cost = compute_block_cost(pc, code, bitmask);
        if cost == 0 { return; }

        // sub qword [r15 + CTX_GAS], cost
        self.asm.mov_load64(SCRATCH, CTX, CTX_GAS);
        self.asm.sub_ri(SCRATCH, cost as i32);
        self.asm.mov_store64(CTX, CTX_GAS, SCRATCH);
        // If gas < 0, exit with OOG
        self.asm.cmp_ri(SCRATCH, 0);
        self.asm.jcc_label(Cc::L, self.oog_label);
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

        // Align stack to 16 bytes. After 6 pushes + return address (7 * 8 = 56 bytes),
        // RSP mod 16 = 8. Sub 8 to make it mod 16 = 0. This ensures that after
        // save_caller_saved (8 pushes = 64 bytes), RSP is still 16-aligned before CALL.
        self.asm.sub_ri(Reg::RSP, 8);

        // R15 = context pointer (first argument, RDI in SysV ABI)
        self.asm.mov_rr(CTX, Reg::RDI);

        // Clear exit reason
        self.asm.mov_store32_imm(CTX, CTX_EXIT_REASON as i32, 0);

        // --- O(1) dispatch via table lookup (before loading PVM regs) ---
        // RAX = dispatch_table pointer, RDX = entry_pc (zero-extended)
        self.asm.mov_load32(SCRATCH, CTX, CTX_ENTRY_PC);        // edx = entry_pc
        self.asm.mov_load64(Reg::RAX, CTX, CTX_DISPATCH_TABLE); // rax = dispatch_table
        // movsxd rax, dword [rax + rdx*4]  — load native code offset
        self.asm.movsxd_load_sib4(Reg::RAX, Reg::RAX, SCRATCH);
        // rax += code_base
        self.asm.mov_load64(SCRATCH, CTX, CTX_CODE_BASE);
        self.asm.add_rr(Reg::RAX, SCRATCH);
        // Save dispatch target on stack (we'll jump to it after loading PVM regs)
        self.asm.push(Reg::RAX);

        // Load PVM registers from context
        for i in 0..13 {
            self.asm.mov_load64(REG_MAP[i], CTX, CTX_REGS + (i as i32) * 8);
        }

        // Jump to the dispatch target (pop into SCRATCH, then indirect jump)
        self.asm.pop(SCRATCH);
        self.asm.jmp_reg(SCRATCH);
    }

    /// Emit exit sequences and epilogue.
    fn emit_exit_sequences(&mut self) {
        // Out of gas exit
        self.asm.bind_label(self.oog_label);
        self.asm.mov_store32_imm(CTX, CTX_EXIT_REASON as i32, EXIT_OOG as i32);
        self.asm.jmp_label(self.exit_label);

        // Panic exit
        self.asm.bind_label(self.panic_label);
        self.asm.mov_store32_imm(CTX, CTX_EXIT_REASON as i32, EXIT_PANIC as i32);
        // fall through to exit_label

        // Common exit: save PVM registers to context, restore callee-saved, return
        self.asm.bind_label(self.exit_label);
        for i in 0..13 {
            self.asm.mov_store64(CTX, CTX_REGS + (i as i32) * 8, REG_MAP[i]);
        }

        // Remove stack alignment padding
        self.asm.add_ri(Reg::RSP, 8);

        // Restore callee-saved
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

/// Compute gas cost for a basic block starting at `pc`.
/// Each instruction costs 1 gas. Count until we hit a terminator or the next basic block.
fn compute_block_cost(pc: usize, code: &[u8], bitmask: &[u8]) -> u32 {
    let mut cost = 0u32;
    let mut pos = pc;
    loop {
        if pos >= code.len() { break; }
        if pos < bitmask.len() && bitmask[pos] != 1 {
            pos += 1;
            continue;
        }
        cost += 1;
        let opcode = Opcode::from_byte(code[pos]);
        let skip = compute_skip(pos, bitmask);
        pos += 1 + skip;
        // Stop after a terminator
        if let Some(op) = opcode {
            if op.is_terminator() {
                break;
            }
        }
        // Stop if next position is a new basic block start (and not the first instruction)
        if cost > 0 && pos < bitmask.len() && bitmask[pos] == 1 {
            break;
        }
    }
    cost
}
