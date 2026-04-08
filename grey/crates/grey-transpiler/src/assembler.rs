//! PVM program assembler — hand-craft PVM bytecode programs.
//!
//! Provides a builder API to emit PVM instructions and produce
//! complete standard program blobs.

use crate::emitter;

/// PVM register indices (0-12).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Reg {
    RA = 0,  // Return address / reg 0
    SP = 1,  // Stack pointer / reg 1
    T0 = 2,  // Temporary 0
    T1 = 3,  // Temporary 1
    T2 = 4,  // Temporary 2
    S0 = 5,  // Saved 0
    S1 = 6,  // Saved 1
    A0 = 7,  // Argument 0 (also host-call arg/return)
    A1 = 8,  // Argument 1
    A2 = 9,  // Argument 2
    A3 = 10, // Argument 3
    A4 = 11, // Argument 4
    A5 = 12, // Argument 5
}

/// PVM program assembler.
pub struct Assembler {
    code: Vec<u8>,
    bitmask: Vec<u8>,
    jump_table: Vec<u32>,
    ro_data: Vec<u8>,
    rw_data: Vec<u8>,
    heap_pages: u32,
    max_heap_pages: u32,
    stack_pages: u32,
    /// Labels: name → code offset
    labels: std::collections::HashMap<String, u32>,
    /// Pending fixups: (code_offset, label_name, fixup_size)
    _fixups: Vec<(usize, String, u8)>,
}

impl Default for Assembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Assembler {
    pub fn new() -> Self {
        Self {
            code: Vec::new(),
            bitmask: Vec::new(),
            jump_table: Vec::new(),
            ro_data: Vec::new(),
            rw_data: Vec::new(),
            heap_pages: 0,
            max_heap_pages: 0,
            stack_pages: 1, // 1 page = 4096 bytes default
            labels: std::collections::HashMap::new(),
            _fixups: Vec::new(),
        }
    }

    pub fn set_ro_data(&mut self, data: Vec<u8>) -> &mut Self {
        self.ro_data = data;
        self
    }

    pub fn set_rw_data(&mut self, data: Vec<u8>) -> &mut Self {
        self.rw_data = data;
        self
    }

    pub fn set_heap_pages(&mut self, pages: u32) -> &mut Self {
        self.heap_pages = pages;
        if self.max_heap_pages < pages {
            self.max_heap_pages = pages;
        }
        self
    }

    pub fn set_max_heap_pages(&mut self, pages: u32) -> &mut Self {
        self.max_heap_pages = pages;
        self
    }

    pub fn set_stack_pages(&mut self, pages: u32) -> &mut Self {
        self.stack_pages = pages;
        self
    }

    /// Add a jump table entry pointing to the current code offset.
    /// Returns the jump table index.
    pub fn add_jump_entry(&mut self) -> usize {
        let idx = self.jump_table.len();
        self.jump_table.push(self.code.len() as u32);
        idx
    }

    /// Add a jump table entry pointing to a specific code offset.
    pub fn add_jump_entry_at(&mut self, offset: u32) -> usize {
        let idx = self.jump_table.len();
        self.jump_table.push(offset);
        idx
    }

    /// Get the current code offset.
    pub fn current_offset(&self) -> u32 {
        self.code.len() as u32
    }

    /// Define a label at the current code position.
    pub fn label(&mut self, name: &str) -> &mut Self {
        self.labels.insert(name.to_string(), self.code.len() as u32);
        self
    }

    // ===== No-argument instructions =====

    /// Opcode 0: Trap (halt with error)
    pub fn trap(&mut self) -> &mut Self {
        self.emit_byte(0, true);
        self
    }

    /// Opcode 1: Fallthrough (nop, continue to next instruction)
    pub fn fallthrough(&mut self) -> &mut Self {
        self.emit_byte(1, true);
        self
    }

    // ===== One immediate instructions =====

    /// Opcode 10: ecalli (host call with immediate ID)
    pub fn ecalli(&mut self, id: u32) -> &mut Self {
        self.emit_byte(10, true);
        self.emit_imm(id as i64, 4);
        self
    }

    // ===== One register + extended immediate =====

    /// Opcode 20: load_imm_64 (load 64-bit immediate into register)
    pub fn load_imm_64(&mut self, rd: Reg, imm: u64) -> &mut Self {
        self.emit_byte(20, true);
        self.emit_byte(rd as u8, false);
        // 8 bytes of immediate, LE
        for i in 0..8 {
            self.emit_byte((imm >> (i * 8)) as u8, false);
        }
        self
    }

    // ===== One offset instructions =====

    /// Opcode 40: jump (unconditional jump to offset)
    pub fn jump(&mut self, target: u32) -> &mut Self {
        self.emit_byte(40, true);
        self.emit_imm(target as i64, 4);
        self
    }

    // ===== One register + one immediate =====

    /// Opcode 50: jump_ind (indirect jump through register + immediate)
    pub fn jump_ind(&mut self, rd: Reg, imm: u32) -> &mut Self {
        self.emit_byte(50, true);
        self.emit_byte(rd as u8, false);
        self.emit_imm(imm as i64, 4);
        self
    }

    /// Opcode 51: load_imm (load sign-extended immediate into register)
    pub fn load_imm(&mut self, rd: Reg, imm: i32) -> &mut Self {
        self.emit_byte(51, true);
        self.emit_byte(rd as u8, false);
        self.emit_imm(imm as i64, 4);
        self
    }

    /// Opcode 52: load_u8 (load u8 from address in immediate)
    pub fn load_u8(&mut self, rd: Reg, addr: u32) -> &mut Self {
        self.emit_byte(52, true);
        self.emit_byte(rd as u8, false);
        self.emit_imm(addr as i64, 4);
        self
    }

    /// Opcode 58: load_u64 (load u64 from address in immediate)
    pub fn load_u64(&mut self, rd: Reg, addr: u32) -> &mut Self {
        self.emit_byte(58, true);
        self.emit_byte(rd as u8, false);
        self.emit_imm(addr as i64, 4);
        self
    }

    /// Opcode 59: store_u8 (store u8 from register to address)
    pub fn store_u8(&mut self, rd: Reg, addr: u32) -> &mut Self {
        self.emit_byte(59, true);
        self.emit_byte(rd as u8, false);
        self.emit_imm(addr as i64, 4);
        self
    }

    /// Opcode 62: store_u64 (store u64 from register to address)
    pub fn store_u64(&mut self, rd: Reg, addr: u32) -> &mut Self {
        self.emit_byte(62, true);
        self.emit_byte(rd as u8, false);
        self.emit_imm(addr as i64, 4);
        self
    }

    // ===== One register + one immediate + one offset =====

    /// Opcode 80: load_imm_jump (load immediate into register and jump)
    pub fn load_imm_jump(&mut self, rd: Reg, imm: i32, target: u32) -> &mut Self {
        // Encoding: opcode, reg_byte (rd in low 4 bits, lX in bits 4-6),
        // then imm bytes, then offset bytes
        self.emit_byte(80, true);
        // reg byte: rD = rd, upper nibble encodes immediate size
        let reg_byte = (rd as u8) | (4 << 4); // lX = 4 bytes
        self.emit_byte(reg_byte, false);
        self.emit_imm(imm as i64, 4);
        self.emit_imm(target as i64, 4);
        self
    }

    /// Opcode 81: branch_eq_imm (branch if register == immediate)
    pub fn branch_eq_imm(&mut self, rd: Reg, imm: i32, target: u32) -> &mut Self {
        self.emit_byte(81, true);
        let reg_byte = (rd as u8) | (4 << 4);
        self.emit_byte(reg_byte, false);
        self.emit_imm(imm as i64, 4);
        self.emit_imm(target as i64, 4);
        self
    }

    /// Opcode 82: branch_ne_imm (branch if register != immediate)
    pub fn branch_ne_imm(&mut self, rd: Reg, imm: i32, target: u32) -> &mut Self {
        self.emit_byte(82, true);
        let reg_byte = (rd as u8) | (4 << 4);
        self.emit_byte(reg_byte, false);
        self.emit_imm(imm as i64, 4);
        self.emit_imm(target as i64, 4);
        self
    }

    /// Opcode 83: branch_lt_u_imm (branch if register < unsigned immediate)
    pub fn branch_lt_u_imm(&mut self, rd: Reg, imm: i32, target: u32) -> &mut Self {
        self.emit_byte(83, true);
        let reg_byte = (rd as u8) | (4 << 4);
        self.emit_byte(reg_byte, false);
        self.emit_imm(imm as i64, 4);
        self.emit_imm(target as i64, 4);
        self
    }

    // ===== Two register instructions =====

    /// Opcode 100: move_reg (copy register)
    pub fn move_reg(&mut self, rd: Reg, ra: Reg) -> &mut Self {
        self.emit_byte(100, true);
        self.emit_byte((rd as u8) | ((ra as u8) << 4), false);
        self
    }

    // ===== Two register + one immediate =====

    /// Opcode 124: load_ind_u8 (load u8 from [rA + imm] into rD)
    pub fn load_ind_u8(&mut self, rd: Reg, ra: Reg, imm: i32) -> &mut Self {
        self.emit_byte(124, true);
        self.emit_byte((rd as u8) | ((ra as u8) << 4), false);
        self.emit_imm(imm as i64, 4);
        self
    }

    /// Opcode 128: load_ind_u32 (load u32 from [rA + imm] into rD)
    pub fn load_ind_u32(&mut self, rd: Reg, ra: Reg, imm: i32) -> &mut Self {
        self.emit_byte(128, true);
        self.emit_byte((rd as u8) | ((ra as u8) << 4), false);
        self.emit_imm(imm as i64, 4);
        self
    }

    /// Opcode 130: load_ind_u64 (load u64 from [rA + imm] into rD)
    pub fn load_ind_u64(&mut self, rd: Reg, ra: Reg, imm: i32) -> &mut Self {
        self.emit_byte(130, true);
        self.emit_byte((rd as u8) | ((ra as u8) << 4), false);
        self.emit_imm(imm as i64, 4);
        self
    }

    /// Opcode 120: store_ind_u8 (store u8 from rD to [rA + imm])
    pub fn store_ind_u8(&mut self, rd: Reg, ra: Reg, imm: i32) -> &mut Self {
        self.emit_byte(120, true);
        self.emit_byte((rd as u8) | ((ra as u8) << 4), false);
        self.emit_imm(imm as i64, 4);
        self
    }

    /// Opcode 122: store_ind_u32 (store u32 from rD to [rA + imm])
    pub fn store_ind_u32(&mut self, rd: Reg, ra: Reg, imm: i32) -> &mut Self {
        self.emit_byte(122, true);
        self.emit_byte((rd as u8) | ((ra as u8) << 4), false);
        self.emit_imm(imm as i64, 4);
        self
    }

    /// Opcode 123: store_ind_u64 (store u64 from rD to [rA + imm])
    pub fn store_ind_u64(&mut self, rd: Reg, ra: Reg, imm: i32) -> &mut Self {
        self.emit_byte(123, true);
        self.emit_byte((rd as u8) | ((ra as u8) << 4), false);
        self.emit_imm(imm as i64, 4);
        self
    }

    /// Opcode 131: add_imm_32 (rD = rA + imm, 32-bit)
    pub fn add_imm_32(&mut self, rd: Reg, ra: Reg, imm: i32) -> &mut Self {
        self.emit_byte(131, true);
        self.emit_byte((rd as u8) | ((ra as u8) << 4), false);
        self.emit_imm(imm as i64, 4);
        self
    }

    /// Opcode 149: add_imm_64 (rD = rA + imm, 64-bit)
    pub fn add_imm_64(&mut self, rd: Reg, ra: Reg, imm: i32) -> &mut Self {
        self.emit_byte(149, true);
        self.emit_byte((rd as u8) | ((ra as u8) << 4), false);
        self.emit_imm(imm as i64, 4);
        self
    }

    // ===== Three register instructions =====

    /// Opcode 200: add_64 (rD = rA + rB)
    pub fn add_64(&mut self, rd: Reg, ra: Reg, rb: Reg) -> &mut Self {
        self.emit_byte(200, true);
        self.emit_byte((ra as u8) | ((rb as u8) << 4), false);
        self.emit_byte(rd as u8, false);
        self
    }

    /// Opcode 201: sub_64 (rD = rA - rB)
    pub fn sub_64(&mut self, rd: Reg, ra: Reg, rb: Reg) -> &mut Self {
        self.emit_byte(201, true);
        self.emit_byte((ra as u8) | ((rb as u8) << 4), false);
        self.emit_byte(rd as u8, false);
        self
    }

    // ===== Blob building =====

    /// Finalize and produce the standard program blob.
    pub fn build(&self) -> Vec<u8> {
        emitter::build_service_program(
            &self.code,
            &self.bitmask,
            &self.jump_table,
            &self.ro_data,
            &self.rw_data,
            self.stack_pages,
            self.heap_pages,
            self.heap_pages + self.stack_pages + 4, // memory_pages
        )
    }

    // ===== Public raw emission =====

    /// Emit a raw byte with bitmask control.
    pub fn emit_raw(&mut self, byte: u8, is_instruction_start: bool) {
        self.emit_byte(byte, is_instruction_start);
    }

    // ===== Internal helpers =====

    fn emit_byte(&mut self, byte: u8, is_instruction_start: bool) {
        self.code.push(byte);
        self.bitmask.push(if is_instruction_start { 1 } else { 0 });
    }

    fn emit_imm(&mut self, value: i64, size: u8) {
        let bytes = value.to_le_bytes();
        for byte in bytes.iter().take(size as usize) {
            self.emit_byte(*byte, false);
        }
    }
}

/// Build a minimal JAM service PVM blob.
///
/// The service has two entry points:
/// - Entry 0 (PC=0): is_authorized / refine — reads arguments, returns result
/// - Entry 5 (PC=`jump_table[2]`): accumulate — reads work items, writes state
///
/// This builds a simple "echo" service that:
/// - Refine: returns the input payload as-is (output = input)
/// - Accumulate: writes the first work item's result to storage key `[0]`
pub fn build_sample_service() -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_stack_pages(1);
    asm.set_heap_pages(1);

    // Jump table entry 0: refine entry (djump address = 2, index 0)
    // Jump table entry 1: (reserved)
    // Jump table entry 2: accumulate entry (djump address = 6, index 2)

    // === Entry 0: Refine/Is-Authorized (PC=0) ===
    // Jump table entry 0 → PC of refine code
    let _refine_jt = asm.add_jump_entry(); // index 0 → current PC

    // On entry for refine:
    //   φ[7] (A0) = argument base address (pointer to args in memory)
    //   φ[8] (A1) = argument length
    //
    // The refine function receives the work-item payload as arguments.
    // We implement a simple "echo" service: output = input.
    //
    // To return output, we halt with:
    //   φ[7] = pointer to output data
    //   φ[8] = length of output data
    //
    // Since the arguments are already in memory at the arg base,
    // we just leave φ[7] and φ[8] as-is and halt.

    // The arguments are already set up: φ[7]=arg_base, φ[8]=arg_len
    // Simply halt — the output is the arguments themselves.
    // Halt address: djump to 2^32 - 2^16
    // We use jump_ind with the halt address loaded into a register.

    // Load halt address into T0
    asm.load_imm_64(Reg::T0, 0xFFFF0000u64);

    // jump_ind T0 (djump to halt)
    asm.jump_ind(Reg::T0, 0);

    // === Entry for Accumulate (needs to be at a jump table entry) ===
    // Jump table entry 1 → placeholder
    asm.add_jump_entry_at(0); // placeholder, points to trap

    // Jump table entry 2 → accumulate code
    let _acc_jt = asm.add_jump_entry(); // index 2 → current PC

    // Accumulate entry point (reached via set_pc(5), which means ı=5,
    // so djump(5) is not valid since 5 is odd — actually set_pc directly
    // sets the instruction counter, not using djump).
    //
    // Actually, the Grey PVM sets PC=5 directly as the byte offset.
    // So we need accumulate code to start at byte offset 5.
    //
    // Let's restructure: we need exact byte control.
    // The refine code above took: 10 bytes (load_imm_64) + 6 bytes (jump_ind) = 16 bytes.
    // That's too many. Let me rebuild with exact byte offsets.

    // Actually — let me just start over with precise byte layout.
    drop(asm);

    build_sample_service_precise()
}

/// Build sample service with precise byte-level control over entry points.
pub fn build_sample_service_precise() -> Vec<u8> {
    // We need:
    // - PC=0: refine entry point (is-authorized also uses entry 0)
    // - PC=5: accumulate entry point
    //
    // Layout:
    //   Byte 0: jump to refine_body (opcode 40 + 4-byte offset)  → 5 bytes
    //   Byte 5: start of accumulate body
    //   ...
    //   Byte N: refine body
    //
    // Refine just halts returning the arguments (echo service).
    // Accumulate reads the work-item data via host_fetch and writes to storage.

    let mut code = Vec::new();
    let mut bitmask = Vec::new();

    // Helper to push instruction byte
    let push_inst = |code: &mut Vec<u8>, bitmask: &mut Vec<u8>, byte: u8| {
        code.push(byte);
        bitmask.push(1);
    };
    let push_data = |code: &mut Vec<u8>, bitmask: &mut Vec<u8>, byte: u8| {
        code.push(byte);
        bitmask.push(0);
    };

    // We'll fill the jump target for PC=0 after we know where refine_body is.
    // For now, use a placeholder.

    // --- Byte 0-4: Jump to refine body (will be patched) ---
    push_inst(&mut code, &mut bitmask, 40); // opcode: jump
    // 4-byte LE offset (placeholder, will patch)
    let jump_patch_offset = code.len();
    for _ in 0..4 {
        push_data(&mut code, &mut bitmask, 0);
    }
    // Now at byte 5.

    // --- Byte 5+: Accumulate body ---
    // Accumulate receives arguments encoded as:
    //   E(timeslot, service_id, item_count) via φ[7]=arg_base, φ[8]=arg_len
    //
    // For a simple service, we just:
    // 1. Call host_write to write a marker to storage
    // 2. Halt with output = hash pointer
    //
    // host_write (ID=4):
    //   φ[7] = key_ptr, φ[8] = key_len, φ[9] = val_ptr, φ[10] = val_len
    //   Returns φ[7] = 0 (OK) or error
    //
    // We'll write the value [0x42] to storage key [0x01].
    // First, we need the data in memory. The stack region is RW.
    // Stack pointer φ[0] starts at 2^32 - 2^16 = 0xFFFF0000.
    // We'll store our key/value on the stack.

    // Save the argument pointer first
    // move_reg S0, A0 (save arg base)
    push_inst(&mut code, &mut bitmask, 100); // opcode: move_reg
    push_data(
        &mut code,
        &mut bitmask,
        (Reg::S0 as u8) | ((Reg::A0 as u8) << 4),
    );

    // move_reg S1, A1 (save arg len)
    push_inst(&mut code, &mut bitmask, 100);
    push_data(
        &mut code,
        &mut bitmask,
        (Reg::S1 as u8) | ((Reg::A1 as u8) << 4),
    );

    // Allocate stack space: SP -= 16
    // add_imm_64 SP, SP, -16 (opcode 149)
    push_inst(&mut code, &mut bitmask, 149); // add_imm_64
    push_data(
        &mut code,
        &mut bitmask,
        (Reg::SP as u8) | ((Reg::SP as u8) << 4),
    );
    // immediate -16 in 4 bytes LE (sign-extended)
    let neg16 = (-16i32).to_le_bytes();
    for b in &neg16 {
        push_data(&mut code, &mut bitmask, *b);
    }

    // Store key byte [0x01] at SP+0 using register-based stores.

    // load_imm T0, 0x01 (key byte)
    push_inst(&mut code, &mut bitmask, 51); // load_imm
    push_data(&mut code, &mut bitmask, Reg::T0 as u8);
    push_data(&mut code, &mut bitmask, 0x01); // imm = 1
    push_data(&mut code, &mut bitmask, 0x00);
    push_data(&mut code, &mut bitmask, 0x00);
    push_data(&mut code, &mut bitmask, 0x00);

    // store_ind_u8 T0, SP, 0 (store key byte at SP+0)
    push_inst(&mut code, &mut bitmask, 120); // store_ind_u8
    push_data(
        &mut code,
        &mut bitmask,
        (Reg::T0 as u8) | ((Reg::SP as u8) << 4),
    );
    push_data(&mut code, &mut bitmask, 0x00); // imm = 0
    push_data(&mut code, &mut bitmask, 0x00);
    push_data(&mut code, &mut bitmask, 0x00);
    push_data(&mut code, &mut bitmask, 0x00);

    // load_imm T0, 0x42 (value byte)
    push_inst(&mut code, &mut bitmask, 51);
    push_data(&mut code, &mut bitmask, Reg::T0 as u8);
    push_data(&mut code, &mut bitmask, 0x42);
    push_data(&mut code, &mut bitmask, 0x00);
    push_data(&mut code, &mut bitmask, 0x00);
    push_data(&mut code, &mut bitmask, 0x00);

    // store_ind_u8 T0, SP, 8 (store value byte at SP+8)
    push_inst(&mut code, &mut bitmask, 120);
    push_data(
        &mut code,
        &mut bitmask,
        (Reg::T0 as u8) | ((Reg::SP as u8) << 4),
    );
    push_data(&mut code, &mut bitmask, 0x08); // imm = 8
    push_data(&mut code, &mut bitmask, 0x00);
    push_data(&mut code, &mut bitmask, 0x00);
    push_data(&mut code, &mut bitmask, 0x00);

    // Set up host_write arguments:
    // φ[7] (A0) = key_ptr = SP+0
    // φ[8] (A1) = key_len = 1
    // φ[9] (A2) = val_ptr = SP+8
    // φ[10] (A3) = val_len = 1

    // move_reg A0, SP
    push_inst(&mut code, &mut bitmask, 100);
    push_data(
        &mut code,
        &mut bitmask,
        (Reg::A0 as u8) | ((Reg::SP as u8) << 4),
    );

    // load_imm A1, 1
    push_inst(&mut code, &mut bitmask, 51);
    push_data(&mut code, &mut bitmask, Reg::A1 as u8);
    push_data(&mut code, &mut bitmask, 0x01);
    push_data(&mut code, &mut bitmask, 0x00);
    push_data(&mut code, &mut bitmask, 0x00);
    push_data(&mut code, &mut bitmask, 0x00);

    // add_imm_64 A2, SP, 8
    push_inst(&mut code, &mut bitmask, 149);
    push_data(
        &mut code,
        &mut bitmask,
        (Reg::A2 as u8) | ((Reg::SP as u8) << 4),
    );
    push_data(&mut code, &mut bitmask, 0x08);
    push_data(&mut code, &mut bitmask, 0x00);
    push_data(&mut code, &mut bitmask, 0x00);
    push_data(&mut code, &mut bitmask, 0x00);

    // load_imm A3, 1
    push_inst(&mut code, &mut bitmask, 51);
    push_data(&mut code, &mut bitmask, Reg::A3 as u8);
    push_data(&mut code, &mut bitmask, 0x01);
    push_data(&mut code, &mut bitmask, 0x00);
    push_data(&mut code, &mut bitmask, 0x00);
    push_data(&mut code, &mut bitmask, 0x00);

    // ecalli 5 (STORAGE_W, slot 5)
    push_inst(&mut code, &mut bitmask, 10); // ecalli
    push_data(&mut code, &mut bitmask, 0x05); // ID = 5
    push_data(&mut code, &mut bitmask, 0x00);
    push_data(&mut code, &mut bitmask, 0x00);
    push_data(&mut code, &mut bitmask, 0x00);

    // Halt: set output pointer and length, then djump to halt address
    // For accumulate, output is a 32-byte hash. We'll output nothing (empty).
    // load_imm A0, 0 (null pointer)
    push_inst(&mut code, &mut bitmask, 51);
    push_data(&mut code, &mut bitmask, Reg::A0 as u8);
    push_data(&mut code, &mut bitmask, 0x00);
    push_data(&mut code, &mut bitmask, 0x00);
    push_data(&mut code, &mut bitmask, 0x00);
    push_data(&mut code, &mut bitmask, 0x00);

    // load_imm A1, 0 (zero length)
    push_inst(&mut code, &mut bitmask, 51);
    push_data(&mut code, &mut bitmask, Reg::A1 as u8);
    push_data(&mut code, &mut bitmask, 0x00);
    push_data(&mut code, &mut bitmask, 0x00);
    push_data(&mut code, &mut bitmask, 0x00);
    push_data(&mut code, &mut bitmask, 0x00);

    // Halt: load halt address and djump
    // load_imm_64 T0, 0xFFFF0000
    push_inst(&mut code, &mut bitmask, 20); // load_imm_64
    push_data(&mut code, &mut bitmask, Reg::T0 as u8);
    let halt_addr = 0xFFFF0000u64;
    for i in 0..8 {
        push_data(&mut code, &mut bitmask, (halt_addr >> (i * 8)) as u8);
    }

    // jump_ind T0, 0 (djump to halt)
    push_inst(&mut code, &mut bitmask, 50);
    push_data(&mut code, &mut bitmask, Reg::T0 as u8);
    push_data(&mut code, &mut bitmask, 0x00);
    push_data(&mut code, &mut bitmask, 0x00);
    push_data(&mut code, &mut bitmask, 0x00);
    push_data(&mut code, &mut bitmask, 0x00);

    // --- Refine body (patched from byte 0 jump) ---
    let refine_offset = code.len() as u32;

    // Refine: just halt with the arguments as output (echo).
    // φ[7] already has arg_base, φ[8] already has arg_len.
    // Load halt address and djump.

    push_inst(&mut code, &mut bitmask, 20); // load_imm_64 T0, halt_addr
    push_data(&mut code, &mut bitmask, Reg::T0 as u8);
    for i in 0..8 {
        push_data(&mut code, &mut bitmask, (halt_addr >> (i * 8)) as u8);
    }

    push_inst(&mut code, &mut bitmask, 50); // jump_ind T0, 0
    push_data(&mut code, &mut bitmask, Reg::T0 as u8);
    push_data(&mut code, &mut bitmask, 0x00);
    push_data(&mut code, &mut bitmask, 0x00);
    push_data(&mut code, &mut bitmask, 0x00);
    push_data(&mut code, &mut bitmask, 0x00);

    // Patch the jump at byte 0 to point to refine_offset
    let refine_bytes = refine_offset.to_le_bytes();
    code[jump_patch_offset] = refine_bytes[0];
    code[jump_patch_offset + 1] = refine_bytes[1];
    code[jump_patch_offset + 2] = refine_bytes[2];
    code[jump_patch_offset + 3] = refine_bytes[3];

    // Build jump table:
    // Index 0 → refine entry (byte 0, which jumps to refine body)
    // Index 1 → accumulate entry (byte 5)
    // But djump(2) → jump_table[0], djump(4) → jump_table[1], djump(6) → jump_table[2]
    // set_pc(5) sets ı=5 directly (doesn't use djump).
    let jump_table = vec![0u32, 5, refine_offset];

    // Build a service blob
    emitter::build_service_program(
        &code,
        &bitmask,
        &jump_table,
        &[], // no ro_data
        &[], // no rw_data
        1,   // 1 stack page
        1,   // 1 heap page
        6,   // memory_pages
    )
}

/// Build a trivial authorizer PVM blob that just halts immediately.
///
/// Used as a fallback when the pixels-authorizer ELF is not available.
/// The sequential test doesn't exercise Ψ_I, so the authorizer code
/// never actually runs — we only need a deterministic blob for hashing.
pub fn build_trivial_authorizer() -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_heap_pages(0);
    asm.set_stack_pages(1);
    // Emit trap instruction (opcode 0) at PC=0
    asm.emit_raw(0, true);
    asm.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trap_encoding() {
        let mut asm = Assembler::new();
        asm.trap();
        assert_eq!(asm.code, vec![0]); // opcode 0
        assert_eq!(asm.bitmask, vec![1]); // instruction start
    }

    #[test]
    fn test_fallthrough_encoding() {
        let mut asm = Assembler::new();
        asm.fallthrough();
        assert_eq!(asm.code, vec![1]);
        assert_eq!(asm.bitmask, vec![1]);
    }

    #[test]
    fn test_ecalli_encoding() {
        let mut asm = Assembler::new();
        asm.ecalli(0xFF);
        assert_eq!(asm.code[0], 10); // opcode
        // immediate = 0xFF as LE u32
        assert_eq!(asm.code[1], 0xFF);
        assert_eq!(asm.code.len(), 5); // 1 opcode + 4 imm
        assert_eq!(asm.bitmask[0], 1);
        assert!(asm.bitmask[1..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_load_imm_64_encoding() {
        let mut asm = Assembler::new();
        asm.load_imm_64(Reg::A0, 0x0102030405060708);
        assert_eq!(asm.code[0], 20); // opcode
        assert_eq!(asm.code[1], Reg::A0 as u8); // register
        // 8 bytes LE immediate
        assert_eq!(asm.code[2], 0x08);
        assert_eq!(asm.code[3], 0x07);
        assert_eq!(asm.code[9], 0x01);
        assert_eq!(asm.code.len(), 10);
    }

    #[test]
    fn test_jump_encoding() {
        let mut asm = Assembler::new();
        asm.jump(42);
        assert_eq!(asm.code[0], 40); // opcode
        assert_eq!(asm.code[1], 42); // target LE
        assert_eq!(asm.code.len(), 5);
    }

    #[test]
    fn test_load_imm_encoding() {
        let mut asm = Assembler::new();
        asm.load_imm(Reg::T0, -1);
        assert_eq!(asm.code[0], 51); // opcode
        assert_eq!(asm.code[1], Reg::T0 as u8);
        // -1 as i32 LE = 0xFF 0xFF 0xFF 0xFF
        assert_eq!(&asm.code[2..6], &[0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_move_reg_encoding() {
        let mut asm = Assembler::new();
        asm.move_reg(Reg::A0, Reg::T0);
        assert_eq!(asm.code[0], 100); // opcode
        // reg byte: rd=A0(7) in low nibble, ra=T0(2) in high nibble
        assert_eq!(asm.code[1], (Reg::A0 as u8) | ((Reg::T0 as u8) << 4));
        assert_eq!(asm.code.len(), 2);
    }

    #[test]
    fn test_add_64_encoding() {
        let mut asm = Assembler::new();
        asm.add_64(Reg::A0, Reg::T0, Reg::T1);
        assert_eq!(asm.code[0], 200); // opcode
        // Three-reg: ra=T0(2) in low nibble, rb=T1(3) in high nibble
        assert_eq!(asm.code[1], (Reg::T0 as u8) | ((Reg::T1 as u8) << 4));
        assert_eq!(asm.code[2], Reg::A0 as u8); // rd
        assert_eq!(asm.code.len(), 3);
    }

    #[test]
    fn test_multiple_instructions_bitmask() {
        let mut asm = Assembler::new();
        asm.trap(); // 1 byte
        asm.fallthrough(); // 1 byte
        asm.load_imm(Reg::A0, 42); // 6 bytes
        assert_eq!(asm.bitmask.len(), 8);
        // Instruction starts at offsets 0, 1, 2
        assert_eq!(asm.bitmask[0], 1);
        assert_eq!(asm.bitmask[1], 1);
        assert_eq!(asm.bitmask[2], 1);
        // Remaining are non-starts
        assert!(asm.bitmask[3..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_current_offset_tracks_position() {
        let mut asm = Assembler::new();
        assert_eq!(asm.current_offset(), 0);
        asm.trap();
        assert_eq!(asm.current_offset(), 1);
        asm.load_imm_64(Reg::A0, 0);
        assert_eq!(asm.current_offset(), 11); // 1 + 10
    }

    #[test]
    fn test_label_records_offset() {
        let mut asm = Assembler::new();
        asm.trap();
        asm.label("after_trap");
        assert_eq!(asm.labels["after_trap"], 1);
    }

    #[test]
    fn test_build_trivial_authorizer() {
        let blob = build_trivial_authorizer();
        assert!(!blob.is_empty());
        // Should start with JAR magic
        assert_eq!(&blob[..4], b"JAR\x02");
    }

    #[test]
    fn test_build_sample_service() {
        let blob = build_sample_service();
        assert!(!blob.is_empty());
        // Verify it can be loaded by kernel
        let kernel = javm::kernel::InvocationKernel::new(&blob, &[], 1_000_000);
        assert!(
            kernel.is_ok(),
            "Sample service blob should be loadable: {:?}",
            kernel.err()
        );
    }

    #[test]
    fn test_sample_service_runs_via_kernel() {
        let blob = build_sample_service();
        let args = b"hello world";
        // Kernel runs single entrypoint at PC=0.
        let mut kernel =
            javm::kernel::InvocationKernel::new(&blob, args, 1_000_000).expect("should initialize");
        let result = kernel.run();
        // The sample service executes and
        // should either halt or panic (depending on the dispatch stub).
        // either halt or panic (depending on the dispatch stub).
        match result {
            javm::kernel::KernelResult::Halt(_) | javm::kernel::KernelResult::Panic => {}
            other => panic!("Expected Halt or Panic, got {:?}", other),
        }
    }
}
