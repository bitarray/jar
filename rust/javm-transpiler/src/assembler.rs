//! PVM program assembler — hand-craft PVM bytecode programs.
//!
//! Provides a builder API to emit individual PVM instructions
//! (opcode + register operand + immediate encoding). Used by unit
//! tests for the opcode encoding tables. Producing full chain
//! Images happens via [`crate::link_elf`]; this module does not
//! emit blobs.

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
            labels: std::collections::HashMap::new(),
            _fixups: Vec::new(),
        }
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
}
