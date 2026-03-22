//! RISC-V instruction decoder and PVM instruction translator.
//!
//! Decodes rv32em/rv64em instructions and translates them to equivalent
//! PVM bytecode sequences.

use crate::TranspileError;

/// RISC-V register to PVM register mapping.
///
/// RISC-V has 16 registers in the `e` (embedded) ABI:
///   x0 (zero), x1 (ra), x2 (sp), x3 (gp), x4 (tp),
///   x5 (t0), x6 (t1), x7 (t2), x8 (s0), x9 (s1),
///   x10 (a0), x11 (a1), x12 (a2), x13 (a3), x14 (a4), x15 (a5)
///
/// PVM has 13 registers (0-12):
///   0=RA, 1=SP, 2=T0, 3=T1, 4=T2, 5=S0, 6=S1,
///   7=A0, 8=A1, 9=A2, 10=A3, 11=A4, 12=A5
///
/// Mapping: x0 → zero (special), x1 → 0, x2 → 1, x5-x15 → 2-12
/// x3 (gp) and x4 (tp) have no direct mapping and must be spilled.
fn map_register(rv_reg: u8) -> Result<Option<u8>, TranspileError> {
    match rv_reg {
        0 => Ok(None),     // x0 = zero register (always 0)
        1 => Ok(Some(0)),  // x1 (ra) → PVM reg 0 (RA)
        2 => Ok(Some(1)),  // x2 (sp) → PVM reg 1 (SP)
        3 | 4 => Err(TranspileError::RegisterMapping(rv_reg)), // gp, tp: no mapping
        5 => Ok(Some(2)),  // x5 (t0) → PVM reg 2 (T0)
        6 => Ok(Some(3)),  // x6 (t1) → PVM reg 3 (T1)
        7 => Ok(Some(4)),  // x7 (t2) → PVM reg 4 (T2)
        8 => Ok(Some(5)),  // x8 (s0) → PVM reg 5 (S0)
        9 => Ok(Some(6)),  // x9 (s1) → PVM reg 6 (S1)
        10 => Ok(Some(7)), // x10 (a0) → PVM reg 7 (A0)
        11 => Ok(Some(8)), // x11 (a1) → PVM reg 8 (A1)
        12 => Ok(Some(9)), // x12 (a2) → PVM reg 9 (A2)
        13 => Ok(Some(10)), // x13 (a3) → PVM reg 10 (A3)
        14 => Ok(Some(11)), // x14 (a4) → PVM reg 11 (A4)
        15 => Ok(Some(12)), // x15 (a5) → PVM reg 12 (A5)
        _ => Err(TranspileError::RegisterMapping(rv_reg)),
    }
}

/// Translation context for converting RISC-V to PVM.
pub struct TranslationContext {
    /// Emitted PVM code bytes.
    pub code: Vec<u8>,
    /// Bitmask: 1 for instruction start, 0 for continuation.
    pub bitmask: Vec<u8>,
    /// Jump table entries.
    pub jump_table: Vec<u32>,
    /// Whether translating 64-bit RISC-V.
    pub is_64bit: bool,
    /// Map from RISC-V address to PVM code offset.
    pub address_map: std::collections::HashMap<u64, u32>,
    /// Pending PC-relative fixups: (pvm_imm_offset, target_rv_address, fixup_size)
    fixups: Vec<(usize, u64, u8)>,
    /// Map from fixup imm offset → instruction PC (for PC-relative encoding)
    fixup_pcs: std::collections::HashMap<usize, u32>,
    /// Pending absolute fixups: (pvm_imm_offset, target_rv_address) — patched with absolute PVM PC
    abs_fixups: Vec<(usize, u64)>,
    /// Last immediate loaded into t0 (x5) — used for ecall → ecalli translation.
    last_t0_imm: Option<i32>,
}

impl TranslationContext {
    pub fn new(is_64bit: bool) -> Self {
        Self {
            code: Vec::new(),
            bitmask: Vec::new(),
            jump_table: Vec::new(),
            is_64bit,
            address_map: std::collections::HashMap::new(),
            fixups: Vec::new(),
            fixup_pcs: std::collections::HashMap::new(),
            last_t0_imm: None,
            abs_fixups: Vec::new(),
        }
    }

    /// Translate one or more 32-bit RISC-V instructions starting at `offset`.
    /// Returns the number of bytes consumed (4 for a single instruction, 8 for fused pairs).
    pub(crate) fn translate_instruction(&mut self, section: &[u8], offset: usize, base: u64) -> Result<usize, TranspileError> {
        let inst = u32::from_le_bytes([section[offset], section[offset+1], section[offset+2], section[offset+3]]);
        let _addr = base + offset as u64;
        let opcode = inst & 0x7F;
        let rd = ((inst >> 7) & 0x1F) as u8;
        let funct3 = (inst >> 12) & 0x7;
        let rs1 = ((inst >> 15) & 0x1F) as u8;
        let rs2 = ((inst >> 20) & 0x1F) as u8;
        let funct7 = (inst >> 25) & 0x7F;

        match opcode {
            0x37 => { // LUI
                let imm = (inst & 0xFFFFF000) as i32;
                self.emit_load_imm(rd, imm as i64)?;
            }
            0x17 => { // AUIPC: rd = PC + sign_extend(imm << 12)
                let hi = (inst & 0xFFFFF000) as i32;

                // Peek at next instruction for AUIPC+JALR fusion (call pattern).
                if offset + 8 <= section.len() {
                    let next = u32::from_le_bytes([
                        section[offset+4], section[offset+5],
                        section[offset+6], section[offset+7],
                    ]);
                    if next & 0x7f == 0x67 && (next >> 12) & 0x7 == 0 {
                        let jalr_rs1 = ((next >> 15) & 0x1f) as u8;
                        if jalr_rs1 == rd {
                            let jalr_rd = ((next >> 7) & 0x1f) as u8;
                            let lo = ((next as i32) >> 20) as i32;
                            let target = ((_addr as i64) + (hi as i64) + (lo as i64)) as u64;
                            let ret_addr = _addr + 8;

                            // Save return address into JALR's link register
                            self.emit_return_address(jalr_rd, ret_addr)?;
                            // Jump to computed target
                            self.emit_jump(target);
                            // Map the JALR's RISC-V address for other fixups
                            self.address_map.insert(_addr + 4, self.code.len() as u32);
                            return Ok(8); // consumed both AUIPC and JALR
                        }
                    }
                }

                // Fallback: emit as load_imm with the RISC-V address (PC + hi)
                let value = (_addr as i64).wrapping_add(hi as i64);
                self.emit_load_imm(rd, value)?;
            }
            0x6F => { // JAL: rd = PC+4, PC = PC + imm
                let imm = decode_j_imm(inst);
                let target = (_addr as i64 + imm as i64) as u64;
                let ret_addr = _addr + 4;

                // Save return address into rd (link register) if rd != 0
                if rd != 0 {
                    self.emit_return_address(rd, ret_addr)?;
                }
                self.emit_jump(target);
            }
            0x67 => { // JALR: rd = PC+4, PC = (rs1 + imm) & ~1
                match funct3 {
                    0 => {
                        let imm = ((inst as i32) >> 20) as i32;
                        if rd == 0 && rs1 == 1 && imm == 0 {
                            // ret (jalr x0, ra, 0): return to caller via RA register.
                            // RA contains either a PVM PC (set by emit_return_address in
                            // the linker path) or 0 (basic transpiler, top-level return).
                            // Use jump_ind for proper function returns.
                            let pvm_rs1 = self.require_reg(rs1)?;
                            self.emit_inst(50); // jump_ind
                            self.emit_data(pvm_rs1);
                            self.emit_imm32(0);
                        } else if rd == 0 && imm == 0 {
                            // jr rs1: indirect jump (tail call or computed goto)
                            let pvm_rs1 = self.require_reg(rs1)?;
                            self.emit_inst(50);
                            self.emit_data(pvm_rs1);
                            self.emit_imm32(0);
                        } else if rd == 0 {
                            // Tail call: jump_ind rs1, imm (no link)
                            let pvm_rs1 = self.require_reg(rs1)?;
                            self.emit_inst(50); // jump_ind
                            self.emit_data(pvm_rs1);
                            self.emit_imm32(imm);
                        } else {
                            // Indirect call: save return address, then jump_ind
                            let ret_addr = _addr + 4;
                            self.emit_return_address(rd, ret_addr)?;
                            let pvm_rs1 = self.require_reg(rs1)?;
                            self.emit_inst(50); // jump_ind
                            self.emit_data(pvm_rs1);
                            self.emit_imm32(imm);
                        }
                    }
                    _ => return Err(TranspileError::UnsupportedInstruction {
                        offset: _addr as usize,
                        detail: format!("JALR funct3={}", funct3),
                    }),
                }
            }
            0x63 => { // Branch
                let imm = decode_b_imm(inst);
                let target = (_addr as i64 + imm as i64) as u64;
                self.translate_branch(funct3, rs1, rs2, target)?;
            }
            0x03 => { // Load
                let imm = ((inst as i32) >> 20) as i32;
                self.translate_load(funct3, rd, rs1, imm)?;
            }
            0x23 => { // Store
                let imm = decode_s_imm(inst);
                self.translate_store(funct3, rs1, rs2, imm)?;
            }
            0x13 => { // OP-IMM (add_i, xor_i, etc.)
                let imm = ((inst as i32) >> 20) as i32;
                self.translate_op_imm(funct3, funct7, rd, rs1, imm)?;
            }
            0x33 => { // OP (add, sub, mul, etc.)
                self.translate_op(funct3, funct7, rd, rs1, rs2)?;
            }
            0x1B => { // OP-IMM-32 (addiw, slliw, etc.) — RV64 only
                let imm = ((inst as i32) >> 20) as i32;
                self.translate_op_imm_32(funct3, funct7, rd, rs1, imm)?;
            }
            0x3B => { // OP-32 (addw, subw, etc.) — RV64 only
                self.translate_op_32(funct3, funct7, rd, rs1, rs2)?;
            }
            0x73 => { // SYSTEM
                match funct3 {
                    0 => {
                        let csr = (inst >> 20) & 0xFFF;
                        match csr {
                            0 => {
                                // ECALL → ecalli N, where N is the last value loaded into t0
                                let id = self.last_t0_imm.unwrap_or(0) as u32;
                                self.emit_ecalli(id);
                                self.last_t0_imm = None;
                            }
                            1 => self.emit_inst(0),   // EBREAK → trap
                            _ => self.emit_inst(1),   // fence etc → fallthrough
                        }
                    }
                    _ => self.emit_inst(1), // CSR ops → fallthrough
                }
            }
            0x0F => { // FENCE
                self.emit_inst(1); // → fallthrough (nop)
            }
            _ => {
                return Err(TranspileError::UnsupportedInstruction {
                    offset: _addr as usize,
                    detail: format!("unknown opcode {:#x}", opcode),
                });
            }
        }

        Ok(4) // consumed one 32-bit instruction
    }

fn translate_branch(&mut self, funct3: u32, rs1: u8, rs2: u8, target: u64) -> Result<(), TranspileError> {
        let pvm_rs1 = self.require_reg(rs1)?;
        let pvm_rs2 = self.require_reg(rs2)?;

        // Two register + one offset: opcodes 170-175
        let pvm_opcode = match funct3 {
            0 => 170, // BEQ → branch_eq
            1 => 171, // BNE → branch_ne
            4 => 173, // BLT → branch_lt_s
            5 => 175, // BGE → branch_ge_s
            6 => 172, // BLTU → branch_lt_u
            7 => 174, // BGEU → branch_ge_u
            _ => return Err(TranspileError::UnsupportedInstruction {
                offset: 0, detail: format!("branch funct3={}", funct3),
            }),
        };

        let inst_pc = self.code.len() as u32;
        self.emit_inst(pvm_opcode);
        self.emit_data(pvm_rs1 | (pvm_rs2 << 4));
        // Fixup target offset (PC-relative)
        let fixup_pos = self.code.len();
        self.fixups.push((fixup_pos, target, 4));
        self.fixup_pcs.insert(fixup_pos, inst_pc);
        self.emit_imm32(0); // placeholder

        Ok(())
    }

    fn translate_load(&mut self, funct3: u32, rd: u8, rs1: u8, imm: i32) -> Result<(), TranspileError> {
        let pvm_rd = self.require_reg(rd)?;
        let pvm_rs1 = self.require_reg(rs1)?;

        // Two register + one immediate: load_ind_*
        let pvm_opcode = match funct3 {
            0 => 125, // LB → load_ind_i8
            1 => 127, // LH → load_ind_i16
            2 => 129, // LW → load_ind_i32
            3 => 130, // LD → load_ind_u64
            4 => 124, // LBU → load_ind_u8
            5 => 126, // LHU → load_ind_u16
            6 => 128, // LWU → load_ind_u32
            _ => return Err(TranspileError::UnsupportedInstruction {
                offset: 0, detail: format!("load funct3={}", funct3),
            }),
        };

        self.emit_inst(pvm_opcode);
        self.emit_data(pvm_rd | (pvm_rs1 << 4));
        self.emit_imm32(imm);

        Ok(())
    }

    fn translate_store(&mut self, funct3: u32, rs1: u8, rs2: u8, imm: i32) -> Result<(), TranspileError> {
        // store_ind: store rD (data) to [rA + imm]
        // In RISC-V: store rs2 to [rs1 + imm]
        let pvm_rs2 = self.require_reg(rs2)?; // data register → rD
        let pvm_rs1 = self.require_reg(rs1)?; // base register → rA

        let pvm_opcode = match funct3 {
            0 => 120, // SB → store_ind_u8
            1 => 121, // SH → store_ind_u16
            2 => 122, // SW → store_ind_u32
            3 => 123, // SD → store_ind_u64
            _ => return Err(TranspileError::UnsupportedInstruction {
                offset: 0, detail: format!("store funct3={}", funct3),
            }),
        };

        self.emit_inst(pvm_opcode);
        self.emit_data(pvm_rs2 | (pvm_rs1 << 4));
        self.emit_imm32(imm);

        Ok(())
    }

    fn translate_op_imm(&mut self, funct3: u32, funct7: u32, rd: u8, rs1: u8, imm: i32) -> Result<(), TranspileError> {
        // Track `li t0, N` (ADDI x5, x0, N) for ecall ID translation
        if funct3 == 0 && rd == 5 && rs1 == 0 {
            self.last_t0_imm = Some(imm);
        }

        // When rs1 = x0 (zero register), treat as loading immediate directly
        // because PVM has no zero register — x0 maps to RA which is NOT zero.
        if rs1 == 0 {
            match funct3 {
                0 => return self.emit_load_imm(rd, imm as i64), // li rd, imm
                2 => { // SLTI rd, x0, imm → rd = (0 < imm) ? 1 : 0
                    return self.emit_load_imm(rd, if 0 < imm { 1 } else { 0 });
                }
                3 => { // SLTIU rd, x0, imm → rd = (0 < imm unsigned) ? 1 : 0
                    return self.emit_load_imm(rd, if imm != 0 { 1 } else { 0 });
                }
                4 => return self.emit_load_imm(rd, imm as i64), // XORI rd, x0, imm = imm
                6 => return self.emit_load_imm(rd, imm as i64), // ORI rd, x0, imm = imm
                7 => return self.emit_load_imm(rd, 0), // ANDI rd, x0, imm = 0
                _ => {} // shifts with x0 → just 0, but rare
            }
        }

        let pvm_rd = self.require_reg(rd)?;
        let pvm_rs1 = self.require_reg(rs1)?;

        let pvm_opcode = match funct3 {
            0 => 149, // ADDI → add_imm_64
            1 => { // SLLI
                let shamt = imm & 0x3F;
                self.emit_inst(151); // shlo_l_imm_64
                self.emit_data(pvm_rd | (pvm_rs1 << 4));
                self.emit_imm32(shamt);
                return Ok(());
            }
            2 => 137, // SLTI → set_lt_s_imm
            3 => 136, // SLTIU → set_lt_u_imm
            4 => 133, // XORI → xor_imm
            5 => { // SRLI/SRAI
                let shamt = imm & 0x3F;
                if funct7 & 0x20 != 0 {
                    self.emit_inst(153); // shar_r_imm_64
                } else {
                    self.emit_inst(152); // shlo_r_imm_64
                }
                self.emit_data(pvm_rd | (pvm_rs1 << 4));
                self.emit_imm32(shamt);
                return Ok(());
            }
            6 => 134, // ORI → or_imm
            7 => 132, // ANDI → and_imm
            _ => unreachable!(),
        };

        self.emit_inst(pvm_opcode);
        self.emit_data(pvm_rd | (pvm_rs1 << 4));
        self.emit_imm32(imm);

        Ok(())
    }

    fn translate_op(&mut self, funct3: u32, funct7: u32, rd: u8, rs1: u8, rs2: u8) -> Result<(), TranspileError> {
        let pvm_rd = self.require_reg(rd)?;
        let pvm_rs1 = self.require_reg(rs1)?;
        let pvm_rs2 = self.require_reg(rs2)?;

        let pvm_opcode = if funct7 == 1 {
            // M extension (multiply/divide)
            match funct3 {
                0 => 202, // MUL → mul_64
                1 => 213, // MULH → mul_upper_ss
                2 => 215, // MULHSU → mul_upper_su
                3 => 214, // MULHU → mul_upper_uu
                4 => 204, // DIV → div_s_64
                5 => 203, // DIVU → div_u_64
                6 => 206, // REM → rem_s_64
                7 => 205, // REMU → rem_u_64
                _ => unreachable!(),
            }
        } else if funct7 == 0x20 {
            match funct3 {
                0 => 201, // SUB → sub_64
                5 => 209, // SRA → shar_r_64
                _ => return Err(TranspileError::UnsupportedInstruction {
                    offset: 0, detail: format!("OP funct7=0x20 funct3={}", funct3),
                }),
            }
        } else {
            match funct3 {
                0 => 200, // ADD → add_64
                1 => 207, // SLL → shlo_l_64
                2 => 217, // SLT → set_lt_s
                3 => 216, // SLTU → set_lt_u
                4 => 211, // XOR → xor
                5 => 208, // SRL → shlo_r_64
                6 => 212, // OR → or
                7 => 210, // AND → and
                _ => unreachable!(),
            }
        };

        // ThreeReg encoding: byte1 = rA | (rB << 4), byte2 = rD
        // where rA=rs1 (source1), rB=rs2 (source2), rD=rd (destination)
        self.emit_inst(pvm_opcode);
        self.emit_data(pvm_rs1 | (pvm_rs2 << 4));
        self.emit_data(pvm_rd);

        Ok(())
    }

    fn translate_op_imm_32(&mut self, funct3: u32, funct7: u32, rd: u8, rs1: u8, imm: i32) -> Result<(), TranspileError> {
        let pvm_rd = self.require_reg(rd)?;
        let pvm_rs1 = self.require_reg(rs1)?;

        match funct3 {
            0 => { // ADDIW → add_imm_32
                self.emit_inst(131);
                self.emit_data(pvm_rd | (pvm_rs1 << 4));
                self.emit_imm32(imm);
            }
            1 => { // SLLIW
                let shamt = imm & 0x1F;
                self.emit_inst(138); // shlo_l_imm_32
                self.emit_data(pvm_rd | (pvm_rs1 << 4));
                self.emit_imm32(shamt);
            }
            5 => { // SRLIW/SRAIW
                let shamt = imm & 0x1F;
                if funct7 & 0x20 != 0 {
                    self.emit_inst(140); // shar_r_imm_32
                } else {
                    self.emit_inst(139); // shlo_r_imm_32
                }
                self.emit_data(pvm_rd | (pvm_rs1 << 4));
                self.emit_imm32(shamt);
            }
            _ => return Err(TranspileError::UnsupportedInstruction {
                offset: 0, detail: format!("OP-IMM-32 funct3={}", funct3),
            }),
        }

        Ok(())
    }

    fn translate_op_32(&mut self, funct3: u32, funct7: u32, rd: u8, rs1: u8, rs2: u8) -> Result<(), TranspileError> {
        let pvm_rd = self.require_reg(rd)?;
        let pvm_rs1 = self.require_reg(rs1)?;
        let pvm_rs2 = self.require_reg(rs2)?;

        let pvm_opcode = if funct7 == 1 {
            match funct3 {
                0 => 192, // MULW → mul_32
                4 => 194, // DIVW → div_s_32
                5 => 193, // DIVUW → div_u_32
                6 => 196, // REMW → rem_s_32
                7 => 195, // REMUW → rem_u_32
                _ => return Err(TranspileError::UnsupportedInstruction {
                    offset: 0, detail: format!("OP-32 M funct3={}", funct3),
                }),
            }
        } else if funct7 == 0x20 {
            match funct3 {
                0 => 191, // SUBW → sub_32
                5 => 199, // SRAW → shar_r_32
                _ => return Err(TranspileError::UnsupportedInstruction {
                    offset: 0, detail: format!("OP-32 funct7=0x20 funct3={}", funct3),
                }),
            }
        } else {
            match funct3 {
                0 => 190, // ADDW → add_32
                1 => 197, // SLLW → shlo_l_32
                5 => 198, // SRLW → shlo_r_32
                _ => return Err(TranspileError::UnsupportedInstruction {
                    offset: 0, detail: format!("OP-32 funct3={}", funct3),
                }),
            }
        };

        // ThreeReg encoding: byte1 = rA | (rB << 4), byte2 = rD
        self.emit_inst(pvm_opcode);
        self.emit_data(pvm_rs1 | (pvm_rs2 << 4));
        self.emit_data(pvm_rd);

        Ok(())
    }

    // ===== Helpers =====

    pub(crate) fn require_reg(&self, rv_reg: u8) -> Result<u8, TranspileError> {
        match map_register(rv_reg)? {
            Some(r) => Ok(r),
            None => Ok(0), // x0 → use reg 0 and ignore writes
        }
    }

    pub(crate) fn emit_inst(&mut self, opcode: u8) {
        self.code.push(opcode);
        self.bitmask.push(1);
    }

    pub(crate) fn emit_data(&mut self, byte: u8) {
        self.code.push(byte);
        self.bitmask.push(0);
    }

    pub(crate) fn emit_imm32(&mut self, imm: i32) {
        let bytes = imm.to_le_bytes();
        for b in &bytes {
            self.emit_data(*b);
        }
    }

    pub(crate) fn emit_load_imm(&mut self, rd: u8, imm: i64) -> Result<(), TranspileError> {
        if rd == 0 { return Ok(()); } // Write to zero register is nop
        let pvm_rd = self.require_reg(rd)?;

        if imm >= i32::MIN as i64 && imm <= i32::MAX as i64 {
            // load_imm (opcode 51)
            self.emit_inst(51);
            self.emit_data(pvm_rd);
            self.emit_imm32(imm as i32);
        } else {
            // load_imm_64 (opcode 20)
            self.emit_inst(20);
            self.emit_data(pvm_rd);
            let bytes = (imm as u64).to_le_bytes();
            for b in &bytes {
                self.emit_data(*b);
            }
        }
        Ok(())
    }

    pub(crate) fn emit_jump(&mut self, target: u64) {
        let inst_pc = self.code.len() as u32;
        self.emit_inst(40); // jump
        let fixup_pos = self.code.len();
        self.fixups.push((fixup_pos, target, 4));
        self.fixup_pcs.insert(fixup_pos, inst_pc);
        self.emit_imm32(0); // placeholder
    }

/// Emit a load_imm for a return address (RISC-V addr → absolute PVM PC).
    pub(crate) fn emit_return_address(&mut self, rd: u8, rv_ret_addr: u64) -> Result<(), TranspileError> {
        if rd == 0 { return Ok(()); }
        let pvm_rd = self.require_reg(rd)?;
        self.emit_inst(51); // load_imm
        self.emit_data(pvm_rd);
        let imm_offset = self.code.len();
        self.emit_imm32(0); // placeholder — absolute fixup will patch
        self.abs_fixups.push((imm_offset, rv_ret_addr));
        Ok(())
    }

    pub(crate) fn emit_ecalli(&mut self, id: u32) {
        self.emit_inst(10);
        self.emit_imm32(id as i32);
    }

    pub(crate) fn apply_fixups(&mut self) {
        // PC-relative fixups (branches, jumps)
        for (pvm_offset, rv_target, size) in self.fixups.drain(..).collect::<Vec<_>>() {
            if let Some(&pvm_target) = self.address_map.get(&rv_target) {
                let inst_pc = self.fixup_pcs.get(&pvm_offset).copied().unwrap_or(pvm_offset as u32 - 1);
                let relative = (pvm_target as i64 - inst_pc as i64) as i32;
                let bytes = relative.to_le_bytes();
                for i in 0..size as usize {
                    self.code[pvm_offset + i] = bytes[i];
                }
            }
            // If target not found, leave as 0 (will trap)
        }
        // Absolute fixups (return addresses in load_imm)
        for (pvm_offset, rv_target) in self.abs_fixups.drain(..).collect::<Vec<_>>() {
            if let Some(&pvm_target) = self.address_map.get(&rv_target) {
                let bytes = (pvm_target as i32).to_le_bytes();
                for i in 0..4 {
                    self.code[pvm_offset + i] = bytes[i];
                }
            }
        }
    }
}

// ===== RISC-V immediate decoders =====

fn decode_j_imm(inst: u32) -> i32 {
    let imm20 = (inst >> 31) & 1;
    let imm10_1 = (inst >> 21) & 0x3FF;
    let imm11 = (inst >> 20) & 1;
    let imm19_12 = (inst >> 12) & 0xFF;
    let imm = (imm20 << 20) | (imm19_12 << 12) | (imm11 << 11) | (imm10_1 << 1);
    // Sign extend from bit 20
    if imm20 != 0 { (imm | 0xFFE00000) as i32 } else { imm as i32 }
}

fn decode_b_imm(inst: u32) -> i32 {
    let imm12 = (inst >> 31) & 1;
    let imm10_5 = (inst >> 25) & 0x3F;
    let imm4_1 = (inst >> 8) & 0xF;
    let imm11 = (inst >> 7) & 1;
    let imm = (imm12 << 12) | (imm11 << 11) | (imm10_5 << 5) | (imm4_1 << 1);
    if imm12 != 0 { (imm | 0xFFFFE000) as i32 } else { imm as i32 }
}

fn decode_s_imm(inst: u32) -> i32 {
    let imm11_5 = (inst >> 25) & 0x7F;
    let imm4_0 = (inst >> 7) & 0x1F;
    let imm = (imm11_5 << 5) | imm4_0;
    if imm11_5 & 0x40 != 0 { (imm | 0xFFFFF000) as i32 } else { imm as i32 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_mapping() {
        assert_eq!(map_register(0).unwrap(), None); // zero
        assert_eq!(map_register(1).unwrap(), Some(0)); // ra
        assert_eq!(map_register(2).unwrap(), Some(1)); // sp
        assert_eq!(map_register(10).unwrap(), Some(7)); // a0
        assert_eq!(map_register(15).unwrap(), Some(12)); // a5
        assert!(map_register(3).is_err()); // gp: no mapping
    }

    #[test]
    fn test_decode_j_imm() {
        // JAL x0, 0 (forward)
        assert_eq!(decode_j_imm(0x0000006F), 0);
        // JAL x0, 4
        assert_eq!(decode_j_imm(0x0040006F), 4);
    }
}
