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

/// Determine the minimum byte width for encoding a signed immediate in PVM format.
///
/// Returns `(lx, bytes)` where `lx` is the byte count (0, 1, 2, or 4) and `bytes`
/// are the little-endian encoded value.
fn encode_var_imm(imm: i32) -> (u8, Vec<u8>) {
    if imm == 0 {
        (0, vec![])
    } else if imm >= -128 && imm <= 127 {
        (1, vec![imm as i8 as u8])
    } else if imm >= -32768 && imm <= 32767 {
        (2, (imm as i16).to_le_bytes().to_vec())
    } else {
        (4, imm.to_le_bytes().to_vec())
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
    /// Pending branch fixups: (pvm_imm_offset, target_rv_address, fixup_size)
    fixups: Vec<(usize, u64, u8)>,
    /// Map from fixup imm offset → instruction PC (for PC-relative encoding)
    fixup_pcs: std::collections::HashMap<usize, u32>,
    /// Pending absolute fixups: (pvm_imm_offset, target_rv_address) — patched with absolute PVM PC
    abs_fixups: Vec<(usize, u64)>,
    /// Return-address fixups: (jump_table_index, risc-v return address).
    /// Resolved during `apply_fixups` to patch jump table entries.
    return_fixups: Vec<(usize, u64)>,
    /// Pending AUIPC: (rd, computed_address). Used to pair with the next JALR.
    pending_auipc: Option<(u8, u64)>,
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
            abs_fixups: Vec::new(),
            return_fixups: Vec::new(),
            pending_auipc: None,
            last_t0_imm: None,
        }
    }

    /// Translate one or more 32-bit RISC-V instructions starting at `offset`.
    /// Returns the number of bytes consumed (always 4).
    pub(crate) fn translate_instruction(&mut self, section: &[u8], offset: usize, base: u64) -> Result<usize, TranspileError> {
        let inst = u32::from_le_bytes([section[offset], section[offset+1], section[offset+2], section[offset+3]]);
        let addr = base + offset as u64;
        self.translate_one(inst, addr)?;
        Ok(4)
    }

    /// Translate a single 32-bit RISC-V instruction.
    fn translate_one(&mut self, inst: u32, _addr: u64) -> Result<(), TranspileError> {
        let opcode = inst & 0x7F;
        let rd = ((inst >> 7) & 0x1F) as u8;
        let funct3 = (inst >> 12) & 0x7;
        let rs1 = ((inst >> 15) & 0x1F) as u8;
        let rs2 = ((inst >> 20) & 0x1F) as u8;
        let funct7 = (inst >> 25) & 0x7F;

        // Flush pending auipc if this isn't a JALR that consumes it.
        if opcode != 0x67 {
            if let Some((auipc_rd, auipc_val)) = self.pending_auipc.take() {
                self.emit_load_imm(auipc_rd, auipc_val as i64)?;
            }
        }

        match opcode {
            0x37 => { // LUI
                let imm = (inst & 0xFFFFF000) as i32;
                self.emit_load_imm(rd, imm as i64)?;
            }
            0x17 => { // AUIPC — PC + upper immediate
                let imm = (inst & 0xFFFFF000) as i32;
                let computed = (_addr as i64 + imm as i64) as u64;
                // Record for pairing with the next JALR instruction.
                // Don't emit anything yet — the JALR handler will use this.
                self.pending_auipc = Some((rd, computed));
            }
            0x6F => { // JAL
                let imm = decode_j_imm(inst);
                let target = (_addr as i64 + imm as i64) as u64;
                if rd == 0 {
                    // Plain jump (tail call / goto)
                    self.emit_jump(target);
                } else {
                    // Function call: set RA to jump table entry for return address
                    let rv_return_addr = _addr + 4;
                    let jt_idx = self.jump_table.len();
                    self.jump_table.push(0); // placeholder
                    self.return_fixups.push((jt_idx, rv_return_addr));
                    let jt_addr = ((jt_idx + 1) * 2) as i64;
                    self.emit_load_imm(rd, jt_addr)?;
                    self.emit_jump(target);
                }
            }
            0x67 => { // JALR
                match funct3 {
                    0 => {
                        let imm = ((inst as i32) >> 20) as i32;
                        self.translate_jalr(rd, rs1, imm, _addr)?;
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
                self.translate_op(funct3, funct7, rd, rs1, rs2, _addr)?;
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

        Ok(())
    }

    /// Flush any pending AUIPC as a standalone load_imm.
    pub(crate) fn flush_pending_auipc(&mut self) -> Result<(), TranspileError> {
        if let Some((rd, val)) = self.pending_auipc.take() {
            self.emit_load_imm(rd, val as i64)?;
        }
        Ok(())
    }

    fn translate_jalr(&mut self, rd: u8, rs1: u8, imm: i32, addr: u64) -> Result<(), TranspileError> {
        // Check for auipc+jalr pair (PC-relative call/jump)
        if let Some((auipc_rd, auipc_val)) = self.pending_auipc.take() {
            if auipc_rd == rs1 {
                // Combined auipc+jalr: target = auipc_val + imm
                let target = (auipc_val as i64 + imm as i64) as u64;
                if rd == 0 {
                    // Tail call: just jump, no return address
                    self.emit_jump(target);
                } else {
                    // Function call: set return address via jump table
                    let rv_return_addr = addr + 4;
                    self.emit_return_address_jt(rd, rv_return_addr)?;
                    self.emit_jump(target);
                }
                return Ok(());
            } else {
                // auipc targeted a different register — emit it as load_imm
                self.emit_load_imm(auipc_rd, auipc_val as i64)?;
            }
        }

        // Plain JALR (no preceding auipc, or auipc was for different reg)
        if rd == 0 && rs1 == 1 && imm == 0 {
            // ret: jump_ind via RA (holds jump table addr or halt addr)
            let pvm_rs1 = self.require_reg(rs1)?;
            self.emit_inst(50); // jump_ind
            self.emit_data(pvm_rs1);
            self.emit_imm32(0);
        } else {
            // General JALR — uncommon without auipc pairing
            let pvm_rs1 = self.require_reg(rs1)?;
            self.emit_inst(50); // jump_ind
            self.emit_data(pvm_rs1);
            self.emit_imm32(imm);
        }
        Ok(())
    }

    fn translate_branch(&mut self, funct3: u32, rs1: u8, rs2: u8, target: u64) -> Result<(), TranspileError> {
        // When one operand is x0 (zero register), use immediate branch variants
        // since PVM register 0 = RA, not zero.
        if rs2 == 0 {
            let pvm_rs1 = self.require_reg(rs1)?;
            let pvm_opcode = match funct3 {
                0 => 81,  // BEQ x, x0 → branch_eq_imm x, 0
                1 => 82,  // BNE x, x0 → branch_ne_imm x, 0
                4 => 87,  // BLT x, x0 → branch_lt_s_imm x, 0
                5 => 89,  // BGE x, x0 → branch_ge_s_imm x, 0
                6 => 83,  // BLTU x, x0 → branch_lt_u_imm x, 0
                7 => 85,  // BGEU x, x0 → branch_ge_u_imm x, 0
                _ => return Err(TranspileError::UnsupportedInstruction {
                    offset: 0, detail: format!("branch funct3={}", funct3),
                }),
            };
            self.emit_branch_imm(pvm_opcode, pvm_rs1, 0, target);
            return Ok(());
        }

        if rs1 == 0 {
            // Compare x0 against rs2: flip the condition
            let pvm_rs2 = self.require_reg(rs2)?;
            match funct3 {
                0 => self.emit_branch_imm(81, pvm_rs2, 0, target), // BEQ x0, y → branch_eq_imm y, 0
                1 => self.emit_branch_imm(82, pvm_rs2, 0, target), // BNE x0, y → branch_ne_imm y, 0
                4 => self.emit_branch_imm(89, pvm_rs2, 1, target), // BLT x0, rs2 → rs2 >= 1 (signed)
                5 => self.emit_branch_imm(87, pvm_rs2, 1, target), // BGE x0, rs2 → rs2 < 1 (signed)
                6 => self.emit_branch_imm(82, pvm_rs2, 0, target), // BLTU x0, rs2 → rs2 != 0
                7 => self.emit_branch_imm(81, pvm_rs2, 0, target), // BGEU x0, rs2 → rs2 == 0
                _ => return Err(TranspileError::UnsupportedInstruction {
                    offset: 0, detail: format!("branch funct3={}", funct3),
                }),
            };
            return Ok(());
        }

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
        if rd == 0 { return Ok(()); } // Write to x0 is a no-op
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
        // x0 (zero register) has no PVM equivalent — PVM reg 0 is RA, not zero.
        // Use store_imm_ind_* to store a literal zero instead.
        if rs2 == 0 {
            let pvm_rs1 = self.require_reg(rs1)?;
            let pvm_opcode = match funct3 {
                0 => 70,  // store_imm_ind_u8
                1 => 71,  // store_imm_ind_u16
                2 => 72,  // store_imm_ind_u32
                3 => 73,  // store_imm_ind_u64
                _ => return Err(TranspileError::UnsupportedInstruction {
                    offset: 0, detail: format!("store funct3={}", funct3),
                }),
            };
            // Format: OneRegTwoImm — reg_byte encodes ra + imm_x length
            // reg_byte = ra | (lx << 4), lx=4 for 4-byte imm_x (offset)
            // imm_y has length 0, which decodes as 0 (the value we want to store)
            self.emit_inst(pvm_opcode);
            self.emit_data(pvm_rs1 | (4 << 4));
            self.emit_imm32(imm);
            return Ok(());
        }

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

        if rd == 0 { return Ok(()); } // Write to x0 is a no-op in RISC-V

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

        // RV32 uses 32-bit PVM ops; RV64 uses 64-bit PVM ops
        let pvm_opcode = match funct3 {
            0 => if self.is_64bit { 149 } else { 131 }, // ADDI → add_imm_64/32
            1 => { // SLLI
                let shamt = imm & if self.is_64bit { 0x3F } else { 0x1F };
                self.emit_inst(if self.is_64bit { 151 } else { 138 }); // shlo_l_imm_64/32
                self.emit_data(pvm_rd | (pvm_rs1 << 4));
                self.emit_imm32(shamt);
                return Ok(());
            }
            2 => 137, // SLTI → set_lt_s_imm
            3 => 136, // SLTIU → set_lt_u_imm
            4 => 133, // XORI → xor_imm
            5 => { // SRLI/SRAI
                let shamt = imm & if self.is_64bit { 0x3F } else { 0x1F };
                if funct7 & 0x20 != 0 {
                    self.emit_inst(if self.is_64bit { 153 } else { 140 }); // shar_r_imm_64/32
                } else {
                    self.emit_inst(if self.is_64bit { 152 } else { 139 }); // shlo_r_imm_64/32
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

    fn translate_op(&mut self, funct3: u32, funct7: u32, rd: u8, rs1: u8, rs2: u8, addr: u64) -> Result<(), TranspileError> {
        if rd == 0 { return Ok(()); } // Write to x0 is a no-op in RISC-V

        // Handle x0 as source: PVM reg 0 = RA, not zero.
        if rs1 == 0 && funct7 == 0 && funct3 == 0 {
            // add rd, x0, rs2 → mv rd, rs2
            let pvm_rd = self.require_reg(rd)?;
            let pvm_rs2 = self.require_reg(rs2)?;
            self.emit_inst(52); // move_reg
            self.emit_data(pvm_rd | (pvm_rs2 << 4));
            return Ok(());
        }
        if rs2 == 0 && funct7 == 0 && funct3 == 0 {
            // add rd, rs1, x0 → mv rd, rs1
            let pvm_rd = self.require_reg(rd)?;
            let pvm_rs1 = self.require_reg(rs1)?;
            self.emit_inst(52); // move_reg
            self.emit_data(pvm_rd | (pvm_rs1 << 4));
            return Ok(());
        }
        // SUB rd, x0, rs2 → neg rd, rs2
        if rs1 == 0 && funct7 == 0x20 && funct3 == 0 {
            let pvm_rd = self.require_reg(rd)?;
            let pvm_rs2 = self.require_reg(rs2)?;
            let neg_op = if self.is_64bit { 154 } else { 141 }; // neg_add_imm_64/32
            self.emit_inst(neg_op);
            self.emit_data(pvm_rd | (pvm_rs2 << 4));
            self.emit_imm32(0);
            return Ok(());
        }
        // Handle remaining x0 source cases
        if rs1 == 0 {
            let pvm_rd = self.require_reg(rd)?;
            let pvm_rs2 = self.require_reg(rs2)?;
            match (funct7, funct3) {
                (0, 1) | (0, 5) | (0x20, 5) => {
                    // SLL/SRL/SRA rd, x0, rs2 → shift 0 by rs2 = 0
                    return self.emit_load_imm(rd, 0);
                }
                (0, 4) | (0, 6) => {
                    // XOR/OR rd, x0, rs2 → rs2
                    self.emit_inst(52);
                    self.emit_data(pvm_rd | (pvm_rs2 << 4));
                    return Ok(());
                }
                (0, 7) => {
                    // AND rd, x0, rs2 → 0
                    return self.emit_load_imm(rd, 0);
                }
                (0, 3) => {
                    // SLTU rd, x0, rs2 → snez rd, rs2
                    self.emit_load_imm(rd, 0)?;
                    self.emit_inst(148); // cmov_nz_imm: if rs2 != 0 then rd = imm
                    self.emit_data(pvm_rd | (pvm_rs2 << 4));
                    self.emit_imm32(1);
                    return Ok(());
                }
                (1, _) => {
                    // M extension with x0 → result is 0
                    return self.emit_load_imm(rd, 0);
                }
                _ => {
                    return Err(TranspileError::UnsupportedInstruction {
                        offset: addr as usize,
                        detail: format!("unhandled x0-as-rs1 op: funct7={funct7:#x} funct3={funct3}"),
                    });
                }
            }
        }
        if rs2 == 0 {
            let pvm_rd = self.require_reg(rd)?;
            let pvm_rs1 = self.require_reg(rs1)?;
            match (funct7, funct3) {
                (0, 2) | (0, 3) => {
                    // slt(u) rd, rs1, x0 → set_lt_(s|u)_imm rd, rs1, 0
                    let pvm_opcode = if funct3 == 2 { 137 } else { 136 };
                    self.emit_inst(pvm_opcode);
                    self.emit_data(pvm_rd | (pvm_rs1 << 4));
                    self.emit_imm32(0);
                    return Ok(());
                }
                (0x20, 0) | (0, 4) | (0, 6) => {
                    // SUB/XOR/OR rd, rs1, x0 → rs1 op 0 = rs1 → move
                    self.emit_inst(52);
                    self.emit_data(pvm_rd | (pvm_rs1 << 4));
                    return Ok(());
                }
                (0, 7) => {
                    // AND rd, rs1, x0 → 0
                    return self.emit_load_imm(rd, 0);
                }
                (0, 1) | (0, 5) | (0x20, 5) => {
                    // SLL/SRL/SRA rd, rs1, x0 → shift by 0 = rs1 → move
                    self.emit_inst(52);
                    self.emit_data(pvm_rd | (pvm_rs1 << 4));
                    return Ok(());
                }
                (1, _) => {
                    // M extension: mul rd, rs1, 0 = 0; div/rem by 0 is undefined
                    return self.emit_load_imm(rd, 0);
                }
                _ => {
                    return Err(TranspileError::UnsupportedInstruction {
                        offset: addr as usize,
                        detail: format!("unhandled x0-as-rs2 op: funct7={funct7:#x} funct3={funct3}"),
                    });
                }
            }
        }

        let pvm_rd = self.require_reg(rd)?;
        let pvm_rs1 = self.require_reg(rs1)?;
        let pvm_rs2 = self.require_reg(rs2)?;

        // RV32 uses 32-bit PVM ops; RV64 uses 64-bit PVM ops
        let pvm_opcode = if funct7 == 1 {
            // M extension (multiply/divide)
            match funct3 {
                0 => if self.is_64bit { 202 } else { 192 }, // MUL
                1 => 213, // MULH → mul_upper_ss (always 64-bit, gives upper bits)
                2 => 215, // MULHSU → mul_upper_su
                3 => 214, // MULHU → mul_upper_uu
                4 => if self.is_64bit { 204 } else { 194 }, // DIV
                5 => if self.is_64bit { 203 } else { 193 }, // DIVU
                6 => if self.is_64bit { 206 } else { 196 }, // REM
                7 => if self.is_64bit { 205 } else { 195 }, // REMU
                _ => unreachable!(),
            }
        } else if funct7 == 0x20 {
            match funct3 {
                0 => if self.is_64bit { 201 } else { 191 }, // SUB
                5 => if self.is_64bit { 209 } else { 199 }, // SRA
                _ => return Err(TranspileError::UnsupportedInstruction {
                    offset: 0, detail: format!("OP funct7=0x20 funct3={}", funct3),
                }),
            }
        } else {
            match funct3 {
                0 => if self.is_64bit { 200 } else { 190 }, // ADD
                1 => if self.is_64bit { 207 } else { 197 }, // SLL
                2 => 217, // SLT → set_lt_s
                3 => 216, // SLTU → set_lt_u
                4 => 211, // XOR → xor
                5 => if self.is_64bit { 208 } else { 198 }, // SRL
                6 => 212, // OR → or
                7 => 210, // AND → and
                _ => unreachable!(),
            }
        };

        // ThreeReg encoding: byte1 = rA | (rB << 4), byte2 = rD
        self.emit_inst(pvm_opcode);
        self.emit_data(pvm_rs1 | (pvm_rs2 << 4));
        self.emit_data(pvm_rd);

        Ok(())
    }

    fn translate_op_imm_32(&mut self, funct3: u32, funct7: u32, rd: u8, rs1: u8, imm: i32) -> Result<(), TranspileError> {
        if rd == 0 { return Ok(()); }
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
        if rd == 0 { return Ok(()); }
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

    /// Emit a return address via jump table entry.
    ///
    /// Allocates a jump table slot for the return address and loads the
    /// jump table address into the given register. The slot is patched
    /// during `apply_fixups` to point to the PVM offset of `rv_ret_addr`.
    pub(crate) fn emit_return_address_jt(&mut self, rd: u8, rv_ret_addr: u64) -> Result<(), TranspileError> {
        if rd == 0 { return Ok(()); }
        let jt_idx = self.jump_table.len();
        self.jump_table.push(0); // placeholder
        self.return_fixups.push((jt_idx, rv_ret_addr));
        let jt_addr = ((jt_idx + 1) * 2) as i64;
        self.emit_load_imm(rd, jt_addr)
    }

    /// Emit a load_imm for a return address (RISC-V addr → absolute PVM PC).
    /// Used by the linker for CALL_PLT relocations.
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

    /// Emit a OneRegImmOffset instruction (used by branch_*_imm opcodes).
    ///
    /// PVM encoding: [opcode][ra | (lx << 4)][imm (lx bytes LE)][offset (4 bytes LE)]
    /// where lx = minimum bytes to represent the signed immediate.
    fn emit_branch_imm(&mut self, opcode: u8, ra: u8, imm: i32, target: u64) {
        let inst_pc = self.code.len() as u32;
        self.emit_inst(opcode);

        let (lx, imm_bytes) = encode_var_imm(imm);

        // Pack register and immediate length into one byte
        self.emit_data(ra | (lx << 4));

        // Emit immediate bytes
        for b in &imm_bytes {
            self.emit_data(*b);
        }

        // Emit offset placeholder (4 bytes, filled by fixup)
        let fixup_pos = self.code.len();
        self.fixups.push((fixup_pos, target, 4));
        self.fixup_pcs.insert(fixup_pos, inst_pc);
        self.emit_imm32(0);
    }

    /// Build a mapping from RISC-V code addresses to PVM jump table addresses.
    ///
    /// Only creates jump table entries for the given `targets` — the set of
    /// RISC-V addresses actually referenced as function pointers (e.g. from
    /// absolute relocations in data sections like vtables). Returns a map of
    /// RISC-V address → jump table address (= (index+1)*2).
    ///
    /// This is needed to fix indirect calls through function pointers stored in
    /// data sections (vtables, callbacks, etc.). The PVM's `jump_ind` instruction
    /// expects jump table addresses, not raw code offsets.
    pub fn build_function_pointer_map(
        &mut self,
        targets: &std::collections::HashSet<u64>,
    ) -> std::collections::HashMap<u64, u32> {
        let mut rv_to_jt: std::collections::HashMap<u64, u32> = std::collections::HashMap::new();

        let mut target_addrs: Vec<u64> = targets.iter().copied().collect();
        target_addrs.sort();

        for rv_addr in &target_addrs {
            if let Some(&pvm_offset) = self.address_map.get(rv_addr) {
                let jt_idx = self.jump_table.len();
                self.jump_table.push(pvm_offset);
                let jt_addr = ((jt_idx + 1) * 2) as u32;
                rv_to_jt.insert(*rv_addr, jt_addr);
            }
        }

        rv_to_jt
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
            } else {
                tracing::warn!("unresolved fixup: rv_target={:#x}, pvm_offset={}", rv_target, pvm_offset);
            }
        }

        // Absolute fixups (return addresses in load_imm, used by linker)
        for (pvm_offset, rv_target) in self.abs_fixups.drain(..).collect::<Vec<_>>() {
            if let Some(&pvm_target) = self.address_map.get(&rv_target) {
                let bytes = (pvm_target as i32).to_le_bytes();
                for i in 0..4 {
                    self.code[pvm_offset + i] = bytes[i];
                }
            }
        }

        // Resolve return address fixups in the jump table
        for (jt_idx, rv_addr) in self.return_fixups.drain(..).collect::<Vec<_>>() {
            if let Some(&pvm_target) = self.address_map.get(&rv_addr) {
                self.jump_table[jt_idx] = pvm_target;
            }
            // If not found, leave as 0 (will trap on return)
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
