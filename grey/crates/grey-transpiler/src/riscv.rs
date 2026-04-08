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
        0 => Ok(None),                                         // x0 = zero register (always 0)
        1 => Ok(Some(0)),                                      // x1 (ra) → PVM reg 0 (RA)
        2 => Ok(Some(1)),                                      // x2 (sp) → PVM reg 1 (SP)
        3 | 4 => Err(TranspileError::RegisterMapping(rv_reg)), // gp, tp: no mapping
        5 => Ok(Some(2)),                                      // x5 (t0) → PVM reg 2 (T0)
        6 => Ok(Some(3)),                                      // x6 (t1) → PVM reg 3 (T1)
        7 => Ok(Some(4)),                                      // x7 (t2) → PVM reg 4 (T2)
        8 => Ok(Some(5)),                                      // x8 (s0) → PVM reg 5 (S0)
        9 => Ok(Some(6)),                                      // x9 (s1) → PVM reg 6 (S1)
        10 => Ok(Some(7)),                                     // x10 (a0) → PVM reg 7 (A0)
        11 => Ok(Some(8)),                                     // x11 (a1) → PVM reg 8 (A1)
        12 => Ok(Some(9)),                                     // x12 (a2) → PVM reg 9 (A2)
        13 => Ok(Some(10)),                                    // x13 (a3) → PVM reg 10 (A3)
        14 => Ok(Some(11)),                                    // x14 (a4) → PVM reg 11 (A4)
        15 => Ok(Some(12)),                                    // x15 (a5) → PVM reg 12 (A5)
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
    } else if (-128..=127).contains(&imm) {
        (1, vec![imm as i8 as u8])
    } else if (-32768..=32767).contains(&imm) {
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
    /// Return-address fixups: (jump_table_index, risc-v return address).
    /// Resolved during `apply_fixups` to patch jump table entries.
    pub(crate) return_fixups: Vec<(usize, u64)>,
    /// Pending AUIPC: (rd, computed_address). Used to pair with the next JALR.
    pending_auipc: Option<(u8, u64)>,
    /// Pending LUI: (rd, upper_imm). Used to fuse LUI+ADDI into single load_imm.
    pending_lui: Option<(u8, i64)>,
    /// Last emitted load_imm: (rd, value, code_position_before_emit).
    /// Enables fusion with a subsequent ADD/AND/OR/XOR/load/store into the
    /// immediate form, eliminating the load_imm instruction entirely.
    pub(crate) pending_load_imm: Option<(u8, i64, usize)>,
    /// Last immediate loaded into t0 (x5) — used for ecalli cap slot.
    last_t0_imm: Option<i32>,
    /// CSR marker for ecall/ecalli distinction.
    /// 0x800 = next ecall → PVM ecall, 0x801 = next ecall → PVM ecalli.
    ecall_marker: Option<u32>,
    /// RISC-V code address ranges (lo, hi) — used to detect function pointers
    /// loaded via auipc+addi that need jump table entries.
    pub code_ranges: Vec<(u64, u64)>,
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
            return_fixups: Vec::new(),
            pending_auipc: None,
            pending_lui: None,
            pending_load_imm: None,
            last_t0_imm: None,
            ecall_marker: None,
            code_ranges: Vec::new(),
        }
    }

    /// Flush any pending buffered instructions (LUI, AUIPC) at section boundaries.
    pub(crate) fn flush_pending(&mut self) -> Result<(), TranspileError> {
        if let Some((auipc_rd, auipc_val)) = self.pending_auipc.take() {
            self.emit_load_imm(auipc_rd, auipc_val as i64)?;
        }
        if let Some((lui_rd, lui_val)) = self.pending_lui.take() {
            self.emit_load_imm(lui_rd, lui_val)?;
        }
        // pending_load_imm is already emitted — just clear the tracking
        if self.pending_load_imm.is_some() {
            self.pending_load_imm = None;
        }
        Ok(())
    }

    /// Translate one or more 32-bit RISC-V instructions starting at `offset`.
    /// Returns the number of bytes consumed (always 4).
    pub(crate) fn translate_instruction(
        &mut self,
        section: &[u8],
        offset: usize,
        base: u64,
    ) -> Result<usize, TranspileError> {
        let inst = u32::from_le_bytes([
            section[offset],
            section[offset + 1],
            section[offset + 2],
            section[offset + 3],
        ]);
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

        // Flush pending auipc if this isn't a JALR or OP-IMM (ADDI) that consumes it.
        if opcode != 0x67
            && opcode != 0x13
            && let Some((auipc_rd, auipc_val)) = self.pending_auipc.take()
        {
            self.emit_load_imm(auipc_rd, auipc_val as i64)?;
        }

        // Flush pending LUI if this isn't an OP-IMM (ADDI) that consumes it.
        if opcode != 0x13
            && let Some((lui_rd, lui_val)) = self.pending_lui.take()
        {
            self.emit_load_imm(lui_rd, lui_val)?;
        }

        // Clear pending_load_imm if this isn't an instruction that can consume it.
        // OP (0x33), OP-32 (0x3B), Branch (0x63), Store (0x23), and Load (0x03)
        // handlers check and potentially fuse.
        if opcode != 0x33 && opcode != 0x3B && opcode != 0x63 && opcode != 0x23 && opcode != 0x03 {
            self.pending_load_imm = None; // already emitted, just clear tracking
        }

        match opcode {
            0x37 => {
                // LUI — buffer for potential LUI+ADDI fusion
                let imm = (inst & 0xFFFFF000) as i32;
                // Flush any previous pending LUI (consecutive LUIs)
                if let Some((prev_rd, prev_val)) = self.pending_lui.take() {
                    self.emit_load_imm(prev_rd, prev_val)?;
                }
                self.pending_lui = Some((rd, imm as i64));
            }
            0x17 => {
                // AUIPC — PC + upper immediate
                let imm = (inst & 0xFFFFF000) as i32;
                let computed = (_addr as i64 + imm as i64) as u64;
                // Record for pairing with the next JALR instruction.
                // Don't emit anything yet — the JALR handler will use this.
                self.pending_auipc = Some((rd, computed));
            }
            0x6F => {
                // JAL
                let imm = decode_j_imm(inst);
                let target = (_addr as i64 + imm as i64) as u64;
                if rd == 0 {
                    // Plain jump (tail call / goto)
                    self.emit_jump(target);
                } else {
                    // Function call: fused load_imm_jump (opcode 80)
                    let rv_return_addr = _addr + 4;
                    self.emit_call(rd, rv_return_addr, target)?;
                }
            }
            0x67 => {
                // JALR
                match funct3 {
                    0 => {
                        let imm = (inst as i32) >> 20;
                        self.translate_jalr(rd, rs1, imm, _addr)?;
                    }
                    _ => {
                        return Err(TranspileError::UnsupportedInstruction {
                            offset: _addr as usize,
                            detail: format!("JALR funct3={}", funct3),
                        });
                    }
                }
            }
            0x63 => {
                // Branch
                let imm = decode_b_imm(inst);
                let target = (_addr as i64 + imm as i64) as u64;
                self.translate_branch(funct3, rs1, rs2, target)?;
            }
            0x03 => {
                // Load
                let imm = (inst as i32) >> 20;
                self.translate_load(funct3, rd, rs1, imm)?;
            }
            0x23 => {
                // Store
                let imm = decode_s_imm(inst);
                self.translate_store(funct3, rs1, rs2, imm)?;
            }
            0x13 => {
                // OP-IMM (add_i, xor_i, etc.)
                let imm = (inst as i32) >> 20;
                self.translate_op_imm(funct3, funct7, rd, rs1, imm)?;
            }
            0x33 => {
                // OP (add, sub, mul, etc.)
                self.translate_op(funct3, funct7, rd, rs1, rs2, _addr)?;
            }
            0x1B => {
                // OP-IMM-32 (addiw, slliw, etc.) — RV64 only
                let imm = (inst as i32) >> 20;
                self.translate_op_imm_32(funct3, funct7, rd, rs1, imm)?;
            }
            0x3B => {
                // OP-32 (addw, subw, etc.) — RV64 only
                self.translate_op_32(funct3, funct7, rd, rs1, rs2)?;
            }
            0x73 => {
                // SYSTEM
                match funct3 {
                    0 => {
                        let csr = (inst >> 20) & 0xFFF;
                        match csr {
                            0 => {
                                // ECALL — dispatch based on CSR marker
                                match self.ecall_marker.take() {
                                    Some(0x800) => {
                                        // CSR 0x800 → PVM ecall (management ops)
                                        self.emit_ecall();
                                    }
                                    Some(0x801) => {
                                        // CSR 0x801 → PVM ecalli (CALL a cap)
                                        let id = self.last_t0_imm.unwrap_or(0) as u32;
                                        self.emit_ecalli(id);
                                        self.last_t0_imm = None;
                                    }
                                    _ => {
                                        // No marker (legacy) — treat as ecalli for backward compat
                                        let id = self.last_t0_imm.unwrap_or(0) as u32;
                                        self.emit_ecalli(id);
                                        self.last_t0_imm = None;
                                    }
                                }
                            }
                            1 => self.emit_inst(0), // EBREAK → trap
                            _ => self.emit_inst(0), // unimp/unknown CSR → trap
                        }
                    }
                    1 => {
                        // CSRRW: check for custom markers 0x800, 0x801
                        let csr = (inst >> 20) & 0xFFF;
                        match csr {
                            0x800 | 0x801 => {
                                // Custom CSR marker for ecall/ecalli distinction
                                self.ecall_marker = Some(csr);
                                // Don't emit any PVM instruction — marker consumed on next ecall
                            }
                            _ => self.emit_inst(0), // unknown CSR → trap
                        }
                    }
                    _ => self.emit_inst(0), // other CSR ops → trap
                }
            }
            0x0F => {
                // FENCE
                self.emit_inst(1); // → fallthrough (nop)
            }
            0x0B => {
                // CUSTOM-0 — T-Head extensions
                match (funct7, funct3) {
                    (0x20, 1) => {
                        // th.mveqz rd, rs1, rs2: if rs2 == 0 then rd = rs1
                        if rd == 0 { /* nop */
                        } else if rs2 == 0 {
                            // Condition is x0 (always 0) → always execute: rd = rs1
                            if rs1 == 0 {
                                self.emit_load_imm(rd, 0)?;
                            } else if rd == rs1 {
                                // Self-move is a nop
                                self.emit_inst(1); // fallthrough
                            } else {
                                let pvm_rd = self.require_reg(rd)?;
                                let pvm_rs1 = self.require_reg(rs1)?;
                                self.emit_inst(100); // move_reg
                                self.emit_data(pvm_rd | (pvm_rs1 << 4));
                            }
                        } else if rs1 == 0 {
                            // Source is x0 (always 0): if rs2 == 0 then rd = 0
                            let pvm_rd = self.require_reg(rd)?;
                            let pvm_rs2 = self.require_reg(rs2)?;
                            self.emit_inst(147); // CmovIzImm
                            self.emit_data(pvm_rd | (pvm_rs2 << 4));
                            self.emit_var_imm(0);
                        } else {
                            let pvm_rd = self.require_reg(rd)?;
                            let pvm_rs1 = self.require_reg(rs1)?;
                            let pvm_rs2 = self.require_reg(rs2)?;
                            self.emit_inst(218); // CmovIz
                            self.emit_data(pvm_rs1 | (pvm_rs2 << 4));
                            self.emit_data(pvm_rd);
                        }
                    }
                    (0x21, 1) => {
                        // th.mvnez rd, rs1, rs2: if rs2 != 0 then rd = rs1
                        if rd == 0 || rs2 == 0 {
                            // rd==0: nop. rs2==x0: condition "x0 != 0" is always false → nop
                            self.emit_inst(1); // fallthrough
                        } else if rs1 == 0 {
                            let pvm_rd = self.require_reg(rd)?;
                            let pvm_rs2 = self.require_reg(rs2)?;
                            self.emit_inst(148); // CmovNzImm
                            self.emit_data(pvm_rd | (pvm_rs2 << 4));
                            self.emit_var_imm(0);
                        } else {
                            let pvm_rd = self.require_reg(rd)?;
                            let pvm_rs1 = self.require_reg(rs1)?;
                            let pvm_rs2 = self.require_reg(rs2)?;
                            self.emit_inst(219); // CmovNz
                            self.emit_data(pvm_rs1 | (pvm_rs2 << 4));
                            self.emit_data(pvm_rd);
                        }
                    }
                    _ => {
                        return Err(TranspileError::UnsupportedInstruction {
                            offset: _addr as usize,
                            detail: format!("custom-0 funct7={:#x} funct3={}", funct7, funct3),
                        });
                    }
                }
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

    fn translate_jalr(
        &mut self,
        rd: u8,
        rs1: u8,
        imm: i32,
        addr: u64,
    ) -> Result<(), TranspileError> {
        // Check for auipc+jalr pair (PC-relative call/jump)
        if let Some((auipc_rd, auipc_val)) = self.pending_auipc.take() {
            if auipc_rd == rs1 {
                // Combined auipc+jalr: target = auipc_val + imm
                let target = (auipc_val as i64 + imm as i64) as u64;
                if rd == 0 {
                    // Tail call: just jump, no return address
                    self.emit_jump(target);
                } else {
                    // Function call: fused load_imm_jump (opcode 80)
                    let rv_return_addr = addr + 4;
                    self.emit_call(rd, rv_return_addr, target)?;
                }
                return Ok(());
            } else {
                // auipc targeted a different register — emit it as load_imm
                self.emit_load_imm(auipc_rd, auipc_val as i64)?;
            }
        }

        // Plain JALR (no preceding auipc, or auipc was for different reg)
        if rd == 0 {
            // Tail call or return: jump_ind without saving return address.
            // Handles ret (rs1=ra, imm=0) and tail calls through any register.
            let pvm_rs1 = self.require_reg(rs1)?;
            self.emit_inst(50); // jump_ind
            self.emit_data(pvm_rs1);
            self.emit_var_imm(imm);
        } else {
            // Indirect call (e.g. vtable dispatch): save return address then jump.
            // Use load_imm_jump_ind (opcode 180): rd = return_addr, jump via rs1+imm.
            let rv_return_addr = addr + 4;
            let jt_idx = self.jump_table.len();
            self.jump_table.push(0); // placeholder
            self.return_fixups.push((jt_idx, rv_return_addr));
            let jt_addr = ((jt_idx + 1) * 2) as i32;

            let pvm_rd = self.require_reg(rd)?;
            let pvm_rs1 = self.require_reg(rs1)?;
            let lx = Self::var_imm_byte_count(jt_addr);

            self.emit_inst(180); // load_imm_jump_ind
            self.emit_data(pvm_rd | (pvm_rs1 << 4)); // reg_byte: ra=rd, rb=rs1
            self.emit_data(lx as u8); // lx: byte count for imm_x (return addr)
            self.emit_var_imm(jt_addr); // imm_x: jump table return address
            self.emit_var_imm(imm); // imm_y: offset added to rs1
        }
        Ok(())
    }

    fn translate_branch(
        &mut self,
        funct3: u32,
        rs1: u8,
        rs2: u8,
        target: u64,
    ) -> Result<(), TranspileError> {
        // Fuse load_imm + branch: if one operand was just loaded via load_imm,
        // use the immediate branch form instead of a two-register branch.
        // Saves one PVM instruction (the load_imm) per fused branch.
        if let Some((load_rd, load_val, undo_pos)) = self.pending_load_imm.take()
            && load_val >= i32::MIN as i64
            && load_val <= i32::MAX as i64
        {
            let imm = load_val as i32;
            // Check if rs2 is the loaded register: branch_*_imm rs1, imm, target
            if rs2 == load_rd && rs1 != load_rd {
                let pvm_rs1 = self.require_reg(rs1)?;
                let pvm_opcode = match funct3 {
                    0 => Some(81), // BEQ → branch_eq_imm
                    1 => Some(82), // BNE → branch_ne_imm
                    4 => Some(87), // BLT → branch_lt_s_imm
                    5 => Some(89), // BGE → branch_ge_s_imm
                    6 => Some(83), // BLTU → branch_lt_u_imm
                    7 => Some(85), // BGEU → branch_ge_u_imm
                    _ => None,
                };
                if let Some(opc) = pvm_opcode {
                    self.code.truncate(undo_pos);
                    self.bitmask.truncate(undo_pos);
                    self.emit_branch_imm(opc, pvm_rs1, imm, target);
                    return Ok(());
                }
            }
            // Check if rs1 is the loaded register: flip the comparison
            // BEQ/BNE are symmetric. BLT(rs1,rs2) with rs1=imm → BGE(rs2,imm+1) etc.
            // Only handle symmetric cases (EQ, NE) to avoid off-by-one complexity.
            if rs1 == load_rd && rs2 != load_rd {
                let pvm_rs2 = self.require_reg(rs2)?;
                let pvm_opcode = match funct3 {
                    0 => Some(81), // BEQ is symmetric → branch_eq_imm rs2, imm
                    1 => Some(82), // BNE is symmetric → branch_ne_imm rs2, imm
                    _ => None,     // Inequalities need careful flipping, skip for now
                };
                if let Some(opc) = pvm_opcode {
                    self.code.truncate(undo_pos);
                    self.bitmask.truncate(undo_pos);
                    self.emit_branch_imm(opc, pvm_rs2, imm, target);
                    return Ok(());
                }
            }
        }
        // Couldn't fuse — load_imm was already emitted, just clear tracking

        // When one operand is x0 (zero register), use immediate branch variants
        // since PVM register 0 = RA, not zero.
        if rs2 == 0 {
            let pvm_rs1 = self.require_reg(rs1)?;
            let pvm_opcode = match funct3 {
                0 => 81, // BEQ x, x0 → branch_eq_imm x, 0
                1 => 82, // BNE x, x0 → branch_ne_imm x, 0
                4 => 87, // BLT x, x0 → branch_lt_s_imm x, 0
                5 => 89, // BGE x, x0 → branch_ge_s_imm x, 0
                6 => 83, // BLTU x, x0 → branch_lt_u_imm x, 0
                7 => 85, // BGEU x, x0 → branch_ge_u_imm x, 0
                _ => {
                    return Err(TranspileError::UnsupportedInstruction {
                        offset: 0,
                        detail: format!("branch funct3={}", funct3),
                    });
                }
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
                _ => {
                    return Err(TranspileError::UnsupportedInstruction {
                        offset: 0,
                        detail: format!("branch funct3={}", funct3),
                    });
                }
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
            _ => {
                return Err(TranspileError::UnsupportedInstruction {
                    offset: 0,
                    detail: format!("branch funct3={}", funct3),
                });
            }
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

    pub(crate) fn translate_load(
        &mut self,
        funct3: u32,
        rd: u8,
        rs1: u8,
        imm: i32,
    ) -> Result<(), TranspileError> {
        if rd == 0 {
            return Ok(());
        } // Write to x0 is a no-op

        // Fuse load_imm + load_ind: if the base register was just loaded with
        // a constant address, use the direct load form (OneRegOneImm) instead.
        // Saves one PVM instruction per fused load.
        if let Some((load_rd, load_val, undo_pos)) = self.pending_load_imm.take()
            && rs1 == load_rd
        {
            let combined = load_val.wrapping_add(imm as i64);
            if combined >= i32::MIN as i64 && combined <= i32::MAX as i64 {
                let direct_opcode = match funct3 {
                    0 => Some(53), // LB → load_i8
                    1 => Some(55), // LH → load_i16
                    2 => Some(57), // LW → load_i32
                    3 => Some(58), // LD → load_u64
                    4 => Some(52), // LBU → load_u8
                    5 => Some(54), // LHU → load_u16
                    6 => Some(56), // LWU → load_u32
                    _ => None,
                };
                if let Some(opc) = direct_opcode {
                    // Only truncate the load_imm if the load destination overwrites
                    // the base register (rd == rs1). If rd != rs1, the base register
                    // value may be needed later (e.g., RISC-V switch table pattern:
                    // lw offset, table(base); add target, offset, base; jr target).
                    if rd == rs1 {
                        self.code.truncate(undo_pos);
                        self.bitmask.truncate(undo_pos);
                    }
                    let pvm_rd = self.require_reg(rd)?;
                    self.emit_inst(opc);
                    self.emit_data(pvm_rd);
                    self.emit_var_imm(combined as i32);
                    return Ok(());
                }
            }
        }
        // Couldn't fuse — load_imm already emitted, just proceed

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
            _ => {
                return Err(TranspileError::UnsupportedInstruction {
                    offset: 0,
                    detail: format!("load funct3={}", funct3),
                });
            }
        };

        self.emit_inst(pvm_opcode);
        self.emit_data(pvm_rd | (pvm_rs1 << 4));
        self.emit_var_imm(imm);

        Ok(())
    }

    pub(crate) fn translate_store(
        &mut self,
        funct3: u32,
        rs1: u8,
        rs2: u8,
        imm: i32,
    ) -> Result<(), TranspileError> {
        // Fuse load_imm + store: check if the base address or stored value was constant.
        if let Some((load_rd, load_val, undo_pos)) = self.pending_load_imm.take()
            && load_val >= i32::MIN as i64
            && load_val <= i32::MAX as i64
        {
            // Case 1: Base register was loaded with constant address → direct store.
            // store_ind_* data, base, offset  where base = constant addr
            //   → store_* data, (addr + offset)
            if rs1 == load_rd && rs2 != load_rd && rs2 != 0 {
                let combined = load_val.wrapping_add(imm as i64);
                if combined >= i32::MIN as i64 && combined <= i32::MAX as i64 {
                    let direct_opcode = match funct3 {
                        0 => Some(59), // SB → store_u8
                        1 => Some(60), // SH → store_u16
                        2 => Some(61), // SW → store_u32
                        3 => Some(62), // SD → store_u64
                        _ => None,
                    };
                    if let Some(opc) = direct_opcode {
                        self.code.truncate(undo_pos);
                        self.bitmask.truncate(undo_pos);
                        let pvm_rs2 = self.require_reg(rs2)?;
                        self.emit_inst(opc);
                        self.emit_data(pvm_rs2);
                        self.emit_var_imm(combined as i32);
                        return Ok(());
                    }
                }
            }
            // Case 2: Value register was loaded with constant → store_imm_ind.
            // NOTE: We intentionally do NOT undo the load_imm here because
            // the register may still be needed after the store (e.g., as a
            // function argument). The load_imm was already emitted, so the
            // register holds the correct value. Just emit a normal store.
            // The load_imm + store costs two instructions instead of one
            // fused store_imm_ind, but is always correct.
        }
        // Couldn't fuse — load_imm was already emitted, just clear tracking

        // x0 (zero register) has no PVM equivalent — PVM reg 0 is RA, not zero.
        // Use store_imm_ind_* to store a literal zero instead.
        if rs2 == 0 {
            let pvm_rs1 = self.require_reg(rs1)?;
            let pvm_opcode = match funct3 {
                0 => 70, // store_imm_ind_u8
                1 => 71, // store_imm_ind_u16
                2 => 72, // store_imm_ind_u32
                3 => 73, // store_imm_ind_u64
                _ => {
                    return Err(TranspileError::UnsupportedInstruction {
                        offset: 0,
                        detail: format!("store funct3={}", funct3),
                    });
                }
            };
            // Format: OneRegTwoImm — reg_byte encodes ra + imm_x length
            // reg_byte = ra | (lx << 4)
            // imm_y has length 0, which decodes as 0 (the value we want to store)
            let (lx, imm_bytes) = encode_var_imm(imm);
            self.emit_inst(pvm_opcode);
            self.emit_data(pvm_rs1 | (lx << 4));
            for b in &imm_bytes {
                self.emit_data(*b);
            }
            return Ok(());
        }

        let pvm_rs2 = self.require_reg(rs2)?; // data register → rD
        let pvm_rs1 = self.require_reg(rs1)?; // base register → rA

        let pvm_opcode = match funct3 {
            0 => 120, // SB → store_ind_u8
            1 => 121, // SH → store_ind_u16
            2 => 122, // SW → store_ind_u32
            3 => 123, // SD → store_ind_u64
            _ => {
                return Err(TranspileError::UnsupportedInstruction {
                    offset: 0,
                    detail: format!("store funct3={}", funct3),
                });
            }
        };

        self.emit_inst(pvm_opcode);
        self.emit_data(pvm_rs2 | (pvm_rs1 << 4));
        self.emit_var_imm(imm);

        Ok(())
    }

    fn translate_op_imm(
        &mut self,
        funct3: u32,
        funct7: u32,
        rd: u8,
        rs1: u8,
        imm: i32,
    ) -> Result<(), TranspileError> {
        // Track `li t0, N` (ADDI x5, x0, N) for ecall ID translation
        if funct3 == 0 && rd == 5 && rs1 == 0 {
            self.last_t0_imm = Some(imm);
        }

        // AUIPC+ADDI fusion: compute full address. If it's a code address (function
        // pointer), emit a jump table entry so indirect calls via djump work.
        if let Some((auipc_rd, auipc_val)) = self.pending_auipc.take() {
            if funct3 == 0 && rd == auipc_rd && rs1 == auipc_rd && rd != 0 {
                let full_addr = (auipc_val as i64 + imm as i64) as u64;
                if self.is_code_addr(full_addr) {
                    let jt_idx = self.jump_table.len();
                    self.jump_table.push(0); // placeholder, resolved by apply_fixups
                    self.return_fixups.push((jt_idx, full_addr));
                    let jt_addr = ((jt_idx + 1) * 2) as i64;
                    let pos = self.code.len();
                    self.emit_load_imm(rd, jt_addr)?;
                    self.pending_load_imm = Some((rd, jt_addr, pos));
                } else {
                    let combined = auipc_val as i64 + imm as i64;
                    let pos = self.code.len();
                    self.emit_load_imm(rd, combined)?;
                    self.pending_load_imm = Some((rd, combined, pos));
                }
                return Ok(());
            }
            // Not a matching ADDI — flush the pending AUIPC
            self.emit_load_imm(auipc_rd, auipc_val as i64)?;
        }

        // LUI+ADDI fusion: if there's a pending LUI and this is ADDI rd, rd, imm
        // with the same register, fuse into a single load_imm with the combined value.
        if let Some((lui_rd, lui_val)) = self.pending_lui.take() {
            if funct3 == 0 && rd == lui_rd && rs1 == lui_rd && rd != 0 {
                let combined = lui_val.wrapping_add(imm as i64);
                // Track for potential fusion with subsequent ALU op
                let pos = self.code.len();
                self.emit_load_imm(rd, combined)?;
                self.pending_load_imm = Some((rd, combined, pos));
                return Ok(());
            }
            // Not a matching ADDI — flush the pending LUI
            self.emit_load_imm(lui_rd, lui_val)?;
        }

        if rd == 0 {
            return Ok(());
        } // Write to x0 is a no-op in RISC-V

        // ADDI rd, rs, 0 is the RISC-V `mv rd, rs` pseudo-instruction.
        // Use compact move_reg (2 bytes) instead of add_imm (6 bytes).
        if funct3 == 0 && imm == 0 && rs1 != 0 {
            if rd == rs1 {
                // ADDI rd, rd, 0 is a NOP
                self.emit_inst(1); // fallthrough
                return Ok(());
            }
            let pvm_rd = self.require_reg(rd)?;
            let pvm_rs1 = self.require_reg(rs1)?;
            self.emit_inst(100); // move_reg
            self.emit_data(pvm_rd | (pvm_rs1 << 4));
            return Ok(());
        }

        // When rs1 = x0 (zero register), treat as loading immediate directly
        // because PVM has no zero register — x0 maps to RA which is NOT zero.
        if rs1 == 0 {
            match funct3 {
                0 => return self.emit_load_imm(rd, imm as i64), // li rd, imm
                2 => {
                    // SLTI rd, x0, imm → rd = (0 < imm) ? 1 : 0
                    return self.emit_load_imm(rd, if 0 < imm { 1 } else { 0 });
                }
                3 => {
                    // SLTIU rd, x0, imm → rd = (0 < imm unsigned) ? 1 : 0
                    return self.emit_load_imm(rd, if imm != 0 { 1 } else { 0 });
                }
                4 => return self.emit_load_imm(rd, imm as i64), // XORI rd, x0, imm = imm
                6 => return self.emit_load_imm(rd, imm as i64), // ORI rd, x0, imm = imm
                7 => return self.emit_load_imm(rd, 0),          // ANDI rd, x0, imm = 0
                _ => {}                                         // shifts with x0 → just 0, but rare
            }
        }

        let pvm_rd = self.require_reg(rd)?;
        let pvm_rs1 = self.require_reg(rs1)?;

        // RV32 uses 32-bit PVM ops; RV64 uses 64-bit PVM ops
        let pvm_opcode = match funct3 {
            0 => {
                if self.is_64bit {
                    149
                } else {
                    131
                }
            } // ADDI → add_imm_64/32
            1 => {
                if funct7 == 0x30 {
                    // Zbb unary: clz/ctz/cpop/sext.b/sext.h
                    let rs2 = (imm & 0x1F) as u8;
                    let opc = match rs2 {
                        0 => {
                            if self.is_64bit {
                                104
                            } else {
                                105
                            }
                        }
                        1 => {
                            if self.is_64bit {
                                106
                            } else {
                                107
                            }
                        }
                        2 => {
                            if self.is_64bit {
                                102
                            } else {
                                103
                            }
                        }
                        4 => 108,
                        5 => 109,
                        _ => {
                            return Err(TranspileError::UnsupportedInstruction {
                                offset: 0,
                                detail: format!("Zbb rs2={}", rs2),
                            });
                        }
                    };
                    self.emit_inst(opc);
                    self.emit_data(pvm_rd | (pvm_rs1 << 4));
                    return Ok(());
                }
                // SLLI (funct7=0x00)
                let shamt = imm & if self.is_64bit { 0x3F } else { 0x1F };
                self.emit_inst(if self.is_64bit { 151 } else { 138 });
                self.emit_data(pvm_rd | (pvm_rs1 << 4));
                self.emit_var_imm(shamt);
                return Ok(());
            }
            2 => 137, // SLTI → set_lt_s_imm
            3 => 136, // SLTIU → set_lt_u_imm
            4 => 133, // XORI → xor_imm
            5 => {
                if (funct7 == 0x35 || funct7 == 0x34) && (imm & 0x1F) == 0x18 {
                    // Zbb rev8 (RV64: 0x35, RV32: 0x34)
                    self.emit_inst(111);
                    self.emit_data(pvm_rd | (pvm_rs1 << 4));
                    return Ok(());
                }
                if funct7 == 0x30 || funct7 == 0x31 {
                    // Zbb RORI: funct6=0x18 (bits 31:26).
                    // funct7=0x30 when shamt<32, funct7=0x31 when shamt>=32 (bit 25 set).
                    let shamt = imm & if self.is_64bit { 0x3F } else { 0x1F };
                    self.emit_inst(if self.is_64bit { 158 } else { 160 });
                    self.emit_data(pvm_rd | (pvm_rs1 << 4));
                    self.emit_var_imm(shamt);
                    return Ok(());
                }
                if funct7 == 0x14 {
                    // Zbb orc.b — OR-combine bytes
                    // No PVM equivalent; emit as trap (rare instruction)
                    return Err(TranspileError::UnsupportedInstruction {
                        offset: 0,
                        detail: "Zbb orc.b not yet supported".into(),
                    });
                }
                // SRLI (funct7=0x00) / SRAI (funct7=0x20+)
                let shamt = imm & if self.is_64bit { 0x3F } else { 0x1F };
                if funct7 & 0x20 != 0 {
                    self.emit_inst(if self.is_64bit { 153 } else { 140 }); // shar_r_imm
                } else {
                    self.emit_inst(if self.is_64bit { 152 } else { 139 }); // shlo_r_imm
                }
                self.emit_data(pvm_rd | (pvm_rs1 << 4));
                self.emit_var_imm(shamt);
                return Ok(());
            }
            6 => 134, // ORI → or_imm
            7 => 132, // ANDI → and_imm
            _ => unreachable!(),
        };

        self.emit_inst(pvm_opcode);
        self.emit_data(pvm_rd | (pvm_rs1 << 4));
        self.emit_var_imm(imm);

        Ok(())
    }

    fn translate_op(
        &mut self,
        funct3: u32,
        funct7: u32,
        rd: u8,
        rs1: u8,
        rs2: u8,
        addr: u64,
    ) -> Result<(), TranspileError> {
        if rd == 0 {
            return Ok(());
        } // Write to x0 is a no-op in RISC-V

        // Fuse load_imm + ALU op: if one operand was just loaded via load_imm
        // and the value fits in i32, undo the load_imm and emit the immediate
        // form instead (saves one instruction).
        if let Some((load_rd, load_val, undo_pos)) = self.pending_load_imm.take()
            && load_val >= i32::MIN as i64
            && load_val <= i32::MAX as i64
        {
            let imm = load_val as i32;
            // Check if rs2 is the loaded register (ADD/AND/OR/XOR rd, rs1, load_rd)
            let (fuse_base, _commutative) = if rs2 == load_rd && rs1 != load_rd {
                (Some(rs1), true)
            } else if rs1 == load_rd && rs2 != load_rd && (funct7, funct3) != (0x20, 0) {
                // rs1 is the loaded register — only for commutative ops (not SUB)
                (Some(rs2), true)
            } else {
                (None, false)
            };

            if let Some(base) = fuse_base {
                let pvm_imm_opcode = match (funct7, funct3) {
                    (0, 0) => Some(if self.is_64bit { 149 } else { 131 }), // ADD → add_imm
                    (0, 7) => Some(132),                                   // AND → and_imm
                    (0, 6) => Some(134),                                   // OR → or_imm
                    (0, 4) => Some(133),                                   // XOR → xor_imm
                    (1, 0) => Some(if self.is_64bit { 150 } else { 135 }), // MUL → mul_imm
                    (0, 2) => Some(137),                                   // SLT → set_lt_s_imm
                    (0, 3) => Some(136),                                   // SLTU → set_lt_u_imm
                    _ => None,
                };

                if let Some(pvm_opcode) = pvm_imm_opcode {
                    // Only truncate the load_imm if the loaded register IS the
                    // destination (rd == load_rd). If it's just an operand,
                    // keep the load_imm so the register retains its value for
                    // future use (e.g., switch table: add idx, base, idx; lw off, 0(idx);
                    // add target, off, base; jr target — base is used twice).
                    if rd == load_rd {
                        self.code.truncate(undo_pos);
                        self.bitmask.truncate(undo_pos);
                        self.address_map.insert(addr, undo_pos as u32);
                    }
                    let pvm_rd = self.require_reg(rd)?;
                    let pvm_base = self.require_reg(base)?;
                    self.emit_inst(pvm_opcode);
                    self.emit_data(pvm_rd | (pvm_base << 4));
                    self.emit_var_imm(imm);
                    return Ok(());
                }
            }

            // Special case: shifts with loaded shift count → shift immediate forms.
            // SLL/SRL/SRA rd, rs1, load_rd → shlo_l/shlo_r/shar_r_imm rd, rs1, imm
            if rs2 == load_rd && matches!((funct7, funct3), (0, 1) | (0, 5) | (0x20, 5)) {
                let pvm_imm_opcode = match (funct7, funct3) {
                    (0, 1) => {
                        if self.is_64bit {
                            151
                        } else {
                            138
                        }
                    } // SLL → shlo_l_imm
                    (0, 5) => {
                        if self.is_64bit {
                            152
                        } else {
                            139
                        }
                    } // SRL → shlo_r_imm
                    (0x20, 5) => {
                        if self.is_64bit {
                            153
                        } else {
                            140
                        }
                    } // SRA → shar_r_imm
                    _ => unreachable!(),
                };
                self.code.truncate(undo_pos);
                self.bitmask.truncate(undo_pos);
                self.address_map.insert(addr, undo_pos as u32);
                let pvm_rd = self.require_reg(rd)?;
                let pvm_rs1 = self.require_reg(rs1)?;
                self.emit_inst(pvm_imm_opcode);
                self.emit_data(pvm_rd | (pvm_rs1 << 4));
                self.emit_var_imm(imm);
                return Ok(());
            }

            // Special case: SUB rd, rs1, load_rd → neg_add_imm rd, rs1, -imm
            // SUB is not commutative, but if rs2 is the loaded register:
            // rd = rs1 - imm = rs1 + (-imm)
            if (funct7, funct3) == (0x20, 0) && rs2 == load_rd && rs1 != load_rd {
                let neg_imm = (-(load_val as i32) as i64) as i32;
                // Use add_imm with negated immediate (avoids neg_add_imm)
                let pvm_opcode = if self.is_64bit { 149 } else { 131 }; // add_imm
                self.code.truncate(undo_pos);
                self.bitmask.truncate(undo_pos);
                self.address_map.insert(addr, undo_pos as u32);
                let pvm_rd = self.require_reg(rd)?;
                let pvm_rs1 = self.require_reg(rs1)?;
                self.emit_inst(pvm_opcode);
                self.emit_data(pvm_rd | (pvm_rs1 << 4));
                self.emit_var_imm(neg_imm);
                return Ok(());
            }
        }
        // Couldn't fuse — load_imm is already emitted, just proceed normally

        // Handle x0 as source: PVM reg 0 = RA, not zero.
        if rs1 == 0 && funct7 == 0 && funct3 == 0 {
            // add rd, x0, rs2 → mv rd, rs2
            let pvm_rd = self.require_reg(rd)?;
            let pvm_rs2 = self.require_reg(rs2)?;
            self.emit_inst(100); // move_reg
            self.emit_data(pvm_rd | (pvm_rs2 << 4));
            return Ok(());
        }
        if rs2 == 0 && funct7 == 0 && funct3 == 0 {
            // add rd, rs1, x0 → mv rd, rs1
            let pvm_rd = self.require_reg(rd)?;
            let pvm_rs1 = self.require_reg(rs1)?;
            self.emit_inst(100); // move_reg
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
            self.emit_var_imm(0);
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
                    self.emit_inst(100); // move_reg
                    self.emit_data(pvm_rd | (pvm_rs2 << 4));
                    return Ok(());
                }
                (0, 7) => {
                    // AND rd, x0, rs2 → 0
                    return self.emit_load_imm(rd, 0);
                }
                (0, 3) => {
                    // SLTU rd, x0, rs2 → snez rd, rs2
                    // When rd == rs2, skip the load_imm to avoid clobbering
                    // the value before the conditional check.
                    if pvm_rd != pvm_rs2 {
                        self.emit_load_imm(rd, 0)?;
                    }
                    self.emit_inst(148); // cmov_nz_imm: if rs2 != 0 then rd = imm
                    self.emit_data(pvm_rd | (pvm_rs2 << 4));
                    self.emit_var_imm(1);
                    return Ok(());
                }
                (1, _) => {
                    // M extension with x0 → result is 0
                    return self.emit_load_imm(rd, 0);
                }
                _ => {
                    return Err(TranspileError::UnsupportedInstruction {
                        offset: addr as usize,
                        detail: format!(
                            "unhandled x0-as-rs1 op: funct7={funct7:#x} funct3={funct3}"
                        ),
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
                    self.emit_var_imm(0);
                    return Ok(());
                }
                (0x20, 0) | (0, 4) | (0, 6) => {
                    // SUB/XOR/OR rd, rs1, x0 → rs1 op 0 = rs1 → move
                    self.emit_inst(100); // move_reg
                    self.emit_data(pvm_rd | (pvm_rs1 << 4));
                    return Ok(());
                }
                (0, 7) => {
                    // AND rd, rs1, x0 → 0
                    return self.emit_load_imm(rd, 0);
                }
                (0, 1) | (0, 5) | (0x20, 5) => {
                    // SLL/SRL/SRA rd, rs1, x0 → shift by 0 = rs1 → move
                    self.emit_inst(100); // move_reg
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
                        detail: format!(
                            "unhandled x0-as-rs2 op: funct7={funct7:#x} funct3={funct3}"
                        ),
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
                0 => {
                    if self.is_64bit {
                        202
                    } else {
                        192
                    }
                } // MUL
                1 => 213, // MULH → mul_upper_ss (always 64-bit, gives upper bits)
                2 => 215, // MULHSU → mul_upper_su
                3 => 214, // MULHU → mul_upper_uu
                4 => {
                    if self.is_64bit {
                        204
                    } else {
                        194
                    }
                } // DIV
                5 => {
                    if self.is_64bit {
                        203
                    } else {
                        193
                    }
                } // DIVU
                6 => {
                    if self.is_64bit {
                        206
                    } else {
                        196
                    }
                } // REM
                7 => {
                    if self.is_64bit {
                        205
                    } else {
                        195
                    }
                } // REMU
                _ => unreachable!(),
            }
        } else if funct7 == 0x20 {
            match funct3 {
                0 => {
                    if self.is_64bit {
                        201
                    } else {
                        191
                    }
                } // SUB
                5 => {
                    if self.is_64bit {
                        209
                    } else {
                        199
                    }
                } // SRA
                7 | 6 | 4 => {
                    // Zbb ANDN/ORN/XNOR: rd = rs1 OP ~rs2
                    if rd == rs1 && rd == rs2 {
                        return self.emit_load_imm(rd, if funct3 == 7 { 0 } else { -1i64 });
                    }
                    let alu: u8 = match funct3 {
                        7 => 210,
                        6 => 212,
                        _ => 211,
                    };
                    if rd != rs1 {
                        // use rd as temp for ~rs2
                        self.emit_inst(133);
                        self.emit_data(pvm_rd | (pvm_rs2 << 4));
                        self.emit_var_imm(-1);
                        self.emit_inst(alu);
                        self.emit_data(pvm_rs1 | (pvm_rd << 4));
                        self.emit_data(pvm_rd);
                    } else {
                        // rd==rs1: NOT rs2 in-place, OP, restore
                        self.emit_inst(133);
                        self.emit_data(pvm_rs2 | (pvm_rs2 << 4));
                        self.emit_var_imm(-1);
                        self.emit_inst(alu);
                        self.emit_data(pvm_rd | (pvm_rs2 << 4));
                        self.emit_data(pvm_rd);
                        self.emit_inst(133);
                        self.emit_data(pvm_rs2 | (pvm_rs2 << 4));
                        self.emit_var_imm(-1);
                    }
                    return Ok(());
                }
                _ => {
                    return Err(TranspileError::UnsupportedInstruction {
                        offset: 0,
                        detail: format!("OP funct7=0x20 funct3={}", funct3),
                    });
                }
            }
        } else if funct7 == 0x05 {
            // Zbb min/max
            match funct3 {
                4 => 229,
                5 => 230,
                6 => 227,
                7 => 228,
                _ => {
                    return Err(TranspileError::UnsupportedInstruction {
                        offset: 0,
                        detail: format!("Zbb f7=5 f3={}", funct3),
                    });
                }
            }
        } else if funct7 == 0x30 {
            // Zbb rotations — emit and return early
            let opc = match funct3 {
                1 => {
                    if self.is_64bit {
                        220
                    } else {
                        221
                    }
                }
                5 => {
                    if self.is_64bit {
                        222
                    } else {
                        223
                    }
                }
                _ => {
                    return Err(TranspileError::UnsupportedInstruction {
                        offset: 0,
                        detail: format!("Zbb f7=30 f3={}", funct3),
                    });
                }
            };
            self.emit_inst(opc);
            self.emit_data(pvm_rs1 | (pvm_rs2 << 4));
            self.emit_data(pvm_rd);
            return Ok(());
        } else if funct7 == 0 {
            match funct3 {
                0 => {
                    if self.is_64bit {
                        200
                    } else {
                        190
                    }
                } // ADD
                1 => {
                    if self.is_64bit {
                        207
                    } else {
                        197
                    }
                } // SLL
                2 => 217,
                3 => 216,
                4 => 211,
                5 => {
                    if self.is_64bit {
                        208
                    } else {
                        198
                    }
                }
                6 => 212,
                7 => 210,
                _ => unreachable!(),
            }
        } else {
            return Err(TranspileError::UnsupportedInstruction {
                offset: 0,
                detail: format!("OP funct7={:#x} funct3={}", funct7, funct3),
            });
        };

        // ThreeReg encoding: byte1 = rA | (rB << 4), byte2 = rD
        self.emit_inst(pvm_opcode);
        self.emit_data(pvm_rs1 | (pvm_rs2 << 4));
        self.emit_data(pvm_rd);

        Ok(())
    }

    fn translate_op_imm_32(
        &mut self,
        funct3: u32,
        funct7: u32,
        rd: u8,
        rs1: u8,
        imm: i32,
    ) -> Result<(), TranspileError> {
        if rd == 0 {
            return Ok(());
        }
        let pvm_rd = self.require_reg(rd)?;
        let pvm_rs1 = self.require_reg(rs1)?;

        match funct3 {
            0 => {
                // ADDIW → add_imm_32
                self.emit_inst(131);
                self.emit_data(pvm_rd | (pvm_rs1 << 4));
                self.emit_var_imm(imm);
            }
            1 => {
                if funct7 == 0x30 {
                    // Zbb: clzw(rs2=0), ctzw(rs2=1), cpopw(rs2=2)
                    let rs2 = (imm & 0x1F) as u8;
                    let opc = match rs2 {
                        0 => 105,
                        1 => 107,
                        2 => 103,
                        _ => {
                            return Err(TranspileError::UnsupportedInstruction {
                                offset: 0,
                                detail: format!("Zbb-W rs2={}", rs2),
                            });
                        }
                    };
                    self.emit_inst(opc);
                    self.emit_data(pvm_rd | (pvm_rs1 << 4));
                } else {
                    // SLLIW (funct7=0x00)
                    let shamt = imm & 0x1F;
                    self.emit_inst(138);
                    self.emit_data(pvm_rd | (pvm_rs1 << 4));
                    self.emit_var_imm(shamt);
                }
            }
            5 => {
                if funct7 == 0x30 {
                    // Zbb roriw
                    let shamt = imm & 0x1F;
                    self.emit_inst(160);
                    self.emit_data(pvm_rd | (pvm_rs1 << 4));
                    self.emit_var_imm(shamt);
                } else if funct7 & 0x20 != 0 {
                    // SRAIW (funct7=0x20)
                    let shamt = imm & 0x1F;
                    self.emit_inst(140);
                    self.emit_data(pvm_rd | (pvm_rs1 << 4));
                    self.emit_var_imm(shamt);
                } else {
                    // SRLIW (funct7=0x00)
                    let shamt = imm & 0x1F;
                    self.emit_inst(139);
                    self.emit_data(pvm_rd | (pvm_rs1 << 4));
                    self.emit_var_imm(shamt);
                }
            }
            _ => {
                return Err(TranspileError::UnsupportedInstruction {
                    offset: 0,
                    detail: format!("OP-IMM-32 funct3={}", funct3),
                });
            }
        }

        Ok(())
    }

    fn translate_op_32(
        &mut self,
        funct3: u32,
        funct7: u32,
        rd: u8,
        rs1: u8,
        rs2: u8,
    ) -> Result<(), TranspileError> {
        if rd == 0 {
            return Ok(());
        }

        // Fuse load_imm + 32-bit ALU op: ADDW, MULW, SUB as negated ADD.
        if let Some((load_rd, load_val, undo_pos)) = self.pending_load_imm.take()
            && load_val >= i32::MIN as i64
            && load_val <= i32::MAX as i64
        {
            let imm = load_val as i32;
            let (fuse_base, _comm) = if rs2 == load_rd && rs1 != load_rd {
                (Some(rs1), true)
            } else if rs1 == load_rd && rs2 != load_rd && (funct7, funct3) != (0x20, 0) {
                (Some(rs2), true)
            } else {
                (None, false)
            };

            if let Some(base) = fuse_base {
                let pvm_imm_opcode = match (funct7, funct3) {
                    (0, 0) => Some(131), // ADDW → add_imm_32
                    (1, 0) => Some(135), // MULW → mul_imm_32
                    _ => None,
                };
                if let Some(pvm_opcode) = pvm_imm_opcode {
                    self.code.truncate(undo_pos);
                    self.bitmask.truncate(undo_pos);
                    let pvm_rd = self.require_reg(rd)?;
                    let pvm_base = self.require_reg(base)?;
                    self.emit_inst(pvm_opcode);
                    self.emit_data(pvm_rd | (pvm_base << 4));
                    self.emit_var_imm(imm);
                    return Ok(());
                }
            }
            // 32-bit shifts with loaded shift count → shift immediate forms.
            // SLLW/SRLW/SRAW rd, rs1, load_rd → shlo_l/shlo_r/shar_r_imm_32
            if rs2 == load_rd && matches!((funct7, funct3), (0, 1) | (0, 5) | (0x20, 5)) {
                let pvm_imm_opcode = match (funct7, funct3) {
                    (0, 1) => 138,    // SLLW → shlo_l_imm_32
                    (0, 5) => 139,    // SRLW → shlo_r_imm_32
                    (0x20, 5) => 140, // SRAW → shar_r_imm_32
                    _ => unreachable!(),
                };
                self.code.truncate(undo_pos);
                self.bitmask.truncate(undo_pos);
                let pvm_rd = self.require_reg(rd)?;
                let pvm_rs1 = self.require_reg(rs1)?;
                self.emit_inst(pvm_imm_opcode);
                self.emit_data(pvm_rd | (pvm_rs1 << 4));
                self.emit_var_imm(imm);
                return Ok(());
            }

            // SUB with loaded rs2: SUBW rd, rs1, load_rd → add_imm_32 rd, rs1, -imm
            if (funct7, funct3) == (0x20, 0) && rs2 == load_rd && rs1 != load_rd {
                let neg_imm = (-(load_val as i32) as i64) as i32;
                self.code.truncate(undo_pos);
                self.bitmask.truncate(undo_pos);
                let pvm_rd = self.require_reg(rd)?;
                let pvm_rs1 = self.require_reg(rs1)?;
                self.emit_inst(131); // add_imm_32
                self.emit_data(pvm_rd | (pvm_rs1 << 4));
                self.emit_var_imm(neg_imm);
                return Ok(());
            }
        }
        // Couldn't fuse

        // Handle x0 as source: PVM reg 0 = RA, not zero.
        if rs1 == 0 {
            let pvm_rd = self.require_reg(rd)?;
            let pvm_rs2 = self.require_reg(rs2)?;
            match (funct7, funct3) {
                (0, 0) => {
                    // ADDW rd, x0, rs2 → sext.w rd, rs2 (sign-extend lower 32 bits)
                    self.emit_inst(131); // add_imm_32
                    self.emit_data(pvm_rd | (pvm_rs2 << 4));
                    self.emit_var_imm(0);
                    return Ok(());
                }
                (0x20, 0) => {
                    // SUBW rd, x0, rs2 → negw rd, rs2
                    self.emit_inst(141); // neg_add_imm_32
                    self.emit_data(pvm_rd | (pvm_rs2 << 4));
                    self.emit_var_imm(0);
                    return Ok(());
                }
                _ => {
                    return Err(TranspileError::UnsupportedInstruction {
                        offset: 0,
                        detail: format!("OP-32 x0-as-rs1: funct7={:#x} funct3={}", funct7, funct3),
                    });
                }
            }
        }
        if rs2 == 0 {
            let pvm_rd = self.require_reg(rd)?;
            let pvm_rs1 = self.require_reg(rs1)?;
            match (funct7, funct3) {
                (0, 0) => {
                    // ADDW rd, rs1, x0 → sext.w rd, rs1
                    self.emit_inst(131); // add_imm_32
                    self.emit_data(pvm_rd | (pvm_rs1 << 4));
                    self.emit_var_imm(0);
                    return Ok(());
                }
                (0x20, 0) => {
                    // SUBW rd, rs1, x0 → sext.w rd, rs1 (subtract zero)
                    self.emit_inst(131); // add_imm_32
                    self.emit_data(pvm_rd | (pvm_rs1 << 4));
                    self.emit_var_imm(0);
                    return Ok(());
                }
                (0x04, 4) => {
                    // PACKW rd, rs1, x0 = ZEXT.H rd, rs1 (Zbb: zero-extend halfword)
                    // rd = rs1 & 0xFFFF
                    self.emit_inst(70); // and_imm
                    self.emit_data(pvm_rd | (pvm_rs1 << 4));
                    self.emit_var_imm(0xFFFF);
                    return Ok(());
                }
                _ => {
                    return Err(TranspileError::UnsupportedInstruction {
                        offset: 0,
                        detail: format!("OP-32 x0-as-rs2: funct7={:#x} funct3={}", funct7, funct3),
                    });
                }
            }
        }

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
                _ => {
                    return Err(TranspileError::UnsupportedInstruction {
                        offset: 0,
                        detail: format!("OP-32 M funct3={}", funct3),
                    });
                }
            }
        } else if funct7 == 0x20 {
            match funct3 {
                0 => 191, // SUBW → sub_32
                5 => 199, // SRAW → shar_r_32
                _ => {
                    return Err(TranspileError::UnsupportedInstruction {
                        offset: 0,
                        detail: format!("OP-32 funct7=0x20 funct3={}", funct3),
                    });
                }
            }
        } else if funct7 == 0x30 {
            // Zbb rolw/rorw
            let opc = match funct3 {
                1 => 221,
                5 => 223,
                _ => {
                    return Err(TranspileError::UnsupportedInstruction {
                        offset: 0,
                        detail: format!("OP-32 f7=30 f3={}", funct3),
                    });
                }
            };
            self.emit_inst(opc);
            self.emit_data(pvm_rs1 | (pvm_rs2 << 4));
            self.emit_data(pvm_rd);
            return Ok(());
        } else if funct7 == 0x04 && funct3 == 4 {
            // Zbb zext.h
            self.emit_inst(110);
            self.emit_data(pvm_rd | (pvm_rs1 << 4));
            return Ok(());
        } else if funct7 == 0 {
            match funct3 {
                0 => 190, // ADDW → add_32
                1 => 197, // SLLW → shlo_l_32
                5 => 198, // SRLW → shlo_r_32
                _ => {
                    return Err(TranspileError::UnsupportedInstruction {
                        offset: 0,
                        detail: format!("OP-32 funct3={}", funct3),
                    });
                }
            }
        } else {
            return Err(TranspileError::UnsupportedInstruction {
                offset: 0,
                detail: format!("OP-32 funct7={:#x} funct3={}", funct7, funct3),
            });
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

    /// Emit a signed immediate using the minimum byte width.
    /// PVM instruction categories OneRegOneImm and TwoRegOneImm derive
    /// immediate length from the instruction skip distance, so shorter
    /// encodings are automatically decoded correctly via sign extension.
    /// Compute the number of bytes needed for a variable-length immediate.
    fn var_imm_byte_count(imm: i32) -> usize {
        if imm == 0 {
            0
        } else if (-128..=127).contains(&imm) {
            1
        } else if (-32768..=32767).contains(&imm) {
            2
        } else {
            4
        }
    }

    pub(crate) fn emit_var_imm(&mut self, imm: i32) {
        if imm == 0 {
            // Zero bytes — decoder gets lx=0, sign_extend(0, 0) = 0
        } else if (-128..=127).contains(&imm) {
            self.emit_data(imm as i8 as u8);
        } else if (-32768..=32767).contains(&imm) {
            let bytes = (imm as i16).to_le_bytes();
            for b in &bytes {
                self.emit_data(*b);
            }
        } else {
            let bytes = imm.to_le_bytes();
            for b in &bytes {
                self.emit_data(*b);
            }
        }
    }

    pub(crate) fn emit_load_imm(&mut self, rd: u8, imm: i64) -> Result<(), TranspileError> {
        if rd == 0 {
            return Ok(());
        } // Write to zero register is nop
        let pvm_rd = self.require_reg(rd)?;

        if imm >= i32::MIN as i64 && imm <= i32::MAX as i64 {
            // load_imm (opcode 51)
            self.emit_inst(51);
            self.emit_data(pvm_rd);
            self.emit_var_imm(imm as i32);
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

    /// Emit load_imm_jump: fuse load_imm + jump into a single PVM instruction.
    /// Opcode 80: OneRegImmOffset format — sets register and jumps in one step.
    /// Saves one instruction (and one gas block boundary) per function call.
    fn emit_load_imm_jump(&mut self, rd: u8, imm: i64, target: u64) -> Result<(), TranspileError> {
        let pvm_rd = self.require_reg(rd)?;

        let inst_pc = self.code.len() as u32;
        self.emit_inst(80); // load_imm_jump

        // OneRegImmOffset encoding: reg_byte (rd + lX), then imm bytes, then offset bytes.
        // Use variable-length encoding for the immediate.
        let imm_len = Self::var_imm_byte_count(imm as i32);
        let reg_byte = pvm_rd | ((imm_len as u8) << 4);
        self.emit_data(reg_byte);
        self.emit_var_imm(imm as i32);

        // Offset (4 bytes, patched by fixup)
        let fixup_pos = self.code.len();
        self.fixups.push((fixup_pos, target, 4));
        self.fixup_pcs.insert(fixup_pos, inst_pc);
        self.emit_imm32(0); // placeholder offset
        Ok(())
    }

    /// Emit a function call: load return address into rd and jump to target.
    /// Uses load_imm_jump (opcode 80) to fuse into a single PVM instruction,
    /// saving one instruction per call site.
    pub(crate) fn emit_call(
        &mut self,
        rd: u8,
        rv_ret_addr: u64,
        target: u64,
    ) -> Result<(), TranspileError> {
        if rd == 0 {
            // No return address needed — just jump
            self.emit_jump(target);
            return Ok(());
        }
        let jt_idx = self.jump_table.len();
        self.jump_table.push(0); // placeholder
        self.return_fixups.push((jt_idx, rv_ret_addr));
        let jt_addr = ((jt_idx + 1) * 2) as i64;
        self.emit_load_imm_jump(rd, jt_addr, target)
    }

    pub(crate) fn emit_ecalli(&mut self, id: u32) {
        self.emit_inst(10);
        self.emit_var_imm(id as i32);
    }

    /// Emit PVM ecall (opcode 3, NoArgs). Management ops + dynamic CALL.
    /// φ[11]=op, φ[12]=subject|object — all operands in registers.
    pub(crate) fn emit_ecall(&mut self) {
        self.emit_inst(3);
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
    /// Check whether an address falls within any RISC-V code section.
    pub fn is_code_addr(&self, addr: u64) -> bool {
        self.code_ranges
            .iter()
            .any(|(lo, hi)| addr >= *lo && addr < *hi)
    }

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
                let inst_pc = self
                    .fixup_pcs
                    .get(&pvm_offset)
                    .copied()
                    .unwrap_or(pvm_offset as u32 - 1);
                let relative = (pvm_target as i64 - inst_pc as i64) as i32;
                let bytes = relative.to_le_bytes();
                self.code[pvm_offset..pvm_offset + size as usize]
                    .copy_from_slice(&bytes[..size as usize]);
            } else {
                tracing::warn!(
                    "unresolved fixup: rv_target={:#x}, pvm_offset={}",
                    rv_target,
                    pvm_offset
                );
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
    if imm20 != 0 {
        (imm | 0xFFE00000) as i32
    } else {
        imm as i32
    }
}

fn decode_b_imm(inst: u32) -> i32 {
    let imm12 = (inst >> 31) & 1;
    let imm10_5 = (inst >> 25) & 0x3F;
    let imm4_1 = (inst >> 8) & 0xF;
    let imm11 = (inst >> 7) & 1;
    let imm = (imm12 << 12) | (imm11 << 11) | (imm10_5 << 5) | (imm4_1 << 1);
    if imm12 != 0 {
        (imm | 0xFFFFE000) as i32
    } else {
        imm as i32
    }
}

fn decode_s_imm(inst: u32) -> i32 {
    let imm11_5 = (inst >> 25) & 0x7F;
    let imm4_0 = (inst >> 7) & 0x1F;
    let imm = (imm11_5 << 5) | imm4_0;
    if imm11_5 & 0x40 != 0 {
        (imm | 0xFFFFF000) as i32
    } else {
        imm as i32
    }
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

    #[test]
    fn test_decode_j_imm_negative() {
        // JAL with negative offset (backward jump)
        // imm[20|10:1|11|19:12] = all 1s → -2
        // Encoding: bit31=1, bits[30:21]=0x3FF, bit20=1, bits[19:12]=0xFF
        let inst = 0xFFFFF06F; // JAL x0, -2 (the standard encoding for JAL x0, -2)
        let imm = decode_j_imm(inst);
        assert!(imm < 0, "negative offset should be negative");
        assert_eq!(imm, -2);
    }

    #[test]
    fn test_decode_j_imm_max_positive() {
        // JAL with maximum positive offset: imm[20]=0, rest=max
        // imm = 0x0FFFFE (1048574)
        let inst = 0x7FFFF06F; // bit31=0, bits[30:21]=0x3FF, bit20=1, bits[19:12]=0xFF
        let imm = decode_j_imm(inst);
        assert!(imm > 0);
    }

    #[test]
    fn test_decode_b_imm_zero() {
        // BEQ x0, x0, 0
        assert_eq!(decode_b_imm(0x00000063), 0);
    }

    #[test]
    fn test_decode_b_imm_positive() {
        // BEQ with offset +8: imm[12|10:5]=0, imm[4:1]=0100, imm[11]=0
        // inst[11:8]=0100 → imm[4:1]=4, shift by 1 → offset=8
        let inst = 0x00000463; // BEQ x0, x0, +8
        let imm = decode_b_imm(inst);
        assert_eq!(imm, 8);
    }

    #[test]
    fn test_decode_b_imm_negative() {
        // BEQ with negative offset
        // All bits set → -2
        let inst = 0xFE000FE3; // BEQ x0, x0, -2
        let imm = decode_b_imm(inst);
        assert_eq!(imm, -2);
    }

    #[test]
    fn test_decode_s_imm_zero() {
        // SD x0, 0(x0): imm=0
        assert_eq!(decode_s_imm(0x00003023), 0);
    }

    #[test]
    fn test_decode_s_imm_positive() {
        // SD x0, 8(x0): imm[11:5]=0, imm[4:0]=01000
        let inst = 0x00003423; // imm4_0 = 8 (at bits[11:7] = 01000)
        let imm = decode_s_imm(inst);
        assert_eq!(imm, 8);
    }

    #[test]
    fn test_decode_s_imm_negative() {
        // SD x0, -8(x0): imm = -8 = 0xFFF8
        // imm[11:5] = 1111111, imm[4:0] = 11000
        let inst = 0xFE003C23; // SD x0, -8(x0)
        let imm = decode_s_imm(inst);
        assert_eq!(imm, -8);
    }

    #[test]
    fn test_register_mapping_all_a_regs() {
        // a0-a5 map to PVM registers 7-12
        for (rv, pvm) in [(10, 7), (11, 8), (12, 9), (13, 10), (14, 11), (15, 12)] {
            assert_eq!(
                map_register(rv).unwrap(),
                Some(pvm),
                "rv{rv} should map to φ[{pvm}]"
            );
        }
    }

    #[test]
    fn test_register_mapping_s_regs() {
        // s0-s1 map to PVM registers 5-6
        assert_eq!(map_register(8).unwrap(), Some(5)); // s0
        assert_eq!(map_register(9).unwrap(), Some(6)); // s1
    }

    #[test]
    fn test_register_mapping_unmapped() {
        // tp(4), t3-t6(28-31) are unmapped → error
        assert!(map_register(4).is_err()); // tp
        assert!(map_register(28).is_err()); // t3
    }
}
