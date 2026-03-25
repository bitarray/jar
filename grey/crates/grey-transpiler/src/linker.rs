//! Linker-based RISC-V ELF to PVM transpilation.
//!
//! Unlike the basic `transpile_elf`, this module processes ELF relocations
//! to correctly handle data references in code. This is required for
//! real-world programs (like k256 crypto) that reference .rodata constants.
//!
//! Approach:
//! 1. Parse ELF sections and relocations
//! 2. Compute PVM memory layout (stack, ro_data, rw_data addresses)
//! 3. Build a relocation map: code_offset → resolved_address
//! 4. Translate RISC-V instructions, using relocation info to replace
//!    AUIPC+LO12 pairs with direct load_imm of the final PVM address

use std::collections::HashMap;
use crate::TranspileError;
use crate::riscv::TranslationContext;
use crate::emitter;

/// RISC-V relocation types we care about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelocType {
    /// R_RISCV_CALL_PLT (19): AUIPC+JALR pair for function calls
    CallPlt,
    /// R_RISCV_PCREL_HI20 (23): Upper 20 bits of PC-relative address (AUIPC)
    PcrelHi20,
    /// R_RISCV_PCREL_LO12_I (24): Lower 12 bits, I-type (load/addi)
    PcrelLo12I,
    /// R_RISCV_PCREL_LO12_S (25): Lower 12 bits, S-type (store)
    PcrelLo12S,
}

impl RelocType {
    fn from_raw(r: u32) -> Option<Self> {
        match r {
            19 => Some(Self::CallPlt),
            23 => Some(Self::PcrelHi20),
            24 => Some(Self::PcrelLo12I),
            25 => Some(Self::PcrelLo12S),
            _ => None,
        }
    }
}


/// Parsed ELF with relocation info for linking.
struct LinkedElf {
    is_64bit: bool,
    /// All code sections: (file_offset, vaddr, data)
    code_sections: Vec<(u64, u64, Vec<u8>)>,
    /// RO data blob and its PVM base address
    ro_data: Vec<u8>,
    _ro_base: u64,
    /// RW data blob and its PVM base address
    rw_data: Vec<u8>,
    _rw_base: u64,
    /// Stack size (= ro_base, so RO data is at the right PVM address)
    stack_size: u32,
    /// Heap pages
    heap_pages: u16,
    /// PCREL_HI20: AUIPC instruction vaddr → resolved data address.
    /// The AUIPC itself should emit load_imm with this address.
    hi20_targets: HashMap<u64, u64>,
    /// PCREL_LO12: instruction vaddr → resolved data address (looked up from paired HI20).
    /// These instructions should use the already-loaded address (from AUIPC/load_imm).
    lo12_targets: HashMap<u64, u64>,
    /// CALL_PLT: AUIPC instruction vaddr → target function RISC-V vaddr.
    call_targets: HashMap<u64, u64>,
    /// Symbols
    symbols: Vec<(String, u64)>,
}

/// Transpile an rv64em ELF with relocation processing.
///
/// This is the proper linker path for real programs. It handles:
/// - AUIPC+load/add pairs (PCREL_HI20/LO12) for data references
/// - AUIPC+JALR pairs (CALL_PLT) for function calls
pub fn link_elf(elf_data: &[u8]) -> Result<Vec<u8>, TranspileError> {
    let elf = parse_linked_elf(elf_data)?;
    let mut ctx = TranslationContext::new(elf.is_64bit);

    // Translate all code sections with relocation awareness.
    // Fixups are applied once at the end (after all sections are translated)
    // so that cross-section jumps resolve correctly.
    for (_file_off, vaddr, data) in &elf.code_sections {
        translate_section_linked(&mut ctx, data, *vaddr, &elf)?;
    }
    ctx.apply_fixups();

    Ok(emitter::build_standard_program(
        &elf.ro_data,
        &elf.rw_data,
        elf.heap_pages,
        elf.stack_size,
        &ctx.code,
        &ctx.bitmask,
        &ctx.jump_table,
    ))
}

/// Transpile an rv64em ELF into a JAM service PVM blob.
///
/// A JAM service has two entry points:
/// - PC=0: refine (called via `_start` / `refine` symbol)
/// - PC=5: accumulate (called via `accumulate` symbol)
///
/// The generated PVM code has a dispatch header:
/// - Bytes 0-4: `jump <refine_code>`
/// - Bytes 5-9: `jump <accumulate_code>`
/// - Bytes 10+: translated RISC-V code
pub fn link_elf_service(elf_data: &[u8]) -> Result<Vec<u8>, TranspileError> {
    let elf = parse_linked_elf(elf_data)?;

    let refine_addr = elf.symbol_address("refine")
        .or_else(|| elf.symbol_address("_start"))
        .ok_or_else(|| TranspileError::InvalidSection(
            "no 'refine' or '_start' symbol found".into()
        ))?;

    let accumulate_addr = elf.symbol_address("accumulate")
        .ok_or_else(|| TranspileError::InvalidSection(
            "no 'accumulate' symbol found".into()
        ))?;

    let mut ctx = TranslationContext::new(elf.is_64bit);

    // Reserve 10 bytes for dispatch header (2 x jump instructions)
    let header_size = 10u32;
    for _ in 0..header_size {
        ctx.code.push(0);
        ctx.bitmask.push(0);
    }
    ctx.bitmask[0] = 1; // jump at byte 0
    ctx.bitmask[5] = 1; // jump at byte 5

    for (_file_off, vaddr, data) in &elf.code_sections {
        translate_section_linked(&mut ctx, data, *vaddr, &elf)?;
    }
    ctx.apply_fixups();

    // Resolve entry points to PVM offsets
    let refine_pvm = ctx.address_map.get(&refine_addr)
        .copied()
        .ok_or_else(|| TranspileError::InvalidSection(
            format!("refine symbol at {:#x} not in translated code", refine_addr)
        ))?;

    let accumulate_pvm = ctx.address_map.get(&accumulate_addr)
        .copied()
        .ok_or_else(|| TranspileError::InvalidSection(
            format!("accumulate symbol at {:#x} not in translated code", accumulate_addr)
        ))?;

    // Patch dispatch header: jump to refine at byte 0, jump to accumulate at byte 5
    ctx.code[0] = 40; // jump opcode
    let refine_rel = (refine_pvm as i32) - 0;
    ctx.code[1..5].copy_from_slice(&refine_rel.to_le_bytes());

    ctx.code[5] = 40; // jump opcode
    let acc_rel = (accumulate_pvm as i32) - 5;
    ctx.code[6..10].copy_from_slice(&acc_rel.to_le_bytes());

    Ok(emitter::build_standard_program(
        &elf.ro_data,
        &elf.rw_data,
        elf.heap_pages,
        elf.stack_size,
        &ctx.code,
        &ctx.bitmask,
        &ctx.jump_table,
    ))
}

impl LinkedElf {
    fn symbol_address(&self, name: &str) -> Option<u64> {
        self.symbols.iter().find(|(n, _)| n == name).map(|(_, a)| *a)
    }
}

/// Parse ELF with full relocation info.
fn parse_linked_elf(data: &[u8]) -> Result<LinkedElf, TranspileError> {
    if data.len() < 64 || data[0..4] != [0x7F, b'E', b'L', b'F'] {
        return Err(TranspileError::ElfParse("not an ELF file".into()));
    }

    let is_64bit = match data[4] {
        1 => false,
        2 => true,
        _ => return Err(TranspileError::ElfParse("unsupported ELF class".into())),
    };

    if !is_64bit {
        return Err(TranspileError::ElfParse(
            "linker requires 64-bit ELF (rv64em)".into()
        ));
    }

    // ELF64 header fields
    let e_shoff = u64::from_le_bytes(data[40..48].try_into().unwrap()) as usize;
    let e_shentsize = u16::from_le_bytes(data[58..60].try_into().unwrap()) as usize;
    let e_shnum = u16::from_le_bytes(data[60..62].try_into().unwrap()) as usize;
    let e_shstrndx = u16::from_le_bytes(data[62..64].try_into().unwrap()) as usize;

    // Section name string table
    let strtab = {
        let sh = e_shoff + e_shstrndx * e_shentsize;
        let off = u64::from_le_bytes(data[sh+24..sh+32].try_into().unwrap()) as usize;
        let sz = u64::from_le_bytes(data[sh+32..sh+40].try_into().unwrap()) as usize;
        &data[off..off+sz]
    };

    let get_name = |name_off: usize| -> &str {
        if name_off >= strtab.len() { return ""; }
        let end = strtab[name_off..].iter().position(|&b| b == 0).unwrap_or(0);
        std::str::from_utf8(&strtab[name_off..name_off+end]).unwrap_or("")
    };

    // First pass: collect section metadata
    struct SectionInfo {
        name_off: usize,
        sh_type: u32,
        flags: u64,
        addr: u64,
        file_off: usize,
        size: usize,
        link: usize,
        _info: usize,
    }

    let mut sections = Vec::with_capacity(e_shnum);
    for i in 0..e_shnum {
        let sh = e_shoff + i * e_shentsize;
        if sh + e_shentsize > data.len() { break; }
        sections.push(SectionInfo {
            name_off: u32::from_le_bytes(data[sh..sh+4].try_into().unwrap()) as usize,
            sh_type: u32::from_le_bytes(data[sh+4..sh+8].try_into().unwrap()),
            flags: u64::from_le_bytes(data[sh+8..sh+16].try_into().unwrap()),
            addr: u64::from_le_bytes(data[sh+16..sh+24].try_into().unwrap()),
            file_off: u64::from_le_bytes(data[sh+24..sh+32].try_into().unwrap()) as usize,
            size: u64::from_le_bytes(data[sh+32..sh+40].try_into().unwrap()) as usize,
            link: u32::from_le_bytes(data[sh+40..sh+44].try_into().unwrap()) as usize,
            _info: u32::from_le_bytes(data[sh+44..sh+48].try_into().unwrap()) as usize,
        });
    }

    // Collect code sections, ro sections, rw sections
    let mut code_sections = Vec::new();
    let mut ro_sections: Vec<(u64, usize, Vec<u8>)> = Vec::new();
    let mut rw_sections: Vec<(u64, usize, Option<Vec<u8>>)> = Vec::new();
    let mut rela_section_indices = Vec::new();
    let mut symtab_idx = None;

    for (i, s) in sections.iter().enumerate() {
        let name = get_name(s.name_off);
        let is_alloc = s.flags & 2 != 0;
        let is_exec = s.flags & 4 != 0;
        let is_write = s.flags & 1 != 0;

        if s.sh_type == 2 { // SYMTAB
            symtab_idx = Some(i);
        }
        if s.sh_type == 4 { // RELA
            rela_section_indices.push(i);
        }
        if !is_alloc || s.sh_type == 0 { continue; }

        if is_exec && s.file_off + s.size <= data.len() {
            code_sections.push((
                s.file_off as u64,
                s.addr,
                data[s.file_off..s.file_off + s.size].to_vec(),
            ));
        } else if !is_write && !is_exec && (name.starts_with(".rodata") || name == ".srodata") {
            if s.file_off + s.size <= data.len() {
                ro_sections.push((s.addr, s.size, data[s.file_off..s.file_off+s.size].to_vec()));
            }
        } else if is_write {
            if s.sh_type == 8 { // NOBITS (.bss)
                rw_sections.push((s.addr, s.size, None));
            } else if s.file_off + s.size <= data.len() {
                rw_sections.push((s.addr, s.size, Some(data[s.file_off..s.file_off+s.size].to_vec())));
            }
        }
    }

    // Parse symbol table
    let mut symbols_by_idx: Vec<(String, u64)> = Vec::new();
    let mut named_symbols = Vec::new();
    if let Some(si) = symtab_idx {
        let s = &sections[si];
        // Get associated string table
        let sym_strtab = {
            let ss = &sections[s.link];
            &data[ss.file_off..ss.file_off+ss.size]
        };
        // ELF64 symbol = 24 bytes
        let count = s.size / 24;
        for j in 0..count {
            let off = s.file_off + j * 24;
            if off + 24 > data.len() { break; }
            let st_name = u32::from_le_bytes(data[off..off+4].try_into().unwrap()) as usize;
            let st_info = data[off + 4];
            let st_value = u64::from_le_bytes(data[off+8..off+16].try_into().unwrap());

            let name = {
                if st_name < sym_strtab.len() {
                    let end = sym_strtab[st_name..].iter().position(|&b| b == 0).unwrap_or(0);
                    std::str::from_utf8(&sym_strtab[st_name..st_name+end]).unwrap_or("")
                } else { "" }
            };

            symbols_by_idx.push((name.to_string(), st_value));
            let st_type = st_info & 0xf;
            let st_bind = st_info >> 4;
            if (st_type == 2 || st_type == 0) && (st_bind == 1 || st_bind == 2) && st_value != 0 {
                if !name.is_empty() && !name.starts_with('$') {
                    named_symbols.push((name.to_string(), st_value));
                }
            }
        }
    }

    // Compute PVM memory layout
    // PVM linear memory: [stack: 0..s) [ro: s..s+|o|) [rw: s+P(|o|)..] [heap...]
    // We set stack_size = minimum power-of-2 page boundary that contains all ro section addrs.
    let ro_min = ro_sections.iter().map(|(a,_,_)| *a).min().unwrap_or(0);
    let ro_max = ro_sections.iter().map(|(a,sz,_)| *a + *sz as u64).max().unwrap_or(0);

    // Round ro_min down to page boundary for stack_size.
    // Minimum 4 pages (16KB) so the stack is usable even without rodata.
    let page_size: u64 = 4096;
    let stack_size = if ro_min > 0 {
        (ro_min / page_size) * page_size
    } else {
        4 * page_size
    };

    // Build ro_data blob: section data placed at (section_addr - stack_size) offset
    let ro_blob_size = if ro_max > stack_size { (ro_max - stack_size) as usize } else { 0 };
    let mut ro_data = vec![0u8; ro_blob_size];
    for (addr, sz, d) in &ro_sections {
        let off = (*addr - stack_size) as usize;
        if off + sz <= ro_data.len() {
            ro_data[off..off+sz].copy_from_slice(d);
        }
    }

    // RW data: placed after ro_data (with page rounding)
    let ro_pages = (ro_data.len() + page_size as usize - 1) / page_size as usize;
    let rw_pvm_base = stack_size + (ro_pages as u64 * page_size);
    let mut rw_data = Vec::new();
    if !rw_sections.is_empty() {
        let rw_min = rw_sections.iter().map(|(a,_,_)| *a).min().unwrap();
        let rw_max = rw_sections.iter().map(|(a,sz,_)| *a + *sz as u64).max().unwrap();
        let rw_blob_size = (rw_max - rw_pvm_base.min(rw_min)) as usize;
        rw_data = vec![0u8; rw_blob_size];
        for (addr, sz, d) in &rw_sections {
            let off = (*addr - rw_pvm_base.min(rw_min)) as usize;
            if let Some(d) = d {
                if off + sz <= rw_data.len() {
                    rw_data[off..off+sz].copy_from_slice(d);
                }
            }
        }
    }

    // Parse relocations in two passes:
    // Pass 1: collect HI20 targets and CALL_PLT targets
    // Pass 2: resolve LO12 by looking up their paired HI20
    let mut hi20_targets: HashMap<u64, u64> = HashMap::new();
    let mut lo12_targets: HashMap<u64, u64> = HashMap::new();
    let mut call_targets: HashMap<u64, u64> = HashMap::new();

    // Temporary: collect LO12 entries for pass 2
    let mut lo12_entries: Vec<(u64, u64)> = Vec::new(); // (lo12_addr, hi20_addr)

    for &ri in &rela_section_indices {
        let rs = &sections[ri];
        let count = rs.size / 24;
        for j in 0..count {
            let off = rs.file_off + j * 24;
            if off + 24 > data.len() { break; }
            let r_offset = u64::from_le_bytes(data[off..off+8].try_into().unwrap());
            let r_info = u64::from_le_bytes(data[off+8..off+16].try_into().unwrap());
            let r_addend = i64::from_le_bytes(data[off+16..off+24].try_into().unwrap());
            let r_type = (r_info & 0xFFFFFFFF) as u32;
            let r_sym = (r_info >> 32) as usize;

            let rtype = match RelocType::from_raw(r_type) {
                Some(t) => t,
                None => continue,
            };

            let sym_value = if r_sym < symbols_by_idx.len() {
                symbols_by_idx[r_sym].1
            } else { 0 };

            let target_addr = (sym_value as i64 + r_addend) as u64;

            match rtype {
                RelocType::CallPlt => {
                    call_targets.insert(r_offset, target_addr);
                }
                RelocType::PcrelHi20 => {
                    // target_addr is the resolved data/function address
                    hi20_targets.insert(r_offset, target_addr);
                }
                RelocType::PcrelLo12I | RelocType::PcrelLo12S => {
                    // sym_value is the address of the paired HI20 instruction.
                    // r_offset is the address of this LO12 instruction.
                    lo12_entries.push((r_offset, sym_value));
                }
            }
        }
    }

    // Pass 2: resolve LO12 targets by looking up paired HI20
    for (lo12_addr, hi20_addr) in lo12_entries {
        if let Some(&data_addr) = hi20_targets.get(&hi20_addr) {
            lo12_targets.insert(lo12_addr, data_addr);
        }
    }

    let heap_pages = 16u16; // 64KB heap

    Ok(LinkedElf {
        is_64bit,
        code_sections,
        ro_data,
        _ro_base: stack_size,
        rw_data,
        _rw_base: rw_pvm_base,
        stack_size: stack_size as u32,
        heap_pages,
        hi20_targets,
        lo12_targets,
        call_targets,
        symbols: named_symbols,
    })
}

/// Translate a code section with relocation awareness.
fn translate_section_linked(
    ctx: &mut TranslationContext,
    data: &[u8],
    base_addr: u64,
    elf: &LinkedElf,
) -> Result<(), TranspileError> {
    let mut offset = 0;
    while offset < data.len() {
        let rv_addr = base_addr + offset as u64;
        ctx.address_map.insert(rv_addr, ctx.code.len() as u32);

        if offset + 4 > data.len() { break; }

        let inst = u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]);

        // Skip non-instruction bytes
        if inst & 0x3 != 0x3 {
            // Compressed instruction — not supported for rv64em
            return Err(TranspileError::UnsupportedInstruction {
                offset: rv_addr as usize,
                detail: "compressed instruction in rv64em ELF".into(),
            });
        }

        let opcode = inst & 0x7f;



        // Check for relocation overrides
        if opcode == 0x17 { // AUIPC
            let rd = ((inst >> 7) & 0x1f) as u8;

            if let Some(&target_addr) = elf.call_targets.get(&rv_addr) {
                // CALL_PLT: AUIPC+JALR pair for function call
                // Peek at JALR to get link register
                if offset + 8 <= data.len() {
                    let jalr = u32::from_le_bytes([
                        data[offset+4], data[offset+5], data[offset+6], data[offset+7],
                    ]);
                    let jalr_rd = ((jalr >> 7) & 0x1f) as u8;
                    let ret_addr = rv_addr + 8;

                    // Emit return address into link register
                    ctx.emit_return_address_jt(jalr_rd, ret_addr)?;
                    // Emit jump to target
                    ctx.emit_jump(target_addr);
                    // Map the JALR address too
                    ctx.address_map.insert(rv_addr + 4, ctx.code.len() as u32);
                    offset += 8; // skip both AUIPC and JALR
                    continue;
                }
            }

            if let Some(&target_addr) = elf.hi20_targets.get(&rv_addr) {
                // PCREL_HI20: AUIPC for data reference.
                // Just load the resolved address into rd. The paired LO12 instruction
                // (which may be several instructions later) will be handled separately.
                ctx.emit_load_imm(rd, target_addr as i64)?;
                offset += 4;
                continue;
            }
        }

        // Check if this instruction has a PCREL_LO12 relocation.
        // If so, the rs1 register already contains the full resolved address
        // (loaded by the paired AUIPC/HI20 above). We need to override the
        // instruction's immediate to 0 since the address is already complete.
        if let Some(&_data_addr) = elf.lo12_targets.get(&rv_addr) {
            let rd = ((inst >> 7) & 0x1f) as u8;
            let rs1 = ((inst >> 15) & 0x1f) as u8;
            let funct3 = (inst >> 12) & 0x7;

            if opcode == 0x13 && funct3 == 0 {
                // ADDI rd, rs1, lo12 → just move rs1 to rd (address already loaded)
                if rd != rs1 && rd != 0 {
                    let pvm_src = ctx.require_reg(rs1)?;
                    let pvm_dst = ctx.require_reg(rd)?;
                    ctx.emit_inst(100); // move_reg
                    ctx.emit_data(pvm_dst | (pvm_src << 4));
                } else if rd == 0 {
                    // Write to x0 is nop
                    ctx.emit_inst(1); // fallthrough
                } else {
                    // rd == rs1: value already in place, emit nop
                    ctx.emit_inst(1); // fallthrough
                }
                offset += 4;
                continue;
            } else if opcode == 0x03 {
                // LOAD rd, lo12(rs1) → LOAD rd, 0(rs1) since rs1 already has full address
                let pvm_dst = ctx.require_reg(rd)?;
                let pvm_base = ctx.require_reg(rs1)?;
                let pvm_load_opcode = match funct3 {
                    0 => 125, 1 => 127, 2 => 129, 3 => 130,
                    4 => 124, 5 => 126, 6 => 128,
                    _ => return Err(TranspileError::UnsupportedInstruction {
                        offset: rv_addr as usize,
                        detail: format!("load funct3={}", funct3),
                    }),
                };
                ctx.emit_inst(pvm_load_opcode);
                ctx.emit_data(pvm_dst | (pvm_base << 4));
                ctx.emit_var_imm(0); // offset 0: address already resolved
                offset += 4;
                continue;
            } else if opcode == 0x23 {
                // STORE rs2, lo12(rs1) → STORE rs2, 0(rs1)
                let rs2 = ((inst >> 20) & 0x1f) as u8;
                let pvm_data = ctx.require_reg(rs2)?;
                let pvm_base = ctx.require_reg(rs1)?;
                let pvm_store_opcode = match funct3 {
                    0 => 120, 1 => 121, 2 => 122, 3 => 123,
                    _ => return Err(TranspileError::UnsupportedInstruction {
                        offset: rv_addr as usize,
                        detail: format!("store funct3={}", funct3),
                    }),
                };
                ctx.emit_inst(pvm_store_opcode);
                ctx.emit_data(pvm_data | (pvm_base << 4));
                ctx.emit_var_imm(0);
                offset += 4;
                continue;
            }
            // Fallthrough: translate normally (shouldn't happen for well-formed code)
        }

        // Normal instruction translation
        let consumed = ctx.translate_instruction(data, offset, base_addr)?;
        offset += consumed;
    }

    // Flush any pending LUI/AUIPC at section boundary
    ctx.flush_pending()?;

    Ok(())
}
