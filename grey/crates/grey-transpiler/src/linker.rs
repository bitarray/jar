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

use crate::TranspileError;
use crate::emitter;
use crate::riscv::TranslationContext;
use std::collections::HashMap;

/// RISC-V relocation types we care about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelocType {
    /// R_RISCV_32 (1): Absolute 32-bit address
    Abs32,
    /// R_RISCV_64 (2): Absolute 64-bit address
    Abs64,
    /// R_RISCV_CALL_PLT (19): AUIPC+JALR pair for function calls
    CallPlt,
    /// R_RISCV_PCREL_HI20 (23): Upper 20 bits of PC-relative address (AUIPC)
    PcrelHi20,
    /// R_RISCV_PCREL_LO12_I (24): Lower 12 bits, I-type (load/addi)
    PcrelLo12I,
    /// R_RISCV_PCREL_LO12_S (25): Lower 12 bits, S-type (store)
    PcrelLo12S,
    /// R_RISCV_ADD32 (35): Add 32-bit (paired with SUB32 for relative jump tables)
    Add32,
    /// R_RISCV_SUB32 (39): Subtract 32-bit (paired with ADD32 for relative jump tables)
    Sub32,
}

impl RelocType {
    fn from_raw(r: u32) -> Option<Self> {
        match r {
            1 => Some(Self::Abs32),
            2 => Some(Self::Abs64),
            19 => Some(Self::CallPlt),
            23 => Some(Self::PcrelHi20),
            24 => Some(Self::PcrelLo12I),
            25 => Some(Self::PcrelLo12S),
            35 => Some(Self::Add32),
            39 => Some(Self::Sub32),
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
    /// Stack size in bytes (= ro_base, so RO data is at the right PVM address)
    stack_size: u32,
    /// Heap pages
    heap_pages: u32,
    /// PCREL_HI20: AUIPC instruction vaddr → resolved data address.
    /// The AUIPC itself should emit load_imm with this address.
    hi20_targets: HashMap<u64, u64>,
    /// PCREL_LO12: instruction vaddr → resolved data address (looked up from paired HI20).
    /// These instructions should use the already-loaded address (from AUIPC/load_imm).
    lo12_targets: HashMap<u64, u64>,
    /// CALL_PLT: AUIPC instruction vaddr → target function RISC-V vaddr.
    call_targets: HashMap<u64, u64>,
    /// Absolute code pointers in data sections: (data_vaddr, target_code_vaddr, entry_size).
    /// entry_size is 4 for 32-bit or 8 for 64-bit entries.
    abs_code_ptrs: Vec<(u64, u64, u8)>,
    /// SUB32 relocations: (data_vaddr, subtracted_addr).
    /// For LLVM relative jump tables: entry = target - subtracted_addr.
    /// Combined with the resolved entry value, we can recover the target.
    sub32_relocs: Vec<(u64, u64)>,
    /// Code section address ranges for detecting code pointers.
    code_ranges: Vec<(u64, u64)>,
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

    // Rewrite absolute code pointers in data sections (LLVM switch tables, vtables).
    // Build PVM jump table entries for referenced code addresses, then replace
    // the RISC-V addresses in data with PVM djump addresses.
    let mut ro_data = elf.ro_data.clone();
    let mut rw_data = elf.rw_data.clone();

    rewrite_data_code_ptrs(&elf, &mut ctx, &mut ro_data, &mut rw_data);

    // Peephole: fuse load_imm + ALU pairs into immediate ALU forms.
    crate::peephole_fuse_load_imm_alu(&mut ctx.code, &mut ctx.bitmask, &ctx.jump_table);

    // Post-pass: ensure all PVM branch targets are basic block starts (ϖ).
    crate::ensure_branch_targets_are_block_starts(
        &mut ctx.code,
        &mut ctx.bitmask,
        &mut ctx.jump_table,
    );

    Ok(emitter::build_standard_program(
        &ro_data,
        &rw_data,
        elf.heap_pages,
        elf.heap_pages, // max_heap_pages = heap_pages (no grow_heap support by default)
        elf.stack_size / 4096,
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

    let refine_addr = elf
        .symbol_address("refine")
        .or_else(|| elf.symbol_address("_start"))
        .ok_or_else(|| {
            TranspileError::InvalidSection("no 'refine' or '_start' symbol found".into())
        })?;

    let accumulate_addr = elf
        .symbol_address("accumulate")
        .ok_or_else(|| TranspileError::InvalidSection("no 'accumulate' symbol found".into()))?;

    let mut ctx = TranslationContext::new(elf.is_64bit);
    ctx.code_ranges = elf.code_ranges.clone();

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

    let mut ro_data = elf.ro_data.clone();
    let mut rw_data = elf.rw_data.clone();
    rewrite_data_code_ptrs(&elf, &mut ctx, &mut ro_data, &mut rw_data);

    // Resolve entry points to PVM offsets BEFORE peephole/branch passes,
    // since ensure_branch_targets_are_block_starts inserts bytes and shifts
    // all offsets (invalidating address_map entries).
    let refine_pvm = ctx.address_map.get(&refine_addr).copied().ok_or_else(|| {
        TranspileError::InvalidSection(format!(
            "refine symbol at {:#x} not in translated code",
            refine_addr
        ))
    })?;

    let accumulate_pvm = ctx
        .address_map
        .get(&accumulate_addr)
        .copied()
        .ok_or_else(|| {
            TranspileError::InvalidSection(format!(
                "accumulate symbol at {:#x} not in translated code",
                accumulate_addr
            ))
        })?;

    // Patch dispatch header BEFORE the passes so the jumps are treated as
    // normal branch instructions and their offsets get adjusted automatically
    // by ensure_branch_targets_are_block_starts.
    ctx.code[0] = 40; // jump opcode
    let refine_rel = refine_pvm as i32;
    ctx.code[1..5].copy_from_slice(&refine_rel.to_le_bytes());

    ctx.code[5] = 40; // jump opcode
    let acc_rel = (accumulate_pvm as i32) - 5;
    ctx.code[6..10].copy_from_slice(&acc_rel.to_le_bytes());

    // Mark dispatch targets as instruction starts so the passes see them.
    if (refine_pvm as usize) < ctx.bitmask.len() {
        ctx.bitmask[refine_pvm as usize] = 1;
    }
    if (accumulate_pvm as usize) < ctx.bitmask.len() {
        ctx.bitmask[accumulate_pvm as usize] = 1;
    }

    crate::peephole_fuse_load_imm_alu(&mut ctx.code, &mut ctx.bitmask, &ctx.jump_table);
    crate::ensure_branch_targets_are_block_starts(
        &mut ctx.code,
        &mut ctx.bitmask,
        &mut ctx.jump_table,
    );

    Ok(emitter::build_standard_program(
        &ro_data,
        &rw_data,
        elf.heap_pages,
        elf.heap_pages, // max_heap_pages = heap_pages (no grow_heap support by default)
        elf.stack_size / 4096,
        &ctx.code,
        &ctx.bitmask,
        &ctx.jump_table,
    ))
}

/// Emit a `load_imm_64 SP, stack_top` preamble (PVM opcode 20).
/// Opcode 20 = load_imm_64: [20, reg_byte, imm0..imm7] = 10 bytes.
/// reg_byte = rD (SP = register 1).
fn emit_sp_preamble(code: &mut Vec<u8>, bitmask: &mut Vec<u8>, stack_top: u64) {
    let start = code.len();
    code.push(20); // load_imm_64 opcode
    code.push(1);  // rD = 1 (SP)
    code.extend_from_slice(&stack_top.to_le_bytes()); // 8-byte immediate
    // bitmask: instruction start at first byte, continuation for the rest
    bitmask.push(1);
    for _ in 0..9 {
        bitmask.push(0);
    }
    assert_eq!(code.len() - start, 10);
}

/// Transpile an rv64em ELF into a JAR v2 capability manifest PVM blob.
pub fn link_elf_v2(elf_data: &[u8]) -> Result<Vec<u8>, TranspileError> {
    let elf = parse_linked_elf(elf_data)?;
    let mut ctx = TranslationContext::new(elf.is_64bit);

    // Emit SP preamble: load_imm_64 SP, stack_top
    let stack_pages = elf.stack_size / 4096;
    let stack_top = stack_pages as u64 * 4096;
    emit_sp_preamble(&mut ctx.code, &mut ctx.bitmask, stack_top);

    for (_file_off, vaddr, data) in &elf.code_sections {
        translate_section_linked(&mut ctx, data, *vaddr, &elf)?;
    }
    ctx.apply_fixups();

    let mut ro_data = elf.ro_data.clone();
    let mut rw_data = elf.rw_data.clone();
    rewrite_data_code_ptrs(&elf, &mut ctx, &mut ro_data, &mut rw_data);

    crate::peephole_fuse_load_imm_alu(&mut ctx.code, &mut ctx.bitmask, &ctx.jump_table);
    crate::ensure_branch_targets_are_block_starts(
        &mut ctx.code,
        &mut ctx.bitmask,
        &mut ctx.jump_table,
    );

    Ok(emitter::build_v2_service_program(
        &ctx.code,
        &ctx.bitmask,
        &ctx.jump_table,
        &ro_data,
        &rw_data,
        stack_pages,
        elf.heap_pages,
        elf.heap_pages,
    ))
}


impl LinkedElf {
    fn symbol_address(&self, name: &str) -> Option<u64> {
        self.symbols
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, a)| *a)
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
            "linker requires 64-bit ELF (rv64em)".into(),
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
        let off = u64::from_le_bytes(data[sh + 24..sh + 32].try_into().unwrap()) as usize;
        let sz = u64::from_le_bytes(data[sh + 32..sh + 40].try_into().unwrap()) as usize;
        &data[off..off + sz]
    };

    let get_name = |name_off: usize| -> &str {
        if name_off >= strtab.len() {
            return "";
        }
        let end = strtab[name_off..].iter().position(|&b| b == 0).unwrap_or(0);
        std::str::from_utf8(&strtab[name_off..name_off + end]).unwrap_or("")
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
        if sh + e_shentsize > data.len() {
            break;
        }
        sections.push(SectionInfo {
            name_off: u32::from_le_bytes(data[sh..sh + 4].try_into().unwrap()) as usize,
            sh_type: u32::from_le_bytes(data[sh + 4..sh + 8].try_into().unwrap()),
            flags: u64::from_le_bytes(data[sh + 8..sh + 16].try_into().unwrap()),
            addr: u64::from_le_bytes(data[sh + 16..sh + 24].try_into().unwrap()),
            file_off: u64::from_le_bytes(data[sh + 24..sh + 32].try_into().unwrap()) as usize,
            size: u64::from_le_bytes(data[sh + 32..sh + 40].try_into().unwrap()) as usize,
            link: u32::from_le_bytes(data[sh + 40..sh + 44].try_into().unwrap()) as usize,
            _info: u32::from_le_bytes(data[sh + 44..sh + 48].try_into().unwrap()) as usize,
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

        if s.sh_type == 2 {
            // SYMTAB
            symtab_idx = Some(i);
        }
        if s.sh_type == 4 {
            // RELA
            rela_section_indices.push(i);
        }
        if !is_alloc || s.sh_type == 0 {
            continue;
        }

        if is_exec && s.file_off + s.size <= data.len() {
            code_sections.push((
                s.file_off as u64,
                s.addr,
                data[s.file_off..s.file_off + s.size].to_vec(),
            ));
        } else if !is_exec
            && (name.starts_with(".rodata")
                || name == ".srodata"
                || name.starts_with(".data.rel.ro"))
        {
            if s.file_off + s.size <= data.len() {
                ro_sections.push((
                    s.addr,
                    s.size,
                    data[s.file_off..s.file_off + s.size].to_vec(),
                ));
            }
        } else if is_write {
            if s.sh_type == 8 {
                // NOBITS (.bss)
                rw_sections.push((s.addr, s.size, None));
            } else if s.file_off + s.size <= data.len() {
                rw_sections.push((
                    s.addr,
                    s.size,
                    Some(data[s.file_off..s.file_off + s.size].to_vec()),
                ));
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
            &data[ss.file_off..ss.file_off + ss.size]
        };
        // ELF64 symbol = 24 bytes
        let count = s.size / 24;
        for j in 0..count {
            let off = s.file_off + j * 24;
            if off + 24 > data.len() {
                break;
            }
            let st_name = u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
            let st_info = data[off + 4];
            let st_value = u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap());

            let name = {
                if st_name < sym_strtab.len() {
                    let end = sym_strtab[st_name..]
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(0);
                    std::str::from_utf8(&sym_strtab[st_name..st_name + end]).unwrap_or("")
                } else {
                    ""
                }
            };

            symbols_by_idx.push((name.to_string(), st_value));
            let st_type = st_info & 0xf;
            let st_bind = st_info >> 4;
            if (st_type == 2 || st_type == 0)
                && (st_bind == 1 || st_bind == 2)
                && st_value != 0
                && !name.is_empty()
                && !name.starts_with('$')
            {
                named_symbols.push((name.to_string(), st_value));
            }
        }
    }

    // Compute PVM memory layout
    // PVM linear memory: [stack: 0..s) [ro: s..s+|o|) [rw: s+P(|o|)..] [heap...]
    // We set stack_size = minimum power-of-2 page boundary that contains all ro section addrs.
    let ro_min = ro_sections.iter().map(|(a, _, _)| *a).min().unwrap_or(0);
    let ro_max = ro_sections
        .iter()
        .map(|(a, sz, _)| *a + *sz as u64)
        .max()
        .unwrap_or(0);

    // Round ro_min down to page boundary for stack_size.
    // Minimum 4 pages (16KB) so the stack is usable even without rodata.
    let page_size: u64 = 4096;
    let stack_size = if ro_min > 0 {
        (ro_min / page_size) * page_size
    } else {
        4 * page_size
    };

    // Build ro_data blob: section data placed at (section_addr - stack_size) offset
    let ro_blob_size = if ro_max > stack_size {
        (ro_max - stack_size) as usize
    } else {
        0
    };
    let mut ro_data = vec![0u8; ro_blob_size];
    for (addr, sz, d) in &ro_sections {
        let off = (*addr - stack_size) as usize;
        if off + sz <= ro_data.len() {
            ro_data[off..off + sz].copy_from_slice(d);
        }
    }

    // RW data: placed after ro_data (with page rounding)
    let ro_pages = ro_data.len().div_ceil(page_size as usize);
    let rw_pvm_base = stack_size + (ro_pages as u64 * page_size);
    let mut rw_data = Vec::new();
    if !rw_sections.is_empty() {
        let rw_min = rw_sections.iter().map(|(a, _, _)| *a).min().unwrap();
        let rw_max = rw_sections
            .iter()
            .map(|(a, sz, _)| *a + *sz as u64)
            .max()
            .unwrap();
        let rw_blob_size = (rw_max - rw_pvm_base.min(rw_min)) as usize;
        rw_data = vec![0u8; rw_blob_size];
        for (addr, sz, d) in &rw_sections {
            let off = (*addr - rw_pvm_base.min(rw_min)) as usize;
            if let Some(d) = d
                && off + sz <= rw_data.len()
            {
                rw_data[off..off + sz].copy_from_slice(d);
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
    let mut abs64_relocs: Vec<(u64, u64, u8)> = Vec::new(); // (offset, target, entry_size)
    let mut sub32_relocs: Vec<(u64, u64)> = Vec::new();
    // Code address ranges for detecting code pointers
    let code_ranges: Vec<(u64, u64)> = code_sections
        .iter()
        .map(|(_, vaddr, data)| (*vaddr, *vaddr + data.len() as u64))
        .collect();

    for &ri in &rela_section_indices {
        let rs = &sections[ri];
        let count = rs.size / 24;
        for j in 0..count {
            let off = rs.file_off + j * 24;
            if off + 24 > data.len() {
                break;
            }
            let r_offset = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
            let r_info = u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap());
            let r_addend = i64::from_le_bytes(data[off + 16..off + 24].try_into().unwrap());
            let r_type = (r_info & 0xFFFFFFFF) as u32;
            let r_sym = (r_info >> 32) as usize;

            let rtype = match RelocType::from_raw(r_type) {
                Some(t) => t,
                None => continue,
            };

            let sym_value = if r_sym < symbols_by_idx.len() {
                symbols_by_idx[r_sym].1
            } else {
                0
            };

            let target_addr = (sym_value as i64 + r_addend) as u64;

            match rtype {
                RelocType::Abs32 => {
                    let is_code_ptr = code_ranges
                        .iter()
                        .any(|(lo, hi)| target_addr >= *lo && target_addr < *hi);
                    if is_code_ptr {
                        abs64_relocs.push((r_offset, target_addr, 4));
                    }
                }
                RelocType::Abs64 => {
                    let is_code_ptr = code_ranges
                        .iter()
                        .any(|(lo, hi)| target_addr >= *lo && target_addr < *hi);
                    if is_code_ptr {
                        abs64_relocs.push((r_offset, target_addr, 8));
                    }
                }
                RelocType::Add32 => {
                    let is_code_ptr = code_ranges
                        .iter()
                        .any(|(lo, hi)| target_addr >= *lo && target_addr < *hi);
                    if is_code_ptr {
                        abs64_relocs.push((r_offset, target_addr, 4));
                    }
                }
                RelocType::Sub32 => {
                    // R_RISCV_SUB32: the subtracted address (typically table base).
                    sub32_relocs.push((r_offset, target_addr));
                }
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

    let heap_pages = 16u32; // 64KB heap

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
        abs_code_ptrs: abs64_relocs,
        sub32_relocs,
        code_ranges,
        symbols: named_symbols,
    })
}

/// Translate a code section with relocation awareness.
/// Rewrite code pointers in data sections (LLVM switch/jump tables, vtables).
///
/// Detects code pointers via:
/// 1. R_RISCV_32/64 absolute relocations targeting code sections
/// 2. R_RISCV_SUB32 relocations (relative jump table entries: value = target - table_base)
/// 3. Heuristic scan for 8-byte values in rodata that match code addresses
///
/// Creates PVM jump table entries for each target and rewrites the data
/// so that the loaded values are valid PVM djump addresses.
fn rewrite_data_code_ptrs(
    elf: &LinkedElf,
    ctx: &mut TranslationContext,
    ro_data: &mut [u8],
    _rw_data: &mut [u8],
) {
    let ro_base = elf.stack_size as u64;
    let is_code_addr = |addr: u64| -> bool {
        elf.code_ranges
            .iter()
            .any(|(lo, hi)| addr >= *lo && addr < *hi)
    };

    struct Entry {
        data_vaddr: u64,
        rv_target: u64,
        size: u8,
        table_base_rv: Option<u64>,
    }
    let mut entries: Vec<Entry> = Vec::new();

    // From absolute relocations (R_RISCV_32/64/ADD32).
    // If a matching SUB32 exists at the same offset, this is a relative entry
    // (ADD32/SUB32 pair for jump tables). Use the SUB32 target as table base.
    for &(vaddr, target, size) in &elf.abs_code_ptrs {
        let table_base = elf
            .sub32_relocs
            .iter()
            .find(|(v, _)| *v == vaddr)
            .map(|(_, base)| *base);
        entries.push(Entry {
            data_vaddr: vaddr,
            rv_target: target,
            size,
            table_base_rv: table_base,
        });
    }

    // SUB32 entries without matching ADD32 (shouldn't happen, but handle gracefully).
    for &(data_vaddr, base_addr) in &elf.sub32_relocs {
        if entries.iter().any(|e| e.data_vaddr == data_vaddr) {
            continue; // Already handled via ADD32 pairing above
        }
        if data_vaddr >= ro_base {
            let off = (data_vaddr - ro_base) as usize;
            if off + 4 <= ro_data.len() {
                let val = i32::from_le_bytes(ro_data[off..off + 4].try_into().unwrap());
                let target = (base_addr as i64 + val as i64) as u64;
                if is_code_addr(target) {
                    entries.push(Entry {
                        data_vaddr,
                        rv_target: target,
                        size: 4,
                        table_base_rv: Some(base_addr),
                    });
                }
            }
        }
    }

    // Heuristic: 8-byte values in rodata that are code addresses
    {
        let mut off = 0;
        while off + 8 <= ro_data.len() {
            let val = u64::from_le_bytes(ro_data[off..off + 8].try_into().unwrap());
            if is_code_addr(val) {
                let vaddr = ro_base + off as u64;
                if !entries.iter().any(|e| e.data_vaddr == vaddr) {
                    entries.push(Entry {
                        data_vaddr: vaddr,
                        rv_target: val,
                        size: 8,
                        table_base_rv: None,
                    });
                }
            }
            off += 8;
        }
    }

    if entries.is_empty() {
        return;
    }

    let targets: std::collections::HashSet<u64> = entries.iter().map(|e| e.rv_target).collect();
    let rv_to_jt = ctx.build_function_pointer_map(&targets);

    for entry in &entries {
        if let Some(&jt_addr) = rv_to_jt.get(&entry.rv_target)
            && entry.data_vaddr >= ro_base
            && (entry.data_vaddr - ro_base) as usize + entry.size as usize <= ro_data.len()
        {
            let off = (entry.data_vaddr - ro_base) as usize;
            match (entry.size, entry.table_base_rv) {
                (8, _) => {
                    ro_data[off..off + 8].copy_from_slice(&(jt_addr as u64).to_le_bytes());
                }
                (4, None) => {
                    ro_data[off..off + 4].copy_from_slice(&jt_addr.to_le_bytes());
                }
                (4, Some(rv_base)) => {
                    // Relative entry: code does `lw off, table(idx); add target, off, base; jr target`.
                    // base register holds the PVM mapping of rv_base (from load_imm).
                    // new_val + pvm_base = jt_addr → new_val = jt_addr - pvm_base.
                    let pvm_base = ctx
                        .address_map
                        .get(&rv_base)
                        .copied()
                        .unwrap_or(rv_base as u32);
                    let new_val = (jt_addr as i64 - pvm_base as i64) as i32;
                    ro_data[off..off + 4].copy_from_slice(&new_val.to_le_bytes());
                }
                _ => {}
            }
        }
    }
}

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

        if offset + 4 > data.len() {
            break;
        }

        let inst = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);

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
        if opcode == 0x17 {
            // AUIPC
            let rd = ((inst >> 7) & 0x1f) as u8;

            if let Some(&target_addr) = elf.call_targets.get(&rv_addr) {
                // CALL_PLT: AUIPC+JALR pair for function call
                // Peek at JALR to get link register
                if offset + 8 <= data.len() {
                    let jalr = u32::from_le_bytes([
                        data[offset + 4],
                        data[offset + 5],
                        data[offset + 6],
                        data[offset + 7],
                    ]);
                    let jalr_rd = ((jalr >> 7) & 0x1f) as u8;
                    let ret_addr = rv_addr + 8;

                    // Fused load_imm_jump: set return address and jump in one instruction
                    ctx.emit_call(jalr_rd, ret_addr, target_addr)?;
                    // Map the JALR address too
                    ctx.address_map.insert(rv_addr + 4, ctx.code.len() as u32);
                    offset += 8; // skip both AUIPC and JALR
                    continue;
                }
            }

            if let Some(&target_addr) = elf.hi20_targets.get(&rv_addr) {
                // PCREL_HI20: AUIPC for data reference.
                // Peek ahead: if the next instruction is a paired LO12 ADDI (nop),
                // skip it and set pending_load_imm to enable cascading fusion
                // with the instruction after (load_ind, store_ind, ALU, branch).
                let next_addr = rv_addr + 4;
                if offset + 8 <= data.len()
                    && let Some(&_) = elf.lo12_targets.get(&next_addr)
                {
                    let next_inst = u32::from_le_bytes([
                        data[offset + 4],
                        data[offset + 5],
                        data[offset + 6],
                        data[offset + 7],
                    ]);
                    let next_opcode = next_inst & 0x7f;
                    let next_funct3 = (next_inst >> 12) & 0x7;
                    let next_rd = ((next_inst >> 7) & 0x1f) as u8;
                    let next_rs1 = ((next_inst >> 15) & 0x1f) as u8;

                    if next_opcode == 0x13 && next_funct3 == 0 && next_rs1 == rd {
                        // LO12 ADDI: address is already complete from HI20.
                        // Emit load_imm into the ADDI's destination register
                        // and set pending_load_imm for cascading fusion.
                        let dest = if next_rd != 0 { next_rd } else { rd };
                        let pos = ctx.code.len();
                        // If target is a code address (function pointer), load
                        // a jump table address instead of the raw RISC-V address.
                        let load_val = if ctx.is_code_addr(target_addr) {
                            let jt_idx = ctx.jump_table.len();
                            ctx.jump_table.push(0);
                            ctx.return_fixups.push((jt_idx, target_addr));
                            ((jt_idx + 1) * 2) as i64
                        } else {
                            target_addr as i64
                        };
                        ctx.emit_load_imm(dest, load_val)?;
                        ctx.pending_load_imm = Some((dest, load_val, pos));
                        ctx.address_map.insert(next_addr, ctx.code.len() as u32);
                        offset += 8; // skip both AUIPC and ADDI
                        continue;
                    }
                }

                // No paired LO12 ADDI next — emit load_imm with pending tracking.
                // This enables fusion with the next load/store/ALU/branch via
                // pending_load_imm even when the LO12 is a LOAD or STORE directly.
                let pos = ctx.code.len();
                // If target is a code address, use jump table address.
                let load_val = if ctx.is_code_addr(target_addr) {
                    let jt_idx = ctx.jump_table.len();
                    ctx.jump_table.push(0);
                    ctx.return_fixups.push((jt_idx, target_addr));
                    ((jt_idx + 1) * 2) as i64
                } else {
                    target_addr as i64
                };
                ctx.emit_load_imm(rd, load_val)?;
                ctx.pending_load_imm = Some((rd, load_val, pos));
                offset += 4;
                continue;
            }
        }

        // Check if this instruction has a PCREL_LO12 relocation.
        // If so, the rs1 register already contains the full resolved address
        // (loaded by the paired AUIPC/HI20 above). Override immediate to 0
        // and route through translate_load/translate_store to enable fusion
        // with the pending_load_imm set by the HI20 handler above.
        if let Some(&_data_addr) = elf.lo12_targets.get(&rv_addr) {
            let rd = ((inst >> 7) & 0x1f) as u8;
            let rs1 = ((inst >> 15) & 0x1f) as u8;
            let funct3 = (inst >> 12) & 0x7;

            if opcode == 0x13 && funct3 == 0 {
                // ADDI rd, rs1, lo12 → address already loaded by HI20.
                // This path is reached when the HI20 peek-ahead didn't consume
                // this ADDI (e.g., non-adjacent HI20/LO12 pair).
                if rd != rs1 && rd != 0 {
                    let pvm_src = ctx.require_reg(rs1)?;
                    let pvm_dst = ctx.require_reg(rd)?;
                    ctx.emit_inst(100); // move_reg
                    ctx.emit_data(pvm_dst | (pvm_src << 4));
                } else {
                    ctx.emit_inst(1); // fallthrough
                }
                offset += 4;
                continue;
            } else if opcode == 0x03 {
                // LOAD rd, lo12(rs1) → route through translate_load with imm=0.
                // If pending_load_imm is set (from HI20), this fuses into a
                // direct load (load_* rd, addr) — saving one instruction.
                ctx.translate_load(funct3, rd, rs1, 0)?;
                offset += 4;
                continue;
            } else if opcode == 0x23 {
                // STORE rs2, lo12(rs1) → route through translate_store with imm=0.
                let rs2 = ((inst >> 20) & 0x1f) as u8;
                ctx.translate_store(funct3, rs1, rs2, 0)?;
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
