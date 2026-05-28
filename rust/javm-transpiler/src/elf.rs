//! ELF parsing helpers shared by the PVM2 linker.
//!
//! Reads section headers + relocations from a 64-bit rv64em ELF and
//! returns a `LinkedElf` with the data the linker needs to lay out
//! code/data and resolve relocations.

use crate::TranspileError;
use std::collections::HashMap;

/// RISC-V relocation types we care about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelocType {
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
pub(crate) struct LinkedElf {
    /// All code sections: (file_offset, vaddr, data)
    pub(crate) code_sections: Vec<(u64, u64, Vec<u8>)>,
    /// RO data blob.
    pub(crate) ro_data: Vec<u8>,
    /// RW data blob.
    pub(crate) rw_data: Vec<u8>,
    /// Stack size in bytes (= ro_base, so RO data is at the right PVM address)
    pub(crate) stack_size: u32,
    /// Heap pages
    pub(crate) heap_pages: u32,
    /// PCREL_HI20: AUIPC instruction vaddr → resolved data address.
    pub(crate) hi20_targets: HashMap<u64, u64>,
    /// PCREL_LO12: instruction vaddr → resolved target address (looked up from paired HI20).
    pub(crate) lo12_targets: HashMap<u64, u64>,
    /// PCREL_LO12: instruction vaddr → its anchor AUIPC (HI20) instruction
    /// vaddr. The LO12's immediate is relative to the *AUIPC's* PC (RISC-V
    /// ABI), so re-encoding a kept code-relative pair after fallthrough
    /// injection needs the anchor's post-injection offset, not the LO12's.
    pub(crate) lo12_to_hi20: HashMap<u64, u64>,
    /// CALL_PLT: AUIPC instruction vaddr → target function RISC-V vaddr.
    pub(crate) call_targets: HashMap<u64, u64>,
    /// Absolute code pointers in data sections: (data_vaddr, target_code_vaddr, entry_size).
    pub(crate) abs_code_ptrs: Vec<(u64, u64, u8)>,
    /// SUB32 relocations: (data_vaddr, subtracted_addr).
    pub(crate) sub32_relocs: Vec<(u64, u64)>,
    /// Code section address ranges for detecting code pointers.
    pub(crate) code_ranges: Vec<(u64, u64)>,
}

/// Locate every section header with the given name and return their
/// bytes, ordered by ELF virtual address. Multiple headers can share a
/// name when LLD doesn't coalesce input sections.
pub(crate) fn find_all_section_bytes<'a>(
    elf_data: &'a [u8],
    section_name: &str,
) -> Result<Vec<&'a [u8]>, TranspileError> {
    if elf_data.len() < 64 || elf_data[0..4] != [0x7F, b'E', b'L', b'F'] {
        return Err(TranspileError::ElfParse("not an ELF file".into()));
    }
    if elf_data[4] != 2 {
        return Err(TranspileError::ElfParse("only 64-bit ELF supported".into()));
    }
    let e_shoff = u64::from_le_bytes(elf_data[40..48].try_into().unwrap()) as usize;
    let e_shentsize = u16::from_le_bytes(elf_data[58..60].try_into().unwrap()) as usize;
    let e_shnum = u16::from_le_bytes(elf_data[60..62].try_into().unwrap()) as usize;
    let e_shstrndx = u16::from_le_bytes(elf_data[62..64].try_into().unwrap()) as usize;

    let strtab = {
        let sh = e_shoff + e_shstrndx * e_shentsize;
        let off = u64::from_le_bytes(elf_data[sh + 24..sh + 32].try_into().unwrap()) as usize;
        let sz = u64::from_le_bytes(elf_data[sh + 32..sh + 40].try_into().unwrap()) as usize;
        &elf_data[off..off + sz]
    };

    let mut hits: Vec<(u64, &[u8])> = Vec::new();
    for i in 0..e_shnum {
        let sh = e_shoff + i * e_shentsize;
        if sh + e_shentsize > elf_data.len() {
            break;
        }
        let name_off = u32::from_le_bytes(elf_data[sh..sh + 4].try_into().unwrap()) as usize;
        let addr = u64::from_le_bytes(elf_data[sh + 16..sh + 24].try_into().unwrap());
        let file_off = u64::from_le_bytes(elf_data[sh + 24..sh + 32].try_into().unwrap()) as usize;
        let size = u64::from_le_bytes(elf_data[sh + 32..sh + 40].try_into().unwrap()) as usize;
        let name = if name_off < strtab.len() {
            let end = strtab[name_off..].iter().position(|&b| b == 0).unwrap_or(0);
            std::str::from_utf8(&strtab[name_off..name_off + end]).unwrap_or("")
        } else {
            ""
        };
        if name == section_name && file_off + size <= elf_data.len() {
            hits.push((addr, &elf_data[file_off..file_off + size]));
        }
    }
    hits.sort_by_key(|&(addr, _)| addr);
    Ok(hits.into_iter().map(|(_, bytes)| bytes).collect())
}

/// Parse ELF with full relocation info.
pub(crate) fn parse_linked_elf(data: &[u8]) -> Result<LinkedElf, TranspileError> {
    if data.len() < 64 || data[0..4] != [0x7F, b'E', b'L', b'F'] {
        return Err(TranspileError::ElfParse("not an ELF file".into()));
    }

    match data[4] {
        2 => {}
        1 => {
            return Err(TranspileError::ElfParse(
                "linker requires 64-bit ELF (rv64em)".into(),
            ));
        }
        _ => return Err(TranspileError::ElfParse("unsupported ELF class".into())),
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
    if let Some(si) = symtab_idx {
        let s = &sections[si];
        let sym_strtab = {
            let ss = &sections[s.link];
            &data[ss.file_off..ss.file_off + ss.size]
        };
        let count = s.size / 24;
        for j in 0..count {
            let off = s.file_off + j * 24;
            if off + 24 > data.len() {
                break;
            }
            let st_name = u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
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
        }
    }

    // Compute PVM memory layout
    let ro_min = ro_sections.iter().map(|(a, _, _)| *a).min().unwrap_or(0);
    let ro_max = ro_sections
        .iter()
        .map(|(a, sz, _)| *a + *sz as u64)
        .max()
        .unwrap_or(0);

    let page_size: u64 = 4096;
    let stack_size = if ro_min > 0 {
        (ro_min / page_size) * page_size
    } else {
        4 * page_size
    };

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

    let mut hi20_targets: HashMap<u64, u64> = HashMap::new();
    let mut lo12_targets: HashMap<u64, u64> = HashMap::new();
    let mut lo12_to_hi20: HashMap<u64, u64> = HashMap::new();
    let mut call_targets: HashMap<u64, u64> = HashMap::new();

    let mut lo12_entries: Vec<(u64, u64)> = Vec::new();
    let mut abs64_relocs: Vec<(u64, u64, u8)> = Vec::new();
    let mut sub32_relocs: Vec<(u64, u64)> = Vec::new();
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
                    sub32_relocs.push((r_offset, target_addr));
                }
                RelocType::CallPlt => {
                    call_targets.insert(r_offset, target_addr);
                }
                RelocType::PcrelHi20 => {
                    hi20_targets.insert(r_offset, target_addr);
                }
                RelocType::PcrelLo12I | RelocType::PcrelLo12S => {
                    lo12_entries.push((r_offset, sym_value));
                }
            }
        }
    }

    for (lo12_addr, hi20_addr) in lo12_entries {
        if let Some(&data_addr) = hi20_targets.get(&hi20_addr) {
            lo12_targets.insert(lo12_addr, data_addr);
            lo12_to_hi20.insert(lo12_addr, hi20_addr);
        }
    }

    let heap_pages = 16u32; // 64KB heap
    let _ = rw_pvm_base;

    Ok(LinkedElf {
        code_sections,
        ro_data,
        rw_data,
        stack_size: stack_size as u32,
        heap_pages,
        hi20_targets,
        lo12_targets,
        lo12_to_hi20,
        call_targets,
        abs_code_ptrs: abs64_relocs,
        sub32_relocs,
        code_ranges,
    })
}
