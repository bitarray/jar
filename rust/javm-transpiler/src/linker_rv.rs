//! ELF → PVM2 (raw RV+C+custom-0 bytes) linker.
//!
//! Parallel to [`super::linker::link_elf`] but emits raw RV bytes
//! instead of PVM-translated bytes. Reuses the ELF parsing + reloc
//! collection done by [`super::linker::parse_linked_elf`].
//!
//! Pipeline:
//! 1. **Parse ELF + relocs** (shared with the PVM path).
//! 2. **Concatenate code sections**. Require a single contiguous
//!    code section for now — typical for LLD PIE output.
//! 3. **Rewrite AUIPC pairs** to LUI with absolute targets. PVM2's
//!    32-bit memory cap guarantees the absolute target fits in 32
//!    bits, so each `auipc + X` collapses to `lui + X` with no
//!    further range adjustment needed.
//! 4. **Replace standard ECALL markers**. The PVM guest convention
//!    is `csrrw x0, 0x800/0x801, x0` followed by `ecall`. Rewrite
//!    the marker slot to a canonical NOP and the `ecall` slot to a
//!    custom-0 `ecall.jar` or `ecalli`.
//! 5. **Validate**: no AUIPC remaining, no x3/x4 use, no remaining
//!    standard `ecall` / `ebreak`, no CSR / atomic / FP / privileged
//!    encodings (see `~/docs/pvm-isa/05-pvm2-rv-diff.md` §"Forbidden
//!    encodings").
//! 6. **Emit Image** with `code = raw RV bytes`, empty
//!    `packed_bitmask`, empty `jump_table`. The recompiler-side
//!    `compile_rv` consumes these directly.
//!
//! This module is **NOT WIRED INTO build-javm yet**. It lives
//! alongside the PVM path until Phase 2 flips the switch.

use crate::TranspileError;
use crate::linker::parse_linked_elf;
use crate::layout::{
    HEAP_CAP_INDEX, PVM_PAGE_SIZE, ProgramLayout, RO_CAP_INDEX, RW_CAP_INDEX, STACK_CAP_INDEX,
};
use javm_cap::SlotIdx;
use javm_cap::abi::{BARE_GAS_SLOT, BARE_QUOTA_SLOT, BARE_YIELD_CATCHER_SLOT};
use javm_cap::image::{EndpointDef, Image, InitialDataCap, MemoryMapping, PinnedCap};
use javm_cap::slot::SlotPath;
use std::collections::BTreeMap;

/// PVM register index for the RISC-V stack pointer (φ[1] = x2).
const SP_REG: u8 = 1;

/// RV opcode major (low 7 bits) for AUIPC.
const OP_AUIPC: u32 = 0b001_0111;
/// RV opcode major for LUI.
const OP_LUI: u32 = 0b011_0111;
/// RV opcode major for SYSTEM (CSR ops, ECALL, EBREAK).
const OP_SYSTEM: u32 = 0b111_0011;
/// RV opcode major for OP-IMM (addi etc.). Used by the test module.
#[cfg(test)]
const OP_OP_IMM: u32 = 0b001_0011;
/// RV opcode major for custom-0 (PVM2 host ops).
const OP_CUSTOM_0: u32 = 0b000_1011;

/// 32-bit canonical NOP: `addi x0, x0, 0`.
const NOP_BYTES: [u8; 4] = [0x13, 0x00, 0x00, 0x00];

/// PVM ecall-marker CSR numbers (custom range).
const CSR_ECALL_JAR: u32 = 0x800;
const CSR_ECALLI: u32 = 0x801;

/// Link an RV ELF into a PVM2 [`Image`] whose `code` field is raw
/// RV+C+custom-0 bytes.
pub fn link_elf_rv(elf_data: &[u8]) -> Result<Image, TranspileError> {
    let elf = parse_linked_elf(elf_data)?;

    // ---- 1. Concatenate code sections ------------------------------
    //
    // Multi-section ELFs from lld place each function in its own
    // `.text.<symbol>` section so dead-code elimination can drop
    // unused ones. To keep all reloc data working unchanged, we
    // preserve the original RV vaddr layout in the output: take the
    // minimum vaddr as the base, allocate a buffer spanning to
    // `max_vaddr + max_section_size`, and copy each section in at
    // its vaddr offset. Gaps stay zero (RVC `c.illegal`); the
    // predecoder records them as Reserved and codegen emits a panic
    // — fine because gaps shouldn't be reached during execution.
    if elf.code_sections.is_empty() {
        return Err(TranspileError::InvalidSection(
            "link_elf_rv: ELF has no code sections".into(),
        ));
    }
    let mut sections_by_vaddr: Vec<&(u64, u64, Vec<u8>)> = elf.code_sections.iter().collect();
    sections_by_vaddr.sort_by_key(|(_, v, _)| *v);
    let base_vaddr = sections_by_vaddr[0].1;
    let mut code_end_vaddr = base_vaddr;
    for (_, v, d) in &sections_by_vaddr {
        let end = v.saturating_add(d.len() as u64);
        if end > code_end_vaddr {
            code_end_vaddr = end;
        }
    }
    let span = (code_end_vaddr - base_vaddr) as usize;
    let mut code: Vec<u8> = vec![0u8; span];
    for (_, v, d) in &sections_by_vaddr {
        let off = (v - base_vaddr) as usize;
        code[off..off + d.len()].copy_from_slice(d);
    }
    let code_len = code.len();

    let vaddr_to_offset = |v: u64| -> Option<usize> {
        if v < base_vaddr {
            return None;
        }
        let o = (v - base_vaddr) as usize;
        if o >= code_len {
            None
        } else {
            Some(o)
        }
    };

    // ---- 2. AUIPC → LUI rewrite ------------------------------------
    //
    // lld emits each `auipc rd, hi20` with `hi20` chosen so that
    //   anchor := auipc_pc + sext(hi20 << 12)
    // sits within ±2 KiB of the symbol. The paired LO12 instruction
    // (load/store/addi/jalr) carries `lo12 = target - anchor`. The
    // anchor's low 12 bits inherit `auipc_pc`'s low 12 bits, so the
    // anchor is *not* 4 KiB-aligned in general.
    //
    // LUI can only load 4-KiB-aligned values, so the rewrite must
    // patch **both** the LUI immediate and the paired LO12's imm
    // field. We compute:
    //
    //   effective_target = `target` for data refs,
    //                    = `target − base_vaddr` for code refs
    //                      (so JALR/branch validation against
    //                      `valid_pc` indexes into our code buffer).
    //   new_lui  = (effective_target + 0x800) & 0xFFFFF000
    //   new_lo12 = effective_target & 0xFFF (12-bit signed)
    //
    // The +0x800 carry compensates for lo12's sign extension when
    // its top bit is set.
    let is_code_addr = |addr: u64| -> bool {
        elf.code_ranges
            .iter()
            .any(|(start, end)| addr >= *start && addr < *end)
    };

    // Compute effective_target per AUIPC reloc.
    let mut auipc_effective: BTreeMap<u64, u32> = BTreeMap::new();
    for (&v, &t) in &elf.call_targets {
        // CALL_PLT — always code.
        auipc_effective.insert(v, t.wrapping_sub(base_vaddr) as u32);
    }
    for (&v, &t) in &elf.hi20_targets {
        let eff = if is_code_addr(t) {
            t.wrapping_sub(base_vaddr) as u32
        } else {
            (t & 0xFFFFFFFF) as u32
        };
        auipc_effective.insert(v, eff);
    }

    // Rewrite AUIPC bytes → LUI.
    for (&v, &eff) in &auipc_effective {
        let off = vaddr_to_offset(v).ok_or_else(|| {
            TranspileError::InvalidSection(format!(
                "link_elf_rv: AUIPC reloc at vaddr {:#x} outside code section",
                v
            ))
        })?;
        if off + 4 > code.len() {
            return Err(TranspileError::InvalidSection(format!(
                "link_elf_rv: AUIPC reloc at vaddr {:#x} truncated by section end",
                v
            )));
        }
        let word = u32::from_le_bytes([
            code[off],
            code[off + 1],
            code[off + 2],
            code[off + 3],
        ]);
        if word & 0x7F != OP_AUIPC {
            return Err(TranspileError::InvalidSection(format!(
                "link_elf_rv: reloc at vaddr {:#x} not an AUIPC (opcode {:#x})",
                v,
                word & 0x7F
            )));
        }
        let rd = (word >> 7) & 0x1F;
        let new_hi = eff.wrapping_add(0x800) & 0xFFFFF000;
        let new_word = new_hi | (rd << 7) | OP_LUI;
        code[off..off + 4].copy_from_slice(&new_word.to_le_bytes());
    }

    // ---- 2b. Patch paired LO12 / JALR lo12 fields ------------------
    //
    // For CALL_PLT entries the paired JALR is the 4-byte slot
    // immediately after the AUIPC at vaddr `v+4`. For PCREL_LO12
    // entries each `lo_v → target` pair names a specific instruction
    // whose lo12 needs the same `effective_target & 0xFFF`.
    let lo12_from_eff = |eff: u32| -> i32 {
        // Sign-extend the low 12 bits.
        (eff as i32) << 20 >> 20
    };
    for (&call_v, &call_target) in &elf.call_targets {
        let eff = call_target.wrapping_sub(base_vaddr) as u32;
        let new_lo12 = lo12_from_eff(eff);
        let jalr_v = call_v + 4;
        if let Some(jalr_off) = vaddr_to_offset(jalr_v) {
            if jalr_off + 4 > code.len() {
                continue;
            }
            patch_imm_i(&mut code[jalr_off..jalr_off + 4], new_lo12);
        }
    }
    for (&lo_v, &target) in &elf.lo12_targets {
        let Some(lo_off) = vaddr_to_offset(lo_v) else {
            continue;
        };
        if lo_off + 4 > code.len() {
            continue;
        }
        let eff = if is_code_addr(target) {
            target.wrapping_sub(base_vaddr) as u32
        } else {
            (target & 0xFFFFFFFF) as u32
        };
        let new_lo12 = lo12_from_eff(eff);
        let opcode = code[lo_off] & 0x7F;
        match opcode {
            // I-type (load, addi, jalr) — imm in [31:20].
            0b0000011 | 0b0010011 | 0b1100111 => {
                patch_imm_i(&mut code[lo_off..lo_off + 4], new_lo12);
            }
            // S-type (store) — imm[11:5] in [31:25], imm[4:0] in [11:7].
            0b0100011 => {
                patch_imm_s(&mut code[lo_off..lo_off + 4], new_lo12);
            }
            _ => {}
        }
    }

    // ---- 3. ECALL marker replacement -------------------------------
    //
    // The guest emits the same CSRRW(0x800/0x801) + ECALL sequence as
    // the PVM path. We scan the code for those exact two-instruction
    // sequences and rewrite them in-place:
    //
    //  - CSRRW x0, 0x800, x0 → NOP, then ECALL → custom-0 ecall.jar.
    //  - CSRRW x0, 0x801, x0 → NOP, then ECALL → custom-0 ecalli imm.
    //
    // For ecalli, the host-call selector is in x5 (t0); we leave that
    // intact and use ecalli with imm=0 (the actual selector flows
    // through x5 at runtime — matching today's PVM ecalli behaviour).
    rewrite_ecall_markers(&mut code)?;

    // ---- 4. Validation pass ----------------------------------------
    //
    // Walk every 2- or 4-byte instruction boundary (RV+C self-describes
    // length via op[1:0]) and reject anything that PVM2 forbids.
    validate_pvm2(&code)?;

    // ---- 4b. Rewrite code pointers in .rodata -----------------------
    //
    // Function pointer tables (e.g. LLVM jump tables, vtables) store
    // code addresses as raw u32/u64 values in .rodata. The original
    // values are ELF vaddrs; the runtime JALR validates against
    // `valid_pc` indexed by RV byte offset (0..code.len()), so we
    // must translate each pointer.
    //
    // Sources of code pointers we recognise:
    //  - `elf.abs_code_ptrs` — explicit R_RISCV_32/64/ADD32 relocs
    //    naming code addresses. Already classified by size (4 or 8).
    //  - 8-byte values in .rodata that happen to be in code_ranges
    //    (heuristic — function pointers without an explicit reloc
    //    show up this way).
    //
    // SUB32-based relative jump tables (entries of the form
    // `target - base`) don't need rewriting: the linear shift of
    // `-base_vaddr` cancels in the differential.
    let mut ro_data_rewritten = elf.ro_data.clone();
    let ro_base = elf.stack_size as u64;
    {
        // Build a set of vaddrs handled via sub32 (so we skip them in
        // the absolute-rewrite pass).
        let sub32_data_vaddrs: std::collections::HashSet<u64> =
            elf.sub32_relocs.iter().map(|(v, _)| *v).collect();

        for &(data_vaddr, rv_target, size) in &elf.abs_code_ptrs {
            if sub32_data_vaddrs.contains(&data_vaddr) {
                // Relative entry — uniform shift preserves the diff.
                continue;
            }
            if !is_code_addr(rv_target) {
                continue;
            }
            if data_vaddr < ro_base {
                continue;
            }
            let off = (data_vaddr - ro_base) as usize;
            let new_val = rv_target.wrapping_sub(base_vaddr);
            match size {
                4 if off + 4 <= ro_data_rewritten.len() => {
                    ro_data_rewritten[off..off + 4]
                        .copy_from_slice(&(new_val as u32).to_le_bytes());
                }
                8 if off + 8 <= ro_data_rewritten.len() => {
                    ro_data_rewritten[off..off + 8]
                        .copy_from_slice(&new_val.to_le_bytes());
                }
                _ => {}
            }
        }

        // Heuristic: 8-byte values in .rodata that look like code
        // pointers but aren't covered by an explicit reloc.
        let mut off = 0;
        let already_covered: std::collections::HashSet<u64> = elf
            .abs_code_ptrs
            .iter()
            .map(|&(v, _, _)| v)
            .collect();
        while off + 8 <= ro_data_rewritten.len() {
            let val = u64::from_le_bytes(
                ro_data_rewritten[off..off + 8].try_into().unwrap(),
            );
            if is_code_addr(val) {
                let vaddr = ro_base + off as u64;
                if !already_covered.contains(&vaddr) {
                    let new_val = val.wrapping_sub(base_vaddr);
                    ro_data_rewritten[off..off + 8]
                        .copy_from_slice(&new_val.to_le_bytes());
                }
            }
            off += 8;
        }
    }

    // ---- 5. Endpoints -----------------------------------------------
    //
    // `parse_linked_elf` doesn't read `.subsoil.endpoints` itself —
    // the PVM path's `read_subsoil_endpoints` resolves fn_ptrs via
    // `TranslationContext.address_map`. For the RV path the address
    // map is identity (rv_vaddr - base == rv_byte_offset == PVM2 PC).
    let endpoints = read_subsoil_endpoints_rv(elf_data, base_vaddr, code.len())?;

    // ---- 6. Memory layout + Image construction ----------------------
    let ro_data = ro_data_rewritten;
    let rw_data = elf.rw_data.clone();

    let stack_pages = elf.stack_size / PVM_PAGE_SIZE;
    let ro_pages = (ro_data.len() as u32).div_ceil(PVM_PAGE_SIZE);
    let rw_pages = (rw_data.len() as u32).div_ceil(PVM_PAGE_SIZE);
    let layout = ProgramLayout::compute(stack_pages, ro_pages, rw_pages, elf.heap_pages);
    let stack_top = layout.stack_top();

    let mut endpoints = endpoints;
    for def in endpoints.values_mut() {
        def.initial_regs.insert(SP_REG, stack_top);
    }

    let mut memory_mappings: Vec<MemoryMapping> = Vec::new();
    let mut pinned_slots: BTreeMap<SlotIdx, PinnedCap> = BTreeMap::new();
    let mut initial_slots: BTreeMap<SlotIdx, InitialDataCap> = BTreeMap::new();
    let page_bytes = u64::from(PVM_PAGE_SIZE);

    let stack_slot = SlotIdx(u32::from(STACK_CAP_INDEX));
    let stack_size = u64::from(layout.stack.page_count) * page_bytes;
    memory_mappings.push(MemoryMapping {
        start: u64::from(layout.stack.base_page) * page_bytes,
        size: stack_size,
        source: SlotPath::root(stack_slot),
    });
    initial_slots.insert(
        stack_slot,
        InitialDataCap {
            content: Vec::new(),
            size: stack_size,
        },
    );

    if let Some(ro) = &layout.ro {
        let ro_slot = SlotIdx(u32::from(RO_CAP_INDEX));
        let size = u64::from(ro.page_count) * page_bytes;
        memory_mappings.push(MemoryMapping {
            start: u64::from(ro.base_page) * page_bytes,
            size,
            source: SlotPath::root(ro_slot),
        });
        pinned_slots.insert(
            ro_slot,
            PinnedCap::Data {
                content: ro_data,
                size,
            },
        );
    }

    if let Some(rw) = &layout.rw {
        let rw_slot = SlotIdx(u32::from(RW_CAP_INDEX));
        let size = u64::from(rw.page_count) * page_bytes;
        memory_mappings.push(MemoryMapping {
            start: u64::from(rw.base_page) * page_bytes,
            size,
            source: SlotPath::root(rw_slot),
        });
        initial_slots.insert(
            rw_slot,
            InitialDataCap {
                content: rw_data,
                size,
            },
        );
    }

    if let Some(heap) = &layout.heap {
        let heap_slot = SlotIdx(u32::from(HEAP_CAP_INDEX));
        let size = u64::from(heap.page_count) * page_bytes;
        memory_mappings.push(MemoryMapping {
            start: u64::from(heap.base_page) * page_bytes,
            size,
            source: SlotPath::root(heap_slot),
        });
        initial_slots.insert(
            heap_slot,
            InitialDataCap {
                content: Vec::new(),
                size,
            },
        );
    }

    Ok(Image {
        code,
        packed_bitmask: Vec::new(),
        jump_table: Vec::new(),
        endpoints,
        memory_mappings,
        gas_slots: vec![BARE_GAS_SLOT],
        quota_slots: vec![BARE_QUOTA_SLOT],
        pinned_slots,
        initial_slots,
        yield_marker_slot: Some(BARE_YIELD_CATCHER_SLOT),
    })
}

/// Walk `code` and rewrite ECALL-related sequences:
///
/// - `CSRRW(0x800) + ECALL` → `NOP + custom-0 ecall.jar`.
/// - `CSRRW(0x801) + ECALL` → `NOP + custom-0 ecalli imm=0`.
/// - Bare standard `ECALL` (not preceded by a marker) → custom-0
///   `ecalli imm=0`. This mirrors the legacy fallback in the PVM
///   transpiler (`riscv.rs`: "No marker (legacy) — treat as ecalli for
///   backward compat").
fn rewrite_ecall_markers(code: &mut [u8]) -> Result<(), TranspileError> {
    let n = code.len();
    let mut i = 0;
    while i + 2 <= n {
        // RVC slots have op[1:0] != 11; skip them.
        let lo = u16::from_le_bytes([code[i], code[i + 1]]);
        if lo & 0b11 != 0b11 {
            i += 2;
            continue;
        }
        if i + 4 > n {
            break;
        }
        let word = u32::from_le_bytes([code[i], code[i + 1], code[i + 2], code[i + 3]]);
        let opcode = word & 0x7F;
        let funct3 = (word >> 12) & 0x7;
        if opcode == OP_SYSTEM && funct3 == 0b001 {
            // CSRRW. Check csr field.
            let csr = (word >> 20) & 0xFFF;
            if csr == CSR_ECALL_JAR || csr == CSR_ECALLI {
                code[i..i + 4].copy_from_slice(&NOP_BYTES);
                let j = i + 4;
                if j + 4 <= n {
                    let nxt = u32::from_le_bytes([
                        code[j],
                        code[j + 1],
                        code[j + 2],
                        code[j + 3],
                    ]);
                    if is_full_length(nxt) && is_standard_ecall(nxt) {
                        let new_word = if csr == CSR_ECALL_JAR {
                            encode_custom0_ecall_jar()
                        } else {
                            encode_custom0_ecalli(0)
                        };
                        code[j..j + 4].copy_from_slice(&new_word.to_le_bytes());
                        i = j + 4;
                        continue;
                    }
                }
                // Marker without follow-up ECALL — pass through as NOP,
                // keep scanning.
                i += 4;
                continue;
            }
        }
        if opcode == OP_SYSTEM && funct3 == 0 && is_standard_ecall(word) {
            // Bare ECALL with no preceding marker → custom-0 ecalli imm=0.
            let new_word = encode_custom0_ecalli(0);
            code[i..i + 4].copy_from_slice(&new_word.to_le_bytes());
        }
        i += 4;
    }
    Ok(())
}

/// Which 5-bit fields of a 4-byte RV instruction encode registers
/// (vs. parts of an immediate). Used by [`validate_pvm2`] so we don't
/// flag S/B-type immediates that happen to match x3/x4 as "register
/// use".
#[derive(Clone, Copy)]
struct RegFields {
    rd: bool,
    rs1: bool,
    rs2: bool,
}
const REG_NONE: RegFields = RegFields {
    rd: false,
    rs1: false,
    rs2: false,
};

/// Return which fields of `w` carry register numbers, given the
/// 7-bit major opcode.
fn reg_fields_for(opcode: u32) -> RegFields {
    match opcode {
        // R-type: rd, rs1, rs2 (OP, OP-32).
        0b011_0011 | 0b011_1011 => RegFields {
            rd: true,
            rs1: true,
            rs2: true,
        },
        // I-type loads (LOAD).
        0b000_0011 => RegFields {
            rd: true,
            rs1: true,
            rs2: false,
        },
        // I-type ALU (OP-IMM, OP-IMM-32) and JALR.
        0b001_0011 | 0b001_1011 | 0b110_0111 => RegFields {
            rd: true,
            rs1: true,
            rs2: false,
        },
        // S-type stores: rs1, rs2 are regs; rd slot is imm[4:0].
        0b010_0011 => RegFields {
            rd: false,
            rs1: true,
            rs2: true,
        },
        // B-type branches: rs1, rs2 are regs; rd slot is imm.
        0b110_0011 => RegFields {
            rd: false,
            rs1: true,
            rs2: true,
        },
        // U-type (LUI, AUIPC): rd is reg; rs1/rs2 slots are imm.
        0b011_0111 | 0b001_0111 => RegFields {
            rd: true,
            rs1: false,
            rs2: false,
        },
        // J-type (JAL): rd is reg; rs1/rs2 slots are imm.
        0b110_1111 => RegFields {
            rd: true,
            rs1: false,
            rs2: false,
        },
        // MISC-MEM (FENCE): no registers in scope.
        0b000_1111 => REG_NONE,
        // custom-0 (PVM2 host ops): trap/ecall.jar/ecalli — all reg
        // fields are zero. ecalli's imm lives in the I-type slot,
        // so we treat it as I-type for safety (rd = x0 always).
        0b000_1011 => RegFields {
            rd: true,
            rs1: true,
            rs2: false,
        },
        _ => REG_NONE,
    }
}

/// Validate that `code` contains only PVM2-conformant encodings.
///
/// Reject: any AUIPC, standard ECALL (not preceded by a marker — so
/// any remaining ECALL after the rewrite pass is unaccounted for),
/// EBREAK, CSR ops, atomics, FP/V, privileged, and any 5-bit reg
/// field that actually carries a register reference to x3 or x4.
fn validate_pvm2(code: &[u8]) -> Result<(), TranspileError> {
    let n = code.len();
    let mut i = 0;
    while i < n {
        if i + 2 > n {
            break;
        }
        let lo16 = u16::from_le_bytes([code[i], code[i + 1]]);
        if lo16 & 0b11 != 0b11 {
            // RVC. RVC reg fields use x8..x15 (3-bit encoding), which
            // can't reference x3/x4. RVC `c.ebreak` is allowed by RV
            // but PVM2 wants standard ebreak rejected; c.ebreak is
            // encoding 0x9002 — reject it explicitly.
            if lo16 == 0x9002 {
                return Err(TranspileError::InvalidSection(format!(
                    "link_elf_rv: c.ebreak at offset {:#x} (forbidden)",
                    i
                )));
            }
            i += 2;
            continue;
        }
        if i + 4 > n {
            break;
        }
        let w = u32::from_le_bytes([code[i], code[i + 1], code[i + 2], code[i + 3]]);
        let opcode = w & 0x7F;
        match opcode {
            OP_AUIPC => {
                return Err(TranspileError::InvalidSection(format!(
                    "link_elf_rv: AUIPC still present at offset {:#x} (rewrite incomplete)",
                    i
                )));
            }
            OP_SYSTEM => {
                let funct3 = (w >> 12) & 0x7;
                let csr_or_imm = (w >> 20) & 0xFFF;
                if funct3 == 0 {
                    return Err(TranspileError::InvalidSection(format!(
                        "link_elf_rv: standard ECALL/EBREAK at offset {:#x} (imm={:#x})",
                        i, csr_or_imm
                    )));
                }
                return Err(TranspileError::InvalidSection(format!(
                    "link_elf_rv: CSR op at offset {:#x} (funct3={})",
                    i, funct3
                )));
            }
            0b010_1111 => {
                return Err(TranspileError::InvalidSection(format!(
                    "link_elf_rv: atomic op at offset {:#x}",
                    i
                )));
            }
            0b000_0111 | 0b010_0111 => {
                return Err(TranspileError::InvalidSection(format!(
                    "link_elf_rv: FP load/store at offset {:#x}",
                    i
                )));
            }
            0b101_0011 => {
                return Err(TranspileError::InvalidSection(format!(
                    "link_elf_rv: FP arithmetic at offset {:#x}",
                    i
                )));
            }
            _ => {}
        }
        // Check register fields based on the instruction encoding type.
        let rf = reg_fields_for(opcode);
        let rd = (w >> 7) & 0x1F;
        let rs1 = (w >> 15) & 0x1F;
        let rs2 = (w >> 20) & 0x1F;
        let check = |name: &str, r: u32| -> Result<(), TranspileError> {
            if r == 3 || r == 4 {
                return Err(TranspileError::InvalidSection(format!(
                    "link_elf_rv: forbidden register x{} ({}) at offset {:#x}",
                    r, name, i
                )));
            }
            Ok(())
        };
        if rf.rd {
            check("rd", rd)?;
        }
        if rf.rs1 {
            check("rs1", rs1)?;
        }
        if rf.rs2 {
            check("rs2", rs2)?;
        }
        i += 4;
    }
    Ok(())
}

/// Identify the `.subsoil.endpoints` section, parse its 16-byte
/// descriptors, and resolve `fn_ptr` (RV vaddr) into an RV-byte-offset
/// PC. The identity map `(rv_vaddr - base_vaddr) -> pc` works because
/// the rewritten code keeps each instruction at its original offset.
fn read_subsoil_endpoints_rv(
    elf_data: &[u8],
    base_vaddr: u64,
    code_len: usize,
) -> Result<BTreeMap<u8, EndpointDef>, TranspileError> {
    let sections = crate::linker::find_all_section_bytes_for_rv(elf_data, ".subsoil.endpoints")?;
    const DESCRIPTOR_SIZE: usize = 16;
    let mut endpoints: BTreeMap<u8, EndpointDef> = BTreeMap::new();
    for section_bytes in &sections {
        if section_bytes.len() % DESCRIPTOR_SIZE != 0 {
            return Err(TranspileError::InvalidSection(format!(
                ".subsoil.endpoints size {} is not a multiple of {}",
                section_bytes.len(),
                DESCRIPTOR_SIZE
            )));
        }
        for chunk in section_bytes.chunks(DESCRIPTOR_SIZE) {
            let fn_ptr = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
            let index = chunk[8];
            let arg_registers = chunk[9];
            let arg_cnode_size = chunk[10];
            if fn_ptr < base_vaddr || fn_ptr >= base_vaddr + code_len as u64 {
                return Err(TranspileError::InvalidSection(format!(
                    "subsoil endpoint {} fn_ptr {:#x} outside code section",
                    index, fn_ptr
                )));
            }
            let rv_pc = fn_ptr - base_vaddr;
            if endpoints
                .insert(
                    index,
                    EndpointDef {
                        entry_pc: rv_pc,
                        arg_registers,
                        arg_cnode_size,
                        initial_regs: BTreeMap::new(),
                    },
                )
                .is_some()
            {
                return Err(TranspileError::InvalidSection(format!(
                    "duplicate #[subsoil::endpoint({})] declaration",
                    index
                )));
            }
        }
    }
    if endpoints.is_empty() {
        return Err(TranspileError::InvalidSection(
            ".subsoil.endpoints section is absent or empty: \
             the guest must declare at least one #[subsoil::endpoint(N)]"
                .into(),
        ));
    }
    Ok(endpoints)
}

/// True iff the 32-bit RV word is a "full-length" (4-byte) instruction
/// (bits[1:0] == 11). For 16-bit RVC instructions the same byte
/// position has bits[1:0] != 11 in the low 16 bits.
#[inline]
fn is_full_length(word: u32) -> bool {
    word & 0b11 == 0b11
}

/// Patch an I-type instruction's 12-bit imm (bits [31:20]) in place.
/// `imm` is the signed 12-bit value; only the low 12 bits are used.
fn patch_imm_i(slot: &mut [u8], imm: i32) {
    let w = u32::from_le_bytes([slot[0], slot[1], slot[2], slot[3]]);
    let cleared = w & 0x000F_FFFF;
    let imm12 = (imm as u32) & 0xFFF;
    let patched = cleared | (imm12 << 20);
    slot[0..4].copy_from_slice(&patched.to_le_bytes());
}

/// Patch an S-type instruction's 12-bit imm (bits [31:25] | [11:7]).
fn patch_imm_s(slot: &mut [u8], imm: i32) {
    let w = u32::from_le_bytes([slot[0], slot[1], slot[2], slot[3]]);
    let cleared = w & 0x01FF_F07F;
    let imm12 = (imm as u32) & 0xFFF;
    let hi7 = (imm12 >> 5) & 0x7F;
    let lo5 = imm12 & 0x1F;
    let patched = cleared | (hi7 << 25) | (lo5 << 7);
    slot[0..4].copy_from_slice(&patched.to_le_bytes());
}

/// True for the standard RV `ECALL` encoding `0x00000073`.
#[inline]
fn is_standard_ecall(word: u32) -> bool {
    word == 0x0000_0073
}

/// Encode custom-0 `ecall.jar`: `(funct3=001)(rest=0)`.
#[inline]
fn encode_custom0_ecall_jar() -> u32 {
    // funct3 = 001 in bits [14:12]; opcode in [6:0].
    (0b001 << 12) | OP_CUSTOM_0
}

/// Encode custom-0 `ecalli imm`: `(funct3=010)(imm[19:0])`.
/// imm placed in bits [31:20] (12-bit signed I-type slot).
#[inline]
fn encode_custom0_ecalli(imm: i32) -> u32 {
    let imm12 = (imm as u32) & 0xFFF;
    (imm12 << 20) | (0b010 << 12) | OP_CUSTOM_0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nop_encoding_matches_addi_x0_x0_0() {
        let w = u32::from_le_bytes(NOP_BYTES);
        assert_eq!(w & 0x7F, OP_OP_IMM, "opcode must be OP-IMM");
        assert_eq!((w >> 7) & 0x1F, 0, "rd must be x0");
        assert_eq!((w >> 15) & 0x1F, 0, "rs1 must be x0");
        assert_eq!((w >> 20) & 0xFFF, 0, "imm must be 0");
        assert_eq!((w >> 12) & 0x7, 0, "funct3 must be 0 (ADDI)");
    }

    #[test]
    fn custom0_ecall_jar_decodes() {
        let w = encode_custom0_ecall_jar();
        assert_eq!(w & 0x7F, OP_CUSTOM_0);
        assert_eq!((w >> 12) & 0x7, 0b001);
        // Other fields zero.
        assert_eq!((w >> 7) & 0x1F, 0);
        assert_eq!((w >> 15) & 0x1F, 0);
    }

    #[test]
    fn custom0_ecalli_decodes() {
        let w = encode_custom0_ecalli(42);
        assert_eq!(w & 0x7F, OP_CUSTOM_0);
        assert_eq!((w >> 12) & 0x7, 0b010);
        assert_eq!((w >> 20) & 0xFFF, 42);
    }

    #[test]
    fn rewrite_ecall_marker_jar() {
        // CSRRW x0, 0x800, x0 = csr=0x800, rs1=0, funct3=1, rd=0, op=SYSTEM
        let csrrw = (0x800u32 << 20) | (0b001 << 12) | OP_SYSTEM;
        let ecall: u32 = 0x0000_0073;
        let mut code = Vec::new();
        code.extend_from_slice(&csrrw.to_le_bytes());
        code.extend_from_slice(&ecall.to_le_bytes());
        rewrite_ecall_markers(&mut code).unwrap();
        let w0 = u32::from_le_bytes(code[0..4].try_into().unwrap());
        assert_eq!(w0, u32::from_le_bytes(NOP_BYTES));
        let w1 = u32::from_le_bytes(code[4..8].try_into().unwrap());
        assert_eq!(w1, encode_custom0_ecall_jar());
    }

    #[test]
    fn rewrite_ecall_marker_ecalli() {
        let csrrw = (0x801u32 << 20) | (0b001 << 12) | OP_SYSTEM;
        let ecall: u32 = 0x0000_0073;
        let mut code = Vec::new();
        code.extend_from_slice(&csrrw.to_le_bytes());
        code.extend_from_slice(&ecall.to_le_bytes());
        rewrite_ecall_markers(&mut code).unwrap();
        let w1 = u32::from_le_bytes(code[4..8].try_into().unwrap());
        assert_eq!(w1, encode_custom0_ecalli(0));
    }

    #[test]
    fn validate_rejects_auipc() {
        let auipc = (0x1000u32 << 12) | (1 << 7) | OP_AUIPC; // auipc x1, 0x1000
        let code = auipc.to_le_bytes().to_vec();
        let err = validate_pvm2(&code).unwrap_err();
        let TranspileError::InvalidSection(msg) = err else {
            panic!("expected InvalidSection, got {:?}", err);
        };
        assert!(msg.contains("AUIPC"));
    }

    #[test]
    fn validate_rejects_standard_ecall() {
        let code = 0x0000_0073u32.to_le_bytes().to_vec();
        let err = validate_pvm2(&code).unwrap_err();
        assert!(matches!(err, TranspileError::InvalidSection(_)));
    }

    #[test]
    fn validate_rejects_x3_use() {
        // addi x3, x0, 0  (rd=3, rs1=0, imm=0, funct3=0, op=OP-IMM)
        let w = (3u32 << 7) | OP_OP_IMM;
        let code = w.to_le_bytes().to_vec();
        let err = validate_pvm2(&code).unwrap_err();
        let TranspileError::InvalidSection(msg) = err else {
            panic!();
        };
        assert!(msg.contains("x3"));
    }

    #[test]
    fn validate_accepts_clean_addi() {
        // addi x1, x0, 5  (rd=1, rs1=0, imm=5, funct3=0, op=OP-IMM)
        let w = (5u32 << 20) | (1 << 7) | OP_OP_IMM;
        let code = w.to_le_bytes().to_vec();
        validate_pvm2(&code).unwrap();
    }

    #[test]
    fn validate_accepts_rvc() {
        // c.li x10, 5 = 0x4515 (h = 0x4515, low 2 bits = 01, RVC)
        let cli = 0x4515u16;
        let code = cli.to_le_bytes().to_vec();
        validate_pvm2(&code).unwrap();
    }
}
