//! ELF → PVM2 (raw RV+C+custom-0 bytes) linker.
//!
//! Pipeline:
//! 1. **Parse ELF + relocs** via `crate::elf::parse_linked_elf`.
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
//! 6. **Emit Image** with `code = raw RV bytes`. The recompiler-side
//!    `compile` consumes these directly.

use crate::TranspileError;
use crate::elf::parse_linked_elf;
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
/// RV opcode major for custom-1 (PVM2 `callf`).
const OP_CUSTOM_1: u32 = 0b010_1011;
/// RV opcode major for JAL.
const OP_JAL: u32 = 0b110_1111;
/// RV opcode major for JALR.
const OP_JALR: u32 = 0b110_0111;

/// 32-bit canonical NOP: `addi x0, x0, 0`.
const NOP_BYTES: [u8; 4] = [0x13, 0x00, 0x00, 0x00];

/// PVM ecall-marker CSR numbers (custom range).
const CSR_ECALL_JAR: u32 = 0x800;
const CSR_ECALLI: u32 = 0x801;

/// Link an RV ELF into a PVM2 [`Image`] whose `code` field is raw
/// RV+C+custom-0 bytes.
pub fn link_elf(elf_data: &[u8]) -> Result<Image, TranspileError> {
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
            "link_elf: ELF has no code sections".into(),
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
        if o >= code_len { None } else { Some(o) }
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
                "link_elf: AUIPC reloc at vaddr {:#x} outside code section",
                v
            ))
        })?;
        if off + 4 > code.len() {
            return Err(TranspileError::InvalidSection(format!(
                "link_elf: AUIPC reloc at vaddr {:#x} truncated by section end",
                v
            )));
        }
        let word = u32::from_le_bytes([code[off], code[off + 1], code[off + 2], code[off + 3]]);
        if word & 0x7F != OP_AUIPC {
            return Err(TranspileError::InvalidSection(format!(
                "link_elf: reloc at vaddr {:#x} not an AUIPC (opcode {:#x})",
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

    // ---- 3b. CFG analysis + br_table-based call/return rewrite ------
    //
    // PVM2 forbids JALR entirely. We rewrite the canonical call /
    // return / tail-call patterns to:
    //   - direct call:   `addi ra, x0, 2*idx+1; jal x0, callee_entry`
    //   - tail call:     `nop;                  jal x0, callee_entry`
    //                    (ra is passed through unchanged so the callee's
    //                     br_table dispatches the upstream caller's idx)
    //   - function ret:  `br_table table_id, ra` (custom-0 funct3=011)
    //
    // Each function gets a per-SCC return table; functions whose
    // tail-call relationships form a SCC share a table. Tail-call
    // predecessors transitively inject their callers' resume PCs
    // into the callee SCC's table so the same ra-idx works at any
    // br_table reached via a tail-call chain.
    //
    // Read endpoint entries first since they're required function
    // entries (the host trampoline jumps directly to these PCs).
    let endpoint_entries_pre: Vec<u32> = {
        match crate::elf::find_all_section_bytes(elf_data, ".subsoil.endpoints") {
            Ok(sections) => sections
                .iter()
                .flat_map(|s| s.chunks(16))
                .filter_map(|chunk| {
                    if chunk.len() < 8 {
                        return None;
                    }
                    let fn_ptr = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
                    if fn_ptr < base_vaddr {
                        return None;
                    }
                    Some((fn_ptr - base_vaddr) as u32)
                })
                .collect(),
            Err(_) => Vec::new(),
        }
    };

    let cfg_pvm2 = analyze_pvm2_cfg(&code, &auipc_effective, base_vaddr, &endpoint_entries_pre)?;
    let return_tables_pre = build_return_tables(&cfg_pvm2)?;
    let (new_code, offset_map_pre, mut tables_new_pcs) =
        rewrite_pvm2_calls_returns(&code, &cfg_pvm2, &return_tables_pre)?;
    let mut code = new_code;

    // ---- 3c. Branch-target alignment (fallthrough injection) -------
    //
    // After the call/return rewrites, branch / jal targets aren't
    // necessarily post-terminator yet. Inject `fallthrough` (4 bytes,
    // custom-0, terminator no-op) before each such target so the
    // predecode's strict bb_start set covers everything reachable.
    //
    // Targets that must be bb_starts:
    //   - branch / jal targets (handled by align_branch_targets internally)
    //   - endpoint entries (host trampoline entry — must remap via
    //     offset_map_pre first)
    //   - .rodata code-pointer targets (also via offset_map_pre)
    //   - every entry in tables_new_pcs (br_table dispatches into these)
    let pre_align_endpoint_offsets: Vec<usize> = endpoint_entries_pre
        .iter()
        .map(|&e| {
            offset_map_pre
                .get(&(e as usize))
                .copied()
                .unwrap_or(e as usize)
        })
        .collect();
    let pre_align_rodata_targets: Vec<usize> = elf
        .abs_code_ptrs
        .iter()
        .filter_map(|&(_, rv_target, _)| {
            if !is_code_addr(rv_target) {
                None
            } else {
                let pre = rv_target.wrapping_sub(base_vaddr) as usize;
                Some(offset_map_pre.get(&pre).copied().unwrap_or(pre))
            }
        })
        .collect();
    let mut extra_targets: Vec<usize> = pre_align_endpoint_offsets;
    extra_targets.extend_from_slice(&pre_align_rodata_targets);
    for table in &tables_new_pcs {
        for &pc in table {
            extra_targets.push(pc as usize);
        }
    }
    let offset_map_align = align_branch_targets(&mut code, &extra_targets)?;

    // Apply the alignment-pass offset_map to the return tables in place.
    for table in tables_new_pcs.iter_mut() {
        for entry in table.iter_mut() {
            let new_pc = offset_map_align
                .get(&(*entry as usize))
                .copied()
                .ok_or_else(|| {
                    TranspileError::InvalidSection(format!(
                        "link_elf: br_table resume pc {:#x} not in align offset_map",
                        *entry
                    ))
                })?;
            *entry = new_pc as u32;
        }
    }

    // Compose offset_map_pre with offset_map_align so the existing
    // `.rodata` + endpoint translation logic below (which uses OLD-pre-
    // rewrite PCs as input) keeps working uniformly.
    let offset_map: BTreeMap<usize, usize> = offset_map_pre
        .iter()
        .filter_map(|(&old_pre, &new_pre)| {
            offset_map_align
                .get(&new_pre)
                .copied()
                .map(|new_post| (old_pre, new_post))
        })
        .collect();

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

        // Translate a code address (RV vaddr) to a post-alignment byte
        // offset within `code`. Applies offset_map to remap shifts
        // introduced by fallthrough injection.
        let translate_code_addr = |rv_target: u64| -> u32 {
            let pre = rv_target.wrapping_sub(base_vaddr) as usize;
            offset_map.get(&pre).copied().unwrap_or(pre) as u32
        };

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
            let new_val = translate_code_addr(rv_target);
            match size {
                4 if off + 4 <= ro_data_rewritten.len() => {
                    ro_data_rewritten[off..off + 4].copy_from_slice(&new_val.to_le_bytes());
                }
                8 if off + 8 <= ro_data_rewritten.len() => {
                    ro_data_rewritten[off..off + 8]
                        .copy_from_slice(&(new_val as u64).to_le_bytes());
                }
                _ => {}
            }
        }

        // Heuristic: 8-byte values in .rodata that look like code
        // pointers but aren't covered by an explicit reloc.
        let mut off = 0;
        let already_covered: std::collections::HashSet<u64> =
            elf.abs_code_ptrs.iter().map(|&(v, _, _)| v).collect();
        while off + 8 <= ro_data_rewritten.len() {
            let val = u64::from_le_bytes(ro_data_rewritten[off..off + 8].try_into().unwrap());
            if is_code_addr(val) {
                let vaddr = ro_base + off as u64;
                if !already_covered.contains(&vaddr) {
                    let new_val = translate_code_addr(val);
                    ro_data_rewritten[off..off + 8]
                        .copy_from_slice(&(new_val as u64).to_le_bytes());
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
    // map is `vaddr → vaddr - base_vaddr → offset_map[…]`, where
    // `offset_map` accounts for any fallthrough injection.
    let mut endpoints = read_subsoil_endpoints_rv(elf_data, base_vaddr, code.len())?;
    for def in endpoints.values_mut() {
        let pre = def.entry_pc as usize;
        if let Some(&new) = offset_map.get(&pre) {
            def.entry_pc = new as u64;
        }
    }

    // ---- 6. Memory layout + Image construction ----------------------
    let ro_data = ro_data_rewritten;
    let rw_data = elf.rw_data.clone();

    let stack_pages = elf.stack_size / PVM_PAGE_SIZE;
    let ro_pages = (ro_data.len() as u32).div_ceil(PVM_PAGE_SIZE);
    let rw_pages = (rw_data.len() as u32).div_ceil(PVM_PAGE_SIZE);
    let layout = ProgramLayout::compute(stack_pages, ro_pages, rw_pages, elf.heap_pages);
    let stack_top = layout.stack_top();

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

    // Flatten per-table br_table targets into the Image's CSR
    // layout: a single `jump_table` Vec<u32> with `jump_table_offsets`
    // recording each sub-table's start. The final offsets entry is
    // jump_table.len() so consumers can compute the last table's
    // length uniformly.
    let mut jump_table: Vec<u32> = Vec::new();
    let mut jump_table_offsets: Vec<u32> = Vec::with_capacity(tables_new_pcs.len() + 1);
    if !tables_new_pcs.is_empty() {
        jump_table_offsets.push(0);
        for table in &tables_new_pcs {
            jump_table.extend_from_slice(table);
            jump_table_offsets.push(jump_table.len() as u32);
        }
    }

    Ok(Image {
        code,
        jump_table,
        jump_table_offsets,
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
                    let nxt = u32::from_le_bytes([code[j], code[j + 1], code[j + 2], code[j + 3]]);
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
        // I-type ALU (OP-IMM, OP-IMM-32). JALR is rejected earlier by
        // the dedicated OP_JALR arm in `validate_pvm2` so we don't
        // include it here.
        0b001_0011 | 0b001_1011 => RegFields {
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
                    "link_elf: c.ebreak at offset {:#x} (forbidden)",
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
                    "link_elf: AUIPC still present at offset {:#x} (rewrite incomplete)",
                    i
                )));
            }
            OP_JALR => {
                return Err(TranspileError::InvalidSection(format!(
                    "link_elf: JALR still present at offset {:#x} (rewrite incomplete) — \
                     PVM2 has no JALR; calls/tail-calls/returns must use \
                     addi+jal-x0 / br_table",
                    i
                )));
            }
            OP_CUSTOM_1 => {
                return Err(TranspileError::InvalidSection(format!(
                    "link_elf: custom-1 opcode at offset {:#x} is reserved in PVM2 \
                     (callf is gone; br_table lives in custom-0)",
                    i
                )));
            }
            OP_SYSTEM => {
                let funct3 = (w >> 12) & 0x7;
                let csr_or_imm = (w >> 20) & 0xFFF;
                if funct3 == 0 {
                    return Err(TranspileError::InvalidSection(format!(
                        "link_elf: standard ECALL/EBREAK at offset {:#x} (imm={:#x})",
                        i, csr_or_imm
                    )));
                }
                return Err(TranspileError::InvalidSection(format!(
                    "link_elf: CSR op at offset {:#x} (funct3={})",
                    i, funct3
                )));
            }
            0b010_1111 => {
                return Err(TranspileError::InvalidSection(format!(
                    "link_elf: atomic op at offset {:#x}",
                    i
                )));
            }
            0b000_0111 | 0b010_0111 => {
                return Err(TranspileError::InvalidSection(format!(
                    "link_elf: FP load/store at offset {:#x}",
                    i
                )));
            }
            0b101_0011 => {
                return Err(TranspileError::InvalidSection(format!(
                    "link_elf: FP arithmetic at offset {:#x}",
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
                    "link_elf: forbidden register x{} ({}) at offset {:#x}",
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
    let sections = crate::elf::find_all_section_bytes(elf_data, ".subsoil.endpoints")?;
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

/// Encode custom-0 `br_table table_id, rs1` — I-type indirect-jump
/// terminator. funct3 = 011, rd = 0, imm[11:0] = table_id (unsigned
/// 12-bit), rs1 = idx-carrier reg.
#[inline]
fn encode_custom0_br_table(table_id: u16, rs1: u8) -> u32 {
    debug_assert!(
        table_id < (1 << 12),
        "br_table table_id must fit in 12 bits"
    );
    debug_assert!(rs1 < 32, "rs1 must be 5-bit");
    let imm12 = (table_id as u32) & 0xFFF;
    (imm12 << 20) | ((rs1 as u32) << 15) | (0b011 << 12) | OP_CUSTOM_0
}

/// Encode custom-0 `fallthrough` (funct3 = 100; all other fields zero).
/// A 4-byte terminator no-op that creates a bb_start at the next byte.
#[inline]
fn encode_custom0_fallthrough() -> u32 {
    (0b100 << 12) | OP_CUSTOM_0
}

/// Encode I-type `addi rd, rs1, imm` (RV `OP-IMM`, funct3=000).
/// `imm` is signed 12-bit (range −2048..=2047).
#[inline]
fn encode_addi(rd: u8, rs1: u8, imm: i32) -> u32 {
    debug_assert!(rd < 32 && rs1 < 32, "register field must fit 5 bits");
    debug_assert!(
        (-2048..=2047).contains(&imm),
        "addi imm must fit signed 12-bit, got {imm}"
    );
    let imm12 = (imm as u32) & 0xFFF;
    ((imm12 << 20) | ((rs1 as u32) << 15)) | ((rd as u32) << 7) | 0b001_0011
}

/// Encode JAL with rd=0 and J-type immediate (= the static-jump form,
/// same encoding as `c.j` once decompressed).
#[inline]
fn encode_jal_x0(imm: i32) -> u32 {
    let v = imm as u32;
    let b20 = (v >> 20) & 0x1;
    let b10_1 = (v >> 1) & 0x3FF;
    let b11 = (v >> 11) & 0x1;
    let b19_12 = (v >> 12) & 0xFF;
    let imm_field = (b20 << 31) | (b10_1 << 21) | (b11 << 20) | (b19_12 << 12);
    imm_field | OP_JAL
}

/// Decode J-type immediate (sign-extended 21-bit).
fn imm_j(w: u32) -> i32 {
    let b20 = (w >> 31) & 1;
    let b10_1 = (w >> 21) & 0x3FF;
    let b11 = (w >> 20) & 1;
    let b19_12 = (w >> 12) & 0xFF;
    let raw = (b20 << 20) | (b19_12 << 12) | (b11 << 11) | (b10_1 << 1);
    ((raw as i32) << 11) >> 11
}

/// Decode B-type immediate (sign-extended 13-bit).
fn imm_b(w: u32) -> i32 {
    let b12 = (w >> 31) & 1;
    let b11 = (w >> 7) & 1;
    let b10_5 = (w >> 25) & 0x3F;
    let b4_1 = (w >> 8) & 0xF;
    let raw = (b12 << 12) | (b11 << 11) | (b10_5 << 5) | (b4_1 << 1);
    ((raw as i32) << 19) >> 19
}

/// Encode B-type immediate into an existing branch instruction word.
fn encode_b_imm(opcode_and_regs: u32, imm: i32) -> u32 {
    let v = imm as u32;
    let b12 = (v >> 12) & 0x1;
    let b11 = (v >> 11) & 0x1;
    let b10_5 = (v >> 5) & 0x3F;
    let b4_1 = (v >> 1) & 0xF;
    // Clear the imm-bearing bits, then OR in the new ones.
    let cleared = opcode_and_regs & 0x01FF_F07F;
    cleared | (b12 << 31) | (b10_5 << 25) | (b4_1 << 8) | (b11 << 7)
}

// ============================================================================
// PVM2 call / return rewrite (br_table-based static dispatch)
// ============================================================================

/// Direct call site identified in the OLD (pre-rewrite) code.
#[derive(Debug, Clone)]
struct DirectCall {
    /// Byte offset of the start of the OLD call sequence:
    ///   - JAL rd != x0:        offset of the JAL (4 bytes long)
    ///   - AUIPC + JALR rd!=x0: offset of the AUIPC (8 bytes long)
    seq_start: u32,
    /// Length of the OLD call sequence in bytes (4 or 8).
    seq_len: u32,
    /// Target callee entry PC in OLD code.
    target: u32,
}

/// Tail-call site (same shape as DirectCall but represents an
/// `auipc + jalr x0` pair — no link register written).
#[derive(Debug, Clone)]
struct TailCall {
    seq_start: u32,
    seq_len: u32,
    target: u32,
}

/// Function return site (`c.jr ra` or uncompressed `jalr x0, x1, 0`).
#[derive(Debug, Clone, Copy)]
struct ReturnSite {
    /// Byte offset of the return instruction.
    pc: u32,
    /// 2 for `c.jr ra`, 4 for uncompressed `jalr x0, x1, 0`.
    len: u32,
}

/// Control-flow graph extracted from OLD code.
#[derive(Debug)]
struct Pvm2Cfg {
    /// Function entry PCs (OLD code coordinates), sorted.
    function_entries: Vec<u32>,
    direct_calls: Vec<DirectCall>,
    tail_calls: Vec<TailCall>,
    returns: Vec<ReturnSite>,
}

/// Walk the (pre-rewrite) code and extract call / tail-call / return
/// sites and the set of function entry PCs.
///
/// Patterns recognised (all anchored at instruction boundaries):
///   - `jal rd != x0, imm`           → DirectCall (4-byte sequence)
///   - `auipc + jalr rd != x0, imm`  → DirectCall (8-byte sequence)
///   - `auipc + jalr x0, imm`        → TailCall (8-byte sequence)
///   - `jalr x0, x1, 0` (uncomp.)    → ReturnSite (4 bytes)
///   - `c.jr ra` (= 0x8082)          → ReturnSite (2 bytes)
///   - `c.j imm` / `c.beqz` / etc.   → no edge added (static jump or branch)
///   - any other JALR pattern        → error (forbidden in PVM2)
///
/// Function entries are derived from call/tail-call targets and from
/// the caller-supplied endpoint entries.
fn analyze_pvm2_cfg(
    code: &[u8],
    auipc_effective: &BTreeMap<u64, u32>,
    base_vaddr: u64,
    endpoint_entries: &[u32],
) -> Result<Pvm2Cfg, TranspileError> {
    let n = code.len();
    let mut direct_calls: Vec<DirectCall> = Vec::new();
    let mut tail_calls: Vec<TailCall> = Vec::new();
    let mut returns: Vec<ReturnSite> = Vec::new();
    let mut entries: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();

    for &e in endpoint_entries {
        if (e as usize) < n {
            entries.insert(e);
        }
    }

    let mut pc: usize = 0;
    while pc < n {
        if pc + 2 > n {
            break;
        }
        let lo = u16::from_le_bytes([code[pc], code[pc + 1]]);
        if lo & 0b11 != 0b11 {
            // Compressed (2 bytes).
            // Only c.jr ra matters here — it's a return site.
            // c.jr ra has wire encoding 0x8082:
            //   bits[15:13]=100  bit12=0  bits[11:7]=rdrs1=1  bits[6:2]=0  bits[1:0]=10
            if lo == 0x8082 {
                returns.push(ReturnSite {
                    pc: pc as u32,
                    len: 2,
                });
            }
            pc += 2;
            continue;
        }
        if pc + 4 > n {
            break;
        }
        let w = u32::from_le_bytes([code[pc], code[pc + 1], code[pc + 2], code[pc + 3]]);
        let opcode = w & 0x7F;

        if opcode == OP_JAL {
            let rd = ((w >> 7) & 0x1F) as u8;
            let imm = imm_j(w);
            if rd != 0 {
                // jal rd, imm — direct call.
                let target_i = (pc as i64) + (imm as i64);
                if target_i < 0 || (target_i as usize) >= n {
                    return Err(TranspileError::InvalidSection(format!(
                        "analyze_pvm2_cfg: JAL at {:#x} target {} out of code range",
                        pc, target_i
                    )));
                }
                let target = target_i as u32;
                direct_calls.push(DirectCall {
                    seq_start: pc as u32,
                    seq_len: 4,
                    target,
                });
                entries.insert(target);
            }
            // rd == 0 (= static jump / c.j-like): not a call edge.
            pc += 4;
            continue;
        }

        if opcode == OP_JALR {
            let rd = ((w >> 7) & 0x1F) as u8;
            let rs1 = ((w >> 15) & 0x1F) as u8;
            let funct3 = (w >> 12) & 0x7;
            let imm12_signed = (w as i32) >> 20;

            if funct3 != 0 {
                return Err(TranspileError::InvalidSection(format!(
                    "analyze_pvm2_cfg: JALR with funct3={} at {:#x} (reserved encoding)",
                    funct3, pc
                )));
            }

            // Check AUIPC pairing.
            let jalr_vaddr = base_vaddr + pc as u64;
            let auipc_vaddr = jalr_vaddr.checked_sub(4);
            let paired_target = auipc_vaddr.and_then(|v| auipc_effective.get(&v).copied());

            if let Some(target_off) = paired_target {
                if pc < 4 {
                    return Err(TranspileError::InvalidSection(format!(
                        "analyze_pvm2_cfg: AUIPC+JALR pair at {:#x} has no AUIPC slot",
                        pc
                    )));
                }
                let target = target_off;
                if (target as usize) >= n {
                    return Err(TranspileError::InvalidSection(format!(
                        "analyze_pvm2_cfg: AUIPC+JALR target {:#x} out of code range (pc {:#x})",
                        target, pc
                    )));
                }
                let seq_start = (pc - 4) as u32;
                if rd == 0 {
                    tail_calls.push(TailCall {
                        seq_start,
                        seq_len: 8,
                        target,
                    });
                } else {
                    direct_calls.push(DirectCall {
                        seq_start,
                        seq_len: 8,
                        target,
                    });
                }
                entries.insert(target);
                pc += 4;
                continue;
            }

            // Standalone JALR. Only the canonical uncompressed return form
            // (`jalr x0, x1, 0`) is allowed; everything else is reserved.
            if rd == 0 && rs1 == 1 && imm12_signed == 0 {
                returns.push(ReturnSite {
                    pc: pc as u32,
                    len: 4,
                });
                pc += 4;
                continue;
            }
            return Err(TranspileError::InvalidSection(format!(
                "analyze_pvm2_cfg: unhandled JALR at {:#x} (rd={}, rs1={}, imm={}) — \
                 PVM2 forbids indirect dispatch; rewrite to call/tail/return \
                 or refactor to remove indirect jumps",
                pc, rd, rs1, imm12_signed
            )));
        }

        pc += 4;
    }

    let mut function_entries: Vec<u32> = entries.into_iter().collect();
    function_entries.sort();
    Ok(Pvm2Cfg {
        function_entries,
        direct_calls,
        tail_calls,
        returns,
    })
}

/// Result of return-table construction.
#[derive(Debug)]
struct ReturnTables {
    /// `function_entry_old_pc → table_id`. Every function in the
    /// function_entries set has an entry here (table_id may be shared
    /// among functions in the same tail-call SCC + transitive
    /// inheritance chain).
    function_to_table: BTreeMap<u32, u16>,
    /// `table_id → ordered list of OLD resume PCs`. Each entry is
    /// `call_site.seq_start + call_site.seq_len`, the byte AFTER the
    /// caller's call sequence in OLD code. After offset_map is
    /// applied (in a separate pass) these become the NEW resume PCs
    /// stored in `Image.jump_table`.
    tables_old_pcs: Vec<Vec<u32>>,
    /// Per-direct-call-site index assignment. `idx_of_call[i]` is the
    /// idx within the callee's table for `cfg.direct_calls[i]`.
    /// `0..table_size`; the encoded value passed in `ra` is
    /// `2*idx + 1`.
    idx_of_call: Vec<u32>,
}

/// Build per-WCC return tables with tail-call propagation.
///
/// Algorithm:
/// 1. Group functions into tail-call **weakly-connected components**
///    (union-find over tail-call edges, treated as undirected).
///    Every pair of functions related by a chain of tail-calls — in
///    either direction — must share one table so that an `ra` value
///    set at any caller in the chain decodes to the same resume PC
///    at any br_table along the chain.
/// 2. For each WCC, the table is the union of direct-caller resume
///    PCs of every function in the WCC, sorted.
/// 3. Each direct call site `C → callee F` gets `idx = position of
///    (C + len(C)) in WCC(F)'s sorted table`. The encoded value
///    passed in `ra` is `2*idx + 1`.
fn build_return_tables(cfg: &Pvm2Cfg) -> Result<ReturnTables, TranspileError> {
    let entries = &cfg.function_entries;
    let n = entries.len();
    if n == 0 {
        return Ok(ReturnTables {
            function_to_table: BTreeMap::new(),
            tables_old_pcs: Vec::new(),
            idx_of_call: vec![0; cfg.direct_calls.len()],
        });
    }

    // Function-entry PC → dense index 0..n.
    let entry_idx: BTreeMap<u32, usize> =
        entries.iter().enumerate().map(|(i, &e)| (e, i)).collect();

    // Union-find over function indices. Every tail-call edge unions
    // its endpoints — direction doesn't matter for the
    // share-a-table constraint.
    let mut uf_parent: Vec<usize> = (0..n).collect();
    fn uf_find(parent: &mut [usize], mut x: usize) -> usize {
        while parent[x] != x {
            parent[x] = parent[parent[x]];
            x = parent[x];
        }
        x
    }
    fn uf_union(parent: &mut [usize], a: usize, b: usize) {
        let ra = uf_find(parent, a);
        let rb = uf_find(parent, b);
        if ra != rb {
            parent[ra] = rb;
        }
    }
    for tc in &cfg.tail_calls {
        let caller_entry = entries
            .partition_point(|&e| e <= tc.seq_start)
            .checked_sub(1)
            .and_then(|i| entries.get(i).copied())
            .ok_or_else(|| {
                TranspileError::InvalidSection(format!(
                    "build_return_tables: tail-call at {:#x} has no enclosing function",
                    tc.seq_start
                ))
            })?;
        let caller_idx = entry_idx[&caller_entry];
        let callee_idx = entry_idx[&tc.target];
        uf_union(&mut uf_parent, caller_idx, callee_idx);
    }

    // Group functions by WCC root. Resolve every function's root
    // once and stash a dense WCC id for it.
    let mut wcc_id: Vec<u32> = vec![u32::MAX; n];
    let mut next_wcc: u32 = 0;
    let mut root_to_wcc: BTreeMap<usize, u32> = BTreeMap::new();
    for (i, w) in wcc_id.iter_mut().enumerate().take(n) {
        let r = uf_find(&mut uf_parent, i);
        let id = *root_to_wcc.entry(r).or_insert_with(|| {
            let id = next_wcc;
            next_wcc += 1;
            id
        });
        *w = id;
    }

    // Per-WCC union of direct-caller resume PCs.
    let num_wccs = next_wcc as usize;
    let mut returns_by_wcc: Vec<std::collections::BTreeSet<u32>> =
        vec![std::collections::BTreeSet::new(); num_wccs];
    for dc in &cfg.direct_calls {
        let callee_fn_idx = entry_idx[&dc.target];
        let w = wcc_id[callee_fn_idx];
        let resume = dc.seq_start + dc.seq_len;
        returns_by_wcc[w as usize].insert(resume);
    }

    // Materialize tables. Empty WCCs (functions that are never called
    // and don't tail-call into a called function) don't get a
    // table_id; their c.jr ra is unreachable in practice.
    let mut tables_old_pcs: Vec<Vec<u32>> = Vec::new();
    let mut wcc_to_table: Vec<Option<u16>> = vec![None; num_wccs];
    for (wid, set) in returns_by_wcc.iter().enumerate() {
        if set.is_empty() {
            continue;
        }
        let table_id = u16::try_from(tables_old_pcs.len()).map_err(|_| {
            TranspileError::InvalidSection(
                "build_return_tables: too many tables (>= 4096)".to_string(),
            )
        })?;
        if (table_id as u32) >= (1 << 12) {
            return Err(TranspileError::InvalidSection(format!(
                "build_return_tables: table_id {} exceeds 12-bit limit",
                table_id
            )));
        }
        wcc_to_table[wid] = Some(table_id);
        let mut v: Vec<u32> = set.iter().copied().collect();
        v.sort();
        tables_old_pcs.push(v);
    }

    // function_to_table: each function's br_table dispatches through
    // its WCC's shared table.
    let mut function_to_table: BTreeMap<u32, u16> = BTreeMap::new();
    for (i, &entry) in entries.iter().enumerate() {
        if let Some(tid) = wcc_to_table[wcc_id[i] as usize] {
            function_to_table.insert(entry, tid);
        }
    }

    // idx_of_call: for each direct call, find its resume PC's position
    // within the callee's WCC table.
    let mut idx_of_call: Vec<u32> = Vec::with_capacity(cfg.direct_calls.len());
    for dc in &cfg.direct_calls {
        let table_id = *function_to_table.get(&dc.target).ok_or_else(|| {
            TranspileError::InvalidSection(format!(
                "build_return_tables: direct call to {:#x} has no return table",
                dc.target
            ))
        })?;
        let table = &tables_old_pcs[table_id as usize];
        let resume = dc.seq_start + dc.seq_len;
        let idx = table.iter().position(|&p| p == resume).ok_or_else(|| {
            TranspileError::InvalidSection(format!(
                "build_return_tables: direct call resume {:#x} missing from \
                     callee {:#x} table",
                resume, dc.target
            ))
        })? as u32;
        idx_of_call.push(idx);
    }

    Ok(ReturnTables {
        function_to_table,
        tables_old_pcs,
        idx_of_call,
    })
}

/// Rewrite OLD code into the new PVM2 call/return layout:
///   - JAL rd ≠ x0           →  addi ra, x0, encoded_idx; jal x0, off  (4B→8B grow)
///   - AUIPC+JALR rd ≠ x0    →  addi ra, x0, encoded_idx; jal x0, off  (8B→8B)
///   - AUIPC+JALR rd == x0   →  addi x0, x0, 0;          jal x0, off  (8B→8B; ra passed through)
///   - c.jr ra (2B)          →  br_table table_id, ra                  (2B→4B grow)
///   - jalr x0, x1, 0 (4B)   →  br_table table_id, ra                  (4B→4B)
///   - everything else copied verbatim.
///
/// Returns:
///   - new code bytes
///   - `offset_map_pre`: old_pc → new_pc for every OLD instruction start
///   - `tables_new_pcs`: per-table list of NEW resume PCs (= offset_map_pre[old_resume_pc]).
type RewriteResult = (Vec<u8>, BTreeMap<usize, usize>, Vec<Vec<u32>>);

fn rewrite_pvm2_calls_returns(
    code: &[u8],
    cfg: &Pvm2Cfg,
    tables: &ReturnTables,
) -> Result<RewriteResult, TranspileError> {
    let n = code.len();

    // Index direct/tail calls by their `seq_start` (so we can recognise
    // them when we visit the AUIPC / JAL position).
    let mut direct_by_seq_start: BTreeMap<u32, &DirectCall> = BTreeMap::new();
    for dc in &cfg.direct_calls {
        direct_by_seq_start.insert(dc.seq_start, dc);
    }
    let direct_idx_by_seq_start: BTreeMap<u32, usize> = cfg
        .direct_calls
        .iter()
        .enumerate()
        .map(|(i, dc)| (dc.seq_start, i))
        .collect();
    let mut tail_by_seq_start: BTreeMap<u32, &TailCall> = BTreeMap::new();
    for tc in &cfg.tail_calls {
        tail_by_seq_start.insert(tc.seq_start, tc);
    }
    let return_pcs: std::collections::BTreeSet<u32> = cfg.returns.iter().map(|r| r.pc).collect();
    // Return site PC → enclosing function entry.
    let return_to_function: BTreeMap<u32, u32> = {
        let entries = &cfg.function_entries;
        let mut m = BTreeMap::new();
        for r in &cfg.returns {
            let enc = entries
                .partition_point(|&e| e <= r.pc)
                .checked_sub(1)
                .and_then(|i| entries.get(i).copied())
                .ok_or_else(|| {
                    TranspileError::InvalidSection(format!(
                        "rewrite_pvm2_calls_returns: return at {:#x} has no enclosing function",
                        r.pc
                    ))
                })?;
            m.insert(r.pc, enc);
        }
        m
    };

    let mut new_code: Vec<u8> = Vec::with_capacity(n + 1024);
    let mut offset_map_pre: BTreeMap<usize, usize> = BTreeMap::new();

    // (new_jal_pc, target_old_pc) pairs to patch up after we know
    // every old_pc → new_pc mapping.
    let mut jal_fixups: Vec<(usize, u32)> = Vec::new();

    let mut pc: usize = 0;
    while pc < n {
        offset_map_pre.insert(pc, new_code.len());

        // Direct call (JAL rd!=0 OR AUIPC+JALR rd!=0): seq_start = pc.
        if let Some(dc) = direct_by_seq_start.get(&(pc as u32)).copied() {
            let dc_idx = direct_idx_by_seq_start[&dc.seq_start];
            let idx = tables.idx_of_call[dc_idx];
            let encoded_idx: i32 = 2 * (idx as i32) + 1;
            if !(-2048..=2047).contains(&encoded_idx) {
                return Err(TranspileError::InvalidSection(format!(
                    "rewrite_pvm2_calls_returns: encoded idx {} (idx={}) at call \
                     site {:#x} does not fit signed 12-bit (table size too large)",
                    encoded_idx, idx, pc
                )));
            }
            // ra = x1. Emit `addi ra, x0, encoded_idx` then a placeholder
            // `jal x0, 0` whose imm we'll patch in pass 2.
            let addi_word = encode_addi(/*rd=*/ 1, /*rs1=*/ 0, encoded_idx);
            new_code.extend_from_slice(&addi_word.to_le_bytes());
            let jal_pc_new = new_code.len();
            new_code.extend_from_slice(&encode_jal_x0(0).to_le_bytes());
            jal_fixups.push((jal_pc_new, dc.target));
            pc += dc.seq_len as usize;
            continue;
        }

        // Tail-call (AUIPC+JALR rd=0): seq_start = pc.
        if let Some(tc) = tail_by_seq_start.get(&(pc as u32)).copied() {
            // Emit `addi x0, x0, 0` (4-byte NOP) so the slot the AUIPC
            // occupied stays a benign instruction. ra is preserved
            // intact — the callee's br_table dispatches on the
            // upstream caller's idx.
            new_code.extend_from_slice(&NOP_BYTES);
            let jal_pc_new = new_code.len();
            new_code.extend_from_slice(&encode_jal_x0(0).to_le_bytes());
            jal_fixups.push((jal_pc_new, tc.target));
            pc += tc.seq_len as usize;
            continue;
        }

        // Return site (c.jr ra: 2 bytes; or jalr x0,x1,0: 4 bytes).
        if return_pcs.contains(&(pc as u32)) {
            let func_entry = return_to_function[&(pc as u32)];
            let table_id = *tables.function_to_table.get(&func_entry).ok_or_else(|| {
                TranspileError::InvalidSection(format!(
                    "rewrite_pvm2_calls_returns: function {:#x} has no return table \
                     (no callers — orphan function?)",
                    func_entry
                ))
            })?;
            let br_word = encode_custom0_br_table(table_id, /*rs1=ra*/ 1);
            new_code.extend_from_slice(&br_word.to_le_bytes());
            // Determine OLD length: c.jr ra is 2 bytes; uncompressed
            // jalr x0,x1,0 is 4 bytes.
            let len = cfg
                .returns
                .iter()
                .find(|r| r.pc as usize == pc)
                .map(|r| r.len)
                .unwrap_or(2);
            pc += len as usize;
            continue;
        }

        // Default: copy this old instruction verbatim.
        if pc + 2 > n {
            break;
        }
        let lo = u16::from_le_bytes([code[pc], code[pc + 1]]);
        let inst_len = if lo & 0b11 == 0b11 { 4 } else { 2 };
        if pc + inst_len > n {
            // Truncated trailing bytes — copy what's there.
            new_code.extend_from_slice(&code[pc..n]);
            pc = n;
            continue;
        }
        new_code.extend_from_slice(&code[pc..pc + inst_len]);
        pc += inst_len;
    }
    // Sentinel: map end-of-code so we can compute offsets uniformly.
    offset_map_pre.insert(n, new_code.len());

    // Pass 2: patch jal x0 offsets now that offset_map_pre is final.
    for (new_jal_pc, target_old) in jal_fixups {
        let new_target = *offset_map_pre.get(&(target_old as usize)).ok_or_else(|| {
            TranspileError::InvalidSection(format!(
                "rewrite_pvm2_calls_returns: jal target {:#x} not in offset_map",
                target_old
            ))
        })?;
        let off = new_target as i64 - new_jal_pc as i64;
        if !(-(1 << 20)..(1 << 20)).contains(&off) {
            return Err(TranspileError::InvalidSection(format!(
                "rewrite_pvm2_calls_returns: jal at new_pc {:#x} offset {} out of \
                 ±1 MiB range",
                new_jal_pc, off
            )));
        }
        let w = encode_jal_x0(off as i32);
        new_code[new_jal_pc..new_jal_pc + 4].copy_from_slice(&w.to_le_bytes());
    }

    // Pass 3: re-encode branch / JAL immediates copied verbatim from
    // OLD code so they point to the correct NEW target after any
    // growth (JAL rd≠0: 4B→8B, c.jr ra: 2B→4B). We walk the OLD
    // instruction stream (which we recompute by iterating the
    // offset_map_pre keys in order) and patch the matching instruction
    // in new_code. The instructions emitted by this pass itself
    // (addi+jal, NOP+jal, br_table) already have correct imms.
    //
    // Sites we patch here:
    //   - c.j imm   (RVC: 2B, op=01, f3=101)
    //   - c.beqz/c.bnez (RVC: 2B, op=01, f3=110/111)
    //   - B-type branch (4B, opcode=0b110_0011)
    //   - JAL rd=0 static jump that we DID NOT rewrite (those we did
    //     rewrite are addi+jal pairs whose jal we already patched).
    //
    // We use the fact that offset_map_pre keys are exactly the old
    // instruction-start byte offsets. For each old_pc whose
    // instruction was NOT rewritten in pass 1, fix up the imm.
    let direct_seq_starts: std::collections::BTreeSet<u32> =
        cfg.direct_calls.iter().map(|d| d.seq_start).collect();
    let tail_seq_starts: std::collections::BTreeSet<u32> =
        cfg.tail_calls.iter().map(|t| t.seq_start).collect();
    let return_pcs_set: std::collections::BTreeSet<u32> =
        cfg.returns.iter().map(|r| r.pc).collect();
    for (&old_pc, &new_pc) in &offset_map_pre {
        if old_pc == n {
            continue; // end-of-code sentinel
        }
        // Skip instructions we ourselves emitted (their imms are
        // either correct already or patched in pass 2).
        if direct_seq_starts.contains(&(old_pc as u32))
            || tail_seq_starts.contains(&(old_pc as u32))
            || return_pcs_set.contains(&(old_pc as u32))
        {
            continue;
        }
        if old_pc + 2 > code.len() {
            continue;
        }
        let lo = u16::from_le_bytes([code[old_pc], code[old_pc + 1]]);
        if lo & 0b11 != 0b11 {
            // RVC. Patch c.j and c.beqz/c.bnez.
            let op = lo & 0b11;
            let f3 = (lo >> 13) & 0b111;
            let (is_jump, is_branch) = (
                op == 0b01 && f3 == 0b101,
                op == 0b01 && (f3 == 0b110 || f3 == 0b111),
            );
            if !is_jump && !is_branch {
                continue;
            }
            let old_imm = if is_jump {
                decompress_cj_imm(lo)
            } else {
                decompress_cb_imm(lo)
            };
            let old_target = old_pc as i64 + old_imm as i64;
            if old_target < 0 || (old_target as usize) >= code.len() {
                continue;
            }
            let new_target = *offset_map_pre.get(&(old_target as usize)).ok_or_else(|| {
                TranspileError::InvalidSection(format!(
                    "rewrite_pvm2_calls_returns: RVC branch target {:#x} not in offset_map",
                    old_target
                ))
            })?;
            let new_imm = new_target as i64 - new_pc as i64;
            let new_h = if is_jump {
                encode_cj_imm(lo, new_imm as i32)
            } else {
                encode_cb_imm(lo, new_imm as i32)
            };
            let new_h = new_h.ok_or_else(|| {
                TranspileError::InvalidSection(format!(
                    "rewrite_pvm2_calls_returns: RVC branch new_imm {} at {:#x} out of range",
                    new_imm, new_pc
                ))
            })?;
            new_code[new_pc..new_pc + 2].copy_from_slice(&new_h.to_le_bytes());
            continue;
        }
        if old_pc + 4 > code.len() {
            continue;
        }
        let w = u32::from_le_bytes([
            code[old_pc],
            code[old_pc + 1],
            code[old_pc + 2],
            code[old_pc + 3],
        ]);
        let opcode = w & 0x7F;
        match opcode {
            0b110_0011 => {
                // B-type branch.
                let old_imm = imm_b(w);
                let old_target = old_pc as i64 + old_imm as i64;
                if old_target < 0 || (old_target as usize) >= code.len() {
                    continue;
                }
                let new_target = *offset_map_pre.get(&(old_target as usize)).ok_or_else(|| {
                    TranspileError::InvalidSection(format!(
                        "rewrite_pvm2_calls_returns: B-branch target {:#x} not in offset_map",
                        old_target
                    ))
                })?;
                let new_imm = new_target as i64 - new_pc as i64;
                if !(-(1 << 12)..(1 << 12)).contains(&new_imm) {
                    return Err(TranspileError::InvalidSection(format!(
                        "rewrite_pvm2_calls_returns: B-branch at {:#x} new_imm {} out of \
                         ±4 KiB range",
                        new_pc, new_imm
                    )));
                }
                let new_w = encode_b_imm(w, new_imm as i32);
                new_code[new_pc..new_pc + 4].copy_from_slice(&new_w.to_le_bytes());
            }
            OP_JAL => {
                // JAL with any rd. Direct calls are handled in pass 2;
                // this path covers `jal x0, imm` (static jump) and any
                // other JAL we didn't rewrite.
                let old_imm = imm_j(w);
                let old_target = old_pc as i64 + old_imm as i64;
                if old_target < 0 || (old_target as usize) >= code.len() {
                    continue;
                }
                let new_target = *offset_map_pre.get(&(old_target as usize)).ok_or_else(|| {
                    TranspileError::InvalidSection(format!(
                        "rewrite_pvm2_calls_returns: JAL target {:#x} not in offset_map",
                        old_target
                    ))
                })?;
                let new_imm = new_target as i64 - new_pc as i64;
                if !(-(1 << 20)..(1 << 20)).contains(&new_imm) {
                    return Err(TranspileError::InvalidSection(format!(
                        "rewrite_pvm2_calls_returns: JAL at {:#x} new_imm {} out of ±1 MiB",
                        new_pc, new_imm
                    )));
                }
                let rd = (w >> 7) & 0x1F;
                let v = new_imm as u32;
                let b20 = (v >> 20) & 0x1;
                let b10_1 = (v >> 1) & 0x3FF;
                let b11 = (v >> 11) & 0x1;
                let b19_12 = (v >> 12) & 0xFF;
                let imm_field = (b20 << 31) | (b10_1 << 21) | (b11 << 20) | (b19_12 << 12);
                let new_w = imm_field | (rd << 7) | OP_JAL;
                new_code[new_pc..new_pc + 4].copy_from_slice(&new_w.to_le_bytes());
            }
            _ => {}
        }
    }

    // Translate per-table OLD resume PCs to NEW resume PCs.
    let mut tables_new_pcs: Vec<Vec<u32>> = Vec::with_capacity(tables.tables_old_pcs.len());
    for old_table in &tables.tables_old_pcs {
        let mut new_table = Vec::with_capacity(old_table.len());
        for &old_resume in old_table {
            let new_resume = *offset_map_pre.get(&(old_resume as usize)).ok_or_else(|| {
                TranspileError::InvalidSection(format!(
                    "rewrite_pvm2_calls_returns: resume {:#x} not in offset_map",
                    old_resume
                ))
            })?;
            new_table.push(new_resume as u32);
        }
        tables_new_pcs.push(new_table);
    }

    Ok((new_code, offset_map_pre, tables_new_pcs))
}

/// Walk the rewritten code and inject a `fallthrough` (4 bytes) before
/// every JAL / Callf / branch target that isn't already preceded by a
/// terminator instruction. After injection, all reachable static
/// targets are guaranteed to be in the strict bb_starts set the
/// predecode computes.
///
/// Mutates `code` in place. Returns `old_pc → new_pc` map so the
/// caller can remap PC values stored elsewhere (endpoint entries,
/// `.rodata` code-pointers) consistently.
///
/// `extra_targets` lets the caller mark additional PCs (e.g. endpoint
/// entries, `.rodata` code-pointer targets) as required bb_starts so
/// they get fallthrough injection too.
fn align_branch_targets(
    code: &mut Vec<u8>,
    extra_targets: &[usize],
) -> Result<BTreeMap<usize, usize>, TranspileError> {
    // ---- Pass 1: scan instructions, identify terminators by PC ----
    // We need to know which PCs follow a terminator (= legitimate
    // bb_starts) so we can skip injection where it isn't needed.

    // Decode each instruction at its byte offset; record:
    //  - The set of all instruction-start byte offsets (`inst_starts`).
    //  - The set of terminator instruction END offsets (their next_pc).
    //  - The list of (callf_or_branch_pc, target_pc) edges.
    let n = code.len();
    let mut inst_starts: Vec<usize> = Vec::with_capacity(n / 4);
    let mut post_terminator: std::collections::HashSet<usize> = std::collections::HashSet::new();
    post_terminator.insert(0); // PC=0 is always a bb_start.
    let mut static_edges: Vec<(usize, usize)> = Vec::new(); // (instruction_pc, target_pc)

    let mut pc: usize = 0;
    while pc < n {
        inst_starts.push(pc);
        let lo = u16::from_le_bytes([code[pc], code[pc + 1]]);
        let inst_len: usize;
        let is_terminator: bool;
        let target: Option<i64>;
        if lo & 0b11 != 0b11 {
            // Compressed (2 bytes).
            inst_len = 2;
            // RVC encodings that are terminators in PVM2:
            //   c.j imm    (op=01, f3=101)        — static jump
            //   c.beqz / c.bnez (op=01, f3=110/111) — conditional branches
            //   c.jr / c.jalr / c.ebreak (op=10, f3=100) — all Reserved
            //     in PVM2; treated as terminators because reaching them
            //     panics. (The linker rewrites the c.jr-ra return idiom
            //     to a 4-byte br_table before reaching this pass, so any
            //     leftover c.jr is a true error.)
            //   c.illegal  (= 0x0000)             — reserved (terminator)
            // Other RVC ops are non-terminators.
            let op = lo & 0b11;
            let f3 = (lo >> 13) & 0b111;
            if lo == 0 {
                // c.illegal: terminator.
                is_terminator = true;
                target = None;
            } else if op == 0b01 && f3 == 0b101 {
                // c.j imm — terminator, has a static target.
                let imm = decompress_cj_imm(lo);
                is_terminator = true;
                target = Some(pc as i64 + imm as i64);
            } else if op == 0b01 && (f3 == 0b110 || f3 == 0b111) {
                // c.beqz / c.bnez — terminators with static targets.
                let imm = decompress_cb_imm(lo);
                is_terminator = true;
                target = Some(pc as i64 + imm as i64);
            } else if op == 0b10 && f3 == 0b100 {
                // (op=10, f3=100) family. Discriminate by bit12 / rdrs1 / rs2:
                //   (0, r, 0) r!=0  → c.jr     (= retf, terminator)
                //   (0, r, s) both!=0 → c.mv  (NOT a terminator)
                //   (1, 0, 0)        → c.ebreak (Reserved, terminator)
                //   (1, r, 0) r!=0   → c.jalr (Reserved, terminator)
                //   (1, r, s) both!=0 → c.add (NOT a terminator)
                let bit12 = (lo >> 12) & 1;
                let rdrs1 = (lo >> 7) & 0x1F;
                let rs2 = (lo >> 2) & 0x1F;
                // c.jr (bit12=0, rdrs1!=0, rs2=0)
                // c.ebreak (bit12=1, rdrs1=0, rs2=0)
                // c.jalr (bit12=1, rdrs1!=0, rs2=0)
                let is_jr_like = rs2 == 0 && (bit12 == 1 || rdrs1 != 0);
                is_terminator = is_jr_like;
                target = None;
            } else {
                is_terminator = false;
                target = None;
            }
        } else {
            // 4-byte instruction.
            if pc + 4 > n {
                break;
            }
            inst_len = 4;
            let w = u32::from_le_bytes([code[pc], code[pc + 1], code[pc + 2], code[pc + 3]]);
            let opcode = w & 0x7F;
            let funct3 = (w >> 12) & 0x7;
            match opcode {
                OP_JAL => {
                    let imm = imm_j(w);
                    is_terminator = true;
                    target = Some(pc as i64 + imm as i64);
                }
                0b110_0011 => {
                    // B-type branch (BEQ/BNE/etc.).
                    let imm = imm_b(w);
                    is_terminator = true;
                    target = Some(pc as i64 + imm as i64);
                }
                OP_CUSTOM_0 => {
                    // trap / ecalli / ecall.jar / br_table / fallthrough —
                    // all terminators. br_table successors come from the
                    // Image jump_table at runtime, not from an
                    // instruction-embedded immediate, so no static target.
                    is_terminator = true;
                    target = None;
                    let _ = funct3;
                }
                _ => {
                    is_terminator = false;
                    target = None;
                }
            }
        }
        let next_pc = pc + inst_len;
        if is_terminator && next_pc < n {
            post_terminator.insert(next_pc);
        }
        if let Some(t) = target
            && t >= 0
            && (t as usize) < n
        {
            static_edges.push((pc, t as usize));
        }
        pc = next_pc;
    }

    // ---- Pass 2: identify targets needing fallthrough injection ----
    let inst_starts_set: std::collections::HashSet<usize> = inst_starts.iter().copied().collect();
    let mut needs_inject: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    for &(_, target) in &static_edges {
        if !post_terminator.contains(&target) && inst_starts_set.contains(&target) {
            needs_inject.insert(target);
        }
    }
    // Also: endpoint entries / .rodata code-pointer targets — any PC
    // the host (or future indirect-dispatch lowering) might enter at.
    // The caller passes these via `extra_targets`.
    for &t in extra_targets {
        if t < n && !post_terminator.contains(&t) && inst_starts_set.contains(&t) {
            needs_inject.insert(t);
        }
    }

    if needs_inject.is_empty() {
        // No injections needed — old offsets are identity.
        let identity: BTreeMap<usize, usize> = inst_starts.into_iter().map(|p| (p, p)).collect();
        return Ok(identity);
    }

    // ---- Pass 3: build new code with fallthrough injected ----
    let new_len = n + needs_inject.len() * 4;
    let mut new_code: Vec<u8> = Vec::with_capacity(new_len);
    // old_pc → new_pc (only for old instruction-start positions; mid-
    // instruction bytes don't get mapped).
    let mut offset_map: BTreeMap<usize, usize> = BTreeMap::new();
    let fallthrough_word = encode_custom0_fallthrough();
    let fallthrough_bytes = fallthrough_word.to_le_bytes();

    let mut next_inject_iter = needs_inject.iter().peekable();
    let mut old_idx = 0;
    while old_idx < inst_starts.len() {
        let old_pc = inst_starts[old_idx];
        // If any injection is scheduled at this old_pc, emit fallthrough first.
        while let Some(&&inject_pc) = next_inject_iter.peek() {
            if inject_pc == old_pc {
                new_code.extend_from_slice(&fallthrough_bytes);
                next_inject_iter.next();
            } else {
                break;
            }
        }
        offset_map.insert(old_pc, new_code.len());
        let next_pc = inst_starts.get(old_idx + 1).copied().unwrap_or(n);
        let inst_len = next_pc - old_pc;
        new_code.extend_from_slice(&code[old_pc..old_pc + inst_len]);
        old_idx += 1;
    }

    // ---- Pass 4: re-encode branch / jal / callf offsets in new_code ----
    // Iterate over OLD instruction starts (not new_code) so we never
    // encounter the injected fallthrough instructions during this pass.
    for &old_pc in &inst_starts {
        let new_pc = offset_map[&old_pc];
        let lo = u16::from_le_bytes([new_code[new_pc], new_code[new_pc + 1]]);
        if lo & 0b11 != 0b11 {
            // RVC. c.j and c.beqz/c.bnez have static targets.
            let op = lo & 0b11;
            let f3 = (lo >> 13) & 0b111;
            if op == 0b01 && f3 == 0b101 {
                let old_imm = decompress_cj_imm(lo);
                let old_target = (old_pc as i64 + old_imm as i64) as usize;
                let new_target = *offset_map.get(&old_target).ok_or_else(|| {
                    TranspileError::InvalidSection(format!(
                        "align_branch_targets: c.j old target {:#x} not in offset_map",
                        old_target
                    ))
                })?;
                let new_imm = new_target as i64 - new_pc as i64;
                if new_imm != old_imm as i64 {
                    let new_h = encode_cj_imm(lo, new_imm as i32).ok_or_else(|| {
                        TranspileError::InvalidSection(format!(
                            "align_branch_targets: c.j at new_pc {:#x} new_imm {} \
                             out of ±2 KiB range",
                            new_pc, new_imm
                        ))
                    })?;
                    new_code[new_pc..new_pc + 2].copy_from_slice(&new_h.to_le_bytes());
                }
            } else if op == 0b01 && (f3 == 0b110 || f3 == 0b111) {
                let old_imm = decompress_cb_imm(lo);
                let old_target = (old_pc as i64 + old_imm as i64) as usize;
                let new_target = *offset_map.get(&old_target).ok_or_else(|| {
                    TranspileError::InvalidSection(format!(
                        "align_branch_targets: c.beqz/c.bnez old target {:#x} not in offset_map",
                        old_target
                    ))
                })?;
                let new_imm = new_target as i64 - new_pc as i64;
                if new_imm != old_imm as i64 {
                    let new_h = encode_cb_imm(lo, new_imm as i32).ok_or_else(|| {
                        TranspileError::InvalidSection(format!(
                            "align_branch_targets: c.beqz/c.bnez at new_pc {:#x} new_imm {} \
                             out of ±256 byte range",
                            new_pc, new_imm
                        ))
                    })?;
                    new_code[new_pc..new_pc + 2].copy_from_slice(&new_h.to_le_bytes());
                }
            }
        } else {
            let w = u32::from_le_bytes([
                new_code[new_pc],
                new_code[new_pc + 1],
                new_code[new_pc + 2],
                new_code[new_pc + 3],
            ]);
            let opcode = w & 0x7F;
            match opcode {
                OP_JAL => {
                    let old_imm = imm_j(w);
                    let old_target = (old_pc as i64 + old_imm as i64) as usize;
                    if let Some(&new_target) = offset_map.get(&old_target) {
                        let new_imm = new_target as i64 - new_pc as i64;
                        if !(-(1 << 20)..(1 << 20)).contains(&new_imm) {
                            return Err(TranspileError::InvalidSection(format!(
                                "align_branch_targets: JAL at new_pc {:#x} out of ±1 MiB \
                                 range after injection (new_imm = {})",
                                new_pc, new_imm
                            )));
                        }
                        let rd = (w >> 7) & 0x1F;
                        let v = new_imm as u32;
                        let b20 = (v >> 20) & 0x1;
                        let b10_1 = (v >> 1) & 0x3FF;
                        let b11 = (v >> 11) & 0x1;
                        let b19_12 = (v >> 12) & 0xFF;
                        let imm_field = (b20 << 31) | (b10_1 << 21) | (b11 << 20) | (b19_12 << 12);
                        let new_w = imm_field | (rd << 7) | OP_JAL;
                        new_code[new_pc..new_pc + 4].copy_from_slice(&new_w.to_le_bytes());
                    }
                }
                0b110_0011 => {
                    let old_imm = imm_b(w);
                    let old_target = (old_pc as i64 + old_imm as i64) as usize;
                    if let Some(&new_target) = offset_map.get(&old_target) {
                        let new_imm = new_target as i64 - new_pc as i64;
                        if !(-(1 << 12)..(1 << 12)).contains(&new_imm) {
                            return Err(TranspileError::InvalidSection(format!(
                                "align_branch_targets: B-type branch at new_pc {:#x} out of ±4 KiB \
                                 range after injection (new_imm = {})",
                                new_pc, new_imm
                            )));
                        }
                        let new_w = encode_b_imm(w, new_imm as i32);
                        new_code[new_pc..new_pc + 4].copy_from_slice(&new_w.to_le_bytes());
                    }
                }
                _ => {}
            }
        }
    }

    *code = new_code;
    Ok(offset_map)
}

/// Decompress a c.j (compressed jump) into a signed byte offset.
/// CJ-type immediate encoding (RV unprivileged spec).
fn decompress_cj_imm(h: u16) -> i32 {
    let h = h as u32;
    let b11 = (h >> 12) & 0x1;
    let b4 = (h >> 11) & 0x1;
    let b9_8 = (h >> 9) & 0x3;
    let b10 = (h >> 8) & 0x1;
    let b6 = (h >> 7) & 0x1;
    let b7 = (h >> 6) & 0x1;
    let b3_1 = (h >> 3) & 0x7;
    let b5 = (h >> 2) & 0x1;
    let raw = (b11 << 11)
        | (b10 << 10)
        | (b9_8 << 8)
        | (b7 << 7)
        | (b6 << 6)
        | (b5 << 5)
        | (b4 << 4)
        | (b3_1 << 1);
    ((raw as i32) << 20) >> 20
}

/// Decompress a c.beqz / c.bnez (compressed branch) into a signed byte offset.
fn decompress_cb_imm(h: u16) -> i32 {
    let h = h as u32;
    let b8 = (h >> 12) & 0x1;
    let b4_3 = (h >> 10) & 0x3;
    let b7_6 = (h >> 5) & 0x3;
    let b2_1 = (h >> 3) & 0x3;
    let b5 = (h >> 2) & 0x1;
    let raw = (b8 << 8) | (b7_6 << 6) | (b5 << 5) | (b4_3 << 3) | (b2_1 << 1);
    ((raw as i32) << 23) >> 23
}

/// Encode a new imm into a c.beqz / c.bnez instruction, preserving
/// funct3 / rs1' / opcode fields. `imm` must fit in 9 bits signed
/// (range ±256 bytes); returns None on overflow.
fn encode_cb_imm(h: u16, imm: i32) -> Option<u16> {
    if !(-(1 << 8)..(1 << 8)).contains(&imm) {
        return None;
    }
    if imm & 1 != 0 {
        return None;
    }
    let v = imm as u32;
    let b8 = (v >> 8) & 0x1;
    let b7_6 = (v >> 6) & 0x3;
    let b5 = (v >> 5) & 0x1;
    let b4_3 = (v >> 3) & 0x3;
    let b2_1 = (v >> 1) & 0x3;
    // Preserve: bits 15:13 (funct3), bits 9:7 (rs1'), bits 1:0 (opcode).
    let preserved = (h as u32) & 0b1110_0011_1000_0011;
    let new_imm = (b8 << 12) | (b4_3 << 10) | (b7_6 << 5) | (b2_1 << 3) | (b5 << 2);
    Some((preserved | new_imm) as u16)
}

/// Encode a new imm into a c.j instruction, preserving funct3 / opcode.
/// `imm` must fit in 12 bits signed (range ±2 KiB); returns None on overflow.
fn encode_cj_imm(h: u16, imm: i32) -> Option<u16> {
    if !(-(1 << 11)..(1 << 11)).contains(&imm) {
        return None;
    }
    if imm & 1 != 0 {
        return None;
    }
    let v = imm as u32;
    let b11 = (v >> 11) & 0x1;
    let b10 = (v >> 10) & 0x1;
    let b9_8 = (v >> 8) & 0x3;
    let b7 = (v >> 7) & 0x1;
    let b6 = (v >> 6) & 0x1;
    let b5 = (v >> 5) & 0x1;
    let b4 = (v >> 4) & 0x1;
    let b3_1 = (v >> 1) & 0x7;
    // Preserve: bits 15:13 (funct3), bits 1:0 (opcode).
    let preserved = (h as u32) & 0b1110_0000_0000_0011;
    let new_imm = (b11 << 12)
        | (b4 << 11)
        | (b9_8 << 9)
        | (b10 << 8)
        | (b6 << 7)
        | (b7 << 6)
        | (b3_1 << 3)
        | (b5 << 2);
    Some((preserved | new_imm) as u16)
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
    fn custom0_br_table_decodes() {
        // br_table table_id=7, rs1=x1 (ra).
        let w = encode_custom0_br_table(7, 1);
        assert_eq!(w & 0x7F, OP_CUSTOM_0);
        assert_eq!((w >> 7) & 0x1F, 0, "rd must be zero");
        assert_eq!((w >> 12) & 0x7, 0b011, "funct3 = 011");
        assert_eq!((w >> 15) & 0x1F, 1, "rs1 = ra");
        assert_eq!((w >> 20) & 0xFFF, 7, "imm12 = table_id");
    }

    #[test]
    fn custom0_fallthrough_decodes() {
        let w = encode_custom0_fallthrough();
        assert_eq!(w & 0x7F, OP_CUSTOM_0);
        assert_eq!((w >> 12) & 0x7, 0b100);
    }

    #[test]
    fn addi_encodes() {
        // addi ra, x0, 5
        let w = encode_addi(1, 0, 5);
        assert_eq!(w & 0x7F, 0b001_0011, "opcode = OP-IMM");
        assert_eq!((w >> 12) & 0x7, 0b000, "funct3 = addi");
        assert_eq!((w >> 7) & 0x1F, 1, "rd = ra");
        assert_eq!((w >> 15) & 0x1F, 0, "rs1 = x0");
        assert_eq!((w >> 20) & 0xFFF, 5, "imm = 5");
    }

    #[test]
    fn addi_negative_encoding() {
        // addi ra, x0, -1 — imm12 sign-extends to 0xFFF.
        let w = encode_addi(1, 0, -1);
        assert_eq!((w >> 20) & 0xFFF, 0xFFF);
    }

    #[test]
    fn jal_x0_round_trips_through_imm_j() {
        for &imm in &[0, 4, 8, -4, -8, 100, -100, 0x7_FFFE, -0x8_0000] {
            let w = encode_jal_x0(imm);
            assert_eq!(w & 0x7F, OP_JAL);
            assert_eq!((w >> 7) & 0x1F, 0);
            assert_eq!(imm_j(w), imm);
        }
    }

    #[test]
    fn cb_imm_round_trips() {
        // (op=01, f3=110 = beqz, rs1'=8, imm=0 placeholder) — start with a real beqz.
        // c.beqz x8 (rs1'=0), imm=0: f3=110, op=01, rs1'=0, all imm=0.
        let base = (0b110u16 << 13) | (0b01u16);
        for &imm in &[0, 2, -2, 4, -4, 128, -128, 254, -256] {
            let h = encode_cb_imm(base, imm).expect("in range");
            assert_eq!(
                decompress_cb_imm(h),
                imm,
                "round-trip failed for imm={}",
                imm
            );
        }
        assert!(encode_cb_imm(base, 256).is_none());
        assert!(encode_cb_imm(base, -258).is_none());
    }

    #[test]
    fn cj_imm_round_trips() {
        // c.j with f3=101, op=01.
        let base = (0b101u16 << 13) | (0b01u16);
        for &imm in &[0, 2, -2, 4, -4, 512, -512, 2046, -2048] {
            let h = encode_cj_imm(base, imm).expect("in range");
            assert_eq!(
                decompress_cj_imm(h),
                imm,
                "round-trip failed for imm={}",
                imm
            );
        }
        assert!(encode_cj_imm(base, 2048).is_none());
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
