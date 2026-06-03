//! ELF → PVM2 (raw RV+C+custom-0 bytes) linker.
//!
//! Pipeline:
//! 1. **Concatenate code sections** at their ELF vaddr offsets (typical
//!    LLD PIE output places each function in its own `.text.<sym>`).
//! 2. **Resolve AUIPC pairs.** *Data* references (an `auipc` paired with
//!    a load/store/addi of a low-memory address) fold to absolute
//!    `lui`+lo12 — data is relocated to its runtime address in
//!    `[DATA_BASE, …)` (the ELF's `[0, extent)` data layout shifted up
//!    by `DATA_BASE`), unrelated to where code maps. *Code* references
//!    (`R_RISCV_CALL_PLT` and
//!    code-targeting `PCREL_HI20`) stay native `auipc`+`jalr`/`addi`:
//!    code is mapped at [`CODE_BASE`], so the
//!    PC-relative computation lands on the right code VA. Kept pairs are
//!    re-encoded after step 4 if fallthrough injection shifts the layout
//!    (LUI is absolute, so injection-stable, and needs no fixup).
//! 3. **Replace standard ECALL markers**. The guest convention is
//!    `csrrw x0, 0x800/0x801, x0` followed by `ecall`; the marker slot
//!    becomes a NOP and the `ecall` a custom-0 `ecall.jar` / `ecalli`.
//! 4. **Inject fallthrough markers** before branch/jal/endpoint targets
//!    that aren't already post-terminator, so the predecoder's strict
//!    basic-block-start set — derived purely from the instruction stream
//!    — covers every reachable jump target. `jalr` targets are validated
//!    against that set at *runtime*; the linker never emits a trusted
//!    target table (the recompiler runs untrusted code).
//! 5. **Validate**: no x3/x4 use, no remaining standard `ecall` /
//!    `ebreak`, no CSR / atomic / FP / custom-1 / privileged encodings
//!    (see `~/docs/pvm-isa/05-pvm2-rv-diff.md`). `auipc`/`jalr` are
//!    standard PVM2 instructions and are accepted.
//! 6. **Emit Image** with the raw code bytes in [`Image::code`], mapped
//!    read-only at the fixed `CODE_BASE` by the runtime. The recompiler
//!    consumes the raw bytes directly.

use crate::TranspileError;
use crate::elf::parse_linked_elf;
use crate::layout::{
    CODE_BASE, DATA_BASE, HEAP_CAP_INDEX, MAX_CODE_SIZE, PVM_PAGE_SIZE, ProgramLayout,
    RO_CAP_INDEX, RW_CAP_INDEX, STACK_CAP_INDEX,
};
use javm_cap::SlotKey;
use javm_cap::abi::BARE_YIELD_CATCHER_SLOT;
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

/// Link an RV ELF into a PVM2 [`Image`]. [`Image::code`] holds the raw
/// RV+C+custom-0 bytes, mapped read-only at [`CODE_BASE`] by the runtime.
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

    let is_code_addr = |addr: u64| -> bool {
        elf.code_ranges
            .iter()
            .any(|(start, end)| addr >= *start && addr < *end)
    };

    // ---- 2. Resolve AUIPC pairs ------------------------------------
    //
    // lld emits each `auipc rd, hi20` with `hi20` chosen so that
    //   anchor := auipc_pc + sext(hi20 << 12)
    // sits within ±2 KiB of the symbol; the paired LO12 instruction
    // (load/store/addi/jalr) carries `lo12 = target - anchor`.
    //
    // *Data* references address the runtime `[DATA_BASE, …)` mapping
    // absolutely, so we fold them to `lui rd, hi; <op> rd, lo12`
    // (loading `target + DATA_BASE`; the +0x800 carry compensates
    // lo12's sign extension). LUI is absolute — unaffected by later
    // fallthrough injection.
    //
    // *Code* references stay native `auipc`/`jalr`/`addi`: code maps at
    // `CODE_BASE`, so `auipc`'s PC-relative result is already the right
    // code VA. We only record them here; their displacement is
    // re-encoded in step 4b after injection settles the final offsets.
    //
    // `code_auipc`: auipc byte-offset → target byte-offset.
    // `code_lo12`:  (lo12 offset, anchor-auipc offset, target offset).
    let mut code_auipc: BTreeMap<usize, usize> = BTreeMap::new();
    let mut code_lo12: Vec<(usize, usize, usize)> = Vec::new();

    // CALL_PLT — always a code target: `auipc` + `jalr` at +4.
    for (&call_v, &target) in &elf.call_targets {
        let auipc_off = vaddr_to_offset(call_v).ok_or_else(|| {
            TranspileError::InvalidSection(format!(
                "link_elf: CALL_PLT AUIPC at vaddr {call_v:#x} outside code section"
            ))
        })?;
        let target_off = vaddr_to_offset(target).ok_or_else(|| {
            TranspileError::InvalidSection(format!(
                "link_elf: CALL_PLT target {target:#x} (from {call_v:#x}) outside code section"
            ))
        })?;
        expect_auipc(&code, auipc_off, call_v)?;
        code_auipc.insert(auipc_off, target_off);
        if let Some(jalr_off) = vaddr_to_offset(call_v + 4) {
            code_lo12.push((jalr_off, auipc_off, target_off));
        }
    }

    // PCREL_HI20 — code target stays native `auipc`; data folds to LUI.
    for (&hi20_v, &target) in &elf.hi20_targets {
        let auipc_off = vaddr_to_offset(hi20_v).ok_or_else(|| {
            TranspileError::InvalidSection(format!(
                "link_elf: PCREL_HI20 AUIPC at vaddr {hi20_v:#x} outside code section"
            ))
        })?;
        if is_code_addr(target) {
            let target_off = vaddr_to_offset(target).ok_or_else(|| {
                TranspileError::InvalidSection(format!(
                    "link_elf: PCREL_HI20 code target {target:#x} (from {hi20_v:#x}) out of range"
                ))
            })?;
            expect_auipc(&code, auipc_off, hi20_v)?;
            code_auipc.insert(auipc_off, target_off);
        } else {
            // Data target: relocate from the ELF's `[0, extent)` data
            // layout to the runtime `[DATA_BASE, …)` mapping.
            let data_target = target.wrapping_add(u64::from(DATA_BASE));
            fold_auipc_to_lui(
                &mut code,
                auipc_off,
                hi20_v,
                (data_target & 0xFFFF_FFFF) as u32,
            )?;
        }
    }

    // PCREL_LO12 — code lo12 re-encoded in step 4b; data lo12 patched
    // to the absolute target's low 12 bits now.
    for (&lo_v, &target) in &elf.lo12_targets {
        let Some(lo_off) = vaddr_to_offset(lo_v) else {
            continue;
        };
        if lo_off + 4 > code.len() {
            continue;
        }
        if is_code_addr(target) {
            if let Some(&hi20_v) = elf.lo12_to_hi20.get(&lo_v)
                && let (Some(auipc_off), Some(target_off)) =
                    (vaddr_to_offset(hi20_v), vaddr_to_offset(target))
            {
                code_lo12.push((lo_off, auipc_off, target_off));
            }
        } else {
            // Data target: relocate to the runtime `[DATA_BASE, …)`
            // mapping (DATA_BASE is page-aligned, so the low 12 bits the
            // LO12 carries are unchanged — kept explicit for clarity).
            let data_target = target.wrapping_add(u64::from(DATA_BASE));
            patch_lo12_abs(&mut code, lo_off, (data_target & 0xFFFF_FFFF) as u32);
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

    // ---- 4. Fallthrough injection ----------------------------------
    //
    // Branch / jal / endpoint / rodata-code-pointer targets aren't
    // necessarily post-terminator. Inject `fallthrough` (4 bytes,
    // custom-0, terminator no-op) before each such target so the
    // predecode's strict basic-block-start set — derived purely from
    // the instruction stream, never trusted from linker metadata —
    // covers everything reachable. `jalr` targets are validated against
    // that set at runtime.
    //
    // A statically-known jalr target must be a block start too. Resume
    // PCs (the instruction after a call's jalr) already are — jalr is a
    // terminator, so its successor is post-terminator. But the *call
    // targets* (CALL_PLT and code-`hi20` function entries reached via
    // `auipc`+`jalr`) are not static jal edges, so they're fed as
    // `extra_targets` alongside endpoint entries and `.rodata`
    // code-pointer targets. `align_branch_targets` only injects where a
    // target isn't already post-terminator, so entries that already
    // follow a `ret`/`j` cost nothing.
    let endpoint_entries_pre: Vec<usize> = {
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
                    Some((fn_ptr - base_vaddr) as usize)
                })
                .collect(),
            Err(_) => Vec::new(),
        }
    };
    let rodata_targets_pre: Vec<usize> = elf
        .abs_code_ptrs
        .iter()
        .filter_map(|&(_, rv_target, _)| {
            if is_code_addr(rv_target) {
                Some(rv_target.wrapping_sub(base_vaddr) as usize)
            } else {
                None
            }
        })
        .collect();
    let mut extra_targets: Vec<usize> = endpoint_entries_pre;
    extra_targets.extend_from_slice(&rodata_targets_pre);
    extra_targets.extend(code_auipc.values().copied());
    let offset_map = align_branch_targets(&mut code, &extra_targets)?;

    // ---- 4b. Re-encode kept code-relative pairs --------------------
    //
    // Injection may have shifted offsets between an `auipc` and its
    // target, invalidating the original displacement. Recompute each
    // kept pair's PC-relative split against the post-injection layout.
    fixup_code_pcrel(&mut code, &offset_map, &code_auipc, &code_lo12)?;

    // ---- 5. Validation pass ----------------------------------------
    //
    // Walk every 2- or 4-byte instruction boundary (RV+C self-describes
    // length via op[1:0]) and reject anything that PVM2 forbids.
    validate_pvm2(&code)?;

    // ---- 5b. Rewrite code pointers in .rodata -----------------------
    //
    // Function pointer tables (e.g. LLVM jump tables, vtables) store
    // code addresses as raw u32/u64 values in .rodata. The original
    // values are ELF vaddrs; at runtime a `jalr` through such a pointer
    // validates the target VA against the basic-block-start set, so each
    // pointer must become `CODE_BASE + post-injection byte offset`.
    //
    // SUB32-based relative jump tables (entries `target - base`) are
    // left as-is: their base register is loaded from a *data* address
    // (the table lives in `.rodata`), so `base + delta` reconstructs the
    // ELF vaddr, not `CODE_BASE + offset`. Such a `jalr` target fails the
    // runtime block-start check and faults loudly rather than corrupting
    // state — relocating relative tables into the CODE_BASE model is a
    // follow-up (TODO). The absolute-pointer path below is correct.
    let mut ro_data_rewritten = elf.ro_data.clone();
    let ro_base = elf.stack_size as u64;
    {
        // Build a set of vaddrs handled via sub32 (so we skip them in
        // the absolute-rewrite pass).
        let sub32_data_vaddrs: std::collections::HashSet<u64> =
            elf.sub32_relocs.iter().map(|(v, _)| *v).collect();

        // Translate a code address (RV vaddr) to its guest VA:
        // `CODE_BASE + post-injection byte offset within the region`.
        let translate_code_addr = |rv_target: u64| -> u32 {
            let pre = rv_target.wrapping_sub(base_vaddr) as usize;
            let off = offset_map.get(&pre).copied().unwrap_or(pre);
            CODE_BASE.wrapping_add(off as u32)
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

    // ---- 5c. Relocate absolute data pointers ------------------------
    //
    // Pointers stored in data that point *into data* (e.g. `&'static`
    // constants in `.data.rel.ro`) hold ELF data vaddrs (the `[0,
    // extent)` layout). The runtime maps data at `[DATA_BASE, …)`, so
    // shift each by `+DATA_BASE`. Data-targeting abs relocs the parser
    // captured but the code-pointer pass above ignored. A pointer that
    // lands in neither the RO nor RW blob is unrelocatable — error
    // loudly rather than emit a silently-wrong pointer.
    let mut rw_data_rewritten = elf.rw_data.clone();
    {
        let ro_base = elf.stack_size as u64;
        let rw_base = elf.rw_base;
        for &(data_vaddr, target, size) in &elf.abs_data_ptrs {
            let new_val = target.wrapping_add(u64::from(DATA_BASE));
            let n = size as usize;
            let bytes = new_val.to_le_bytes();
            if data_vaddr >= ro_base
                && (data_vaddr - ro_base) as usize + n <= ro_data_rewritten.len()
            {
                let off = (data_vaddr - ro_base) as usize;
                ro_data_rewritten[off..off + n].copy_from_slice(&bytes[..n]);
            } else if data_vaddr >= rw_base
                && (data_vaddr - rw_base) as usize + n <= rw_data_rewritten.len()
            {
                let off = (data_vaddr - rw_base) as usize;
                rw_data_rewritten[off..off + n].copy_from_slice(&bytes[..n]);
            } else {
                return Err(TranspileError::InvalidSection(format!(
                    "link_elf: absolute data pointer at vaddr {data_vaddr:#x} (→ {target:#x}) \
                     falls outside the RO/RW data blobs; cannot relocate to DATA_BASE"
                )));
            }
        }
    }

    // ---- 6. Endpoints -----------------------------------------------
    //
    // `entry_pc` stays a code-region byte offset; the runtime adds
    // `CODE_BASE` when it seeds the PC. Remap through `offset_map` to
    // account for any fallthrough injection.
    let mut endpoints = read_subsoil_endpoints_rv(elf_data, base_vaddr, code.len())?;
    for def in endpoints.values_mut() {
        let pre = def.entry_pc as usize;
        if let Some(&new) = offset_map.get(&pre) {
            def.entry_pc = new as u64;
        }
    }

    // ---- 7. Memory layout + Image construction ----------------------
    let ro_data = ro_data_rewritten;
    let rw_data = rw_data_rewritten;

    let stack_pages = elf.stack_size / PVM_PAGE_SIZE;
    let ro_pages = (ro_data.len() as u32).div_ceil(PVM_PAGE_SIZE);
    let rw_pages = (rw_data.len() as u32).div_ceil(PVM_PAGE_SIZE);
    let layout = ProgramLayout::compute(stack_pages, ro_pages, rw_pages, elf.heap_pages);
    let stack_top = layout.stack_top();

    for def in endpoints.values_mut() {
        def.initial_regs.insert(SP_REG, stack_top);
    }

    let mut memory_mappings: Vec<MemoryMapping> = Vec::new();
    let mut pinned_slots: BTreeMap<SlotKey, PinnedCap> = BTreeMap::new();
    let mut initial_slots: BTreeMap<SlotKey, InitialDataCap> = BTreeMap::new();
    let page_bytes = u64::from(PVM_PAGE_SIZE);

    let stack_slot = SlotKey::from(STACK_CAP_INDEX);
    let stack_size = u64::from(layout.stack.page_count) * page_bytes;
    memory_mappings.push(MemoryMapping {
        start: u64::from(layout.stack.base_page) * page_bytes,
        size: stack_size,
        source: SlotPath::root(stack_slot.clone()),
    });
    initial_slots.insert(
        stack_slot,
        InitialDataCap {
            content: Vec::new(),
            size: stack_size,
        },
    );

    if let Some(ro) = &layout.ro {
        let ro_slot = SlotKey::from(RO_CAP_INDEX);
        let size = u64::from(ro.page_count) * page_bytes;
        memory_mappings.push(MemoryMapping {
            start: u64::from(ro.base_page) * page_bytes,
            size,
            source: SlotPath::root(ro_slot.clone()),
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
        let rw_slot = SlotKey::from(RW_CAP_INDEX);
        let size = u64::from(rw.page_count) * page_bytes;
        memory_mappings.push(MemoryMapping {
            start: u64::from(rw.base_page) * page_bytes,
            size,
            source: SlotPath::root(rw_slot.clone()),
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
        let heap_slot = SlotKey::from(HEAP_CAP_INDEX);
        let size = u64::from(heap.page_count) * page_bytes;
        memory_mappings.push(MemoryMapping {
            start: u64::from(heap.base_page) * page_bytes,
            size,
            source: SlotPath::root(heap_slot.clone()),
        });
        initial_slots.insert(
            heap_slot,
            InitialDataCap {
                content: Vec::new(),
                size,
            },
        );
    }

    // Layout geometry: code occupies `[CODE_BASE, CODE_BASE +
    // code_size)` and must stay below DATA_BASE (i.e. `code_size ≤
    // MAX_CODE_SIZE`); data occupies `[DATA_BASE, DATA_BASE +
    // data_extent)` and must stay within the 4 GiB guest range.
    let code_base = u64::from(CODE_BASE);
    let code_size = (code.len() as u64).div_ceil(page_bytes) * page_bytes;
    if code_base + code_size > u64::from(DATA_BASE) {
        return Err(TranspileError::InvalidSection(format!(
            "link_elf: code size {code_size:#x} exceeds MAX_CODE_SIZE {:#x} (would overlap DATA_BASE {:#x})",
            MAX_CODE_SIZE, DATA_BASE,
        )));
    }
    let data_end = u64::from(DATA_BASE) + u64::from(layout.total_data_pages()) * page_bytes;
    if data_end > (1u64 << 32) {
        return Err(TranspileError::InvalidSection(format!(
            "link_elf: data end {data_end:#x} exceeds the 4 GiB guest range"
        )));
    }
    // Code is mapped RO at the fixed `CODE_BASE` by the runtime — not
    // via a declarative mapping, so an untrusted Image cannot relocate
    // it. `memory_mappings` describes data/slot regions only.

    Ok(Image {
        code,
        endpoints,
        memory_mappings,
        pinned_slots,
        initial_slots,
        yield_marker_slot: Some(SlotKey::from(BARE_YIELD_CATCHER_SLOT)),
    })
}

/// Verify the 4 bytes at `off` decode to an `auipc`; error otherwise.
/// Used before recording a code reference whose AUIPC we keep native.
fn expect_auipc(code: &[u8], off: usize, v: u64) -> Result<(), TranspileError> {
    if off + 4 > code.len() {
        return Err(TranspileError::InvalidSection(format!(
            "link_elf: AUIPC reloc at vaddr {v:#x} truncated by section end"
        )));
    }
    let word = u32::from_le_bytes([code[off], code[off + 1], code[off + 2], code[off + 3]]);
    if word & 0x7F != OP_AUIPC {
        return Err(TranspileError::InvalidSection(format!(
            "link_elf: reloc at vaddr {v:#x} not an AUIPC (opcode {:#x})",
            word & 0x7F
        )));
    }
    Ok(())
}

/// Fold a *data* `auipc rd, hi20` at `off` into `lui rd, hi` loading the
/// absolute 4 KiB-aligned base of `eff` (the paired lo12 supplies the
/// rest). The +0x800 carry compensates the lo12's sign extension.
fn fold_auipc_to_lui(code: &mut [u8], off: usize, v: u64, eff: u32) -> Result<(), TranspileError> {
    if off + 4 > code.len() {
        return Err(TranspileError::InvalidSection(format!(
            "link_elf: AUIPC reloc at vaddr {v:#x} truncated by section end"
        )));
    }
    let word = u32::from_le_bytes([code[off], code[off + 1], code[off + 2], code[off + 3]]);
    if word & 0x7F != OP_AUIPC {
        return Err(TranspileError::InvalidSection(format!(
            "link_elf: reloc at vaddr {v:#x} not an AUIPC (opcode {:#x})",
            word & 0x7F
        )));
    }
    let rd = (word >> 7) & 0x1F;
    let new_word = (eff.wrapping_add(0x800) & 0xFFFF_F000) | (rd << 7) | OP_LUI;
    code[off..off + 4].copy_from_slice(&new_word.to_le_bytes());
    Ok(())
}

/// Patch a *data* LO12 instruction (I- or S-type) with the absolute
/// low 12 bits of `eff` (sign-extended).
fn patch_lo12_abs(code: &mut [u8], off: usize, eff: u32) {
    let new_lo12 = ((eff as i32) << 20) >> 20;
    match code[off] & 0x7F {
        // I-type (load, addi, jalr) — imm in [31:20].
        0b0000011 | 0b0010011 | 0b1100111 => patch_imm_i(&mut code[off..off + 4], new_lo12),
        // S-type (store) — imm[11:5] in [31:25], imm[4:0] in [11:7].
        0b0100011 => patch_imm_s(&mut code[off..off + 4], new_lo12),
        _ => {}
    }
}

/// Re-encode the displacement of every kept code-relative `auipc` pair
/// against the post-injection layout. The `auipc` carries the high 20
/// bits (with the +0x800 carry) and the paired `jalr`/`addi`/load/store
/// the low 12 (sign-extended), both relative to the *AUIPC's* PC.
fn fixup_code_pcrel(
    code: &mut [u8],
    offset_map: &BTreeMap<usize, usize>,
    code_auipc: &BTreeMap<usize, usize>,
    code_lo12: &[(usize, usize, usize)],
) -> Result<(), TranspileError> {
    let remap = |o: usize| -> Result<usize, TranspileError> {
        offset_map.get(&o).copied().ok_or_else(|| {
            TranspileError::InvalidSection(format!(
                "fixup_code_pcrel: offset {o:#x} not in offset_map"
            ))
        })
    };
    for (&auipc_off, &target_off) in code_auipc {
        let na = remap(auipc_off)?;
        let nt = remap(target_off)?;
        if na + 4 > code.len() {
            continue;
        }
        let word = u32::from_le_bytes([code[na], code[na + 1], code[na + 2], code[na + 3]]);
        if word & 0x7F != OP_AUIPC {
            return Err(TranspileError::InvalidSection(format!(
                "fixup_code_pcrel: expected AUIPC at offset {na:#x} (opcode {:#x})",
                word & 0x7F
            )));
        }
        let disp = nt as i64 - na as i64;
        let rd = (word >> 7) & 0x1F;
        let new_word = ((disp as u32).wrapping_add(0x800) & 0xFFFF_F000) | (rd << 7) | OP_AUIPC;
        code[na..na + 4].copy_from_slice(&new_word.to_le_bytes());
    }
    for &(lo12_off, auipc_off, target_off) in code_lo12 {
        let nl = remap(lo12_off)?;
        let na = remap(auipc_off)?;
        let nt = remap(target_off)?;
        if nl + 4 > code.len() {
            continue;
        }
        let disp = nt as i64 - na as i64;
        let new_lo12 = ((disp as i32) << 20) >> 20;
        match code[nl] & 0x7F {
            0b0000011 | 0b0010011 | 0b1100111 => patch_imm_i(&mut code[nl..nl + 4], new_lo12),
            0b0100011 => patch_imm_s(&mut code[nl..nl + 4], new_lo12),
            _ => {}
        }
    }
    Ok(())
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
        // I-type ALU (OP-IMM, OP-IMM-32) and JALR — rd + rs1 are
        // registers; the I-type slot holds the immediate.
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
            OP_CUSTOM_1 => {
                return Err(TranspileError::InvalidSection(format!(
                    "link_elf: custom-1 opcode at offset {:#x} is reserved in PVM2",
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
        // Reserved registers: x3/x4 (PVM2-specific) and x16..x31 (do not
        // exist in RV64E — a 16-register base — so they are illegal). This
        // producer-side check mirrors the consensus source of truth,
        // `javm_exec::regs::reg_is_reserved`; kept local so the transpiler
        // need not depend on the executor crate.
        let check = |name: &str, r: u32| -> Result<(), TranspileError> {
            if r == 3 || r == 4 || r >= 16 {
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

/// Encode custom-0 `fallthrough` (funct3 = 100; all other fields zero).
/// A 4-byte terminator no-op that creates a bb_start at the next byte.
#[inline]
fn encode_custom0_fallthrough() -> u32 {
    (0b100 << 12) | OP_CUSTOM_0
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

/// Walk the code and inject a `fallthrough` (4 bytes) before every
/// JAL / branch target that isn't already preceded by a terminator
/// instruction. After injection, all reachable static targets are
/// guaranteed to be in the strict bb_starts set the predecode computes.
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
    //  - The list of (branch_or_jal_pc, target_pc) static edges.
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
            //   c.jr (op=10, f3=100) — `jalr x0, rs1, 0` (return /
            //     indirect jump): a terminator. c.jalr is a call (also a
            //     terminator); c.ebreak is Reserved (panics, terminator).
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
                OP_JALR => {
                    // jalr — return / indirect call. A terminator; its
                    // successor comes via the runtime dispatch table, not
                    // a static immediate.
                    is_terminator = true;
                    target = None;
                }
                0b110_0011 => {
                    // B-type branch (BEQ/BNE/etc.).
                    let imm = imm_b(w);
                    is_terminator = true;
                    target = Some(pc as i64 + imm as i64);
                }
                OP_CUSTOM_0 => {
                    // trap / ecalli / ecall.jar / fallthrough — all
                    // terminators with no statically-embedded successor.
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
    fn custom0_fallthrough_decodes() {
        let w = encode_custom0_fallthrough();
        assert_eq!(w & 0x7F, OP_CUSTOM_0);
        assert_eq!((w >> 12) & 0x7, 0b100);
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
    fn validate_accepts_auipc_and_jalr() {
        // PVM2 now uses native RISC-V control flow: AUIPC computes a
        // code VA, JALR jumps to it (validated against bb_starts at
        // runtime). Both are accepted by the linker.
        let auipc = (0x1000u32 << 12) | (1 << 7) | OP_AUIPC; // auipc x1, 0x1000
        validate_pvm2(&auipc.to_le_bytes()).unwrap();
        let jalr = (1u32 << 15) | (1 << 7) | OP_JALR; // jalr x1, x1, 0
        validate_pvm2(&jalr.to_le_bytes()).unwrap();
        // jalr to x3/x4 is still forbidden (reserved registers).
        let jalr_x3 = (3u32 << 15) | (1 << 7) | OP_JALR; // jalr x1, x3, 0
        assert!(validate_pvm2(&jalr_x3.to_le_bytes()).is_err());
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
