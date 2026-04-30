//! Shared program layout for transpiler-emitted JAR blobs.
//!
//! [`ProgramLayout`] assigns `cap_index`, `base_page`, `page_count`, and
//! `access` to each DATA cap that appears in a transpiler-emitted blob.
//! It is computed once per blob and consumed by:
//!
//! - [`crate::emitter::build_service_program`], to populate the JAR
//!   manifest (`CapManifestEntry` per DATA cap; the manifest no longer
//!   carries `base_page`/`init_access` after the kernel-side pre-mmap
//!   was retired).
//! - [`emit_prologue`], to emit the stackless `MGMT_MAP` prologue plus
//!   `load_imm_64 SP, stack_top` that runs before user code. The kernel
//!   no longer pre-maps DATA caps; the prologue is the guest's
//!   responsibility.
//!
//! Cap-index convention: 64 = CODE, 65 = stack, 66 = ro, 67 = rw,
//! 68 = heap, 69 = args. Address layout starts at page 0 and stacks
//! linearly: stack lives at `[0, stack_pages)`, ro at
//! `[stack_pages, stack_pages + ro_pages)`, etc.

use javm::cap::Access;

/// Cap index of the CODE cap in transpiler-emitted blobs. Matches the
/// JAR `init_cap` field.
pub const CODE_CAP_INDEX: u8 = 64;
/// Cap index of the stack DATA cap.
pub const STACK_CAP_INDEX: u8 = 65;
/// Cap index of the read-only DATA cap (`.rodata`).
pub const RO_CAP_INDEX: u8 = 66;
/// Cap index of the read-write DATA cap (`.data` + `.bss`).
pub const RW_CAP_INDEX: u8 = 67;
/// Cap index of the heap DATA cap.
pub const HEAP_CAP_INDEX: u8 = 68;
/// PVM page size in bytes.
pub const PVM_PAGE_SIZE: u32 = 4096;

/// One DATA cap's layout: where it lives in the manifest, where it maps
/// in guest memory, and at what access mode.
#[derive(Debug, Clone, Copy)]
pub struct DataCapEntry {
    pub cap_index: u8,
    pub base_page: u32,
    pub page_count: u32,
    pub access: Access,
}

/// Full DATA-cap layout of a transpiler-emitted blob. `stack` and
/// `args` are always present; `ro`, `rw`, `heap` are present only when
/// their page count is non-zero.
#[derive(Debug, Clone)]
pub struct ProgramLayout {
    pub stack: DataCapEntry,
    pub ro: Option<DataCapEntry>,
    pub rw: Option<DataCapEntry>,
    pub heap: Option<DataCapEntry>,
    pub args: DataCapEntry,
}

impl ProgramLayout {
    /// Compute the layout from per-region page counts. `stack_pages`
    /// must be ≥ 1 in any sane build, but the function does not enforce
    /// that. `ro_pages`, `rw_pages`, `heap_pages` of zero omit those
    /// caps entirely.
    pub fn compute(stack_pages: u32, ro_pages: u32, rw_pages: u32, heap_pages: u32) -> Self {
        let mut next_page = 0u32;

        let stack = DataCapEntry {
            cap_index: STACK_CAP_INDEX,
            base_page: next_page,
            page_count: stack_pages,
            access: Access::RW,
        };
        next_page += stack_pages;

        let ro = if ro_pages > 0 {
            let e = DataCapEntry {
                cap_index: RO_CAP_INDEX,
                base_page: next_page,
                page_count: ro_pages,
                access: Access::RO,
            };
            next_page += ro_pages;
            Some(e)
        } else {
            None
        };

        let rw = if rw_pages > 0 {
            let e = DataCapEntry {
                cap_index: RW_CAP_INDEX,
                base_page: next_page,
                page_count: rw_pages,
                access: Access::RW,
            };
            next_page += rw_pages;
            Some(e)
        } else {
            None
        };

        let heap = if heap_pages > 0 {
            let e = DataCapEntry {
                cap_index: HEAP_CAP_INDEX,
                base_page: next_page,
                page_count: heap_pages,
                access: Access::RW,
            };
            next_page += heap_pages;
            Some(e)
        } else {
            None
        };

        let args = DataCapEntry {
            cap_index: crate::ARGS_CAP_INDEX,
            base_page: next_page,
            page_count: 1,
            access: Access::RW,
        };

        Self {
            stack,
            ro,
            rw,
            heap,
            args,
        }
    }

    /// Iterate every DATA cap entry in cap-index (and base-page) order:
    /// stack, ro?, rw?, heap?, args.
    pub fn data_caps(&self) -> impl Iterator<Item = &DataCapEntry> + '_ {
        std::iter::once(&self.stack)
            .chain(self.ro.iter())
            .chain(self.rw.iter())
            .chain(self.heap.iter())
            .chain(std::iter::once(&self.args))
    }

    /// Top-of-stack address (initial SP). RISC-V SP grows downward, so
    /// the first push lands at `stack_top - 8`.
    pub fn stack_top(&self) -> u64 {
        (self.stack.base_page + self.stack.page_count) as u64 * PVM_PAGE_SIZE as u64
    }

    /// Total pages across all DATA caps in this layout. Used by
    /// `build_service_program` to compute `memory_pages` (the
    /// per-invocation Untyped budget).
    pub fn total_data_pages(&self) -> u32 {
        self.data_caps().map(|d| d.page_count).sum()
    }
}

// =============================================================================
// Prologue emission
//
// PVM/JAVM is Harvard: CODE bytes execute from the CodeCap, never via a
// mapped DATA address. The prologue can therefore run with the entire
// data address space unmapped, as long as it sticks to register-only
// instructions (no loads/stores, no stack spills) until at least the
// stack DATA cap is mapped.
//
// Each `MGMT_MAP` is encoded as a no-immediate `ecall` (PVM opcode 3).
// `ecalli` (opcode 10) accepts only `imm ∈ [0, 127]`, so management ops
// are dispatched via `ecall` instead, with the op selector in φ[11] and
// the cap-ref in the low 32 bits of φ[12]. `ecall_map` (the kernel
// handler) reads:
//
//   φ[7]  = base_offset   (where in the active VM's window to map the cap)
//   φ[8]  = page_offset   (within the cap, which page to start; 0 = start)
//   φ[9]  = page_count    (how many pages to map)
//   φ[10] = access        (0 = RO, 1 = RW)
//   φ[11] = MGMT_MAP_OP   (= 0x02)
//   φ[12] = subject_ref   (low 32 bits = cap-ref to the DATA cap)
//
// A direct cap-ref to slot N is the bare value `N` with no indirection
// bytes — just the low byte of the u32. The high 32 bits of φ[12] are
// the object-ref, unused for MAP.
//
// Per-cap emission (61 bytes):
//   load_imm_64 φ[7],  base_page            (10 bytes)
//   load_imm_64 φ[8],  0                    (10 bytes)
//   load_imm_64 φ[9],  page_count           (10 bytes)
//   load_imm_64 φ[10], access (0|1)         (10 bytes)
//   load_imm_64 φ[11], MGMT_MAP_OP          (10 bytes)
//   load_imm_64 φ[12], cap_index            (10 bytes)
//   ecall                                    ( 1 byte)
//
// Plus, after the stack is mapped, a single SP setup (10 bytes):
//   load_imm_64 SP, stack_top
//
// SP setup is sequenced AFTER the stack `MGMT_MAP` so any subsequent
// instruction that touches memory (none in the prologue itself, but
// user code right after) finds the stack already mapped.
// =============================================================================

/// PVM opcode for `load_imm_64 reg, imm64` (10 bytes total).
const PVM_OPCODE_LOAD_IMM_64: u8 = 20;
/// PVM opcode for `ecall` (1 byte; no immediate, op in φ[11]).
const PVM_OPCODE_ECALL: u8 = 3;
/// PVM opcode for `move_reg rd, ra` (2 bytes total).
const PVM_OPCODE_MOVE_REG: u8 = 100;
/// Stack-pointer register.
const SP_REG: u8 = 1;
/// `ecall_map` argument register layout (mirrors `javm::kernel::ecall_map`).
const ARG_REG_BASE_OFFSET: u8 = 7;
const ARG_REG_PAGE_OFFSET: u8 = 8;
const ARG_REG_PAGE_COUNT: u8 = 9;
const ARG_REG_ACCESS: u8 = 10;
const ARG_REG_OP: u8 = 11;
const ARG_REG_REFS: u8 = 12;
/// Scratch registers used to save/restore φ[7..=12] across the
/// prologue. The prologue clobbers φ[7..=12] for `MGMT_MAP` arg
/// passing; we save them to φ[0] + φ[2..=6] (T0..T2, S0..S1, RA)
/// before the first MGMT_MAP and restore after the last, so
/// host-set arg registers survive the prologue.
const SCRATCH_REGS: [u8; 6] = [0, 2, 3, 4, 5, 6];

/// Emit `load_imm_64 reg, value` (PVM opcode 20, 10 bytes total:
/// opcode + reg + 8-byte LE immediate). Bitmask: `1, 0, 0, 0, 0, 0, 0, 0, 0, 0`.
fn emit_load_imm_64(code: &mut Vec<u8>, bitmask: &mut Vec<u8>, reg: u8, value: u64) {
    code.push(PVM_OPCODE_LOAD_IMM_64);
    code.push(reg);
    code.extend_from_slice(&value.to_le_bytes());
    bitmask.push(1);
    for _ in 0..9 {
        bitmask.push(0);
    }
}

/// Emit `ecall` (PVM opcode 3, 1 byte total). Bitmask: `1`. ecall is a
/// terminator — the next instruction must be a basic-block start.
fn emit_ecall(code: &mut Vec<u8>, bitmask: &mut Vec<u8>) {
    code.push(PVM_OPCODE_ECALL);
    bitmask.push(1);
}

/// Emit `move_reg rd, ra` (PVM opcode 100, 2 bytes total: opcode + reg
/// byte where reg_byte = `(ra << 4) | rd`). Bitmask: `1, 0`.
fn emit_move_reg(code: &mut Vec<u8>, bitmask: &mut Vec<u8>, rd: u8, ra: u8) {
    code.push(PVM_OPCODE_MOVE_REG);
    code.push(((ra & 0x0F) << 4) | (rd & 0x0F));
    bitmask.push(1);
    bitmask.push(0);
}

/// Save host-set φ[7..=12] into [`SCRATCH_REGS`] before the prologue
/// clobbers them. 12 bytes (6 × `move_reg`).
fn emit_save_arg_regs(code: &mut Vec<u8>, bitmask: &mut Vec<u8>) {
    let arg_regs = [
        ARG_REG_BASE_OFFSET,
        ARG_REG_PAGE_OFFSET,
        ARG_REG_PAGE_COUNT,
        ARG_REG_ACCESS,
        ARG_REG_OP,
        ARG_REG_REFS,
    ];
    for (scratch, src) in SCRATCH_REGS.iter().zip(arg_regs.iter()) {
        emit_move_reg(code, bitmask, *scratch, *src);
    }
}

/// Restore φ[7..=12] from [`SCRATCH_REGS`] after the prologue's
/// MGMT_MAPs are done. 12 bytes (6 × `move_reg`).
fn emit_restore_arg_regs(code: &mut Vec<u8>, bitmask: &mut Vec<u8>) {
    let arg_regs = [
        ARG_REG_BASE_OFFSET,
        ARG_REG_PAGE_OFFSET,
        ARG_REG_PAGE_COUNT,
        ARG_REG_ACCESS,
        ARG_REG_OP,
        ARG_REG_REFS,
    ];
    for (dst, scratch) in arg_regs.iter().zip(SCRATCH_REGS.iter()) {
        emit_move_reg(code, bitmask, *dst, *scratch);
    }
}

/// Emit the `MGMT_MAP` ecall sequence for one DATA cap entry: six
/// `load_imm_64` setups (61 bytes total including the trailing ecall).
fn emit_mgmt_map(code: &mut Vec<u8>, bitmask: &mut Vec<u8>, entry: &DataCapEntry) {
    let base_offset = entry.base_page;
    let page_count = entry.page_count;
    let access_word: u64 = match entry.access {
        Access::RO => 0,
        Access::RW => 1,
    };
    emit_load_imm_64(code, bitmask, ARG_REG_BASE_OFFSET, base_offset as u64);
    emit_load_imm_64(code, bitmask, ARG_REG_PAGE_OFFSET, 0);
    emit_load_imm_64(code, bitmask, ARG_REG_PAGE_COUNT, page_count as u64);
    emit_load_imm_64(code, bitmask, ARG_REG_ACCESS, access_word);
    emit_load_imm_64(code, bitmask, ARG_REG_OP, javm::kernel::MGMT_MAP as u64);
    // φ[12] = (subject_ref << 32) | object_ref. The kernel reads:
    //   subject_ref = (φ[12] >> 32) as u32
    //   object_ref  = (φ[12] & 0xFFFFFFFF) as u32
    // Subject is a direct cap-ref to the cap_index slot (no
    // indirection); object is unused for MAP.
    let refs: u64 = (entry.cap_index as u64) << 32;
    emit_load_imm_64(code, bitmask, ARG_REG_REFS, refs);
    emit_ecall(code, bitmask);
}

/// Emit the stackless `MGMT_MAP` prologue + SP setup for the given
/// layout. Returns `(code, bitmask)` ready to be prepended to user
/// code. The prologue runs at PC=0 of every invocation; user code
/// follows immediately after (no trailing jump — falls through).
///
/// Emission order:
/// 1. `MGMT_MAP` for the stack cap (so subsequent stack accesses work).
/// 2. `load_imm_64 SP, stack_top` (RISC-V SP grows down).
/// 3. `MGMT_MAP` for ro / rw / heap (skipping absent ones).
/// 4. `MGMT_MAP` for args.
///
/// Caller must shift `jump_table` entries by `code.len()` after
/// concatenating user code, since they encode absolute byte offsets
/// into the final code blob.
pub fn emit_prologue(layout: &ProgramLayout) -> (Vec<u8>, Vec<u8>) {
    let mut code = Vec::new();
    let mut bitmask = Vec::new();

    // 1. Save host-set φ[7..=12] into scratch regs (φ[0] + φ[2..=6])
    //    so the prologue can clobber them for MGMT_MAP arg passing
    //    without losing host-passed args (e.g. javm-guest-tests sets
    //    φ[8] = args_addr, φ[9] = args_len before calling run()).
    emit_save_arg_regs(&mut code, &mut bitmask);

    // 2. Map the stack first — the SP setup that follows must reference
    //    a mapped page, and any user code falling through to a memory
    //    op needs the stack live.
    emit_mgmt_map(&mut code, &mut bitmask, &layout.stack);

    // 3. Set SP to stack_top. RISC-V SP convention: grows downward, so
    //    the first push lands at SP - 8 inside the just-mapped region.
    emit_load_imm_64(&mut code, &mut bitmask, SP_REG, layout.stack_top());

    // 4. Map ro / rw / heap if present.
    for opt in [layout.ro.as_ref(), layout.rw.as_ref(), layout.heap.as_ref()]
        .iter()
        .copied()
        .flatten()
    {
        emit_mgmt_map(&mut code, &mut bitmask, opt);
    }

    // 5. Map args.
    emit_mgmt_map(&mut code, &mut bitmask, &layout.args);

    // 6. Restore φ[7..=12] from scratch regs.
    emit_restore_arg_regs(&mut code, &mut bitmask);

    debug_assert_eq!(code.len(), bitmask.len());
    (code, bitmask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_minimal_stack_and_args() {
        let l = ProgramLayout::compute(1, 0, 0, 0);
        assert_eq!(l.stack.cap_index, STACK_CAP_INDEX);
        assert_eq!(l.stack.base_page, 0);
        assert_eq!(l.stack.page_count, 1);
        assert!(l.ro.is_none());
        assert!(l.rw.is_none());
        assert!(l.heap.is_none());
        assert_eq!(l.args.cap_index, crate::ARGS_CAP_INDEX);
        assert_eq!(l.args.base_page, 1);
        assert_eq!(l.args.page_count, 1);
        assert_eq!(l.stack_top(), 4096);
        assert_eq!(l.total_data_pages(), 2);
    }

    #[test]
    fn layout_full_stack_ro_rw_heap_args() {
        let l = ProgramLayout::compute(2, 1, 1, 4);
        assert_eq!(l.stack.base_page, 0);
        assert_eq!(l.ro.as_ref().unwrap().base_page, 2);
        assert_eq!(l.rw.as_ref().unwrap().base_page, 3);
        assert_eq!(l.heap.as_ref().unwrap().base_page, 4);
        assert_eq!(l.args.base_page, 8);
        assert_eq!(l.stack_top(), 2 * 4096);
        assert_eq!(l.total_data_pages(), 2 + 1 + 1 + 4 + 1);
    }

    #[test]
    fn prologue_basic_shape() {
        let l = ProgramLayout::compute(1, 0, 0, 0);
        let (code, bitmask) = emit_prologue(&l);
        assert_eq!(code.len(), bitmask.len());
        // save (12) + stack MGMT_MAP (61) + SP setup (10) + args MGMT_MAP (61) + restore (12) = 156 bytes.
        assert_eq!(code.len(), 12 + 61 + 10 + 61 + 12);
        // First instruction must be a basic-block start.
        assert_eq!(bitmask[0], 1);
        // First instruction is move_reg (opcode 100) — saving φ[7] to φ[0].
        assert_eq!(code[0], PVM_OPCODE_MOVE_REG);
    }

    #[test]
    fn prologue_with_all_regions() {
        let l = ProgramLayout::compute(2, 1, 1, 4);
        let (code, _bitmask) = emit_prologue(&l);
        // save(12) + stack(61) + SP(10) + ro(61) + rw(61) + heap(61) + args(61) + restore(12) = 339 bytes.
        assert_eq!(code.len(), 12 + 61 + 10 + 61 + 61 + 61 + 61 + 12);
    }
}
