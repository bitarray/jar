//! In-kernel JIT execution at ring 3.
//!
//! Takes a PVM program (raw RISC-V code) and runs it inside a
//! per-invocation page table at ring 3. The PVM exits through
//! `int 0x81` (a hand-rolled trampoline placed after the JIT'd code at
//! a user-RX VA); the kernel handler longjmps back to the caller of
//! [`enter_frame`] and we read the JitContext that the JIT wrote
//! during execution.
//!
//! ## Memory layout (per invocation, in the new page table)
//!
//! Guest memory lives in `PML4[0]` (low VA, kernel relocated to slot 511
//! in Stage F kernel-high) with PVM addr == native VA, so mem accesses
//! can use `[rdx]` baseless. **True zero-setup demand paging:** the whole
//! `PML4[0]` (covering CODE at `CODE_BASE` = 4 MiB and DATA at
//! `DATA_BASE` = 256 MiB) starts with NO page-table entries; the #PF
//! handler builds the PML4→PT path and materializes each page (code RO,
//! data RO/CoW) on first touch, charging category-#3. `[0, CODE_BASE)`
//! and the inter-region gap are never declared, so they fault (null guard).
//!
//! CTX + the per-Image arena + STACK live in `PML4[1]` at 512 GiB,
//! outside the PVM u32 address range so guest addresses can't spoof
//! them. CTX is reached via RIP-relative addressing from the JIT code
//! in the arena, which the slot keeps within ±2 GiB.
//!
//! ```text
//!   PML4[1] (512..1024 GiB)
//!     PDPT[0] (512..513 GiB)  ← CTX, 4 KiB JitContext          (user-RW)
//!     PDPT[1] (513..514 GiB)  ← META arena, template-owned
//!                               (DISPATCH | JIT | TRAMP)
//!         DISPATCH                                              (user-RO)
//!         JIT / TRAMP                                           (user-RX)
//!     PDPT[2] (514..515 GiB)  ← STACK, ring-3 x86 stack, 4 KiB (user-RW)
//! ```
//!
//! Guest code is lazily materialized read-only at its `CODE_BASE` (a
//! `PinnedCapRo` region, like a pinned data cap), so PVM PCs are real VAs
//! and a guest PIC `auipc`+load pages in the touched code page on first
//! read (charging category-#3, identical to the interpreter).
//!
//! The Image arena lives in [`jit_cache::CompiledImage`] (one per
//! Image, allocated once and mapped read-only into every Instance's
//! PT). Per-call work allocates only CTX / MEM / STACK pages from
//! talc, then maps the cached arena's pages into the per-invocation
//! page table.
//!
//! Per-page PVM `RO`/`RW` enforcement is delegated to the page table —
//! faults outside `[MEM_VA, MEM_VA + mem_size)` route via
//! `jit_pf_handler`.

#![cfg(target_os = "none")]

extern crate alloc;

use crate::jit_cache;
use crate::page_alloc::PageBuf;
use crate::paging::{PAGE_SIZE, PageTable, Perm};
use crate::ring3;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use hyperlight_guest_bin::exception::arch::{Context, ExceptionInfo, HANDLERS};
use javm_recompiler_x86::JitContext;
use javm_recompiler_x86::codegen::HelperFns;

// === Per-invocation context for the #PF handler ===========================
//
// Set by `enter_frame` immediately before `enter_ring3`, read by
// `jit_pf_handler` if a #PF fires from inside the JIT'd code window.
// Single-threaded (Hyperlight serialises calls), so unsynchronised
// statics are safe — we use atomics for `&'static mut` avoidance only.

static JIT_CODE_BASE: AtomicU64 = AtomicU64::new(0);
static JIT_CODE_LEN: AtomicU64 = AtomicU64::new(0);
static EXIT_LABEL_VA: AtomicU64 = AtomicU64::new(0);
static TRAP_TABLE_PTR: AtomicPtr<(u32, u32, u32)> = AtomicPtr::new(core::ptr::null_mut());
static TRAP_TABLE_LEN: AtomicU64 = AtomicU64::new(0);
static CTX_KVA: AtomicU64 = AtomicU64::new(0);

// === Per-invocation category-#3 materialization state =====================
//
// Set by `enter_frame` so `jit_pf_handler` can lazily materialize the
// guest address space under true zero-setup demand paging: PML4[0] starts
// with NO entries, so the first guest read/write of each page faults here.
// The handler builds the page-table path (via `pt_map_leaf`, recording new
// tables in `OWNED_VEC_PTR`) and materializes the page: a read maps it RO
// (page-in), a write maps it RW (CoW, with a fresh page for cap-backed
// initial slots), charging category-#3 gas against the saved gas register
// (R15). The CODE region (`MAT_CODE_*`) is `PinnedCapRo` (page-in RO,
// write-faults). In the DATA region, pages in a `MAT_RANGES` entry are
// cap-backed (pinned RO / initial CoW); the rest are ephemeral, backed by
// the frame's private `mem_buf`. CoW'd cap pages are appended to the
// per-frame dirty sink (frame-local scaffolding, see `call_loop`).

static MAT_RANGES_PTR: AtomicPtr<crate::call_loop::MatRange> =
    AtomicPtr::new(core::ptr::null_mut());
static MAT_RANGES_LEN: AtomicU64 = AtomicU64::new(0);
/// Per-page source PA arena indexed by `MatRange.pas_off + page_within_range`
/// (a dense DataCap's pages are non-contiguous slabs). `Empty` cap pages point
/// at the frame's shared zero page.
static MAT_PAS_PTR: AtomicPtr<u64> = AtomicPtr::new(core::ptr::null_mut());
static MAT_PAS_LEN: AtomicU64 = AtomicU64::new(0);
/// Per-page [`javm_exec::mat::PageState`] (one byte/page), len =
/// `(mem_top - data_base) / PAGE_SIZE`. Mutated in place by the handler.
static MAT_STATE_PTR: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
static MAT_STATE_LEN: AtomicU64 = AtomicU64::new(0);
/// Guest VA bounds of the lazily-materialized data extent.
static MAT_DATA_BASE: AtomicU64 = AtomicU64::new(0);
static MAT_MEM_TOP: AtomicU64 = AtomicU64::new(0);
/// Physical address of the ephemeral `mem_buf` page 0 (== `DATA_BASE`).
static MAT_MEM_BUF_PA: AtomicU64 = AtomicU64::new(0);
/// Read-only CODE region `[code_base, code_top)` (page-rounded). A
/// `PinnedCapRo` region: guest PIC data reads page each touched code page
/// in RO on first read (charging #3 page-in, identical to the interp),
/// writes hard-fault. `MAT_CODE_PA` is the source PA of code page 0.
static MAT_CODE_BASE: AtomicU64 = AtomicU64::new(0);
static MAT_CODE_TOP: AtomicU64 = AtomicU64::new(0);
static MAT_CODE_PA: AtomicU64 = AtomicU64::new(0);
/// Per-2 MiB-cluster materialization flag for **read-only** regions, namely
/// code and `PinnedCapRo` data caps, indexed by absolute cluster
/// ([`javm_exec::mat::cluster_of`]). The first RO fault in a cluster pays
/// one `page_in` and fault-arounds the cluster's RO pages; the interpreter
/// tracks the same per-cluster flag, so both charge a cluster exactly once.
/// Materialized read-only **units** — pointer to the running frame's sorted
/// `Vec<u32>` of [`javm_exec::mat::unit_base`] values (one per `cap ∩ 2 MiB
/// cluster` paged in). The handler binary-searches/inserts here so each RO
/// unit is charged one `page_in` exactly once, matching the interpreter. A
/// `Vec` (not a fixed bitmap) because the unit set is keyed by `unit_base`,
/// not a dense cluster index, and it grows in the handler (realloc-safe via
/// the `&mut Vec` indirection, like `DIRTY_PAGE_SINK`).
static MAT_RO_UNITS_SINK: AtomicPtr<alloc::vec::Vec<u32>> = AtomicPtr::new(core::ptr::null_mut());
static DIRTY_PAGE_SINK: AtomicPtr<alloc::vec::Vec<crate::call_loop::DirtyPage>> =
    AtomicPtr::new(core::ptr::null_mut());
static ACTIVE_PT_PML4_KVA: AtomicU64 = AtomicU64::new(0);
/// Type-erased pointer ([`crate::paging::PageTable::owned_vec_ptr`]) to
/// the active PT's `owned` table list — the handler's `pt_map_leaf`
/// records fault-allocated intermediate tables here (freed at `Drop`),
/// enabling true zero-setup demand paging (PML4[0] empty at entry).
static OWNED_VEC_PTR: AtomicU64 = AtomicU64::new(0);

/// Hyperlight-chained #PF handler. Fires AFTER Hyperlight's own
/// stack-growth handler has declined to handle the fault.
///
/// If the faulting RIP is inside the registered JIT code window:
/// resolve the PVM PC via the trap table, populate
/// `JitContext::{exit_reason, exit_arg, pc}`, redirect the saved RIP
/// in the iretq frame to the JIT's exit label, return `true`. The
/// CPU then `iretq`s back to ring 3 at the exit label, which `ret`s
/// to the trampoline, which `int 0x81`s back to the kernel — exactly
/// the same path as a clean `ecalli` exit.
///
/// Returns `false` for any fault outside the JIT window, letting
/// Hyperlight abort.
fn jit_pf_handler(
    _exception_number: u64,
    info: *mut ExceptionInfo,
    ctx: *mut Context,
    gva: u64,
) -> bool {
    // SAFETY: Hyperlight passes a valid pointer to the iretq frame.
    let saved_rip = unsafe { (&raw const (*info).rip).read_volatile() };
    let code_base = JIT_CODE_BASE.load(Ordering::SeqCst);
    let code_len = JIT_CODE_LEN.load(Ordering::SeqCst);
    if code_len == 0 || saved_rip < code_base || saved_rip >= code_base + code_len {
        return false;
    }

    // Resolve the faulting PVM PC + access width from the trap table.
    let offset = (saved_rip - code_base) as u32;
    let (pvm_pc, width) = trap_lookup(offset);

    // Category #3: try lazy materialization (page-in / CoW) of the
    // faulting access's page set, charging gas. The error code's write
    // bit (bit 1) picks page-in-RO vs CoW-RW. On success, retry the
    // faulting instruction (RIP untouched).
    // SAFETY: `info` is the valid iretq frame Hyperlight passed.
    let error_code = unsafe { (&raw const (*info).error_code).read_volatile() };
    let is_write = (error_code & 0x2) != 0;
    if width != 0 && try_materialize(gva, width, is_write, ctx) {
        return true;
    }

    // Not materializable (outside the declared region, or a write to a
    // pinned read-only page) → a PVM-level PageFault, charging nothing.
    let ctx_kva = CTX_KVA.load(Ordering::SeqCst);
    // SAFETY: ctx_kva is the kernel VA of the JitContext page for the
    // current invocation; valid while the handler runs.
    unsafe {
        let jc = ctx_kva as *mut JitContext;
        (*jc).exit_reason = 3; // PageFault
        (*jc).exit_arg = gva as u32;
        (*jc).pc = pvm_pc;
    }

    let exit_va = EXIT_LABEL_VA.load(Ordering::SeqCst);
    // SAFETY: info is a valid pointer to a writable iretq frame.
    unsafe {
        (&raw mut (*info).rip).write_volatile(exit_va);
    }
    true
}

/// Resolve a faulting native offset to its `(pvm_pc, access_width)` via
/// the trap table. Returns `(0, 0)` when no entry covers the offset
/// (not a guest memory op → width 0 → caller treats as a PageFault).
fn trap_lookup(offset: u32) -> (u32, u32) {
    let tt_ptr = TRAP_TABLE_PTR.load(Ordering::SeqCst);
    let tt_len = TRAP_TABLE_LEN.load(Ordering::SeqCst) as usize;
    if tt_ptr.is_null() || tt_len == 0 {
        return (0, 0);
    }
    // SAFETY: tt_ptr + tt_len describes a contiguous slice in kernel
    // memory, valid for the duration of `enter_frame` (the only function
    // that publishes / clears the statics that point at it).
    let tt = unsafe { core::slice::from_raw_parts(tt_ptr, tt_len) };
    match tt.binary_search_by_key(&offset, |&(no, _, _)| no) {
        Ok(idx) => (tt[idx].1, tt[idx].2),
        Err(0) => (0, 0),
        Err(idx) => (tt[idx - 1].1, tt[idx - 1].2),
    }
}

/// Find the cap-backed [`crate::call_loop::MatRange`] covering page
/// `page_va` (page-aligned), or `None` for an ephemeral page.
fn mat_range_for(page_va: u32) -> Option<crate::call_loop::MatRange> {
    let ptr = MAT_RANGES_PTR.load(Ordering::SeqCst);
    let len = MAT_RANGES_LEN.load(Ordering::SeqCst) as usize;
    if ptr.is_null() || len == 0 {
        return None;
    }
    // SAFETY: ptr/len describe the running FrameRuntime's `mat_ranges`
    // Vec, valid until enter_frame clears these statics.
    let ranges = unsafe { core::slice::from_raw_parts(ptr, len) };
    ranges
        .iter()
        .copied()
        .find(|r| r.start <= page_va && page_va < r.end)
}

/// Source PA of page `page_va` (page-aligned) within cap-backed range `r`,
/// read from the published per-page `MAT_PAS` arena. Every page in
/// `[r.start, r.end)` has an arena entry (`pas_len == range page count`), so the
/// index is in bounds by construction.
fn mat_pa_at(r: &crate::call_loop::MatRange, page_va: u64) -> u64 {
    let ptr = MAT_PAS_PTR.load(Ordering::SeqCst);
    let len = MAT_PAS_LEN.load(Ordering::SeqCst) as usize;
    let idx = r.pas_off as usize + ((page_va as u32 - r.start) / PAGE_SIZE as u32) as usize;
    debug_assert!(idx < len && !ptr.is_null(), "mat_pa_at: index out of arena");
    if ptr.is_null() || idx >= len {
        return 0;
    }
    // SAFETY: ptr/len describe the running FrameRuntime's `mat_pas` Vec, valid
    // until enter_frame clears these statics; `idx < len` checked above.
    unsafe { *ptr.add(idx) }
}

/// Read-only materialization source for a 2 MiB unit: either a contiguous slab
/// (code — page PA = `base_pa + offset`) or a cap-backed range whose pages have
/// per-page PAs in the `MAT_PAS` arena.
enum RoSrc {
    Contig { base_pa: u64 },
    Cap(crate::call_loop::MatRange),
}

/// The static [`javm_exec::mat::PageKind`] of guest page `page_va`:
/// cap-backed pages take their kind from the matching `MatRange`; every
/// other page in the declared extent is ephemeral.
fn page_kind(page_va: u32) -> javm_exec::mat::PageKind {
    match mat_range_for(page_va) {
        Some(r) => javm_exec::mat::PageKind::from_u8(r.kind)
            .unwrap_or(javm_exec::mat::PageKind::PinnedCapRo),
        None => javm_exec::mat::PageKind::EphemeralZero,
    }
}

/// Lazily materialize the page set of a `width`-byte access at `gva`,
/// charging category-#3 gas against the saved gas register. Handles BOTH
/// the read-only CODE region (`PinnedCapRo`: page-in RO on read, write
/// hard-faults) and the DATA region (ephemeral / cap-backed, with CoW).
/// True zero-setup demand paging: the guest's PML4[0] starts empty, so
/// the handler builds the page-table path on the first fault to each page
/// via [`crate::paging::pt_map_leaf`].
///
/// Returns `false` (charging nothing, mutating nothing) if any page is
/// outside the declared code/data regions or a write targets a read-only
/// page — the caller then raises a PVM PageFault. Uses the *same*
/// [`javm_exec::mat`] state machine + page-set rule as the interpreter,
/// so both engines charge bit-identically (gas-cost.md §3).
fn try_materialize(gva: u64, width: u32, is_write: bool, ctx: *mut Context) -> bool {
    let data_base = MAT_DATA_BASE.load(Ordering::SeqCst);
    let mem_top = MAT_MEM_TOP.load(Ordering::SeqCst);
    let mem_buf_pa = MAT_MEM_BUF_PA.load(Ordering::SeqCst);
    let code_base = MAT_CODE_BASE.load(Ordering::SeqCst);
    let code_top = MAT_CODE_TOP.load(Ordering::SeqCst);
    let code_pa = MAT_CODE_PA.load(Ordering::SeqCst);
    let pml4 = ACTIVE_PT_PML4_KVA.load(Ordering::SeqCst);
    let owned_vec = OWNED_VEC_PTR.load(Ordering::SeqCst);
    if pml4 == 0 || owned_vec == 0 {
        return false;
    }

    let in_code = |pv: u64| code_top > code_base && pv >= code_base && pv < code_top;
    let in_data = |pv: u64| mem_top > data_base && pv >= data_base && pv < mem_top;

    let set = javm_exec::mat::access_pages(gva as u32, width);

    // Region dispatch by the BASE page, then accessibility-all *within* that
    // one region — mirroring the interpreter's `touch` (base-page dispatch to
    // `touch_code`/`touch_data`, each all-or-nothing). The whole access
    // belongs to the base page's region; any other page leaving it faults
    // charging nothing. This crucially includes a code↔data straddle when a
    // maximal code region abuts `DATA_BASE` (`code_top == DATA_BASE`): both
    // engines then fault it, rather than the recompiler materializing across
    // the boundary while the interpreter faults. Writes to code (read-only)
    // and to pinned data caps fault too.
    let base = set.as_slice()[0] as u64;
    let base_in_code = in_code(base);
    if !base_in_code && !in_data(base) {
        return false; // base page undeclared (null guard / gap / out of range)
    }
    for &p in set.as_slice() {
        let pv = p as u64;
        if base_in_code {
            // CODE region: read-only; every page must be a code page.
            if is_write || !in_code(pv) {
                return false;
            }
        } else {
            // DATA region: every page must be a data page; pinned write faults.
            if !in_data(pv) || (is_write && page_kind(p) == javm_exec::mat::PageKind::PinnedCapRo) {
                return false;
            }
        }
    }

    // Per-region state arrays. Null only when a region is undeclared, in
    // which case no page of `set` lies in it (guarded by in_code/in_data).
    let dstate_ptr = MAT_STATE_PTR.load(Ordering::SeqCst);
    let dstate_len = MAT_STATE_LEN.load(Ordering::SeqCst) as usize;
    let ro_units_ptr = MAT_RO_UNITS_SINK.load(Ordering::SeqCst);
    // SAFETY: each ptr describes the running FrameRuntime's state
    // (single-threaded → exclusive); empty slice / scratch Vec if undeclared.
    let dstate: &mut [u8] = if dstate_ptr.is_null() {
        &mut []
    } else {
        unsafe { core::slice::from_raw_parts_mut(dstate_ptr, dstate_len) }
    };
    let mut ro_units_scratch = alloc::vec::Vec::new();
    let ro_units: &mut alloc::vec::Vec<u32> = if ro_units_ptr.is_null() {
        &mut ro_units_scratch
    } else {
        unsafe { &mut *ro_units_ptr }
    };

    // Materialize-all (low→high), accumulating the charge. Read-only pages
    // (code + PinnedCapRo data caps) materialize per unit (one page_in per
    // `cap ∩ 2 MiB cluster`, fault-around the unit's RO pages); writable
    // (CoW / ephemeral) pages stay per-page.
    let mut total: u64 = 0;
    for &p in set.as_slice() {
        let pv = p as u64;
        // Classify the read-only source range (if any): code, or a pinned
        // data cap. Writes to RO pages were already excluded above.
        let ro_range: Option<(u64, u64, RoSrc)> = if in_code(pv) {
            // Code is a single contiguous slab: page PA = code_pa + offset.
            Some((code_base, code_top, RoSrc::Contig { base_pa: code_pa }))
        } else {
            match mat_range_for(p) {
                Some(r) if r.kind == javm_exec::mat::PageKind::PinnedCapRo.as_u8() => {
                    Some((r.start as u64, r.end as u64, RoSrc::Cap(r)))
                }
                _ => None,
            }
        };
        if let Some((r_start, r_end, src)) = ro_range {
            match materialize_ro_unit(pv, r_start, r_end, src, ro_units, pml4, owned_vec) {
                Some(c) => total = total.saturating_add(c),
                None => return false,
            }
            continue;
        }

        // WRITABLE DATA: ephemeral / cap-backed (UnpinnedCapCow) with CoW.
        let idx = ((pv - data_base) / PAGE_SIZE as u64) as usize;
        let cur = javm_exec::mat::PageState::from_u8(dstate[idx]);
        let range = mat_range_for(p);
        let (kind, src_pa) = match range {
            Some(r) => (
                javm_exec::mat::PageKind::from_u8(r.kind)
                    .unwrap_or(javm_exec::mat::PageKind::PinnedCapRo),
                // Per-page source PA (dense cap slabs are non-contiguous).
                mat_pa_at(&r, pv),
            ),
            None => (
                javm_exec::mat::PageKind::EphemeralZero,
                mem_buf_pa + (pv - data_base),
            ),
        };
        let (charge, next) = match javm_exec::mat::charge_for(cur, kind, is_write) {
            Ok(v) => v,
            Err(_) => return false, // pinned write (already excluded; defensive)
        };
        match next {
            javm_exec::mat::PageState::PresentRo => {
                if cur == javm_exec::mat::PageState::NotPresent {
                    // SAFETY: live PT, single writer; builds the path.
                    if unsafe {
                        crate::paging::pt_map_leaf(
                            pml4,
                            pv,
                            src_pa,
                            crate::paging::Perm::user_ro(),
                            owned_vec,
                        )
                    }
                    .is_none()
                    {
                        return false;
                    }
                    // No invlpg: NotPresent → present is not TLB-cached (the
                    // page had no prior translation), so the faulting retry
                    // walks the fresh entry. invlpg is needed only when an
                    // existing present mapping changes (the CoW remap below).
                }
            }
            javm_exec::mat::PageState::PresentRw => {
                // Map only when *transitioning into* PresentRw (cur != PresentRw).
                // An already-PresentRw page is mapped writable at its final PA, so
                // re-mapping it is wrong: for a CoW cap page it would re-allocate
                // and re-copy the cap bytes over the guest's writes at a *new* PA.
                // This case is reached when a straddle access faults on its other
                // (not-present) page and the loop re-visits this present partner;
                // charge_for already returned 0, so skipping the map is gas-neutral.
                if cur != javm_exec::mat::PageState::PresentRw {
                    // Flush only when an *existing* present (RO) mapping is being
                    // changed to RW (read-then-write CoW): that stale RO entry may
                    // be TLB-cached. A first-touch write (cur == NotPresent) maps a
                    // page that was never present, so it needs no invlpg.
                    let flush = cur == javm_exec::mat::PageState::PresentRo;
                    if kind == javm_exec::mat::PageKind::EphemeralZero {
                        // Frame-private buffer: map it writable (builds path).
                        // SAFETY: as above.
                        if unsafe {
                            crate::paging::pt_map_leaf(
                                pml4,
                                pv,
                                src_pa,
                                crate::paging::Perm::user_rw(),
                                owned_vec,
                            )
                        }
                        .is_none()
                        {
                            return false;
                        }
                        if flush {
                            crate::paging::invlpg(pv);
                        }
                    } else if !cow_into_fresh(pv, src_pa, pml4, owned_vec, range, flush) {
                        // Allocation / remap failure → fault (nothing charged
                        // yet for THIS page, but earlier pages of a straddle
                        // were already advanced; an OOM here is fatal anyway).
                        return false;
                    }
                }
            }
            javm_exec::mat::PageState::NotPresent => {}
        }
        total = total.saturating_add(charge);
        dstate[idx] = next.as_u8();
    }

    // Charge: decrement the saved gas register (R15 == gprs[0]). The
    // block reserve guarantees R15 covers the worst case, so no OOG
    // check is needed (mirrors the interpreter's reserved charge).
    // SAFETY: ctx is the valid saved register Context Hyperlight passed.
    unsafe {
        let r15 = (&raw const (*ctx).gprs[0]).read_volatile();
        (&raw mut (*ctx).gprs[0]).write_volatile(r15.wrapping_sub(total));
    }
    true
}

/// Copy-on-write a cap-backed page: allocate a fresh page, copy the
/// cap's bytes from `src_pa`, remap the leaf writable at the new PA, and
/// append a [`crate::call_loop::DirtyPage`] to the per-frame sink. Returns
/// `false` on allocation / remap failure.
///
/// `flush` invalidates the TLB for `page_va` after the remap: pass `true`
/// only when an *existing* present mapping is being changed (read-then-write
/// CoW, where the page was mapped RO and may be cached); a first-touch write
/// (the page was `NotPresent`) needs no flush.
fn cow_into_fresh(
    page_va: u64,
    src_pa: u64,
    pml4: u64,
    owned_vec: u64,
    range: Option<crate::call_loop::MatRange>,
    flush: bool,
) -> bool {
    let Some(src_kva) = crate::paging::pa_to_va(src_pa) else {
        return false;
    };
    let Some(new_page) = crate::page_alloc::PageBuf::new(PAGE_SIZE) else {
        return false;
    };
    let new_pa = new_page.pa();
    let new_kva = new_page.kva();
    // SAFETY: src_kva is a live 4 KiB cap page (pinned by the frame);
    // new_page is a fresh owned 4 KiB page. Both are page-aligned.
    unsafe {
        core::ptr::copy_nonoverlapping(src_kva as *const u8, new_kva as *mut u8, PAGE_SIZE);
    }
    // SAFETY: live PT, single writer; builds the path if needed (the page
    // may be NotPresent under zero-setup) or reuses it (read-then-write).
    if unsafe {
        crate::paging::pt_map_leaf(
            pml4,
            page_va,
            new_pa,
            crate::paging::Perm::user_rw(),
            owned_vec,
        )
    }
    .is_none()
    {
        return false;
    }
    if flush {
        crate::paging::invlpg(page_va);
    }

    let sink_ptr = DIRTY_PAGE_SINK.load(Ordering::SeqCst);
    if !sink_ptr.is_null() {
        // SAFETY: sink_ptr is the running frame's `dirty_pages` Vec,
        // re-published each enter_frame; stable for the handler's life.
        let sink = unsafe { &mut *sink_ptr };
        let (source_hash, source_slot) = match range {
            Some(r) => (r.source_hash, r.source_slot),
            None => ([0u8; 32], javm_cap::slot::SlotIdx(0)),
        };
        sink.push(crate::call_loop::DirtyPage {
            guest_va: page_va as u32,
            source_hash,
            source_slot,
            page: new_page,
        });
    }
    true
}

/// Materialize the read-only **unit** containing `pv`: the intersection of
/// the cap `[r_start, r_end)` (physical base `r_pa`) with the 2 MiB cluster
/// containing `pv`, named by [`javm_exec::mat::unit_base`]. Charges one
/// `page_in` the first time the unit faults (a fresh `unit_base` inserted
/// into the sorted `ro_units` set), `0` thereafter — so a large read-only
/// input materializes for one fault per 2 MiB, not one per page, and two
/// caps sharing a cluster each pay their own page-in (the fault-around is
/// clamped to one cap, so a page-in touches at most one DataCap). The unit's
/// RO pages are **fault-arounded**: mapped present read-only straight from
/// the cap so the retry (and later reads in the unit) hit no further faults.
///
/// No `invlpg`: every page mapped here goes `NotPresent → present`, which is
/// not TLB-cached, so the faulting retry walks the fresh entries. Returns
/// the charge, or `None` on a page-table allocation failure. Mirrors the
/// interpreter's `ro_unit_charge` so the two agree bit-for-bit.
fn materialize_ro_unit(
    pv: u64,
    r_start: u64,
    r_end: u64,
    src: RoSrc,
    ro_units: &mut alloc::vec::Vec<u32>,
    pml4: u64,
    owned_vec: u64,
) -> Option<u64> {
    let ub = javm_exec::mat::unit_base(pv as u32, r_start as u32);
    match ro_units.binary_search(&ub) {
        // Unit already materialized (its pages are present): no charge, and
        // no re-map — the fault that brought us here was a different unit's.
        Ok(_) => return Some(0),
        Err(pos) => ro_units.insert(pos, ub),
    }
    // Fault-around: map the cap's pages within this cluster, read-only.
    let cluster_lo = (pv >> javm_exec::mat::CLUSTER_SHIFT) << javm_exec::mat::CLUSTER_SHIFT;
    let cluster_hi = cluster_lo + (1u64 << javm_exec::mat::CLUSTER_SHIFT);
    let lo = r_start.max(cluster_lo);
    let hi = r_end.min(cluster_hi);
    let mut q = lo;
    while q < hi {
        // Per-page source PA: contiguous code maps `base_pa + offset`; a dense
        // cap's pages each resolve their own slab PA from the arena.
        let page_pa = match &src {
            RoSrc::Contig { base_pa } => base_pa + (q - r_start),
            RoSrc::Cap(r) => mat_pa_at(r, q),
        };
        // SAFETY: live PT, single writer; builds the path (zero-setup).
        unsafe {
            crate::paging::pt_map_leaf(pml4, q, page_pa, crate::paging::Perm::user_ro(), owned_vec)
        }?;
        // No invlpg: NotPresent → present is not TLB-cached.
        q += PAGE_SIZE as u64;
    }
    Some(javm_exec::gas_const::PAGE_IN_COST)
}

/// Result of an in-kernel PVM run.
#[derive(Debug, Clone, Copy)]
pub struct ExitInfo {
    /// Sentinel from JitContext.exit_reason.
    pub exit_reason: u32,
    /// Sentinel from JitContext.exit_arg.
    pub exit_arg: u32,
    /// Gas remaining at exit.
    pub gas_remaining: i64,
    /// PVM register file at exit. φ[7] is the program's return value
    /// (PVM ABI); the call loop also reads φ[7..=12] for HOST_CALL
    /// args + φ[11] as the op code on plain `ecall` exits.
    pub regs: [u64; 13],
    /// PVM PC at exit (the instruction *after* the ecall on a clean
    /// HOST_CALL / ECALL exit, the faulting PC on a PageFault).
    pub pc: u32,
}

// === Per-invocation memory layout =======================================
//
// Lives in PML4 slot 0 (low VA 0..512 GiB) — now empty after the
// Stage F kernel relocation moved the kernel to PML4 slot 511. User
// VA mirrors PVM's u32 address space directly (native VA == guest
// addr) so mem accesses can use `[rdx]` baseless. The PVM layout is
// `[0, CODE_BASE)` unmapped (null guard), `[CODE_BASE, …)` code (RO
// direct-map), `[DATA_BASE, mem_size)` the flat RW data buffer; the
// recompiler does no bounds-checking on guest mem (the PT does, via
// faults outside the mapped ranges) so PVM addresses can reach
// anywhere in the low 4 GiB. CTX sits in PML4 slot 1 (512 GiB),
// outside the PVM u32 range, so guest addresses can't spoof it.

const MEM_VA_M: u64 = 0;
/// PML4 slot 1 (base 512 GiB) hosts CTX + the per-Image arena + STACK.
/// MEM stays in `PML4[0]` at VA 0 so PVM addresses are still native VAs.
/// Placing CTX in this slot too keeps it within ±2 GiB of the JIT
/// region so codegen's RIP-relative addressing reaches it.
///
/// The three sub-regions occupy distinct 1 GiB PDPT slots within the
/// PML4 slot so the per-Image template PT can own the META PD without
/// colliding with the per-call CTX/STACK PDs.
///
/// ```text
///   PML4[1] (512..1024 GiB)
///     PDPT[0] (512..513 GiB)  ← CTX, per-call alloc
///     PDPT[1] (513..514 GiB)  ← META arena, template-owned
///     PDPT[2] (514..515 GiB)  ← STACK, per-call alloc
/// ```
const META_PML4_BASE: u64 = 1u64 << 39; // 512 GiB
/// CTX sits at the slot base. CTX_VA_M must match
/// `javm_recompiler_x86::codegen::CTX_VA`.
const CTX_VA_M: u64 = META_PML4_BASE;
/// Base of the per-Image arena (DISPATCH | JIT | TRAMP).
/// 1 GiB past CTX so the arena occupies its own PDPT slot, enabling
/// template-PT sharing of the entire PD subtree.
const META_BASE_M: u64 = META_PML4_BASE + (1u64 << 30);
/// STACK_VA — 2 GiB past the PML4 base, in its own PDPT slot.
const STACK_VA_M: u64 = META_PML4_BASE + (2u64 << 30);

/// One PVM region (arg / ro / rw) to populate before entry.
#[derive(Clone, Copy)]
pub struct MemRegion<'a> {
    pub start: u32,
    pub data: &'a [u8],
}

/// Per-frame ring-3 resources retained across re-entries.
///
/// Holds the per-call page table + private mem/ctx/stack pages, plus
/// the cached `CompiledImage` fields needed to publish #PF-handler
/// atomics on every entry. Built once per `KernelFrame` (lazily on
/// first [`enter_frame`]); reused across re-entries on the same frame
/// — saves N PageTable + 3 PageBuf allocations in a depth-N recursion.
///
/// Frame-constant `JitContext` fields (dispatch_table, code_base,
/// flat_buf, …) are written once when the runtime is built.
/// [`enter_frame`] only updates regs/pc/gas/exit_*.
pub struct FrameRuntime {
    pt: PageTable,
    #[allow(dead_code)] // kept solely to own the backing page (referenced by `pt`).
    mem_buf: PageBuf,
    #[allow(dead_code)] // kept solely to own the backing page (referenced by `pt`).
    ctx_buf: PageBuf,
    stack_buf: PageBuf,
    jit_va: u64,
    jit_size: u64,
    exit_label_va: u64,
    trap_table_ptr: *const (u32, u32, u32),
    trap_table_len: u64,
    tramp_va: u64,
    new_cr3: u64,
    ctx_kva: u64,
    // ---- Category-#3 lazy-materialization state (persists across
    // re-entries on this frame; published to the #PF handler each entry). ----
    /// Cap-backed data mappings (pinned RO / initial CoW), each indexing a
    /// window into `mat_pas`. Pages not covered here are ephemeral (`mem_buf`).
    mat_ranges: alloc::vec::Vec<crate::call_loop::MatRange>,
    /// Per-page source PA arena for `mat_ranges` (see `MAT_PAS_PTR`).
    mat_pas: alloc::vec::Vec<u64>,
    /// Shared zero page sourcing `Empty` cap pages (RO) / CoW-from-zero writes.
    /// Owned here to keep its PA (recorded in `mat_pas`) valid for the frame.
    #[allow(dead_code)]
    zero_page: PageBuf,
    /// Per-page [`javm_exec::mat::PageState`], one byte/page over
    /// `[data_base, mem_top)`. Advances NotPresent → PresentRo → PresentRw.
    mat_state: alloc::vec::Vec<u8>,
    /// Guest VA bounds of the lazily-materialized data extent.
    data_base: u32,
    mem_top: u32,
    /// Physical address of `mem_buf` page 0 (the `DATA_BASE` page).
    mem_buf_pa: u64,
    /// Read-only CODE region (page-rounded): `[code_base, code_top)`,
    /// source PA `code_pa`. Lazily materialized `PinnedCapRo` like a
    /// pinned data cap, per unit (`code ∩ cluster`, see `ro_units`).
    code_base: u32,
    code_top: u32,
    code_pa: u64,
    /// Materialized read-only **units** — sorted set of
    /// [`javm_exec::mat::unit_base`] values (one per `cap ∩ 2 MiB cluster`).
    /// Grows in the #PF handler; the interpreter keeps the identical set.
    ro_units: alloc::vec::Vec<u32>,
}

/// Build a per-frame runtime: compile the Image (cached), allocate
/// per-call mem/ctx/stack pages, populate mem from `arg`/`ro`/`rw`,
/// initialise the frame-constant `JitContext` fields, and build the
/// per-call page table.
///
/// Per-entry mutable state (regs, pc, gas, exit_*) is written by
/// [`enter_frame`]; this function only touches frame-constant fields.
///
/// The `code` is raw RV+C+custom-0 bytes; the JIT cache predecodes it
/// once and reuses the result on subsequent calls. `code_base` is the
/// guest VA the region maps at — it's threaded into the compiler (so
/// `auipc`/`jalr` resolve correctly) and into the cache key.
///
/// The dense dispatch table (one `i32` per code byte, built by
/// `jit_cache::get_or_compile`; non-block-start slots hold the
/// panic-stub offset) doubles as the `jalr`-target validator — there
/// is no BB region or jump table.
///
/// **True zero-setup demand paging:** the guest's whole low VA range
/// (PML4[0], covering CODE and DATA) is left with NO page-table entries
/// at build time; the #PF handler builds the path + materializes each
/// page on first touch. `code_pa` is the physical address of the Image's
/// code bytes (page-rounded, zero-padded tail); the code region is a
/// `PinnedCapRo` region lazily paged in RO on guest PIC reads.
///
/// # Safety
/// The guest runs single-threaded (Hyperlight serialises calls); the
/// `code` / overlay slices and `code_pa` / cap PAs must outlive the
/// returned [`FrameRuntime`], which owns the per-call page table.
#[allow(clippy::too_many_arguments)]
pub unsafe fn build_frame_runtime(
    image_hash: &javm_cap::CapHash,
    code: &[u8],
    code_base: u32,
    code_pa: u64,
    entry_pc: u32,
    mem_size: u32,
    arg: MemRegion,
    ro: MemRegion,
    rw: MemRegion,
    mat_ranges: alloc::vec::Vec<crate::call_loop::MatRange>,
    mat_pas: alloc::vec::Vec<u64>,
    zero_page: PageBuf,
) -> Option<FrameRuntime> {
    let helpers = HelperFns {
        mem_read_u8: 0x1001,
        mem_read_u16: 0x1002,
        mem_read_u32: 0x1003,
        mem_read_u64: 0x1004,
        mem_write_u8: 0x1005,
        mem_write_u16: 0x1006,
        mem_write_u32: 0x1007,
        mem_write_u64: 0x1008,
    };
    // Category #2: scale the load/store base latency (mem_cycles) ×1..4
    // by the Instance's declared footprint. `mem_size` is the same
    // high-water-mark the interpreter derives, so both pick the same
    // tier (and it is per-Image, so the jit_cache keying by image_hash
    // stays sound under v3 static memory).
    let mem_cycles = javm_exec::gas_const::mem_cycles_for(javm_exec::gas_const::accessible_pages(
        mem_size,
        javm_cap::layout::DATA_BASE,
    ));
    let cached = jit_cache::get_or_compile(
        image_hash,
        code,
        code_base,
        META_BASE_M,
        CTX_VA_M,
        mem_cycles,
        helpers,
    );
    if cached.jit_size == 0 {
        return None;
    }

    let dispatch_va = META_BASE_M + cached.dispatch_offset as u64;
    let jit_va = META_BASE_M + cached.jit_offset as u64;
    let tramp_va = META_BASE_M + cached.tramp_offset as u64;

    // Data lives at [DATA_BASE, mem_size). The flat RW buffer covers
    // only that extent and is mapped at native VA DATA_BASE, leaving
    // [0, DATA_BASE) unmapped — a null guard, save for the code
    // direct-map at CODE_BASE. `mem_size` is the absolute max data VA.
    let data_base = javm_cap::layout::DATA_BASE as usize;
    let mem_bytes = (mem_size as usize)
        .saturating_sub(data_base)
        .next_multiple_of(PAGE_SIZE);

    let mem_buf = PageBuf::new(mem_bytes.max(PAGE_SIZE))?;
    let ctx_buf = PageBuf::new(PAGE_SIZE)?;
    let stack_buf = PageBuf::new(PAGE_SIZE)?;

    for region in [arg, ro, rw] {
        if region.data.is_empty() {
            continue;
        }
        // Overlay starts are absolute guest VAs (≥ DATA_BASE); rebase
        // into the buffer.
        let off = (region.start as usize).checked_sub(data_base)?;
        let end = off.checked_add(region.data.len())?;
        if end > mem_bytes {
            return None;
        }
        // SAFETY: bounds-checked.
        unsafe {
            core::ptr::copy_nonoverlapping(
                region.data.as_ptr(),
                (mem_buf.kva() + off as u64) as *mut u8,
                region.data.len(),
            );
        }
    }

    let ctx_kva = ctx_buf.kva();
    let ctx = ctx_kva as *mut JitContext;
    // SAFETY: ctx points to a fresh zeroed page.
    unsafe {
        (*ctx).heap_base = 0;
        (*ctx).heap_top = 0;
        // jalr targets are validated by the dense dispatch table (a
        // non-block-start offset holds the panic-stub offset) — no
        // separate bb_starts set.
        (*ctx).entry_pc = entry_pc;
        (*ctx).dispatch_table = dispatch_va as *const i32;
        (*ctx).code_base = jit_va;
        // Vestigial (codegen addresses mem baseless as `[reg]`); set to
        // the data buffer's native base for documentation.
        (*ctx).flat_buf = (MEM_VA_M + data_base as u64) as *mut u8;
        (*ctx).fast_reentry = 0;
        (*ctx)._pad2 = 0;
        (*ctx).max_heap_pages = 0;
        (*ctx)._pad3 = 0;
    }

    let mut pt = PageTable::new()?;
    pt.map(CTX_VA_M, ctx_buf.pa(), ctx_buf.size(), Perm::user_rw())?;
    // True zero-setup demand paging: the WHOLE guest low VA range (PML4[0]
    // — both CODE at CODE_BASE and DATA at DATA_BASE) is left with NO
    // page-table entries here. The first guest touch of each page faults
    // into `jit_pf_handler`, which builds the PML4→PT path (recording the
    // new tables in `pt.owned`) and materializes the page (page-in / CoW),
    // charging #3. `mem_buf` stays eagerly *allocated* (and seeded with
    // overlays above) — only the mapping is lazy.
    let mat_state = alloc::vec![0u8; mem_bytes / PAGE_SIZE];
    let mem_buf_pa = mem_buf.pa();
    let mem_top = (data_base + mem_bytes) as u32;
    // Code region: page-rounded `[code_base, code_top)`, lazily paged in
    // RO (PinnedCapRo) per unit on guest PIC reads. The code buffer is
    // page-aligned with a zeroed tail, so paging in the last (partial) page
    // is safe.
    let code_bytes_rounded = code.len().next_multiple_of(PAGE_SIZE);
    let code_top = code_base.saturating_add(code_bytes_rounded as u32);
    // Materialized RO units, keyed by unit_base (cap ∩ 2 MiB cluster) — a
    // sorted set, grown on demand in the #PF handler.
    let ro_units = alloc::vec::Vec::new();
    pt.install_borrowed_pd(META_BASE_M, cached.template_pd_pa)?;
    pt.map(
        STACK_VA_M,
        stack_buf.pa(),
        stack_buf.size(),
        Perm::user_rw(),
    )?;
    let new_cr3 = pt.cr3()?;

    Some(FrameRuntime {
        pt,
        mem_buf,
        ctx_buf,
        stack_buf,
        jit_va,
        jit_size: cached.jit_size as u64,
        exit_label_va: jit_va + cached.exit_label_offset as u64,
        trap_table_ptr: cached.trap_table.as_ptr(),
        trap_table_len: cached.trap_table.len() as u64,
        tramp_va,
        new_cr3,
        ctx_kva,
        mat_ranges,
        mat_pas,
        zero_page,
        mat_state,
        data_base: data_base as u32,
        mem_top,
        mem_buf_pa,
        code_base,
        code_top,
        code_pa,
        ro_units,
    })
}

/// Enter ring 3 on `rt`. Updates per-entry `JitContext` fields (regs,
/// pc, gas, exit_*), publishes the #PF handler atomics (including the
/// category-#3 materialization state from `rt`), drops to ring 3, then
/// reads back the post-exit state.
///
/// `dirty_sink` is the per-frame `Vec` the handler appends a
/// [`crate::call_loop::DirtyPage`] to on each cap-page CoW (may be null
/// to disable bookkeeping). The lazily-materialized data ranges + per-
/// page state live in `rt` and are republished here each entry.
///
/// # Safety
/// Mutates CR3 + GDT + IDT during the call. Single-threaded by
/// Hyperlight construction. `dirty_sink` must outlive the call.
#[allow(clippy::too_many_arguments)]
pub unsafe fn enter_frame(
    rt: &mut FrameRuntime,
    initial_gas: i64,
    entry_pc: u32,
    initial_regs: [u64; 13],
    dirty_sink: *mut alloc::vec::Vec<crate::call_loop::DirtyPage>,
) -> ExitInfo {
    let ctx = rt.ctx_kva as *mut JitContext;
    // SAFETY: ctx_kva owned by `rt.ctx_buf`, alive across this call.
    unsafe {
        // The persisted register file is the 13 host-mapped slots; the two
        // spilled slots (x3/x4) are invocation-local and start at 0, matching
        // the interpreter (which rebuilds from the same 13-register cap).
        let mut all_regs = [0u64; 15];
        all_regs[..13].copy_from_slice(&initial_regs);
        (*ctx).regs = all_regs;
        (*ctx).gas = initial_gas;
        (*ctx).exit_reason = 0;
        (*ctx).exit_arg = 0;
        (*ctx).entry_pc = entry_pc;
        (*ctx).pc = entry_pc;
    }

    // ---- install ring-3 GDT/IDT + JIT #PF handler ------------------------
    // SAFETY: ring-0 mutation of GDT/IDT; serialised by Hyperlight.
    unsafe { ring3::install_ring3_exit_gate() };

    JIT_CODE_BASE.store(rt.jit_va, Ordering::SeqCst);
    JIT_CODE_LEN.store(rt.jit_size, Ordering::SeqCst);
    EXIT_LABEL_VA.store(rt.exit_label_va, Ordering::SeqCst);
    TRAP_TABLE_PTR.store(rt.trap_table_ptr as *mut (u32, u32, u32), Ordering::SeqCst);
    TRAP_TABLE_LEN.store(rt.trap_table_len, Ordering::SeqCst);
    CTX_KVA.store(rt.ctx_kva, Ordering::SeqCst);
    MAT_RANGES_PTR.store(
        rt.mat_ranges.as_ptr() as *mut crate::call_loop::MatRange,
        Ordering::SeqCst,
    );
    MAT_RANGES_LEN.store(rt.mat_ranges.len() as u64, Ordering::SeqCst);
    MAT_PAS_PTR.store(rt.mat_pas.as_ptr() as *mut u64, Ordering::SeqCst);
    MAT_PAS_LEN.store(rt.mat_pas.len() as u64, Ordering::SeqCst);
    MAT_STATE_PTR.store(rt.mat_state.as_mut_ptr(), Ordering::SeqCst);
    MAT_STATE_LEN.store(rt.mat_state.len() as u64, Ordering::SeqCst);
    MAT_DATA_BASE.store(rt.data_base as u64, Ordering::SeqCst);
    MAT_MEM_TOP.store(rt.mem_top as u64, Ordering::SeqCst);
    MAT_MEM_BUF_PA.store(rt.mem_buf_pa, Ordering::SeqCst);
    MAT_CODE_BASE.store(rt.code_base as u64, Ordering::SeqCst);
    MAT_CODE_TOP.store(rt.code_top as u64, Ordering::SeqCst);
    MAT_CODE_PA.store(rt.code_pa, Ordering::SeqCst);
    MAT_RO_UNITS_SINK.store(&mut rt.ro_units as *mut _, Ordering::SeqCst);
    DIRTY_PAGE_SINK.store(dirty_sink, Ordering::SeqCst);
    ACTIVE_PT_PML4_KVA.store(rt.pt.pml4_kva(), Ordering::SeqCst);
    OWNED_VEC_PTR.store(rt.pt.owned_vec_ptr(), Ordering::SeqCst);
    HANDLERS[14].store(jit_pf_handler as *const () as u64, Ordering::Release);

    let user_stack_top = STACK_VA_M + rt.stack_buf.size();
    // SAFETY: trampoline (inside the Image arena) + stack mapped above;
    // new_cr3 carries kernel half.
    let _user_rax = unsafe { ring3::nub_enter_ring3(rt.tramp_va, user_stack_top, rt.new_cr3) };

    HANDLERS[14].store(0, Ordering::Release);
    TRAP_TABLE_PTR.store(core::ptr::null_mut(), Ordering::SeqCst);
    TRAP_TABLE_LEN.store(0, Ordering::SeqCst);
    JIT_CODE_LEN.store(0, Ordering::SeqCst);
    MAT_RANGES_PTR.store(core::ptr::null_mut(), Ordering::SeqCst);
    MAT_RANGES_LEN.store(0, Ordering::SeqCst);
    MAT_PAS_PTR.store(core::ptr::null_mut(), Ordering::SeqCst);
    MAT_PAS_LEN.store(0, Ordering::SeqCst);
    MAT_STATE_PTR.store(core::ptr::null_mut(), Ordering::SeqCst);
    MAT_STATE_LEN.store(0, Ordering::SeqCst);
    MAT_MEM_TOP.store(0, Ordering::SeqCst);
    MAT_CODE_TOP.store(0, Ordering::SeqCst);
    MAT_RO_UNITS_SINK.store(core::ptr::null_mut(), Ordering::SeqCst);
    DIRTY_PAGE_SINK.store(core::ptr::null_mut(), Ordering::SeqCst);
    ACTIVE_PT_PML4_KVA.store(0, Ordering::SeqCst);
    OWNED_VEC_PTR.store(0, Ordering::SeqCst);

    // Suppress unused-field warning: `pt` is referenced indirectly via
    // `new_cr3` (the PML4's PA) and kept alive by owning the page tables.
    let _ = &rt.pt;

    // SAFETY: ctx_kva still points to the same page (ctx_buf alive).
    unsafe {
        // Copy the 15-register file out first (avoids autoref on the raw
        // pointer deref), then persist only the 13 host-mapped slots — x3/x4
        // (slots 13/14) are invocation-local and dropped at exit (matching
        // the interpreter).
        let all_regs = (*ctx).regs;
        ExitInfo {
            exit_reason: (*ctx).exit_reason,
            exit_arg: (*ctx).exit_arg,
            gas_remaining: (*ctx).gas,
            regs: all_regs[..13].try_into().expect("13 persisted regs"),
            pc: (*ctx).pc,
        }
    }
}
