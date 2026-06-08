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

extern crate alloc;

use crate::cached_cap::CachedCap;
use crate::execution_lane::{ExecutionLane, MAX_EXECUTION_LANES};
use crate::jit_cache;
use crate::page_alloc::GlobalPage;
use crate::paging::{PAGE_SIZE, PageTable};
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
static LAST_GLOBAL_ARENA_TOKEN: [AtomicU64; MAX_EXECUTION_LANES] =
    [const { AtomicU64::new(0) }; MAX_EXECUTION_LANES];
static LAST_GLOBAL_ARENA_PAGES: [AtomicU64; MAX_EXECUTION_LANES] =
    [const { AtomicU64::new(0) }; MAX_EXECUTION_LANES];

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
// write-faults). The DATA region is fully covered by `MAT_RANGES` entries
// sourced from the Instance's `mem` DataCap: pinned VAs are `PinnedCapRo`, the
// rest `UnpinnedCapCow` (initial slabs or — for ephemeral/zero pages — the
// shared zero page, CoW-from-zero on write). CoW'd pages are inserted into the
// running frame's `mem` DataCap overlay (the cap is the source of truth — see
// `OVERLAY_SINK` and `call_loop`).

/// Process-global, leak-once read-only zero page — the shared CoW/page-in source
/// for every `Empty` (absent / zero) guest data page across all frames. It is
/// only ever a materialization *source* (a write CoWs a fresh private page), so
/// one immutable physical page backs every frame without aliasing hazard.
static ZERO_PAGE: GlobalPage = GlobalPage::new();

/// Process-global, leak-once ring-3 [`JitContext`] scratch page (mapped at the
/// fixed [`CTX_VA_M`] in every frame's PT) and ring-3 native x86 stack page
/// (at [`STACK_VA_M`]). Shared across frames because only **one** frame runs in
/// ring 3 at a time (cooperative nesting — each `host_call` fully exits to ring
/// 0), and no ctx/stack state must survive a `host_call` exit: everything the
/// driver needs persists through [`ExitInfo`] → `KernelFrame` and is re-stamped
/// by [`enter_frame`] on resume (regs/gas/pc + the frame-constant
/// `dispatch_table`/`code_base`); the ring-3 stack is reset to its top every
/// entry; `host_rsp_base` and the spilled x3/x4 are per-execution scratch the
/// guest re-initialises. This removes the per-frame CTX + STACK `PageBuf`s.
static CTX_PAGE: GlobalPage = GlobalPage::new();
static STACK_PAGE: GlobalPage = GlobalPage::new();

/// PD physical addresses of the process-global CTX / STACK 1 GiB PD subtrees
/// (PD -> PT -> the shared CTX/STACK page above), built + leaked once and
/// borrowed as the CTX/STACK entries of *every* Image's `Pml4SlotTemplate`, so
/// those identical tables are not duplicated per Image.
static CTX_PD_PA: AtomicU64 = AtomicU64::new(0);
static STACK_PD_PA: AtomicU64 = AtomicU64::new(0);
static GLOBAL_PD_INIT: spin::Mutex<()> = spin::Mutex::new(());

/// Resolve a global CTX/STACK PD PA, building + leaking the PD subtree mapping
/// `page_pa` at `va` on first call.
fn global_pd_pa(slot: &AtomicU64, va: u64, page_pa: u64) -> u64 {
    let cur = slot.load(Ordering::Acquire);
    if cur != 0 {
        return cur;
    }
    let _guard = GLOBAL_PD_INIT.lock();
    let cur = slot.load(Ordering::Acquire);
    if cur != 0 {
        return cur;
    }
    let pa = crate::paging::Pml4SlotTemplate::leak_global_pd(va, page_pa)
        .expect("global CTX/STACK PD alloc");
    slot.store(pa, Ordering::Release);
    pa
}

static MAT_RANGES_PTR: AtomicPtr<crate::call_loop::MatRange> =
    AtomicPtr::new(core::ptr::null_mut());
static MAT_RANGES_LEN: AtomicU64 = AtomicU64::new(0);
/// Physical address of the process-global shared zero page ([`ZERO_PAGE`]) — the
/// source an `Empty` (absent / zero) data page resolves to (mapped RO on read,
/// CoW-from-zero on write). Republished each `enter_frame` so the #PF handler
/// reads it with one atomic load. Per-page cap source PAs are resolved **lazily**
/// on fault from the frame's `mem` DataCap (see [`mem_source_pa`]); there is no
/// eager per-page PA arena, so demand paging materializes only touched pages.
static MAT_ZERO_PA: AtomicU64 = AtomicU64::new(0);
/// Per-page [`javm_exec::mat::PageState`] (one byte/page), len =
/// `(mem_top - data_base) / PAGE_SIZE`. Mutated in place by the handler.
static MAT_STATE_PTR: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
static MAT_STATE_LEN: AtomicU64 = AtomicU64::new(0);
/// Guest VA bounds of the lazily-materialized data extent.
static MAT_DATA_BASE: AtomicU64 = AtomicU64::new(0);
static MAT_MEM_TOP: AtomicU64 = AtomicU64::new(0);
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
/// the `&mut Vec` indirection, like `OVERLAY_SINK`'s `&mut DataCap`).
static MAT_RO_UNITS_SINK: AtomicPtr<alloc::vec::Vec<u32>> = AtomicPtr::new(core::ptr::null_mut());
/// Pointer to the running frame's `mem` DataCap (`KernelFrame.mem`). The #PF
/// handler copy-on-writes each guest write into a fresh page and inserts it
/// into this cap's `overlay` (keyed by data-extent page index) — so the cap
/// carries the frame's writes across any future runtime reclamation (host-backed
/// swap: a rebuilt runtime sources the overlay page, not the immutable backing)
/// and, in Phase 3, a frame-to-frame move at HALT. Re-published every
/// `enter_frame`. The Arc
/// pointee of each inserted page is address-stable across `BTreeMap` realloc,
/// so the PA mapped into the guest PT stays valid (same guarantee the old
/// per-frame dirty-page `Vec` relied on).
static OVERLAY_SINK: AtomicPtr<javm_cap::DataCap> = AtomicPtr::new(core::ptr::null_mut());
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

/// Find the [`crate::call_loop::MatRange`] covering page `page_va` in `ranges`,
/// or `None` for an ephemeral page. Pinned ranges are pushed first, so the
/// first hit is the read-only one when a VA is covered by both a pinned range
/// and the catch-all RW range.
fn mat_range_for_in(
    ranges: &[crate::call_loop::MatRange],
    page_va: u32,
) -> Option<crate::call_loop::MatRange> {
    ranges
        .iter()
        .copied()
        .find(|r| r.start <= page_va && page_va < r.end)
}

/// Find the cap-backed [`crate::call_loop::MatRange`] covering page
/// `page_va` (page-aligned) in the running frame's published `mat_ranges`, or
/// `None` for an ephemeral page.
fn mat_range_for(page_va: u32) -> Option<crate::call_loop::MatRange> {
    let ptr = MAT_RANGES_PTR.load(Ordering::SeqCst);
    let len = MAT_RANGES_LEN.load(Ordering::SeqCst) as usize;
    if ptr.is_null() || len == 0 {
        return None;
    }
    // SAFETY: ptr/len describe the running FrameRuntime's `mat_ranges`
    // Vec, valid until enter_frame clears these statics.
    let ranges = unsafe { core::slice::from_raw_parts(ptr, len) };
    mat_range_for_in(ranges, page_va)
}

/// Resolve the **source physical address** of guest data page `page_va`
/// (page-aligned) on demand from the running frame's `mem` DataCap — the lazy
/// replacement for the former eager per-page `MAT_PAS` arena. A `Loaded` slab
/// resolves to its own PA (dense cap pages are non-contiguous); an `Empty`
/// (absent / zero) page resolves to the shared zero page; a `Missing` page
/// (elided — V1 never mints one) yields `None`, so the caller raises a PVM
/// fault.
///
/// Reading `mem` through `OVERLAY_SINK` is sound: the guest is single-threaded,
/// and this shared read returns a `u64` (the borrow ends) before any `&mut`
/// write to the same cap in [`cow_into_fresh`].
fn mem_source_pa(page_va: u64) -> Option<u64> {
    let data_base = MAT_DATA_BASE.load(Ordering::SeqCst);
    let sink = OVERLAY_SINK.load(Ordering::SeqCst);
    if sink.is_null() {
        return None;
    }
    // SAFETY: OVERLAY_SINK is the running frame's `mem` DataCap, exclusively
    // ours under Hyperlight serialisation; borrowed read-only here.
    let mem = unsafe { &*sink };
    mem_source_pa_in(mem, data_base, page_va, MAT_ZERO_PA.load(Ordering::SeqCst))
}

/// Core of [`mem_source_pa`] over an explicit `mem` / `data_base` / `zero_pa`.
/// `zero_pa` is the shared zero page's PA ([`ZERO_PAGE`]); a `Loaded` slab
/// resolves to its own PA, an `Empty` page to `zero_pa`, a `Missing` page to
/// `None` (→ PVM fault).
fn mem_source_pa_in(
    mem: &javm_cap::DataCap,
    data_base: u64,
    page_va: u64,
    zero_pa: u64,
) -> Option<u64> {
    let i = ((page_va - data_base) / PAGE_SIZE as u64) as usize;
    match mem.page_slot(i) {
        javm_cap::PageSlot::Loaded(pr) => crate::paging::va_to_pa(pr.bytes.as_ptr() as u64),
        javm_cap::PageSlot::Empty => (zero_pa != 0).then_some(zero_pa),
        javm_cap::PageSlot::Missing(_) => None,
    }
}

/// Whether guest data page `page_va` is **privately CoW'd** — present in the
/// running frame's `mem` overlay (rather than sourced read-only from the
/// shared backing). The page-table reuse path keys off this: a write fault
/// on an already-private page (its leaf re-armed read-only at the previous
/// HALT) only needs its leaf W bit flipped back, whereas a write to a shared
/// backing page must CoW a fresh private copy.
fn overlay_has_page(page_va: u64, data_base: u64) -> bool {
    let sink = OVERLAY_SINK.load(Ordering::SeqCst);
    if sink.is_null() {
        return false;
    }
    let idx = ((page_va - data_base) / PAGE_SIZE as u64) as u32;
    // SAFETY: OVERLAY_SINK is the running frame's `mem` DataCap, exclusively
    // ours under Hyperlight serialisation; borrowed read-only here.
    unsafe { (*sink).overlay.contains_key(&idx) }
}

/// Read-only materialization source for a 2 MiB unit: a contiguous slab (code —
/// page PA = `base_pa + offset`) or a cap-backed range whose page PAs are
/// resolved lazily from the frame's `mem` (see [`mem_source_pa`]).
enum RoSrc {
    Contig { base_pa: u64 },
    Mem,
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

    // Materialize-all (low→high), accumulating the CoW charge. Read-only
    // pages (code + PinnedCapRo data caps) are fault-arounded per unit
    // (`cap ∩ 2 MiB cluster`) with **no gas** — read-only page-in is charged
    // at the CALL; only writable (CoW / ephemeral) pages charge per page here.
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
                    Some((r.start as u64, r.end as u64, RoSrc::Mem))
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

        // WRITABLE DATA: cap-backed (UnpinnedCapCow) with CoW. Every in-data
        // page is covered by a `MatRange` (the catch-all RW range spans the
        // whole extent, sourced per-page from `inst.mem`; an `Empty`/ephemeral
        // page resolves to the shared zero page). A page with no range can't be
        // in-data, so it faults.
        let idx = ((pv - data_base) / PAGE_SIZE as u64) as usize;
        let cur = javm_exec::mat::PageState::from_u8(dstate[idx]);
        let kind = match mat_range_for(p) {
            Some(r) => javm_exec::mat::PageKind::from_u8(r.kind)
                .unwrap_or(javm_exec::mat::PageKind::PinnedCapRo),
            None => return false,
        };
        let (charge, next) = match javm_exec::mat::charge_for(cur, kind, is_write) {
            Ok(v) => v,
            Err(_) => return false, // pinned write (already excluded; defensive)
        };
        match next {
            javm_exec::mat::PageState::PresentRo => {
                if cur == javm_exec::mat::PageState::NotPresent {
                    // Page-in: map the page RO at its source PA (resolved lazily
                    // from the frame's `mem`; `None`/`Missing` → fault).
                    let Some(src_pa) = mem_source_pa(pv) else {
                        return false;
                    };
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
                    // Page-table reuse fast path: if this page is already a
                    // private (overlay) page whose leaf was re-armed read-only at
                    // the previous HALT, just flip the leaf's W bit back and reuse
                    // the existing private page — no fresh allocation, no re-copy.
                    // (A present-RO leaf mapping the *shared backing* is NOT in the
                    // overlay, so it correctly falls through to a real CoW.) The
                    // RO translation may be TLB-cached by the faulting write, so
                    // invlpg after the flip.
                    let flipped = overlay_has_page(pv, data_base)
                        && unsafe { crate::paging::pt_set_leaf_w(pml4, pv, true) };
                    if flipped {
                        crate::paging::invlpg(pv);
                    } else {
                        // Flush only when an *existing* present (RO) mapping is
                        // being changed to RW (read-then-write CoW): that stale RO
                        // entry may be TLB-cached. A first-touch write (cur ==
                        // NotPresent) maps a page that was never present, so it
                        // needs no invlpg.
                        let flush = cur == javm_exec::mat::PageState::PresentRo;
                        // Resolve the source PA lazily (from the frame's `mem`): a
                        // `Loaded` cap slab, or the shared zero page for an
                        // ephemeral page (so the CoW yields a fresh zeroed page).
                        // `None` (a `Missing` page) → fault.
                        let Some(src_pa) = mem_source_pa(pv) else {
                            return false;
                        };
                        if !cow_into_fresh(pv, src_pa, pml4, owned_vec, data_base, flush) {
                            // Allocation / remap failure → fault (nothing charged
                            // yet for THIS page, but earlier pages of a straddle
                            // were already advanced; an OOM here is fatal anyway).
                            return false;
                        }
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

/// Copy-on-write a guest page into the running frame's `mem` DataCap overlay:
/// allocate a fresh page-aligned slab, copy the source bytes from `src_pa`,
/// remap the leaf writable at the new PA, and insert the page into the cap's
/// `overlay` (keyed by data-extent page index, `(page_va - data_base) / PAGE`).
/// Returns `false` on allocation / remap failure.
///
/// The overlay carries the write past the runtime's lifetime: a runtime rebuilt
/// after a future reclamation (host-backed swap), or a Phase-3 frame move,
/// sources the overlay page rather than the immutable backing, so the frame's
/// writes are never lost.
/// The slab is `unhashed` (a `[0;32]` sentinel) — overlay pages are hashed
/// only at [`javm_cap::DataCap::flush`], which recomputes; keeping SHA-256 out
/// of the fault path preserves interp==recomp gas parity.
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
    data_base: u64,
    flush: bool,
) -> bool {
    let Some(src_kva) = crate::paging::pa_to_va(src_pa) else {
        return false;
    };
    // SAFETY: src_kva is a live 4 KiB page (cap slab or shared zero page,
    // pinned by the frame), page-aligned.
    let src = unsafe { core::slice::from_raw_parts(src_kva as *const u8, PAGE_SIZE) };
    // Fresh page-aligned overlay slab, copied from the source. Held via `Arc`
    // in the cap overlay; the `PageBytes` pointee (and its `bytes` slab) is
    // address-stable across later `BTreeMap` inserts, so `new_pa` stays valid.
    let page = alloc::sync::Arc::new(javm_cap::PageBytes::from_page_copy_unhashed(src));
    let Some(new_pa) = crate::paging::va_to_pa(page.bytes.as_ptr() as u64) else {
        return false;
    };
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

    let sink_ptr = OVERLAY_SINK.load(Ordering::SeqCst);
    if !sink_ptr.is_null() {
        // SAFETY: sink_ptr is the running frame's `mem` DataCap, re-published
        // each enter_frame; exclusively ours (single-threaded) for the
        // handler's life.
        let mem = unsafe { &mut *sink_ptr };
        let page_idx = ((page_va - data_base) / PAGE_SIZE as u64) as u32;
        // Insert drops any prior overlay page at this index: always empty on the
        // first CoW today (a frame CoWs each page at most once per run). The
        // drop-prior logic stays correct for a future swap-reclaim re-CoW, where
        // the old page would already be unmapped.
        mem.insert_overlay_page(page_idx, javm_cap::PageSlot::Loaded(page));
    }
    true
}

/// Materialize the read-only **unit** containing `pv`: the intersection of
/// the cap `[r_start, r_end)` with the 2 MiB cluster containing `pv`, named
/// by [`javm_exec::mat::unit_base`]. The first time the unit faults (a fresh
/// `unit_base` inserted into the sorted `ro_units` set) its RO pages are
/// **fault-arounded** — mapped present read-only straight from the cap so
/// the retry (and later reads in the unit) hit no further faults — and a
/// later fault on the same unit is a no-op. This **charges no gas**:
/// read-only page-in is accounted eagerly at the CALL
/// ([`javm_exec::gas_const::call_frame_cost`]); the `ro_units` set here is
/// purely a fault-reduction / mapping optimization. Clamping the fault-around
/// to one cap means a single map event touches at most one DataCap.
///
/// No `invlpg`: every page mapped here goes `NotPresent → present`, which is
/// not TLB-cached, so the faulting retry walks the fresh entries. Returns
/// `Some(0)` on success, or `None` on a page-table allocation failure.
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
        // cap's pages each resolve their own slab PA lazily from the frame mem.
        let page_pa = match &src {
            RoSrc::Contig { base_pa } => base_pa + (q - r_start),
            RoSrc::Mem => mem_source_pa(q)?,
        };
        // SAFETY: live PT, single writer; builds the path (zero-setup).
        unsafe {
            crate::paging::pt_map_leaf(pml4, q, page_pa, crate::paging::Perm::user_ro(), owned_vec)
        }?;
        // No invlpg: NotPresent → present is not TLB-cached.
        q += PAGE_SIZE as u64;
    }
    // Read-only page-in is charged at the CALL, not here: mapping is free.
    Some(0)
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

/// PML4 slot 1 (base 512 GiB) hosts CTX + the per-Image arena + STACK.
/// MEM stays in `PML4[0]` at VA 0 so PVM addresses are still native VAs.
/// Placing CTX in this slot too keeps it within ±2 GiB of the JIT
/// region so codegen's RIP-relative addressing reaches it.
///
/// The three sub-regions occupy distinct 1 GiB PDPT slots within the
/// PML4 slot so the per-Image template PT can own the META PD without
/// colliding with the CTX/STACK PDs.
///
/// CTX and STACK are process-global shared pages ([`CTX_PAGE`] /
/// [`STACK_PAGE`]) mapped at the fixed VAs below in every frame's PT — only
/// one frame runs in ring 3 at a time, so they need no per-call copy.
///
/// ```text
///   PML4[1] (512..1024 GiB)
///     PDPT[0] (512..513 GiB)  ← CTX, global shared page
///     PDPT[1] (513..514 GiB)  ← META arena, template-owned
///     PDPT[2] (514..515 GiB)  ← STACK, global shared page
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
/// Ring-3 native x86 stack size (one page) — the SP starts at
/// `STACK_VA_M + STACK_SIZE` every entry.
const STACK_SIZE: u64 = PAGE_SIZE as u64;

/// Per-frame ring-3 resources retained across re-entries.
///
/// Holds the per-call page table plus the cached `CompiledImage` fields needed
/// to publish #PF-handler atomics on every entry. Built once per `KernelFrame`
/// (lazily on first [`enter_frame`]) and reused across every re-entry on the
/// same frame — it is **not** evicted (the synchronous call stack is bounded
/// structurally, so all live page tables stay resident). The CTX, STACK, and
/// zero scratch pages are process-global ([`CTX_PAGE`] / [`STACK_PAGE`] /
/// [`ZERO_PAGE`]), shared by every frame (only one runs in ring 3 at a time),
/// so the page table is the bulk of a frame's footprint.
///
/// The category-#3 materialization *bookkeeping* (`mat_state` / `ro_units`)
/// lives on the [`KernelFrame`](crate::call_loop), not here — it is gas history
/// that must outlive any future reclamation of this runtime (host-backed swap),
/// so that a resumed frame never re-charges gas for pages it already paid for
/// (which would fork the never-reclaiming interpreter).
///
/// The frame-constant `JitContext` fields the JIT reads — `dispatch_table`
/// (= [`Self::dispatch_va`]) and `code_base` (= [`Self::jit_va`]) — are
/// re-stamped by [`enter_frame`] each entry (they differ per image, and the
/// ctx page is shared), alongside the per-entry regs/pc/gas/exit_*.
pub struct FrameRuntime {
    lane: ExecutionLane,
    pt: PageTable,
    jit_va: u64,
    jit_size: u64,
    /// Dispatch-table VA (`META_BASE_M + dispatch_offset`) — re-stamped into
    /// the shared ctx page's `dispatch_table` each entry.
    dispatch_va: u64,
    exit_label_va: u64,
    trap_table_ptr: *const (u32, u32, u32),
    trap_table_len: u64,
    tramp_va: u64,
    new_cr3: u64,
    /// Identity + page count for the per-Image META arena whose template leaf
    /// PTEs are marked global. Used to invalidate stale global translations
    /// only when switching Images.
    global_arena_token: u64,
    global_arena_pages: u64,
    // ---- Category-#3 lazy-materialization map (region bounds + kind;
    // published to the #PF handler each entry). The mutable per-page *state*
    // lives on the `KernelFrame` so it survives any future reclamation of this
    // runtime (host-backed swap). ----
    /// Cap-backed data mappings (pinned RO / initial CoW) covering the data
    /// extent — region bounds + kind only. Per-page source PAs are resolved
    /// lazily on fault ([`mem_source_pa`]); there is no per-page PA arena.
    mat_ranges: alloc::vec::Vec<crate::call_loop::MatRange>,
    /// Guest VA bounds of the lazily-materialized data extent.
    data_base: u32,
    mem_top: u32,
    /// Read-only CODE region (page-rounded): `[code_base, code_top)`,
    /// source PA `code_pa`. Lazily materialized `PinnedCapRo` like a
    /// pinned data cap, per unit (`code ∩ cluster`).
    code_base: u32,
    code_top: u32,
    code_pa: u64,
}

impl FrameRuntime {
    /// Page-aligned byte size of the lazily-materialized data extent
    /// (`mem_top − data_base`). For a reused runtime this must equal the
    /// instance's `mem.content_len()` — images are immutable, so the extent
    /// is fixed per image (asserted on reuse).
    pub fn data_extent(&self) -> u64 {
        (self.mem_top as u64).saturating_sub(self.data_base as u64)
    }

    /// HALT re-arm for a runtime that is about to be **parked** for reuse by
    /// the next CALL of its resident instance: clear the Writable bit on the
    /// leaf of every privately-CoW'd page (the keys of the instance's
    /// `overlay`), so the next CALL re-faults on first write and re-charges
    /// its CoW — exactly the per-frame CoW charge a fresh frame would pay, so
    /// gas stays identical whether or not the page table was cached. The page
    /// itself is reused: only the W bit toggles, no allocation.
    ///
    /// No `invlpg`: every `enter_frame` reloads CR3, which flushes every
    /// non-global TLB entry, so the cleared-W leaves are re-walked next CALL.
    pub fn rearm_cow<I: Iterator<Item = u32>>(&self, overlay_page_indices: I) {
        let pml4 = self.pt.pml4_kva();
        let data_base = self.data_base as u64;
        for idx in overlay_page_indices {
            let va = data_base + (idx as u64) * PAGE_SIZE as u64;
            // SAFETY: `pml4` is this runtime's live page table; single-threaded
            // (the guest is suspended). A leaf that is absent (never faulted in)
            // simply returns `false` — nothing to re-arm.
            unsafe {
                crate::paging::pt_set_leaf_w(pml4, va, false);
            }
        }
    }
}

/// Build a per-frame runtime: compile the Image (cached) and build the
/// per-call page table, mapping the global CTX/STACK pages + the borrowed
/// per-Image arena PD into it.
///
/// All `JitContext` fields are written by [`enter_frame`] (the ctx page is
/// shared, so even the frame-constant `dispatch_table`/`code_base` are
/// re-stamped per entry); this function writes none.
///
/// The `code` is raw RV+C+custom-0 bytes; the JIT cache predecodes it
/// once and reuses the result on subsequent calls. `code_base` is the
/// guest VA the region maps at — it's threaded into the compiler (so
/// `auipc`/`jalr` resolve correctly) and into the cache key.
///
/// The dense dispatch table (one `i32` per code byte, built by
/// `jit_cache::with_compiled_image`; non-block-start slots hold the
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
    lane: ExecutionLane,
    image_cap: &CachedCap,
    image_hash: &javm_cap::CapHash,
    code: &[u8],
    code_base: u32,
    code_pa: u64,
    mem_size: u32,
    mat_ranges: alloc::vec::Vec<crate::call_loop::MatRange>,
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
    jit_cache::with_compiled_image(
        image_cap,
        image_hash,
        code,
        code_base,
        META_BASE_M,
        CTX_VA_M,
        STACK_VA_M,
        global_pd_pa(&CTX_PD_PA, CTX_VA_M, CTX_PAGE.pa()),
        global_pd_pa(&STACK_PD_PA, STACK_VA_M, STACK_PAGE.pa()),
        mem_cycles,
        helpers,
        |cached| {
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

            // Memory is sourced lazily from the Instance's `mem` DataCap via
            // `mat_ranges`: every data page is covered by a `MatRange` (initial/pinned
            // slabs or the shared zero page), so there is NO eager flat buffer. CTX and
            // STACK are process-global shared pages ([`CTX_PAGE`] / [`STACK_PAGE`]) —
            // nothing is allocated per call but the page table itself. The shared ctx's
            // frame-constant fields (`dispatch_table` / `code_base`) are re-stamped by
            // [`enter_frame`] each entry (the page is shared, the image differs).

            let mut pt = PageTable::new()?;
            // True zero-setup demand paging: the WHOLE guest low VA range (PML4[0]
            // — both CODE at CODE_BASE and DATA at DATA_BASE) is left with NO
            // page-table entries here. The first guest touch of each page faults
            // into `jit_pf_handler`, which builds the PML4→PT path (recording the
            // new tables in `pt.owned`) and materializes the page (page-in / CoW),
            // charging #3. There is no eager data buffer: every page is materialized
            // from the frame's `mem` DataCap (cap slabs or the shared zero page).
            //
            // The per-page #3 *state* (`mat_state`) and the RO-unit set (`ro_units`)
            // live on the owning `KernelFrame`, NOT here — they are gas history that
            // must outlive any future reclamation of this runtime (host-backed swap).
            let mem_top = (data_base + mem_bytes) as u32;
            // Code region: page-rounded `[code_base, code_top)`, lazily paged in
            // RO (PinnedCapRo) per unit on guest PIC reads. The code buffer is
            // page-aligned with a zeroed tail, so paging in the last (partial) page
            // is safe.
            let code_bytes_rounded = code.len().next_multiple_of(PAGE_SIZE);
            let code_top = code_base.saturating_add(code_bytes_rounded as u32);
            // Install the entire PML4 slot-1 subtree (CTX | META arena | STACK) with a
            // single borrowed PML4 write. CTX/STACK are the global shared pages and the
            // arena PD is per-Image, so the whole PDPT is an Image constant built once
            // in `with_compiled_image` — no per-frame CTX/STACK PDPT/PD/PT allocation.
            pt.install_borrowed_pdpt(META_PML4_BASE, cached.template_pdpt_pa)?;
            let new_cr3 = pt.cr3()?;

            Some(FrameRuntime {
                lane,
                pt,
                jit_va,
                jit_size: cached.jit_size as u64,
                dispatch_va,
                exit_label_va: jit_va + cached.exit_label_offset as u64,
                trap_table_ptr: cached.trap_table.as_ptr(),
                trap_table_len: cached.trap_table.len() as u64,
                tramp_va,
                new_cr3,
                global_arena_token: cached.global_arena_token,
                global_arena_pages: (cached.arena_size / PAGE_SIZE) as u64,
                mat_ranges,
                data_base: data_base as u32,
                mem_top,
                code_base,
                code_top,
                code_pa,
            })
        },
    )
}

/// Enter ring 3 on `rt`. Updates per-entry `JitContext` fields (regs,
/// pc, gas, exit_*), publishes the #PF handler atomics (including the
/// category-#3 materialization state from `rt`), drops to ring 3, then
/// reads back the post-exit state.
///
/// `overlay_sink` is the running frame's `mem` DataCap; the handler inserts
/// each CoW'd page into its `overlay` (may be null to disable bookkeeping).
/// `mat_state` (per-page `PageState`, len = data-extent pages) and `ro_units`
/// (sorted RO-unit set) are the category-#3 bookkeeping — they live on the
/// owning [`KernelFrame`](crate::call_loop) (gas history that outlives any
/// future reclamation of this runtime), and the caller passes raw pointers so
/// the #PF handler can mutate them in place
/// while the JIT runs. The lazily-materialized data *ranges* live in `rt` and
/// are republished here each entry.
///
/// # Safety
/// Mutates CR3 + GDT + IDT during the call. Single-threaded by
/// Hyperlight construction. `overlay_sink`, `mat_state_ptr` (valid for
/// `mat_state_len` bytes), and `ro_units` must outlive the call.
#[allow(clippy::too_many_arguments)]
pub unsafe fn enter_frame(
    lane: ExecutionLane,
    rt: &mut FrameRuntime,
    initial_gas: i64,
    entry_pc: u32,
    initial_regs: [u64; 13],
    overlay_sink: *mut javm_cap::DataCap,
    mat_state_ptr: *mut u8,
    mat_state_len: u64,
    ro_units: *mut alloc::vec::Vec<u32>,
) -> ExitInfo {
    assert_eq!(rt.lane, lane, "FrameRuntime entered on the wrong lane");
    let ctx_kva = CTX_PAGE.kva();
    let ctx = ctx_kva as *mut JitContext;
    // SAFETY: CTX_PAGE is the process-global ring-3 ctx page, leaked for the
    // kernel's lifetime; mapped at CTX_VA_M in this frame's PT.
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
        // Frame-constant fields the JIT reads. Re-stamped every entry because
        // the ctx page is shared across frames running different images
        // (build-time init is gone). `host_rsp_base` + the spilled x3/x4 are
        // per-execution scratch the prologue re-initialises; the vestigial
        // heap_*/flat_buf/fast_reentry/max_heap_pages are never read by codegen
        // and stay zero (the page's leak-once init).
        (*ctx).dispatch_table = rt.dispatch_va as *const i32;
        (*ctx).code_base = rt.jit_va;
    }

    // ---- install ring-3 GDT/IDT + select lane-local exit state ------------
    // SAFETY: ring-0 mutation of GDT/IDT/GS base; `lane` is owned by the
    // current vCPU worker.
    unsafe { ring3::prepare_ring3_entry(lane) };

    JIT_CODE_BASE.store(rt.jit_va, Ordering::SeqCst);
    JIT_CODE_LEN.store(rt.jit_size, Ordering::SeqCst);
    EXIT_LABEL_VA.store(rt.exit_label_va, Ordering::SeqCst);
    TRAP_TABLE_PTR.store(rt.trap_table_ptr as *mut (u32, u32, u32), Ordering::SeqCst);
    TRAP_TABLE_LEN.store(rt.trap_table_len, Ordering::SeqCst);
    CTX_KVA.store(ctx_kva, Ordering::SeqCst);
    MAT_RANGES_PTR.store(
        rt.mat_ranges.as_ptr() as *mut crate::call_loop::MatRange,
        Ordering::SeqCst,
    );
    MAT_RANGES_LEN.store(rt.mat_ranges.len() as u64, Ordering::SeqCst);
    MAT_ZERO_PA.store(ZERO_PAGE.pa(), Ordering::SeqCst);
    MAT_STATE_PTR.store(mat_state_ptr, Ordering::SeqCst);
    MAT_STATE_LEN.store(mat_state_len, Ordering::SeqCst);
    MAT_DATA_BASE.store(rt.data_base as u64, Ordering::SeqCst);
    MAT_MEM_TOP.store(rt.mem_top as u64, Ordering::SeqCst);
    MAT_CODE_BASE.store(rt.code_base as u64, Ordering::SeqCst);
    MAT_CODE_TOP.store(rt.code_top as u64, Ordering::SeqCst);
    MAT_CODE_PA.store(rt.code_pa, Ordering::SeqCst);
    MAT_RO_UNITS_SINK.store(ro_units, Ordering::SeqCst);
    OVERLAY_SINK.store(overlay_sink, Ordering::SeqCst);
    ACTIVE_PT_PML4_KVA.store(rt.pt.pml4_kva(), Ordering::SeqCst);
    OWNED_VEC_PTR.store(rt.pt.owned_vec_ptr(), Ordering::SeqCst);
    HANDLERS[14].store(jit_pf_handler as *const () as u64, Ordering::Release);

    crate::paging::enable_global_pages();
    flush_global_arena_on_image_switch(lane, rt.global_arena_token, rt.global_arena_pages);

    let user_stack_top = STACK_VA_M + STACK_SIZE;
    // SAFETY: trampoline (inside the Image arena) + stack mapped above;
    // new_cr3 carries kernel half.
    let _user_rax = unsafe { ring3::nub_enter_ring3(rt.tramp_va, user_stack_top, rt.new_cr3) };

    HANDLERS[14].store(0, Ordering::Release);
    TRAP_TABLE_PTR.store(core::ptr::null_mut(), Ordering::SeqCst);
    TRAP_TABLE_LEN.store(0, Ordering::SeqCst);
    JIT_CODE_LEN.store(0, Ordering::SeqCst);
    MAT_RANGES_PTR.store(core::ptr::null_mut(), Ordering::SeqCst);
    MAT_RANGES_LEN.store(0, Ordering::SeqCst);
    MAT_ZERO_PA.store(0, Ordering::SeqCst);
    MAT_STATE_PTR.store(core::ptr::null_mut(), Ordering::SeqCst);
    MAT_STATE_LEN.store(0, Ordering::SeqCst);
    MAT_MEM_TOP.store(0, Ordering::SeqCst);
    MAT_CODE_TOP.store(0, Ordering::SeqCst);
    MAT_RO_UNITS_SINK.store(core::ptr::null_mut(), Ordering::SeqCst);
    OVERLAY_SINK.store(core::ptr::null_mut(), Ordering::SeqCst);
    ACTIVE_PT_PML4_KVA.store(0, Ordering::SeqCst);
    OWNED_VEC_PTR.store(0, Ordering::SeqCst);

    // Suppress unused-field warning: `pt` is referenced indirectly via
    // `new_cr3` (the PML4's PA) and kept alive by owning the page tables.
    let _ = &rt.pt;

    // SAFETY: ctx still points to the shared global ctx page (leaked, alive).
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

fn flush_global_arena_on_image_switch(lane: ExecutionLane, next_token: u64, next_pages: u64) {
    let idx = lane.index();
    lane.assert_in_range();
    let prev_token = LAST_GLOBAL_ARENA_TOKEN[idx].load(Ordering::SeqCst);
    if prev_token != 0 && prev_token != next_token {
        let prev_pages = LAST_GLOBAL_ARENA_PAGES[idx].load(Ordering::SeqCst);
        for page in 0..prev_pages {
            crate::paging::invlpg(META_BASE_M + page * PAGE_SIZE as u64);
        }
    }
    LAST_GLOBAL_ARENA_PAGES[idx].store(next_pages, Ordering::SeqCst);
    LAST_GLOBAL_ARENA_TOKEN[idx].store(next_token, Ordering::SeqCst);
}
