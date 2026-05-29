//! In-kernel JIT execution at ring 3.
//!
//! Takes a PVM program (code + basic-block-start set) and runs it
//! inside a per-invocation page table at ring 3. The PVM exits
//! through `int 0x81` (a hand-rolled trampoline placed after the
//! JIT'd code at a user-RX VA); the kernel handler longjmps back to
//! the caller of [`run_pvm_with_mem`] and we read the JitContext
//! that the JIT wrote during execution.
//!
//! ## Memory layout (per invocation, in the new page table)
//!
//! Everything lives in PML4 slot 0 (low VA, kernel relocated to slot
//! 511 in Stage F kernel-high). PVM addr == native VA: guest memory
//! starts at VA 0 so mem accesses can use `[rdx]` baseless. The
//! NULL-deref guard the old layout provided at VA 0 is moot here —
//! the JIT page table is per-invocation and only the guest's own
//! mem region is mapped low.
//!
//! CTX sits at VA 4 GiB — the first page above the PVM u32 address
//! range. The recompiler doesn't bounds-check guest mem (the PT does)
//! so the full low 4 GiB belongs to the program; CTX must be outside.
//! CTX is reached via RIP-relative addressing from the JIT code in
//! META, which is within ±2 GiB.
//!
//! ```text
//!   MEM_VA   = 0                  mem_size bytes guest memory     (user-RW)
//!   CTX_VA   = 4 GiB              4 KiB JitContext                (user-RW)
//!
//!   META_BASE= 4 GiB + 16 MiB     per-Image arena base
//!                                 (BB | DISPATCH | JIT | TRAMP)
//!     BB / DISPATCH                                               (user-RO)
//!     JIT / TRAMP                                                 (user-RX)
//!
//!   STACK    = META + 1 GiB       ring-3 x86 stack, 4 KiB         (user-RW)
//! ```
//!
//! Guest code is mapped read-only into the low-4 GiB guest range at its
//! `CODE_BASE` (a `DirectMap`, like a pinned data cap), so PVM PCs are
//! real VAs and the guest can read its own bytes (PIC AUIPC+load).
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
// Set by `run_pvm_with_mem` immediately before `enter_ring3`, read by
// `jit_pf_handler` if a #PF fires from inside the JIT'd code window.
// Single-threaded (Hyperlight serialises calls), so unsynchronised
// statics are safe — we use atomics for `&'static mut` avoidance only.

static JIT_CODE_BASE: AtomicU64 = AtomicU64::new(0);
static JIT_CODE_LEN: AtomicU64 = AtomicU64::new(0);
static EXIT_LABEL_VA: AtomicU64 = AtomicU64::new(0);
static TRAP_TABLE_PTR: AtomicPtr<(u32, u32)> = AtomicPtr::new(core::ptr::null_mut());
static TRAP_TABLE_LEN: AtomicU64 = AtomicU64::new(0);
static CTX_KVA: AtomicU64 = AtomicU64::new(0);

// === Per-invocation CoW state =============================================
//
// Set by `enter_frame` so `jit_pf_handler` can recognise legitimate
// guest writes to mapped DataCap pages, allocate a fresh page, and
// remap the PTE writable + new PA. The handler appends the dirty
// page to a per-frame sink for downstream auto-mint (Commit 5).

static COW_RANGES_PTR: AtomicPtr<crate::call_loop::CowRange> =
    AtomicPtr::new(core::ptr::null_mut());
static COW_RANGES_LEN: AtomicU64 = AtomicU64::new(0);
static DIRTY_PAGE_SINK: AtomicPtr<alloc::vec::Vec<crate::call_loop::DirtyPage>> =
    AtomicPtr::new(core::ptr::null_mut());
static ACTIVE_PT_PML4_KVA: AtomicU64 = AtomicU64::new(0);

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
    _ctx: *mut Context,
    gva: u64,
) -> bool {
    // SAFETY: Hyperlight passes a valid pointer to the iretq frame.
    let saved_rip = unsafe { (&raw const (*info).rip).read_volatile() };
    let code_base = JIT_CODE_BASE.load(Ordering::SeqCst);
    let code_len = JIT_CODE_LEN.load(Ordering::SeqCst);
    if code_len == 0 || saved_rip < code_base || saved_rip >= code_base + code_len {
        return false;
    }

    // CoW: if the faulting GVA falls inside a CoW-armed range, copy
    // the cap page onto a fresh kernel-allocated page, rewrite the
    // PTE writable + new PA, invlpg, retry the faulting instruction.
    if try_handle_cow(gva) {
        return true;
    }

    let offset = (saved_rip - code_base) as u32;
    let tt_ptr = TRAP_TABLE_PTR.load(Ordering::SeqCst);
    let tt_len = TRAP_TABLE_LEN.load(Ordering::SeqCst) as usize;
    let mut pvm_pc = 0u32;
    if !tt_ptr.is_null() && tt_len > 0 {
        // SAFETY: tt_ptr + tt_len describes a contiguous slice in
        // kernel memory, valid for the duration of `run_pvm_with_mem`
        // (which is the only function that publishes / clears the
        // statics that point at it).
        let tt = unsafe { core::slice::from_raw_parts(tt_ptr, tt_len) };
        match tt.binary_search_by_key(&offset, |&(no, _)| no) {
            Ok(idx) => pvm_pc = tt[idx].1,
            Err(0) => {}
            Err(idx) => pvm_pc = tt[idx - 1].1,
        }
    }

    let ctx_kva = CTX_KVA.load(Ordering::SeqCst);
    // SAFETY: ctx_kva is the kernel VA of the JitContext page for the
    // current invocation; valid while the handler runs.
    unsafe {
        let ctx = ctx_kva as *mut JitContext;
        (*ctx).exit_reason = 3; // PageFault
        (*ctx).exit_arg = gva as u32;
        (*ctx).pc = pvm_pc;
    }

    let exit_va = EXIT_LABEL_VA.load(Ordering::SeqCst);
    // SAFETY: info is a valid pointer to a writable iretq frame.
    unsafe {
        (&raw mut (*info).rip).write_volatile(exit_va);
    }
    true
}

/// If `gva` falls inside one of the per-frame CoW-armed ranges
/// published at `enter_frame` time, allocate a fresh page, copy from
/// the read-only cap page currently mapped there, rewrite the PTE
/// writable, invlpg, and append a [`crate::call_loop::DirtyPage`] to
/// the per-frame sink. Returns `true` on success — the caller should
/// retry the faulting instruction by leaving RIP untouched.
fn try_handle_cow(gva: u64) -> bool {
    let cow_ptr = COW_RANGES_PTR.load(Ordering::SeqCst);
    let cow_len = COW_RANGES_LEN.load(Ordering::SeqCst) as usize;
    if cow_ptr.is_null() || cow_len == 0 {
        return false;
    }
    // SAFETY: cow_ptr/cow_len describe a contiguous slice owned by
    // the running KernelFrame's `cow_ranges` Vec, valid until
    // enter_frame returns and clears these statics.
    let cows = unsafe { core::slice::from_raw_parts(cow_ptr, cow_len) };
    let cow = cows
        .iter()
        .find(|c| (c.start as u64) <= gva && gva < (c.end as u64));
    let Some(cow) = cow else {
        return false;
    };

    let page_va = gva & !(PAGE_SIZE as u64 - 1);
    let pml4_kva = ACTIVE_PT_PML4_KVA.load(Ordering::SeqCst);
    if pml4_kva == 0 {
        return false;
    }
    // SAFETY: pml4_kva was set by enter_frame to the kernel VA of
    // the live per-call page table; valid while the handler runs.
    let current_pa = match unsafe { crate::paging::pt_lookup_leaf(pml4_kva, page_va) } {
        Some(pa) => pa,
        None => return false,
    };
    let Some(src_kva) = crate::paging::pa_to_va(current_pa) else {
        return false;
    };
    let Some(new_page) = crate::page_alloc::PageBuf::new(PAGE_SIZE) else {
        return false;
    };
    let new_pa = new_page.pa();
    let new_kva = new_page.kva();
    // SAFETY: src_kva points at a 4 KiB page in talc-heap memory
    // (refcount-pinned by the frame); new_page is a fresh, owned 4
    // KiB page. Both pointers are 4 KiB-aligned.
    unsafe {
        core::ptr::copy_nonoverlapping(src_kva as *const u8, new_kva as *mut u8, PAGE_SIZE);
    }

    // SAFETY: pml4_kva is the live PT; we're the only writer
    // (single-threaded guest). page_va was just looked up so the
    // walk is guaranteed to terminate at a present leaf PTE.
    if unsafe {
        crate::paging::pt_remap_leaf(pml4_kva, page_va, new_pa, crate::paging::Perm::user_rw())
    }
    .is_none()
    {
        return false;
    }
    crate::paging::invlpg(page_va);

    let sink_ptr = DIRTY_PAGE_SINK.load(Ordering::SeqCst);
    if sink_ptr.is_null() {
        // No sink; the write still succeeded but we lose the
        // ability to auto-mint at frame pop. Should not happen
        // in normal flow (enter_frame always publishes a sink).
        return true;
    }
    // SAFETY: sink_ptr was set by enter_frame to a *mut Vec<…>
    // pointing into a KernelFrame field; the Vec struct's address
    // is stable across pushes (only the underlying buffer moves).
    let sink = unsafe { &mut *sink_ptr };
    sink.push(crate::call_loop::DirtyPage {
        guest_va: page_va as u32,
        source_hash: cow.source_hash,
        source_slot: cow.source_slot,
        page: new_page,
    });
    true
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
// VA `[0, mem_size)` mirrors PVM's u32 address space directly so
// mem accesses can use `[rdx]` baseless. CTX sits at exactly 4 GiB
// — the first page above the PVM u32 range. The recompiler does no
// bounds-checking on guest mem (the PT does, via faults outside
// `[0, mem_size)`) so PVM addresses can reach anywhere in the low
// 4 GiB; CTX must be outside that range to avoid spoofing.

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
/// Base of the per-Image arena (BB | DISPATCH | JIT | TRAMP).
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

/// One direct mem mapping projected straight into the per-call PT.
/// `start` is the guest VA (4 KiB-aligned), `pa` the source physical
/// address (in the talc-heap PA range under [`crate::paging::va_to_pa`]),
/// `size` the length to map (4 KiB-aligned). Mapped read-only over
/// the per-frame mem_buf so guest reads pull straight from the shared
/// cap pages — no per-call memcpy.
#[derive(Clone, Copy)]
pub struct DirectMap {
    pub start: u32,
    pub pa: u64,
    pub size: u32,
}

/// Per-frame ring-3 resources retained across re-entries.
///
/// Holds the per-call page table + private mem/ctx/stack pages, plus
/// the cached `CompiledImage` fields needed to publish #PF-handler
/// atomics on every entry. Built once per `KernelFrame` (lazily on
/// first [`enter_frame`]); reused across re-entries on the same frame
/// — saves N PageTable + 3 PageBuf allocations in a depth-N recursion.
///
/// Frame-constant `JitContext` fields (bb_starts, dispatch_table,
/// code_base, flat_buf, …) are written once when the runtime is built.
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
    trap_table_ptr: *const (u32, u32),
    trap_table_len: u64,
    tramp_va: u64,
    new_cr3: u64,
    ctx_kva: u64,
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
/// The BB region holds the basic-block-start set (sized to `code.len()`,
/// populated by `jit_cache::get_or_compile`); `jalr` targets are
/// validated against it directly (no jump table). The code itself is
/// RO-mapped into the guest range at `code_base` via `direct_maps`.
///
/// # Safety
/// Same constraints as [`build_frame_runtime`].
#[allow(clippy::too_many_arguments)]
pub unsafe fn build_frame_runtime(
    image_hash: &javm_cap::CapHash,
    code: &[u8],
    code_base: u32,
    entry_pc: u32,
    mem_size: u32,
    arg: MemRegion,
    ro: MemRegion,
    rw: MemRegion,
    direct_maps: &[DirectMap],
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
        sbrk_helper: 0x1009,
    };
    let cached = jit_cache::get_or_compile(
        image_hash,
        code,
        code_base,
        META_BASE_M,
        CTX_VA_M,
        javm_exec::gas_cost::DEFAULT_MEM_CYCLES,
        helpers,
    );
    if cached.jit_size == 0 {
        return None;
    }

    let bb_va = META_BASE_M + cached.bb_offset as u64;
    let dispatch_va = META_BASE_M + cached.dispatch_offset as u64;
    let jit_va = META_BASE_M + cached.jit_offset as u64;
    let tramp_va = META_BASE_M + cached.tramp_offset as u64;

    let mem_bytes = (mem_size as usize).next_multiple_of(PAGE_SIZE);

    let mem_buf = PageBuf::new(mem_bytes.max(PAGE_SIZE))?;
    let ctx_buf = PageBuf::new(PAGE_SIZE)?;
    let stack_buf = PageBuf::new(PAGE_SIZE)?;

    for region in [arg, ro, rw] {
        if region.data.is_empty() {
            continue;
        }
        let off = region.start as usize;
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
        // jalr validation uses the BB (basic-block-start) set directly —
        // no separate jump table.
        (*ctx).bb_starts = bb_va as *const u8;
        (*ctx).bb_len = code.len() as u32;
        (*ctx)._pad1 = 0;
        (*ctx).entry_pc = entry_pc;
        (*ctx).dispatch_table = dispatch_va as *const i32;
        (*ctx).code_base = jit_va;
        (*ctx).flat_buf = MEM_VA_M as *mut u8;
        (*ctx).fast_reentry = 0;
        (*ctx)._pad2 = 0;
        (*ctx).max_heap_pages = 0;
        (*ctx)._pad3 = 0;
    }

    let mut pt = PageTable::new()?;
    pt.map(CTX_VA_M, ctx_buf.pa(), ctx_buf.size(), Perm::user_rw())?;
    if mem_bytes > 0 {
        pt.map(MEM_VA_M, mem_buf.pa(), mem_buf.size(), Perm::user_rw())?;
    }
    for dm in direct_maps {
        if dm.size == 0 {
            continue;
        }
        pt.map(
            MEM_VA_M + dm.start as u64,
            dm.pa,
            dm.size as u64,
            Perm::user_ro(),
        )?;
    }
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
    })
}

/// Enter ring 3 on `rt`. Updates per-entry `JitContext` fields (regs,
/// pc, gas, exit_*), publishes the #PF handler atomics (including
/// CoW state), drops to ring 3, then reads back the post-exit state.
///
/// `cow_ranges` describes which guest VAs the #PF handler should
/// CoW on a write fault. `dirty_sink` is the per-frame `Vec` the
/// handler appends to on each successful CoW (may be null to
/// disable bookkeeping).
///
/// # Safety
/// Mutates CR3 + GDT + IDT during the call. Single-threaded by
/// Hyperlight construction. `cow_ranges` + `dirty_sink` must outlive
/// the call.
#[allow(clippy::too_many_arguments)]
pub unsafe fn enter_frame(
    rt: &mut FrameRuntime,
    initial_gas: i64,
    entry_pc: u32,
    initial_regs: [u64; 13],
    cow_ranges: &[crate::call_loop::CowRange],
    dirty_sink: *mut alloc::vec::Vec<crate::call_loop::DirtyPage>,
) -> ExitInfo {
    let ctx = rt.ctx_kva as *mut JitContext;
    // SAFETY: ctx_kva owned by `rt.ctx_buf`, alive across this call.
    unsafe {
        (*ctx).regs = initial_regs;
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
    TRAP_TABLE_PTR.store(rt.trap_table_ptr as *mut (u32, u32), Ordering::SeqCst);
    TRAP_TABLE_LEN.store(rt.trap_table_len, Ordering::SeqCst);
    CTX_KVA.store(rt.ctx_kva, Ordering::SeqCst);
    COW_RANGES_PTR.store(
        cow_ranges.as_ptr() as *mut crate::call_loop::CowRange,
        Ordering::SeqCst,
    );
    COW_RANGES_LEN.store(cow_ranges.len() as u64, Ordering::SeqCst);
    DIRTY_PAGE_SINK.store(dirty_sink, Ordering::SeqCst);
    ACTIVE_PT_PML4_KVA.store(rt.pt.pml4_kva(), Ordering::SeqCst);
    HANDLERS[14].store(jit_pf_handler as *const () as u64, Ordering::Release);

    let user_stack_top = STACK_VA_M + rt.stack_buf.size();
    // SAFETY: trampoline (inside the Image arena) + stack mapped above;
    // new_cr3 carries kernel half.
    let _user_rax = unsafe { ring3::nub_enter_ring3(rt.tramp_va, user_stack_top, rt.new_cr3) };

    HANDLERS[14].store(0, Ordering::Release);
    TRAP_TABLE_PTR.store(core::ptr::null_mut(), Ordering::SeqCst);
    TRAP_TABLE_LEN.store(0, Ordering::SeqCst);
    JIT_CODE_LEN.store(0, Ordering::SeqCst);
    COW_RANGES_PTR.store(core::ptr::null_mut(), Ordering::SeqCst);
    COW_RANGES_LEN.store(0, Ordering::SeqCst);
    DIRTY_PAGE_SINK.store(core::ptr::null_mut(), Ordering::SeqCst);
    ACTIVE_PT_PML4_KVA.store(0, Ordering::SeqCst);

    // Suppress unused-field warning: `pt` is referenced indirectly via
    // `new_cr3` (the PML4's PA) and kept alive by owning the page tables.
    let _ = &rt.pt;

    // SAFETY: ctx_kva still points to the same page (ctx_buf alive).
    unsafe {
        ExitInfo {
            exit_reason: (*ctx).exit_reason,
            exit_arg: (*ctx).exit_arg,
            gas_remaining: (*ctx).gas,
            regs: (*ctx).regs,
            pc: (*ctx).pc,
        }
    }
}
