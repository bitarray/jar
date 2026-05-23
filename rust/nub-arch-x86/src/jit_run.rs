//! In-kernel JIT execution at ring 3.
//!
//! Takes a PVM program (code + bitmask + jump_table) and runs it
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
//!                                 (BB | JT | DISPATCH | JIT | TRAMP)
//!     BB / JT / DISPATCH                                          (user-RO)
//!     JIT / TRAMP                                                 (user-RX)
//!
//!   STACK    = META + 1 GiB       ring-3 x86 stack, 4 KiB         (user-RW)
//! ```
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
/// MEM stays in PML4[0] at VA 0 so PVM addresses are still native VAs.
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
/// Base of the per-Image arena (BB | JT | DISPATCH | JIT | TRAMP).
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

/// Run a PVM program with a real flat-memory mapping at ring 3.
///
/// All backing memory (mem, perms, ctx, bb, jt, dispatch, JIT code,
/// trampoline, stack, page tables) is allocated from talc for this
/// invocation only, then freed when this function returns. Per call:
///   1. Compile the PVM program.
///   2. Allocate per-buffer pages sized to the program.
///   3. Copy program bitmask + jump_table + dispatch + JIT code in.
///   4. Mark `[0, mem_size)` pages RW in perms.
///   5. Populate arg / ro / rw regions.
///   6. Build a fresh page table, drop to ring 3, read back ctx.
///
/// # Safety
/// Modifies CR3 + GDT + IDT during the call. Single-threaded by
/// Hyperlight construction.
#[allow(clippy::too_many_arguments)]
pub unsafe fn run_pvm_with_mem(
    image_hash: &javm_cap::CapHash,
    code: &[u8],
    bitmask: &[u8],
    jump_table: &[u32],
    initial_gas: i64,
    entry_pc: u32,
    initial_regs: [u64; 13],
    mem_size: u32,
    arg: MemRegion,
    ro: MemRegion,
    rw: MemRegion,
) -> Option<ExitInfo> {
    assert_eq!(code.len(), bitmask.len());

    // ---- compile (cached by image_hash) into per-Image arena --------------
    //
    // The codegen reads the helper-fn addresses to look up the access
    // width (`if fn_addr == helpers.mem_write_u8 { width = 1 }`).
    // We never actually *call* the helpers in this in-kernel path
    // (the recompiler only emits inline SIB loads/stores), but the
    // helper addresses must be distinct non-zero sentinels so the
    // width dispatch picks the right size. Using all-zeroes makes
    // every store collapse to u8 (the first match) — see codegen's
    // `emit_mem_read_sized` / `emit_mem_write`.
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
        bitmask,
        jump_table,
        META_BASE_M,
        CTX_VA_M,
        javm_exec::gas_cost::DEFAULT_MEM_CYCLES,
        helpers,
    );
    if cached.jit_size == 0 {
        return None;
    }

    // ---- per-region VAs derived from the cached arena offsets -------------
    let bb_va = META_BASE_M + cached.bb_offset as u64;
    let jt_va = META_BASE_M + cached.jt_offset as u64;
    let dispatch_va = META_BASE_M + cached.dispatch_offset as u64;
    let jit_va = META_BASE_M + cached.jit_offset as u64;
    let tramp_va = META_BASE_M + cached.tramp_offset as u64;

    let mem_bytes = (mem_size as usize).next_multiple_of(PAGE_SIZE);

    // ---- allocate per-invocation buffers ---------------------------------
    // CTX (mutable, written by JIT every instruction) and per-call MEM /
    // STACK stay private. The five Image-shared regions live in `cached.arena`.
    let mem_buf = PageBuf::new(mem_bytes.max(PAGE_SIZE))?;
    let ctx_buf = PageBuf::new(PAGE_SIZE)?;
    let stack_buf = PageBuf::new(PAGE_SIZE)?;

    // ---- populate mem regions ----------------------------------------------
    // (mem_buf is already zeroed by alloc_zeroed.)
    for region in [arg, ro, rw] {
        if region.data.is_empty() {
            continue;
        }
        let off = region.start as usize;
        let end = off.checked_add(region.data.len())?;
        if end > mem_bytes {
            return None;
        }
        // SAFETY: bounds-checked against mem_bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(
                region.data.as_ptr(),
                (mem_buf.kva() + off as u64) as *mut u8,
                region.data.len(),
            );
        }
    }

    // ---- build JitContext in the ctx page ----------------------------------
    let ctx_kva = ctx_buf.kva();
    let ctx = ctx_kva as *mut JitContext;

    // SAFETY: ctx points to a fresh zeroed ctx page. Pointer fields use
    // the per-Image VAs computed above (not the old fixed constants).
    unsafe {
        (*ctx).regs = initial_regs;
        (*ctx).gas = initial_gas;
        (*ctx).exit_reason = 0;
        (*ctx).exit_arg = 0;
        (*ctx).heap_base = 0;
        (*ctx).heap_top = 0;
        (*ctx).jt_ptr = jt_va as *const u32;
        (*ctx).jt_len = jump_table.len() as u32;
        (*ctx)._pad0 = 0;
        (*ctx).bb_starts = bb_va as *const u8;
        (*ctx).bb_len = bitmask.len() as u32;
        (*ctx)._pad1 = 0;
        (*ctx).entry_pc = entry_pc;
        (*ctx).pc = entry_pc;
        (*ctx).dispatch_table = dispatch_va as *const i32;
        (*ctx).code_base = jit_va;
        (*ctx).flat_buf = MEM_VA_M as *mut u8;
        (*ctx).fast_reentry = 0;
        (*ctx)._pad2 = 0;
        (*ctx).max_heap_pages = 0;
        (*ctx)._pad3 = 0;
    }

    // ---- build the page table ----------------------------------------------
    // CTX + MEM + STACK are per-call: each maps fresh PD/PT pages owned
    // by this PageTable. The per-Image arena lives under a shared PD
    // owned by the Image's TemplatePT; install_borrowed_pd writes its
    // PA into PDPT[1] of the META PML4 slot without per-call alloc.
    let mut pt = PageTable::new()?;
    pt.map(CTX_VA_M, ctx_buf.pa(), ctx_buf.size(), Perm::user_rw())?;
    if mem_bytes > 0 {
        pt.map(MEM_VA_M, mem_buf.pa(), mem_buf.size(), Perm::user_rw())?;
    }
    pt.install_borrowed_pd(META_BASE_M, cached.template_pd_pa)?;
    pt.map(
        STACK_VA_M,
        stack_buf.pa(),
        stack_buf.size(),
        Perm::user_rw(),
    )?;
    let new_cr3 = pt.cr3()?;

    // ---- install ring-3 GDT/IDT + JIT #PF handler --------------------------
    // SAFETY: ring-0 mutation of GDT/IDT; serialised by Hyperlight.
    unsafe { ring3::install_ring3_exit_gate() };

    JIT_CODE_BASE.store(jit_va, Ordering::SeqCst);
    JIT_CODE_LEN.store(cached.jit_size as u64, Ordering::SeqCst);
    EXIT_LABEL_VA.store(jit_va + cached.exit_label_offset as u64, Ordering::SeqCst);
    TRAP_TABLE_PTR.store(
        cached.trap_table.as_ptr() as *mut (u32, u32),
        Ordering::SeqCst,
    );
    TRAP_TABLE_LEN.store(cached.trap_table.len() as u64, Ordering::SeqCst);
    CTX_KVA.store(ctx_kva, Ordering::SeqCst);
    HANDLERS[14].store(jit_pf_handler as *const () as u64, Ordering::Release);

    // ---- drop to ring 3 ----------------------------------------------------
    let user_stack_top = STACK_VA_M + stack_buf.size();
    // SAFETY: trampoline (inside the Image arena) + stack mapped above;
    // new_cr3 carries kernel half.
    let _user_rax = unsafe { ring3::nub_enter_ring3(tramp_va, user_stack_top, new_cr3) };

    HANDLERS[14].store(0, Ordering::Release);
    TRAP_TABLE_PTR.store(core::ptr::null_mut(), Ordering::SeqCst);
    TRAP_TABLE_LEN.store(0, Ordering::SeqCst);
    JIT_CODE_LEN.store(0, Ordering::SeqCst);

    // SAFETY: ctx_kva still points to the same page (ctx_buf alive until end of fn).
    let info = unsafe {
        ExitInfo {
            exit_reason: (*ctx).exit_reason,
            exit_arg: (*ctx).exit_arg,
            gas_remaining: (*ctx).gas,
            regs: (*ctx).regs,
            pc: (*ctx).pc,
        }
    };

    // PageTable + all PageBufs drop here, freeing per-invocation memory
    // back to talc.
    drop(pt);

    Some(info)
}
