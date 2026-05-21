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
//!   MEM_VA   = 0                               mem_size bytes guest memory
//!   CTX_VA   = 4 GiB                           4 KiB JitContext
//!
//!   META_BASE= 4 GiB + 16 MiB                  clear of CTX, well-aligned
//!   BB_VA    = META_BASE                       bitmask scratch (user-RO)
//!   JT_VA    = META_BASE + 16 MiB              jump-table scratch (user-RO)
//!   DISPATCH = META_BASE + 32 MiB              dispatch table (user-RO)
//!   JIT_VA   = META_BASE + 64 MiB              JIT'd native (user-RX)
//!   TRAMP    = META_BASE + 128 MiB             trampoline (user-RX)
//!   STACK    = TRAMP + 4 KiB                   stack (user-RW)
//! ```
//!
//! All backing pages come from the global heap (talc). Per-page PVM
//! `RO`/`RW` enforcement was removed alongside the PERMS sweep — the
//! per-invocation PT itself enforces bounds (faults outside
//! `[MEM_VA, MEM_VA + mem_size)` route via `jit_pf_handler`).

#![cfg(target_os = "none")]

extern crate alloc;

use crate::jit_cache;
use crate::paging::{PAGE_SIZE, PageTable, Perm};
use crate::ring3;
use alloc::alloc::{alloc_zeroed, dealloc};
use core::alloc::Layout;
use core::ptr::NonNull;
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
    /// PVM register 7 (PVM ABI: the program's u32 return value).
    pub reg_a0: u64,
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
const CTX_VA_M: u64 = 1u64 << 32; // 4 GiB — first page above PVM u32 range
const META_BASE_M: u64 = CTX_VA_M + (1u64 << 24); // CTX + 16 MiB headroom
const BB_VA_M: u64 = META_BASE_M;
const JT_VA_M: u64 = META_BASE_M + (1u64 << 24); // +16 MiB
const DISPATCH_VA_M: u64 = META_BASE_M + (1u64 << 25); // +32 MiB
const JIT_VA_M: u64 = META_BASE_M + (1u64 << 26); // +64 MiB
const TRAMP_VA_M: u64 = META_BASE_M + (1u64 << 27); // +128 MiB
const STACK_VA_M: u64 = TRAMP_VA_M + PAGE_SIZE as u64;

/// One PVM region (arg / ro / rw) to populate before entry.
#[derive(Clone, Copy)]
pub struct MemRegion<'a> {
    pub start: u32,
    pub data: &'a [u8],
}

/// Page-aligned heap allocation. Frees on drop.
struct PageBuf {
    ptr: NonNull<u8>,
    layout: Layout,
}

impl PageBuf {
    /// Allocate `size` bytes (rounded up to a page boundary), zeroed,
    /// aligned to a page.
    fn new(size: usize) -> Option<Self> {
        let size = size.next_multiple_of(PAGE_SIZE).max(PAGE_SIZE);
        let layout = Layout::from_size_align(size, PAGE_SIZE).ok()?;
        // SAFETY: layout is non-zero and well-formed.
        let raw = unsafe { alloc_zeroed(layout) };
        let ptr = NonNull::new(raw)?;
        Some(Self { ptr, layout })
    }

    /// Kernel VA of the buffer.
    fn kva(&self) -> u64 {
        self.ptr.as_ptr() as u64
    }

    /// Physical address. Talc heap lives at high kernel VA (Stage F);
    /// `va_to_pa` walks back through the kernel-half offset.
    fn pa(&self) -> u64 {
        crate::paging::va_to_pa(self.kva()).expect("talc kva must lie in kernel half")
    }

    /// Total size in bytes (multiple of `PAGE_SIZE`).
    fn size(&self) -> u64 {
        self.layout.size() as u64
    }
}

impl Drop for PageBuf {
    fn drop(&mut self) {
        // SAFETY: layout matches the one we passed to `alloc_zeroed`.
        unsafe {
            dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
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

    // ---- compile (cached by image_hash) -----------------------------------
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
        JIT_VA_M,
        javm_exec::gas_cost::DEFAULT_MEM_CYCLES,
        helpers,
    );
    let native: &[u8] = cached.native.as_slice();
    let dispatch_table: &[i32] = cached.dispatch_table.as_slice();
    let trap_table: &[(u32, u32)] = cached.trap_table.as_slice();
    let exit_label_offset = cached.exit_label_offset;
    if native.is_empty() {
        return None;
    }

    // ---- size each buffer to the actual program --------------------------
    let mem_bytes = (mem_size as usize).next_multiple_of(PAGE_SIZE);
    let bb_bytes = bitmask.len();
    let jt_bytes = jump_table.len().checked_mul(core::mem::size_of::<u32>())?;
    let dispatch_bytes = dispatch_table
        .len()
        .checked_mul(core::mem::size_of::<i32>())?;
    let dispatch_size_bytes = code.len().checked_mul(core::mem::size_of::<i32>())?;
    let jit_bytes = native.len();

    // ---- allocate per-invocation buffers ---------------------------------
    let mem_buf = PageBuf::new(mem_bytes.max(PAGE_SIZE))?;
    let ctx_buf = PageBuf::new(PAGE_SIZE)?;
    let bb_buf = PageBuf::new(bb_bytes.max(PAGE_SIZE))?;
    let jt_buf = PageBuf::new(jt_bytes.max(PAGE_SIZE))?;
    let dispatch_buf = PageBuf::new(dispatch_size_bytes.max(PAGE_SIZE))?;
    let jit_buf = PageBuf::new(jit_bytes)?;
    let tramp_buf = PageBuf::new(PAGE_SIZE)?;
    let stack_buf = PageBuf::new(PAGE_SIZE)?;

    // ---- write the JIT code ------------------------------------------------
    // SAFETY: jit_buf has at least `jit_bytes` of capacity.
    unsafe {
        core::ptr::copy_nonoverlapping(native.as_ptr(), jit_buf.kva() as *mut u8, jit_bytes);
    }

    // ---- write bb_starts / jt scratch --------------------------------------
    // SAFETY: bb_buf/jt_buf are sized to fit the actual lengths.
    unsafe {
        core::ptr::copy_nonoverlapping(bitmask.as_ptr(), bb_buf.kva() as *mut u8, bb_bytes);
        core::ptr::copy_nonoverlapping(
            jump_table.as_ptr() as *const u8,
            jt_buf.kva() as *mut u8,
            jt_bytes,
        );
    }

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

    // ---- write the dispatch table -----------------------------------------
    // SAFETY: dispatch_buf is sized to dispatch_size_bytes (capped at code.len() * 4);
    // dispatch_bytes ≤ dispatch_size_bytes since dispatch_table.len() ≤ code.len().
    unsafe {
        core::ptr::copy_nonoverlapping(
            dispatch_table.as_ptr() as *const u8,
            dispatch_buf.kva() as *mut u8,
            dispatch_bytes,
        );
    }

    // ---- build JitContext in the ctx page ----------------------------------
    let ctx_kva = ctx_buf.kva();
    let ctx = ctx_kva as *mut JitContext;

    // SAFETY: ctx points to a fresh zeroed ctx page.
    unsafe {
        (*ctx).regs = initial_regs;
        (*ctx).gas = initial_gas;
        (*ctx).exit_reason = 0;
        (*ctx).exit_arg = 0;
        (*ctx).heap_base = 0;
        (*ctx).heap_top = 0;
        (*ctx).jt_ptr = JT_VA_M as *const u32;
        (*ctx).jt_len = jump_table.len() as u32;
        (*ctx)._pad0 = 0;
        (*ctx).bb_starts = BB_VA_M as *const u8;
        (*ctx).bb_len = bitmask.len() as u32;
        (*ctx)._pad1 = 0;
        (*ctx).entry_pc = entry_pc;
        (*ctx).pc = entry_pc;
        (*ctx).dispatch_table = DISPATCH_VA_M as *const i32;
        (*ctx).code_base = JIT_VA_M;
        (*ctx).flat_buf = MEM_VA_M as *mut u8;
        (*ctx).fast_reentry = 0;
        (*ctx)._pad2 = 0;
        (*ctx).max_heap_pages = 0;
        (*ctx)._pad3 = 0;
    }

    // ---- write the trampoline ----------------------------------------------
    // mov rdi, ctx_va    ; 48 BF <imm64>  (10)
    // mov rax, jit_va    ; 48 B8 <imm64>  (10)
    // call rax           ; FF D0          (2)
    // int 0x81           ; CD 81          (2)
    // ud2                ; 0F 0B          (2)
    let mut tramp = [0u8; 26];
    tramp[0] = 0x48;
    tramp[1] = 0xBF;
    tramp[2..10].copy_from_slice(&CTX_VA_M.to_le_bytes());
    tramp[10] = 0x48;
    tramp[11] = 0xB8;
    tramp[12..20].copy_from_slice(&JIT_VA_M.to_le_bytes());
    tramp[20] = 0xFF;
    tramp[21] = 0xD0;
    tramp[22] = 0xCD;
    tramp[23] = 0x81;
    tramp[24] = 0x0F;
    tramp[25] = 0x0B;
    // SAFETY: tramp_buf is a 4 KiB page.
    unsafe {
        core::ptr::copy_nonoverlapping(tramp.as_ptr(), tramp_buf.kva() as *mut u8, tramp.len());
    }

    // ---- build the page table ----------------------------------------------
    let mut pt = PageTable::new()?;
    pt.map(CTX_VA_M, ctx_buf.pa(), ctx_buf.size(), Perm::user_rw())?;
    if mem_bytes > 0 {
        pt.map(MEM_VA_M, mem_buf.pa(), mem_buf.size(), Perm::user_rw())?;
    }
    pt.map(BB_VA_M, bb_buf.pa(), bb_buf.size(), Perm::user_ro())?;
    pt.map(JT_VA_M, jt_buf.pa(), jt_buf.size(), Perm::user_ro())?;
    pt.map(
        DISPATCH_VA_M,
        dispatch_buf.pa(),
        dispatch_buf.size(),
        Perm::user_ro(),
    )?;
    pt.map(JIT_VA_M, jit_buf.pa(), jit_buf.size(), Perm::user_rx())?;
    pt.map(
        TRAMP_VA_M,
        tramp_buf.pa(),
        tramp_buf.size(),
        Perm::user_rx(),
    )?;
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

    JIT_CODE_BASE.store(JIT_VA_M, Ordering::SeqCst);
    JIT_CODE_LEN.store(jit_buf.size(), Ordering::SeqCst);
    EXIT_LABEL_VA.store(JIT_VA_M + exit_label_offset as u64, Ordering::SeqCst);
    TRAP_TABLE_PTR.store(trap_table.as_ptr() as *mut (u32, u32), Ordering::SeqCst);
    TRAP_TABLE_LEN.store(trap_table.len() as u64, Ordering::SeqCst);
    CTX_KVA.store(ctx_kva, Ordering::SeqCst);
    HANDLERS[14].store(jit_pf_handler as *const () as u64, Ordering::Release);

    // ---- drop to ring 3 ----------------------------------------------------
    let user_stack_top = STACK_VA_M + stack_buf.size();
    // SAFETY: trampoline + stack mapped above; new_cr3 carries kernel half.
    let _user_rax = unsafe { ring3::nub_enter_ring3(TRAMP_VA_M, user_stack_top, new_cr3) };

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
            reg_a0: (*ctx).regs[7],
        }
    };

    // PageTable + all PageBufs drop here, freeing per-invocation memory
    // back to talc.
    drop(pt);

    Some(info)
}
