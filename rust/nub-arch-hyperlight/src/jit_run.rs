//! In-kernel JIT execution at ring 3.
//!
//! Takes a PVM program (code + bitmask + jump_table) and runs it
//! inside the per-invocation page table at ring 3. The PVM exits
//! through `int 0x81` (a hand-rolled trampoline placed after the
//! JIT'd code at a user-RX VA); the kernel handler longjmps back
//! to the caller of [`run_pvm`] and we read the JitContext that
//! the JIT wrote during execution.
//!
//! ## Memory layout (per invocation, in the new page table)
//!
//! Everything lives at user VAs derived from a single base
//! (`BASE`). The base is chosen high enough not to collide with any
//! kernel mapping carried over from the source PML4.
//!
//! ```text
//!   ctx_va    = BASE                  4 KiB JitContext + dispatch_table
//!   jit_va    = BASE + 0x10000        N × 4 KiB JIT'd code (user-RX)
//!   tramp_va  = BASE + 0x20000        4 KiB trampoline page (user-RX)
//!   stack_va  = BASE + 0x21000        4 KiB user stack (user-RW)
//! ```
//!
//! `R15` (the JIT's "guest memory base" register) is set to
//! `ctx_va + CTX_OFFSET` (one page past the ctx page) — for PVM
//! programs that *don't* touch guest memory (Stage C3 smoke), R15
//! is only used as a base for `[r15 - 4096 + field]` accesses
//! into the ctx struct.

#![cfg(target_os = "none")]

use crate::bump::{BumpArena, PAGE_SIZE};
use crate::paging::{self, PageTable, Perm};
use crate::pool;
use crate::ring3;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use hyperlight_guest_bin::exception::arch::{Context, ExceptionInfo, HANDLERS};
use javm_recompiler_x86::JitContext;
use javm_recompiler_x86::codegen::{Compiler, HelperFns};

// === Per-invocation context for the #PF handler ===========================
//
// Set by `run_pvm` immediately before `enter_ring3`, read by
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
/// stack-growth / CoW handlers have declined to handle the fault.
///
/// If the faulting RIP is inside the registered JIT code window:
/// resolve the PVM PC via the trap table, populate
/// `JitContext::{exit_reason, exit_arg, pc}`, redirect the saved RIP
/// in the iretq frame to the JIT's exit label, return `true`. The
/// CPU then `iretq`s back to ring 3 at the exit label, which `ret`s
/// to the trampoline, which `int 0x81`s back to the kernel — exactly
/// the same path as a clean `ecalli` exit (Stage C3).
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
        // kernel scratch memory, valid for the duration of `run_pvm`
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
    // SAFETY: ctx_kva is the scratch VA of the JitContext page for the
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

const PROG_BASE: u64 = 32u64 << 39; // PML4 idx 32 = 16 TiB
const CTX_VA: u64 = PROG_BASE;
const JIT_VA: u64 = PROG_BASE + 0x10000;
const TRAMP_VA: u64 = PROG_BASE + 0x20000;
const STACK_VA: u64 = PROG_BASE + 0x21000;
const DISPATCH_TABLE_VA_OFFSET: u64 = 0x800; // within ctx page

/// Run a tiny PVM program in-kernel and return its exit info.
///
/// Allocates a fresh BumpArena + PageTable per call (smoke-only —
/// production reuses a single per-invocation arena reset between
/// calls).
///
/// # Safety
/// Modifies CR3 + GDT + IDT during the call. The caller must not be
/// holding any references to ring-3-only mappings across the call.
pub unsafe fn run_pvm(
    code: &[u8],
    bitmask: &[u8],
    jump_table: &[u32],
    initial_gas: i64,
) -> Option<ExitInfo> {
    // SAFETY: caller upholds preconditions.
    unsafe { run_pvm_full(code, bitmask, jump_table, initial_gas, 0, [0u64; 13]) }
}

/// Like [`run_pvm`] but also seeds the entry PC and initial PVM
/// registers — used by the `nub_invoke` host-callable entry point
/// (D1+).
///
/// # Safety
/// Same as [`run_pvm`].
pub unsafe fn run_pvm_full(
    code: &[u8],
    bitmask: &[u8],
    jump_table: &[u32],
    initial_gas: i64,
    entry_pc: u32,
    initial_regs: [u64; 13],
) -> Option<ExitInfo> {
    assert_eq!(code.len(), bitmask.len());

    // ---- compile -----------------------------------------------------------
    // Helper addresses must be distinct non-zero sentinels — see
    // `run_pvm_with_mem` for the rationale.
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
    let compiler = Compiler::new(
        bitmask,
        jump_table,
        helpers,
        code.len(),
        false,
        javm_exec::gas_cost::DEFAULT_MEM_CYCLES,
    );
    let result = compiler.compile(code, bitmask);
    let native = result.native_code;
    let dispatch_table = result.dispatch_table;
    let trap_table = result.trap_table;
    let exit_label_offset = result.exit_label_offset;
    if native.is_empty() {
        return None;
    }

    // ---- allocate phys pages -----------------------------------------------
    let jit_pages = native.len().div_ceil(PAGE_SIZE);
    let ctx_pa = unsafe { hyperlight_guest::prim_alloc::alloc_phys_pages(1) };
    let jit_pa = unsafe { hyperlight_guest::prim_alloc::alloc_phys_pages(jit_pages as u64) };
    let tramp_pa = unsafe { hyperlight_guest::prim_alloc::alloc_phys_pages(1) };
    let stack_pa = unsafe { hyperlight_guest::prim_alloc::alloc_phys_pages(1) };

    let ctx_kva = paging::pa_to_va(ctx_pa)?;
    let jit_kva = paging::pa_to_va(jit_pa)?;
    let tramp_kva = paging::pa_to_va(tramp_pa)?;

    // ---- write JIT bytes ---------------------------------------------------
    // SAFETY: jit_kva covers jit_pages * 4 KiB freshly allocated scratch.
    unsafe {
        core::ptr::copy_nonoverlapping(native.as_ptr(), jit_kva as *mut u8, native.len());
    }

    // ---- build JitContext + dispatch_table in the ctx page -----------------
    // SAFETY: ctx_kva is a fresh 4 KiB phys page; we zero it then
    // initialise field-by-field.
    unsafe {
        core::ptr::write_bytes(ctx_kva as *mut u8, 0, PAGE_SIZE);
    }
    let ctx = ctx_kva as *mut JitContext;
    let dispatch_table_kva = ctx_kva + DISPATCH_TABLE_VA_OFFSET;
    let dispatch_table_va = CTX_VA + DISPATCH_TABLE_VA_OFFSET;
    // Copy dispatch_table entries (i32) into the ctx page.
    // SAFETY: dispatch_table_kva+sizeof(i32)*N fits in the 4 KiB ctx
    // page provided N is small (we only handle small PVM programs in
    // the smoke; the dispatch table holds one i32 per PVM byte).
    let dt_bytes = dispatch_table.len() * core::mem::size_of::<i32>();
    assert!(
        DISPATCH_TABLE_VA_OFFSET as usize + dt_bytes <= PAGE_SIZE,
        "dispatch_table doesn't fit in ctx page"
    );
    unsafe {
        core::ptr::copy_nonoverlapping(
            dispatch_table.as_ptr() as *const u8,
            dispatch_table_kva as *mut u8,
            dt_bytes,
        );
    }

    // SAFETY: ctx_kva points to a freshly mapped ctx page with the
    // right alignment for JitContext.
    unsafe {
        (*ctx).regs = initial_regs;
        (*ctx).gas = initial_gas;
        (*ctx).exit_reason = 0;
        (*ctx).exit_arg = 0;
        (*ctx).heap_base = 0;
        (*ctx).heap_top = 0;
        (*ctx).jt_ptr = core::ptr::null();
        (*ctx).jt_len = jump_table.len() as u32;
        (*ctx)._pad0 = 0;
        (*ctx).bb_starts = core::ptr::null();
        (*ctx).bb_len = bitmask.len() as u32;
        (*ctx)._pad1 = 0;
        (*ctx).entry_pc = entry_pc;
        (*ctx).pc = entry_pc;
        (*ctx).dispatch_table = dispatch_table_va as *const i32;
        (*ctx).code_base = JIT_VA;
        (*ctx).flat_buf = core::ptr::null_mut();
        (*ctx).flat_perms = core::ptr::null();
        (*ctx).fast_reentry = 0;
        (*ctx)._pad2 = 0;
        (*ctx).max_heap_pages = 0;
        (*ctx)._pad3 = 0;
    }

    // ---- write the trampoline ----------------------------------------------
    // mov rdi, ctx_va     ; 48 BF <imm64>     (10 bytes)
    // mov rax, jit_va     ; 48 B8 <imm64>     (10 bytes)
    // call rax            ; FF D0             (2  bytes)
    // int 0x81            ; CD 81             (2  bytes)
    // ud2                 ; 0F 0B             (2  bytes, sentinel — never executed)
    let mut tramp = [0u8; 26];
    tramp[0] = 0x48;
    tramp[1] = 0xBF;
    tramp[2..10].copy_from_slice(&CTX_VA.to_le_bytes());
    tramp[10] = 0x48;
    tramp[11] = 0xB8;
    tramp[12..20].copy_from_slice(&JIT_VA.to_le_bytes());
    tramp[20] = 0xFF;
    tramp[21] = 0xD0;
    tramp[22] = 0xCD;
    tramp[23] = 0x81;
    tramp[24] = 0x0F;
    tramp[25] = 0x0B;
    // SAFETY: tramp_kva covers the freshly allocated 4 KiB trampoline page.
    unsafe {
        core::ptr::copy_nonoverlapping(tramp.as_ptr(), tramp_kva as *mut u8, tramp.len());
    }

    // ---- build the page table ----------------------------------------------
    let arena = BumpArena::new(crate::bump::SMOKE_CAPACITY)?;
    let mut pt = PageTable::new_in(&arena)?;
    pt.map(CTX_VA, ctx_pa, PAGE_SIZE as u64, Perm::user_rw())?;
    pt.map(
        JIT_VA,
        jit_pa,
        (jit_pages * PAGE_SIZE) as u64,
        Perm::user_rx(),
    )?;
    pt.map(TRAMP_VA, tramp_pa, PAGE_SIZE as u64, Perm::user_rx())?;
    pt.map(STACK_VA, stack_pa, PAGE_SIZE as u64, Perm::user_rw())?;
    let new_cr3 = pt.cr3()?;

    // ---- install ring-3 GDT/IDT + JIT #PF handler --------------------------
    // SAFETY: ring-0 mutation of GDT/IDT; serialised by Hyperlight.
    unsafe { ring3::install_ring3_exit_gate() };

    // Publish per-invocation state for the #PF handler, then install
    // the handler at HANDLERS[14]. Hyperlight's own stack-growth /
    // CoW handlers run first; we only see faults inside the JIT'd
    // code window.
    JIT_CODE_BASE.store(JIT_VA, Ordering::SeqCst);
    JIT_CODE_LEN.store((jit_pages * PAGE_SIZE) as u64, Ordering::SeqCst);
    EXIT_LABEL_VA.store(JIT_VA + exit_label_offset as u64, Ordering::SeqCst);
    TRAP_TABLE_PTR.store(trap_table.as_ptr() as *mut (u32, u32), Ordering::SeqCst);
    TRAP_TABLE_LEN.store(trap_table.len() as u64, Ordering::SeqCst);
    CTX_KVA.store(ctx_kva, Ordering::SeqCst);
    HANDLERS[14].store(jit_pf_handler as *const () as u64, Ordering::Release);

    // ---- drop to ring 3 ----------------------------------------------------
    let user_stack_top = STACK_VA + PAGE_SIZE as u64;
    // SAFETY: trampoline + stack mapped above; new_cr3 carries the
    // kernel half so kernel reentry survives.
    let _user_rax_at_exit = unsafe { ring3::nub_enter_ring3(TRAMP_VA, user_stack_top, new_cr3) };

    // Clear the #PF handler so subsequent kernel-mode faults don't
    // get redirected into our stale exit_label.
    HANDLERS[14].store(0, Ordering::Release);
    TRAP_TABLE_PTR.store(core::ptr::null_mut(), Ordering::SeqCst);
    TRAP_TABLE_LEN.store(0, Ordering::SeqCst);
    JIT_CODE_LEN.store(0, Ordering::SeqCst);

    // Keep `trap_table` alive across the run — the handler held a raw
    // pointer into its buffer.
    drop(trap_table);

    // ---- read the ctx the JIT wrote ----------------------------------------
    // The CR3 has been restored by ring3_exit_stub. The JitContext
    // page is still resident at ctx_kva (its scratch VA never went
    // away).
    // SAFETY: ctx_kva is the scratch VA of the same phys page the JIT
    // wrote to via its user VA mapping.
    let info = unsafe {
        ExitInfo {
            exit_reason: (*ctx).exit_reason,
            exit_arg: (*ctx).exit_arg,
            gas_remaining: (*ctx).gas,
            reg_a0: (*ctx).regs[7],
        }
    };
    Some(info)
}

// === Full-memory invocation path (Stage E1/E2) ===========================
//
// `run_pvm_full` (above) is the smoke-only path: no guest memory, no
// perms table, no bb_starts / jt_ptr publication. Real PVM programs
// (conformance + bench) need a full memory layout with R15 pointing at
// a mapped flat-buffer.
//
// Layout in the per-invocation page table when `mem_size > 0`:
//
// ```text
//   PERMS_VA = PROG_BASE                       1 MiB user-RW perms
//   CTX_VA   = PROG_BASE + 0x100000            4 KiB ctx + dispatch_table
//   MEM_VA   = PROG_BASE + 0x101000            mem_size bytes guest memory (R15)
//
//   META_BASE= PROG_BASE + (4 GiB)             — clear of any mem range
//   BB_VA    = META_BASE                        bitmask scratch (user-RO)
//   JT_VA    = META_BASE + 16 MiB               jump-table scratch (user-RO)
//   JIT_VA_M = META_BASE + 32 MiB               JIT'd native (user-RX)
//   TRAMP_M  = META_BASE + 64 MiB               trampoline (user-RX)
//   STACK_M  = TRAMP_M + 4 KiB                  stack (user-RW)
// ```
//
// R15 = MEM_VA satisfies the JIT's layout invariants:
//   * `[r15 - CTX_OFFSET + field]`   → CTX_VA + field
//   * `[r15 - PERMS_OFFSET + page]`  → PERMS_VA + page
//   * `[r15 + rdx]`                  → MEM_VA + rdx (guest mem access)

const PROG_BASE_M: u64 = 32u64 << 39;
const PERMS_VA_M: u64 = PROG_BASE_M;
const CTX_VA_M: u64 = PROG_BASE_M + 0x100000;
const MEM_VA_M: u64 = PROG_BASE_M + 0x101000;
const META_BASE_M: u64 = PROG_BASE_M + (4u64 << 30); // +4 GiB
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

/// Run a PVM program with a real flat-memory mapping at ring 3.
///
/// Uses the per-process pool ([`crate::pool`]) for backing storage so
/// repeated invocations don't exhaust Hyperlight's bump-pointer phys
/// allocator. Per call:
///   1. Reset the page-table arena.
///   2. Copy program bitmask + jump_table into bb / jt scratch pools.
///   3. Compile + copy native code into the JIT pool.
///   4. Zero perms; mark `[0, mem_size)` pages RW.
///   5. Zero mem; populate arg / ro / rw regions.
///   6. Build a fresh page table, drop to ring 3, read back ctx.
///
/// # Safety
/// Modifies CR3 + GDT + IDT during the call. Single-threaded by
/// Hyperlight construction.
#[allow(clippy::too_many_arguments)]
pub unsafe fn run_pvm_with_mem(
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

    // ---- size checks against pool bounds -----------------------------------
    let mem_bytes_needed = (mem_size as usize).next_multiple_of(PAGE_SIZE);
    if mem_bytes_needed > pool::MEM_POOL_BYTES {
        return None;
    }
    if bitmask.len() > pool::BB_POOL_BYTES {
        return None;
    }
    let jt_bytes = jump_table.len().checked_mul(core::mem::size_of::<u32>())?;
    if jt_bytes > pool::JT_POOL_BYTES {
        return None;
    }
    // Dispatch table has one i32 per PVM byte.
    let dt_bytes = code.len().checked_mul(core::mem::size_of::<i32>())?;
    if dt_bytes > pool::DISPATCH_POOL_BYTES {
        return None;
    }

    // ---- compile -----------------------------------------------------------
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
    let compiler = Compiler::new(
        bitmask,
        jump_table,
        helpers,
        code.len(),
        false,
        javm_exec::gas_cost::DEFAULT_MEM_CYCLES,
    );
    let result = compiler.compile(code, bitmask);
    let native = result.native_code;
    let dispatch_table = result.dispatch_table;
    let trap_table = result.trap_table;
    let exit_label_offset = result.exit_label_offset;
    if native.is_empty() {
        return None;
    }
    if native.len() > pool::JIT_POOL_BYTES {
        return None;
    }

    let p = pool::get_or_init();

    // ---- scratch VAs into the pool buffers ---------------------------------
    let mem_kva = paging::pa_to_va(p.mem_pa)?;
    let perms_kva = paging::pa_to_va(p.perms_pa)?;
    let ctx_kva = paging::pa_to_va(p.ctx_pa)?;
    let bb_kva = paging::pa_to_va(p.bb_pa)?;
    let jt_kva = paging::pa_to_va(p.jt_pa)?;
    let dispatch_kva = paging::pa_to_va(p.dispatch_pa)?;
    let jit_kva = paging::pa_to_va(p.jit_pa)?;
    let tramp_kva = paging::pa_to_va(p.tramp_pa)?;

    // ---- write the JIT code ------------------------------------------------
    // SAFETY: jit_kva points to JIT_POOL_BYTES of scratch; native.len() ≤ that.
    unsafe {
        core::ptr::copy_nonoverlapping(native.as_ptr(), jit_kva as *mut u8, native.len());
    }

    // ---- write bb_starts / jt scratch --------------------------------------
    // SAFETY: bb_kva/jt_kva cover their pool sizes; bitmask/jt fit per checks above.
    unsafe {
        core::ptr::copy_nonoverlapping(bitmask.as_ptr(), bb_kva as *mut u8, bitmask.len());
        core::ptr::copy_nonoverlapping(
            jump_table.as_ptr() as *const u8,
            jt_kva as *mut u8,
            jt_bytes,
        );
    }

    // ---- zero perms; mark [0, mem_size) pages RW ---------------------------
    let num_pages = (mem_size as usize).div_ceil(PAGE_SIZE);
    // SAFETY: perms_kva covers PERMS_POOL_BYTES; we write num_pages bytes (≤ 256 K).
    unsafe {
        core::ptr::write_bytes(perms_kva as *mut u8, 0, pool::PERMS_POOL_BYTES);
        core::ptr::write_bytes(perms_kva as *mut u8, javm_exec::perm::RW, num_pages);
    }

    // ---- zero mem; populate arg / ro / rw ----------------------------------
    // SAFETY: mem_kva covers MEM_POOL_BYTES; mem_bytes_needed ≤ that.
    unsafe {
        core::ptr::write_bytes(mem_kva as *mut u8, 0, mem_bytes_needed);
    }
    for region in [arg, ro, rw] {
        if region.data.is_empty() {
            continue;
        }
        let off = region.start as usize;
        let end = off.checked_add(region.data.len())?;
        if end > mem_bytes_needed {
            return None;
        }
        // SAFETY: bounds-checked against mem_bytes_needed.
        unsafe {
            core::ptr::copy_nonoverlapping(
                region.data.as_ptr(),
                (mem_kva + off as u64) as *mut u8,
                region.data.len(),
            );
        }
    }

    // ---- write the dispatch table into its own pool page -------------------
    let dispatch_actual = dispatch_table.len() * core::mem::size_of::<i32>();
    // SAFETY: dispatch_kva covers DISPATCH_POOL_BYTES; dispatch_actual ≤ that
    // (checked above via dt_bytes ≤ DISPATCH_POOL_BYTES, with dispatch_actual
    // ≤ dt_bytes because dispatch_table.len() ≤ code.len() by construction).
    unsafe {
        core::ptr::copy_nonoverlapping(
            dispatch_table.as_ptr() as *const u8,
            dispatch_kva as *mut u8,
            dispatch_actual,
        );
    }

    // ---- build JitContext in the ctx page ----------------------------------
    // SAFETY: ctx_kva is a 4 KiB pool page; zero then init field-by-field.
    unsafe {
        core::ptr::write_bytes(ctx_kva as *mut u8, 0, PAGE_SIZE);
    }
    let ctx = ctx_kva as *mut JitContext;

    // SAFETY: ctx points to a fresh ctx page.
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
        (*ctx).flat_perms = PERMS_VA_M as *const u8;
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
    // SAFETY: tramp_kva covers a 4 KiB pool page.
    unsafe {
        core::ptr::copy_nonoverlapping(tramp.as_ptr(), tramp_kva as *mut u8, tramp.len());
    }

    // ---- build the page table ----------------------------------------------
    let arena = pool::arena()?;
    let mut pt = PageTable::new_in(&arena)?;
    pt.map(
        PERMS_VA_M,
        p.perms_pa,
        pool::PERMS_POOL_BYTES as u64,
        Perm::user_rw(),
    )?;
    pt.map(CTX_VA_M, p.ctx_pa, PAGE_SIZE as u64, Perm::user_rw())?;
    if mem_bytes_needed > 0 {
        pt.map(MEM_VA_M, p.mem_pa, mem_bytes_needed as u64, Perm::user_rw())?;
    }
    pt.map(
        BB_VA_M,
        p.bb_pa,
        pool::BB_POOL_BYTES as u64,
        Perm::user_ro(),
    )?;
    pt.map(
        JT_VA_M,
        p.jt_pa,
        pool::JT_POOL_BYTES as u64,
        Perm::user_ro(),
    )?;
    pt.map(
        DISPATCH_VA_M,
        p.dispatch_pa,
        pool::DISPATCH_POOL_BYTES as u64,
        Perm::user_ro(),
    )?;
    let jit_map_bytes = native.len().next_multiple_of(PAGE_SIZE) as u64;
    pt.map(JIT_VA_M, p.jit_pa, jit_map_bytes, Perm::user_rx())?;
    pt.map(TRAMP_VA_M, p.tramp_pa, PAGE_SIZE as u64, Perm::user_rx())?;
    pt.map(STACK_VA_M, p.stack_pa, PAGE_SIZE as u64, Perm::user_rw())?;
    let new_cr3 = pt.cr3()?;

    // ---- install ring-3 GDT/IDT + JIT #PF handler --------------------------
    // SAFETY: ring-0 mutation of GDT/IDT; serialised by Hyperlight.
    unsafe { ring3::install_ring3_exit_gate() };

    JIT_CODE_BASE.store(JIT_VA_M, Ordering::SeqCst);
    JIT_CODE_LEN.store(jit_map_bytes, Ordering::SeqCst);
    EXIT_LABEL_VA.store(JIT_VA_M + exit_label_offset as u64, Ordering::SeqCst);
    TRAP_TABLE_PTR.store(trap_table.as_ptr() as *mut (u32, u32), Ordering::SeqCst);
    TRAP_TABLE_LEN.store(trap_table.len() as u64, Ordering::SeqCst);
    CTX_KVA.store(ctx_kva, Ordering::SeqCst);
    HANDLERS[14].store(jit_pf_handler as *const () as u64, Ordering::Release);

    // ---- drop to ring 3 ----------------------------------------------------
    let user_stack_top = STACK_VA_M + PAGE_SIZE as u64;
    // SAFETY: trampoline + stack mapped above; new_cr3 carries kernel half.
    let _user_rax = unsafe { ring3::nub_enter_ring3(TRAMP_VA_M, user_stack_top, new_cr3) };

    HANDLERS[14].store(0, Ordering::Release);
    TRAP_TABLE_PTR.store(core::ptr::null_mut(), Ordering::SeqCst);
    TRAP_TABLE_LEN.store(0, Ordering::SeqCst);
    JIT_CODE_LEN.store(0, Ordering::SeqCst);

    drop(trap_table);

    // SAFETY: ctx_kva still points to the same phys page; read final state.
    let info = unsafe {
        ExitInfo {
            exit_reason: (*ctx).exit_reason,
            exit_arg: (*ctx).exit_arg,
            gas_remaining: (*ctx).gas,
            reg_a0: (*ctx).regs[7],
        }
    };
    Some(info)
}
