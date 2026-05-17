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
use crate::ring3;
use javm_recompiler_x86::JitContext;
use javm_recompiler_x86::codegen::{Compiler, HelperFns};

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
    assert_eq!(code.len(), bitmask.len());

    // ---- compile -----------------------------------------------------------
    let helpers = HelperFns {
        mem_read_u8: 0,
        mem_read_u16: 0,
        mem_read_u32: 0,
        mem_read_u64: 0,
        mem_write_u8: 0,
        mem_write_u16: 0,
        mem_write_u32: 0,
        mem_write_u64: 0,
        sbrk_helper: 0,
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
        (*ctx).regs = [0u64; 13];
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
        (*ctx).entry_pc = 0;
        (*ctx).pc = 0;
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

    // ---- install ring-3 GDT/IDT (idempotent) -------------------------------
    // SAFETY: ring-0 mutation of GDT/IDT; serialised by Hyperlight.
    unsafe { ring3::install_ring3_exit_gate() };

    // ---- drop to ring 3 ----------------------------------------------------
    let user_stack_top = STACK_VA + PAGE_SIZE as u64;
    // SAFETY: trampoline + stack mapped above; new_cr3 carries the
    // kernel half so kernel reentry survives.
    let _user_rax_at_exit = unsafe { ring3::nub_enter_ring3(TRAMP_VA, user_stack_top, new_cr3) };

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
