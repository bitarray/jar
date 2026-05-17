//! Per-process pool of physical-page buffers, lazily initialised on
//! first use.
//!
//! Hyperlight's `prim_alloc::alloc_phys_pages` is a one-way bump: pages
//! cannot be returned. For long-running tests / benches with many
//! invocations we'd exhaust the scratch zone within a few calls.
//!
//! The pool allocates a fixed budget of phys pages for each buffer the
//! kernel needs (program memory, perm table, JIT code, bitmask scratch,
//! jump-table scratch, page-table arena, JitContext, trampoline,
//! stack) on the *first* invocation, then re-uses the same physical
//! frames on every subsequent invocation. Per-invocation isolation is
//! provided by the page-table arena reset + per-call CR3 swap; the
//! buffer contents are overwritten before each run.
//!
//! All sizes are conservative upper bounds chosen to cover the largest
//! programs the conformance suite / bench harness throw at the kernel.
//! If a program exceeds a buffer, allocation fails and the call
//! returns an error from the host.

#![cfg(target_os = "none")]

use crate::bump::{BumpArena, PAGE_SIZE};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// 64 MiB of program working memory. Sized to cover the host-side
/// `FlatMemory::FLAT_BUF_SIZE` so anything that runs against the
/// host-recompiler also fits here.
pub const MEM_POOL_BYTES: usize = 64 * 1024 * 1024;
/// 1 MiB of perm-table bytes — matches the recompiler's `PERMS_OFFSET`
/// window (covers up to 4 GiB of guest memory at 1 byte / 4 KiB page).
pub const PERMS_POOL_BYTES: usize = 1 << 20;
/// 4 MiB of bb_starts (unpacked bitmask) scratch. One byte per PVM
/// instruction; programs up to ~4 MiB of code fit.
pub const BB_POOL_BYTES: usize = 4 * 1024 * 1024;
/// 4 MiB of jump_table scratch. Programs with up to 1 M jump-table
/// entries (u32 each) fit.
pub const JT_POOL_BYTES: usize = 4 * 1024 * 1024;
/// 16 MiB of dispatch-table scratch. The dispatch table has one i32
/// per PVM byte; 16 MiB covers programs up to ~4 MiB of byte-code.
pub const DISPATCH_POOL_BYTES: usize = 16 * 1024 * 1024;
/// 16 MiB of JIT'd native code. JIT output ranges 4–10× the PVM byte
/// count; 16 MiB covers PVM programs up to ~2 MiB of byte-code.
pub const JIT_POOL_BYTES: usize = 16 * 1024 * 1024;
/// 4 MiB of bump-arena scratch for per-invocation page tables. Each
/// PT is 4 KiB and can map 2 MiB of contiguous virt; 1024 PTs = 2 GiB
/// of mappable virt, far more than any program needs.
pub const ARENA_POOL_BYTES: usize = 4 * 1024 * 1024;

const CTX_POOL_BYTES: usize = PAGE_SIZE;
const TRAMP_POOL_BYTES: usize = PAGE_SIZE;
const STACK_POOL_BYTES: usize = PAGE_SIZE;

static INITIALISED: AtomicBool = AtomicBool::new(false);
static MEM_PA: AtomicU64 = AtomicU64::new(0);
static PERMS_PA: AtomicU64 = AtomicU64::new(0);
static CTX_PA: AtomicU64 = AtomicU64::new(0);
static BB_PA: AtomicU64 = AtomicU64::new(0);
static JT_PA: AtomicU64 = AtomicU64::new(0);
static DISPATCH_PA: AtomicU64 = AtomicU64::new(0);
static JIT_PA: AtomicU64 = AtomicU64::new(0);
static TRAMP_PA: AtomicU64 = AtomicU64::new(0);
static STACK_PA: AtomicU64 = AtomicU64::new(0);
static ARENA_PA: AtomicU64 = AtomicU64::new(0);

/// Physical addresses of the pool buffers.
#[derive(Clone, Copy)]
pub struct Pool {
    pub mem_pa: u64,
    pub perms_pa: u64,
    pub ctx_pa: u64,
    pub bb_pa: u64,
    pub jt_pa: u64,
    pub dispatch_pa: u64,
    pub jit_pa: u64,
    pub tramp_pa: u64,
    pub stack_pa: u64,
    pub arena_pa: u64,
}

fn pages(bytes: usize) -> u64 {
    bytes.div_ceil(PAGE_SIZE) as u64
}

/// Lazily allocate the pool on first call; return the cached PAs.
/// Single-threaded by Hyperlight construction — no synchronisation
/// beyond the `Acquire`/`Release` fence on `INITIALISED`.
pub fn get_or_init() -> Pool {
    if !INITIALISED.load(Ordering::Acquire) {
        unsafe {
            MEM_PA.store(
                hyperlight_guest::prim_alloc::alloc_phys_pages(pages(MEM_POOL_BYTES)),
                Ordering::Relaxed,
            );
            PERMS_PA.store(
                hyperlight_guest::prim_alloc::alloc_phys_pages(pages(PERMS_POOL_BYTES)),
                Ordering::Relaxed,
            );
            CTX_PA.store(
                hyperlight_guest::prim_alloc::alloc_phys_pages(pages(CTX_POOL_BYTES)),
                Ordering::Relaxed,
            );
            BB_PA.store(
                hyperlight_guest::prim_alloc::alloc_phys_pages(pages(BB_POOL_BYTES)),
                Ordering::Relaxed,
            );
            JT_PA.store(
                hyperlight_guest::prim_alloc::alloc_phys_pages(pages(JT_POOL_BYTES)),
                Ordering::Relaxed,
            );
            DISPATCH_PA.store(
                hyperlight_guest::prim_alloc::alloc_phys_pages(pages(DISPATCH_POOL_BYTES)),
                Ordering::Relaxed,
            );
            JIT_PA.store(
                hyperlight_guest::prim_alloc::alloc_phys_pages(pages(JIT_POOL_BYTES)),
                Ordering::Relaxed,
            );
            TRAMP_PA.store(
                hyperlight_guest::prim_alloc::alloc_phys_pages(pages(TRAMP_POOL_BYTES)),
                Ordering::Relaxed,
            );
            STACK_PA.store(
                hyperlight_guest::prim_alloc::alloc_phys_pages(pages(STACK_POOL_BYTES)),
                Ordering::Relaxed,
            );
            ARENA_PA.store(
                hyperlight_guest::prim_alloc::alloc_phys_pages(pages(ARENA_POOL_BYTES)),
                Ordering::Relaxed,
            );
        }
        INITIALISED.store(true, Ordering::Release);
    }
    Pool {
        mem_pa: MEM_PA.load(Ordering::Relaxed),
        perms_pa: PERMS_PA.load(Ordering::Relaxed),
        ctx_pa: CTX_PA.load(Ordering::Relaxed),
        bb_pa: BB_PA.load(Ordering::Relaxed),
        jt_pa: JT_PA.load(Ordering::Relaxed),
        dispatch_pa: DISPATCH_PA.load(Ordering::Relaxed),
        jit_pa: JIT_PA.load(Ordering::Relaxed),
        tramp_pa: TRAMP_PA.load(Ordering::Relaxed),
        stack_pa: STACK_PA.load(Ordering::Relaxed),
        arena_pa: ARENA_PA.load(Ordering::Relaxed),
    }
}

/// Build a [`BumpArena`] backed by the pool's pre-allocated arena
/// pages. Resets the cursor to zero so previously-published page
/// tables are clobbered on the next call.
pub fn arena() -> Option<BumpArena> {
    let pool = get_or_init();
    BumpArena::from_existing(pool.arena_pa, ARENA_POOL_BYTES)
}
