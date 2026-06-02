//! Per-Image JIT code cache + page-aligned arena.
//!
//! Each Image gets one [`PageBuf`] arena containing three regions
//! laid out contiguously, each starting on a page boundary:
//!
//! ```text
//!   arena base (page-aligned)
//!     + dispatch_offset : DISPATCH table    RO
//!     + jit_offset      : JIT native code   RX
//!     + tramp_offset    : trampoline (26B)  RX
//! ```
//!
//! `jalr` targets are validated by the dispatch table itself: it is
//! *dense* (one `i32` native offset per code byte), and every
//! non-block-start offset holds the panic-stub offset, so an invalid
//! target jumps to the panic stub. There is no separate basic-block-
//! start set or jump table.
//!
//! The arena lives for the cache entry's lifetime and is mapped into
//! every Instance's page table that runs this Image — so we only pay
//! the alloc + memcpy + perm setup once per Image (not per call).
//!
//! `Compiler::compile` emits RIP-relative references to `CTX_VA`
//! (a fixed constant) and embeds the per-Image `JIT_VA` for any
//! within-JIT branch fix-ups. The dispatch table contains `i32`
//! offsets relative to that `JIT_VA`; runtime resolution adds
//! `code_base` (a `JitContext` field) to land on absolute native
//! addresses.

#![cfg(target_os = "none")]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cell::UnsafeCell;

use javm_recompiler_x86::codegen::{CompileResult, Compiler, HelperFns};

use javm_cap::CapHash;

use crate::page_alloc::PageBuf;
use crate::paging::{PAGE_SIZE, Perm, TemplatePT};

/// One cached Image's worth of compiled artifacts.
///
/// The arena holds DISPATCH / JIT / TRAMP regions contiguously,
/// page-aligned. The `template` is a pre-built PD
/// subtree (one PD + up to a handful of PT pages) whose leaf PTEs
/// already point at the arena's pages with the right permissions —
/// per-call page tables install the PD via
/// [`PageTable::install_borrowed_pd`](crate::paging::PageTable::install_borrowed_pd)
/// instead of running `pt.map` over the arena.
///
/// The `trap_table` is kept outside the arena — `jit_pf_handler` reads
/// it via static atomics and never needs it mapped into ring-3.
pub struct CompiledImage {
    /// Page-aligned buffer holding the three regions
    /// (DISPATCH | JIT | TRAMP).
    ///
    /// Kept solely to own the backing pages — referenced by the
    /// template's leaf PTEs and freed when the cache entry is evicted.
    #[allow(dead_code)]
    pub arena: PageBuf,
    /// Offsets into `arena` for each region (in bytes from arena base).
    pub dispatch_offset: usize,
    pub jit_offset: usize,
    pub tramp_offset: usize,
    /// Byte size of the JIT region (page-rounded). Read by the #PF
    /// handler to bound the JIT-window check.
    pub jit_size: usize,
    /// Native-code offset (within the JIT region) of the exit label
    /// — `jit_pf_handler` redirects the saved RIP here on page fault.
    pub exit_label_offset: u32,
    /// `(native_offset, pvm_pc, access_width)` triples the #PF handler
    /// binary-searches to recover the PVM PC (PageFault exit / OOG
    /// resume) and the access width (category-#3 straddle page-set) from
    /// a faulting RIP.
    pub trap_table: Vec<(u32, u32, u32)>,
    /// Template PD subtree mapping the arena pages at per-call VAs.
    /// Per-call PTs install [`template_pd_pa`] into PDPT[1] of the
    /// META PML4 slot; this `template` owns the backing PD + PT pages
    /// and frees them on eviction (V1: effectively never).
    #[allow(dead_code)]
    pub template: TemplatePT,
    /// Physical address of `template`'s PD page, cached for fast
    /// install on the per-call hot path.
    pub template_pd_pa: u64,
}

/// Process-wide compile cache.
///
/// Hyperlight serialises host calls, so the guest is single-threaded
/// and a plain `UnsafeCell` is sound. We wrap it in a newtype so the
/// `unsafe` is local and the public API can stay safe.
struct CompileCache {
    inner: UnsafeCell<BTreeMap<CapHash, CompiledImage>>,
}

/// SAFETY: single-threaded guest (Hyperlight serialisation).
unsafe impl Sync for CompileCache {}

static CACHE: CompileCache = CompileCache {
    inner: UnsafeCell::new(BTreeMap::new()),
};

/// Round a byte count up to the next [`PAGE_SIZE`] boundary, with a
/// minimum of one page (so even empty regions occupy a single page
/// in the arena — keeps the per-region PTEs uniform).
fn page_round_up_min1(n: usize) -> usize {
    n.next_multiple_of(PAGE_SIZE).max(PAGE_SIZE)
}

/// Drop every compiled image from the cache.
///
/// Bench-only: each `CompiledImage`'s `Drop` releases its arena pages
/// and template PD/PT pages, which is fine between invocations (no
/// in-flight call references them). The next `get_or_compile` will
/// pay full recompile cost. Safe under Hyperlight serialisation; not
/// meant for production paths.
pub fn evict_all() {
    // SAFETY: single-threaded guest (Hyperlight serialisation), no
    // concurrent call in progress when this RPC fires.
    let map = unsafe { &mut *CACHE.inner.get() };
    map.clear();
}

/// Look up the compile cache by `image_hash`. On miss, compile the
/// Image and materialise the per-Image arena. Returns a `'static`
/// borrow into the cache entry.
///
/// `arena_base_va` is the ring-3 VA where the arena will be mapped
/// (used to compute the per-Image `JIT_VA` so codegen embeds correct
/// RIP-relative displacements). Callers must map the arena at this
/// exact VA on every entry.
///
/// # Safety
///
/// Hyperlight serialises host calls; the returned reference is valid
/// until eviction (V1 never evicts), effectively `'static`.
#[allow(clippy::too_many_arguments)]
pub fn get_or_compile(
    image_hash: &CapHash,
    code: &[u8],
    code_base: u32,
    arena_base_va: u64,
    ctx_va: u64,
    mem_cycles: u8,
    helpers: HelperFns,
) -> &'static CompiledImage {
    // SAFETY: single-threaded guest.
    let map = unsafe { &mut *CACHE.inner.get() };
    if !map.contains_key(image_hash) {
        // Region sizing. Layout: DISPATCH | JIT | TRAMP. The dispatch
        // table is dense — one i32 native offset per code byte — and
        // doubles as the jalr-target validator (no separate BB set).
        let dispatch_size = page_round_up_min1(code.len() * core::mem::size_of::<i32>());

        let dispatch_offset = 0usize;
        let jit_offset = dispatch_offset + dispatch_size;
        let jit_va = arena_base_va + jit_offset as u64;

        let compiler = Compiler::new(helpers, code.len(), jit_va, mem_cycles, code_base);
        let CompileResult {
            native_code,
            dispatch_entries,
            trap_table,
            exit_label_offset,
            panic_offset,
        } = compiler.compile(code);

        let jit_size = page_round_up_min1(native_code.len());
        let tramp_offset = jit_offset + jit_size;
        let tramp_size = PAGE_SIZE;
        let total = tramp_offset + tramp_size;

        let mut arena = PageBuf::new(total).expect("PageBuf alloc for Image arena");
        let buf = arena.as_mut_slice();

        // DISPATCH region — dense fill. First set *every* code-byte slot
        // to the panic-stub offset, so a jalr to any non-block-start
        // offset lands on the panic stub; then overwrite the block-start
        // offsets with their real native targets. This folds the
        // block-start validation into the dispatch lookup.
        //
        // SECURITY-CRITICAL: the panic-fill must cover all `code.len()`
        // slots — a slot left zero (the arena is page-zeroed) would route
        // a bad jalr target to native offset 0 instead of faulting.
        //
        // The panic-fill is the per-recompile (cold-path) cost of the
        // dense table, so do it at memset speed via a u32 view rather
        // than a per-slot byte copy. `dispatch_offset` is 0 in the
        // page-aligned arena, so the region is 4-aligned and holds
        // exactly `code.len()` i32 slots. The host is little-endian
        // (x86-64), so a native u32 store matches the LE bytes the JIT
        // reads back as i32.
        let dispatch_slots = code.len();
        debug_assert_eq!(dispatch_offset, 0);
        // SAFETY: 4-aligned (page-aligned arena base), in-bounds
        // (dispatch_size ≥ dispatch_slots * 4), no aliasing (exclusive
        // `buf`).
        let dispatch_u32: &mut [u32] = unsafe {
            core::slice::from_raw_parts_mut(
                buf.as_mut_ptr().add(dispatch_offset) as *mut u32,
                dispatch_slots,
            )
        };
        dispatch_u32.fill(panic_offset);
        for &(pvm_pc, off) in &dispatch_entries {
            dispatch_u32[pvm_pc as usize] = off as u32;
        }

        // JIT region.
        buf[jit_offset..jit_offset + native_code.len()].copy_from_slice(&native_code);

        // TRAMP region (same 26-byte sequence as PVM).
        let tramp_start = tramp_offset;
        buf[tramp_start] = 0x48;
        buf[tramp_start + 1] = 0xBF;
        buf[tramp_start + 2..tramp_start + 10].copy_from_slice(&ctx_va.to_le_bytes());
        buf[tramp_start + 10] = 0x48;
        buf[tramp_start + 11] = 0xB8;
        buf[tramp_start + 12..tramp_start + 20].copy_from_slice(&jit_va.to_le_bytes());
        buf[tramp_start + 20] = 0xFF;
        buf[tramp_start + 21] = 0xD0;
        buf[tramp_start + 22] = 0xCD;
        buf[tramp_start + 23] = 0x81;
        buf[tramp_start + 24] = 0x0F;
        buf[tramp_start + 25] = 0x0B;

        // Template PD: same RO-then-RX split as the PVM path.
        let arena_pa = arena.pa();
        let mut template = TemplatePT::new().expect("TemplatePT alloc");
        let ro_end = jit_offset;
        let mut off = 0usize;
        while off < total {
            let perm = if off < ro_end {
                Perm::user_ro()
            } else {
                Perm::user_rx()
            };
            template
                .map_leaf(off as u64, arena_pa + off as u64, perm)
                .expect("TemplatePT::map_leaf");
            off += PAGE_SIZE;
        }
        let template_pd_pa = template
            .pd_pa()
            .expect("template PD must be in kernel half");

        map.insert(
            *image_hash,
            CompiledImage {
                arena,
                dispatch_offset,
                jit_offset,
                tramp_offset,
                jit_size,
                exit_label_offset,
                trap_table,
                template,
                template_pd_pa,
            },
        );
    }
    map.get(image_hash).expect("inserted above")
}
