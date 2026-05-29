//! Per-Image JIT code cache + page-aligned arena.
//!
//! Each Image gets one [`PageBuf`] arena containing four regions
//! laid out contiguously, each starting on a page boundary:
//!
//! ```text
//!   arena base (page-aligned)
//!     + bb_offset       : BB (bitmask)      RO
//!     + dispatch_offset : DISPATCH table    RO
//!     + jit_offset      : JIT native code   RX
//!     + tramp_offset    : trampoline (26B)  RX
//! ```
//!
//! `jalr` targets are validated against the BB (basic-block-start) set
//! directly — there is no separate jump table.
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

use javm_recompiler_x86::codegen::{Compiler, HelperFns, LazyInit};

use javm_cap::CapHash;

use crate::page_alloc::PageBuf;
use crate::paging::{PAGE_SIZE, Perm, TemplatePT};

/// One cached Image's worth of compiled artifacts.
///
/// The arena holds BB / JT / DISPATCH / JIT / TRAMP regions
/// contiguously, page-aligned. The `template` is a pre-built PD
/// subtree (one PD + up to a handful of PT pages) whose leaf PTEs
/// already point at the arena's pages with the right permissions —
/// per-call page tables install the PD via
/// [`PageTable::install_borrowed_pd`](crate::paging::PageTable::install_borrowed_pd)
/// instead of running `pt.map` over the arena.
///
/// The `trap_table` is kept outside the arena — `jit_pf_handler` reads
/// it via static atomics and never needs it mapped into ring-3.
pub struct CompiledImage {
    /// Page-aligned buffer holding the four regions
    /// (BB | DISPATCH | JIT | TRAMP).
    ///
    /// Kept solely to own the backing pages — referenced by the
    /// template's leaf PTEs and freed when the cache entry is evicted.
    #[allow(dead_code)]
    pub arena: PageBuf,
    /// Offsets into `arena` for each region (in bytes from arena base).
    pub bb_offset: usize,
    pub dispatch_offset: usize,
    pub jit_offset: usize,
    pub tramp_offset: usize,
    /// Byte size of the JIT region (page-rounded). Read by the #PF
    /// handler to bound the JIT-window check.
    pub jit_size: usize,
    /// Native-code offset (within the JIT region) of the exit label
    /// — `jit_pf_handler` redirects the saved RIP here on page fault.
    pub exit_label_offset: u32,
    /// (native_offset, pvm_pc) pairs the #PF handler binary-searches
    /// to recover the PVM PC from a faulting RIP. Grows as pages are
    /// lazily compiled; pre-reserved to its worst case so the backing
    /// allocation (and hence the pointer the #PF handler caches) never
    /// moves. Stays sorted by native offset because each newly-compiled
    /// page occupies the next contiguous native range.
    pub trap_table: Vec<(u32, u32)>,
    /// Template PD subtree mapping the arena pages at per-call VAs.
    /// Per-call PTs install [`template_pd_pa`] into PDPT[1] of the
    /// META PML4 slot; this `template` owns the backing PD + PT pages
    /// and frees them on eviction (V1: effectively never).
    #[allow(dead_code)]
    pub template: TemplatePT,
    /// Physical address of `template`'s PD page, cached for fast
    /// install on the per-call hot path.
    pub template_pd_pa: u64,

    // === Lazy per-page compilation state ============================
    /// Persistent compiler: owns the assembler (prologue, shared stubs,
    /// and every page body compiled so far) plus the whole-blob
    /// block-start set. `compile_page_into_arena` appends a page body on
    /// first entry.
    ///
    /// Self-referential (`asm.buf` → its own Vec heap; `bitmask_ptr` →
    /// `rv_valid_pc` heap). Both target heap allocations that survive a
    /// move of this struct (BTreeMap rebalance), so caching it is sound.
    pub compiler: Compiler,
    /// Guest code bytes — `compile_lazy_page` decodes a page from these.
    pub code: Vec<u8>,
    /// Per-4 KiB-page "already compiled" flag (len = number of code
    /// pages). Guards against compiling a page twice.
    pub compiled: Vec<bool>,
    /// Byte size of one JIT region (== `tramp_offset - jit_offset`),
    /// the upper bound a lazily-appended page must not exceed.
    pub jit_region_size: usize,
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
        // Region sizing. Layout: BB | DISPATCH | JIT | TRAMP (no jump
        // table — jalr targets are validated against BB directly).
        //
        // BB / DISPATCH scale exactly with code length. The JIT region,
        // under lazy compilation, must be sized to its *worst case* up
        // front: pages compile in on first entry (in execution order),
        // appending to a fixed arena that's mapped RX once and never
        // moves.
        //
        // 32× code length + 16 KiB is the per-byte worst case. The
        // recompiler runs untrusted code, so the bound must hold for any
        // input, not just typical guests (~3× expansion): a page of
        // 0x0000 halfwords — the zero-padding `CodeRegionCap` appends to
        // round code up to a page — compiles to ~22.5× (each illegal
        // halfword is a terminating panic stub, so the next halfword is a
        // fresh gas block too), and a worst-case cross-page conditional
        // branch is ~27×. `compile_page_into_arena` hard-checks against
        // the bound, so even an under-estimate fails cleanly (a
        // pathological guest just won't run) rather than corrupting.
        let bb_size = page_round_up_min1(code.len());
        let dispatch_size = page_round_up_min1(code.len() * core::mem::size_of::<i32>());
        let jit_region_size = page_round_up_min1(code.len() * 32 + 16384);

        let bb_offset = 0usize;
        let dispatch_offset = bb_offset + bb_size;
        let jit_offset = dispatch_offset + dispatch_size;
        let jit_va = arena_base_va + jit_offset as u64;

        let mut compiler = Compiler::new(helpers, code.len(), jit_va, mem_cycles, code_base);
        // Emit prologue + shared stubs only (incl. the compile-page
        // stub). Page bodies compile lazily on first entry.
        let init: LazyInit = compiler.compile_lazy_init(code);

        // #PF window covers the whole (worst-case) JIT region: a fault's
        // RIP is always inside already-compiled code, which lives within
        // this window.
        let jit_size = jit_region_size;
        let tramp_offset = jit_offset + jit_size;
        let tramp_size = PAGE_SIZE;
        let total = tramp_offset + tramp_size;

        let mut arena = PageBuf::new(total).expect("PageBuf alloc for Image arena");
        let buf = arena.as_mut_slice();

        // BB region: valid_pc as bytes (Vec<bool> is 0/1 single-byte
        // representation, so a raw-pointer reinterpret is sound).
        let bb_ptr = init.valid_pc.as_ptr() as *const u8;
        // SAFETY: bb_ptr valid for valid_pc.len() bytes.
        let bb_bytes = unsafe { core::slice::from_raw_parts(bb_ptr, init.valid_pc.len()) };
        buf[bb_offset..bb_offset + init.valid_pc.len()].copy_from_slice(bb_bytes);

        // DISPATCH region — point every block start at the compile-page
        // stub (sparse write; arena is page-zero, so non-block-start
        // slots stay 0 and are never used as dispatch targets). As pages
        // compile, `compile_page_into_arena` patches their block starts
        // to the real native offsets.
        let stub_bytes = (init.compile_stub_offset as i32).to_le_bytes();
        for off in 0..init.valid_pc.len() {
            if init.valid_pc[off] {
                let slot_off = dispatch_offset + off * core::mem::size_of::<i32>();
                buf[slot_off..slot_off + 4].copy_from_slice(&stub_bytes);
            }
        }

        // JIT region — prologue + shared stubs (offsets 0..init.len).
        let init_bytes = compiler.asm.written();
        buf[jit_offset..jit_offset + init.len].copy_from_slice(&init_bytes[..init.len]);

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

        // Trap table: empty after init (prologue + stubs have no memory
        // ops). Pre-reserve to the worst case — at most one entry per
        // instruction, and instructions are ≥ 2 bytes — so lazily
        // appending page trap entries never reallocates, keeping the
        // backing pointer (cached by the #PF handler) stable.
        let trap_table: Vec<(u32, u32)> = Vec::with_capacity(code.len() / 2 + 64);

        let n_pages = code.len().div_ceil(PAGE_SIZE);

        map.insert(
            *image_hash,
            CompiledImage {
                arena,
                bb_offset,
                dispatch_offset,
                jit_offset,
                tramp_offset,
                jit_size,
                exit_label_offset: init.exit_label_offset,
                trap_table,
                template,
                template_pd_pa,
                compiler,
                code: code.to_vec(),
                compiled: alloc::vec![false; n_pages],
                jit_region_size,
            },
        );
    }
    map.get(image_hash).expect("inserted above")
}

/// Image not present in the cache (must be inserted by `get_or_compile`
/// before a page is compiled).
pub const ERR_LAZY_NO_IMAGE: u32 = 70;
/// Requested page index is past the end of the code.
pub const ERR_LAZY_PAGE_OOB: u32 = 71;
/// Compiled page would overrun the worst-case JIT region — only a
/// pathological guest can hit this (see the 32× bound in `get_or_compile`).
pub const ERR_LAZY_ARENA_FULL: u32 = 72;

/// Lazily compile one 4 KiB code page into the cached Image's arena.
///
/// Called from the `EXIT_COMPILE_PAGE` runtime path when a dispatch
/// landed on a block whose page is not compiled yet. Compiles the page
/// body (appending to the persistent compiler's JIT buffer), copies the
/// new native bytes into the arena's JIT region, patches the page's
/// block-start dispatch entries to their real native offsets, and
/// appends the page's trap entries.
///
/// Returns the `(ptr, len)` of the (possibly-grown) trap table so the
/// caller can refresh the live frame's #PF-handler view before
/// re-entering ring 3. Idempotent: a page already compiled is a no-op
/// that returns the current trap view.
///
/// `Err(())` on a bad page index or if the worst-case JIT region bound
/// is exceeded (never expected for real guests — a clean failure rather
/// than an arena overwrite).
///
/// # Safety
/// Single-threaded guest; the runtime sequences this between ring-3
/// entries, so no live `&CompiledImage` borrow overlaps the `&mut` here.
pub fn compile_page_into_arena(
    image_hash: &CapHash,
    page: usize,
) -> Result<(*const (u32, u32), u64), u32> {
    // SAFETY: single-threaded guest.
    let map = unsafe { &mut *CACHE.inner.get() };
    let image = map.get_mut(image_hash).ok_or(ERR_LAZY_NO_IMAGE)?;

    if page >= image.compiled.len() {
        return Err(ERR_LAZY_PAGE_OOB);
    }
    if image.compiled[page] {
        // Already compiled — dispatch entries already point at real
        // code; this re-entry just needs the current trap view.
        return Ok((image.trap_table.as_ptr(), image.trap_table.len() as u64));
    }

    // Compile the page body (appends to the compiler's JIT buffer).
    // Disjoint field borrows: `compiler` (&mut) vs `code` (&).
    let lazy = image.compiler.compile_lazy_page(&image.code, page);

    // Worst-case JIT region bound — refuse to overrun the arena (would
    // only fire for a pathological/adversarial guest; the 32× sizing
    // covers every real workload). Clean failure, never a corrupting
    // write past the arena.
    if lazy.end > image.jit_region_size {
        return Err(ERR_LAZY_ARENA_FULL);
    }

    // Copy the newly-emitted bytes into the arena JIT region. `compiler`
    // and `arena` are disjoint fields, so the two borrows don't alias.
    {
        let src = image.compiler.asm.written();
        let bytes = &src[lazy.start..lazy.end];
        let buf = image.arena.as_mut_slice();
        let dst = image.jit_offset + lazy.start;
        buf[dst..dst + bytes.len()].copy_from_slice(bytes);
    }

    // Patch this page's block-start dispatch entries to real offsets.
    {
        let dispatch_offset = image.dispatch_offset;
        let buf = image.arena.as_mut_slice();
        for &(pc, noff) in &lazy.dispatch_entries {
            let slot = dispatch_offset + (pc as usize) * core::mem::size_of::<i32>();
            buf[slot..slot + 4].copy_from_slice(&noff.to_le_bytes());
        }
    }

    // Append trap entries — pre-reserved, so no realloc; stays sorted by
    // native offset because this page occupies the next native range.
    image.trap_table.extend_from_slice(&lazy.trap_entries);
    image.compiled[page] = true;

    Ok((image.trap_table.as_ptr(), image.trap_table.len() as u64))
}
