//! Per-Image JIT code cache + page-aligned arena.
//!
//! Each Image gets one [`PageBuf`] arena containing five regions
//! laid out contiguously, each starting on a page boundary:
//!
//! ```text
//!   arena base (page-aligned)
//!     + bb_offset       : BB (bitmask)      RO
//!     + jt_offset       : JT (jump table)   RO
//!     + dispatch_offset : DISPATCH table    RO
//!     + jit_offset      : JIT native code   RX
//!     + tramp_offset    : trampoline (26B)  RX
//! ```
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
    /// Page-aligned buffer holding the five regions.
    ///
    /// Kept solely to own the backing pages — referenced by the
    /// template's leaf PTEs and freed when the cache entry is evicted.
    #[allow(dead_code)]
    pub arena: PageBuf,
    /// Offsets into `arena` for each region (in bytes from arena base).
    pub bb_offset: usize,
    pub jt_offset: usize,
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
    /// to recover the PVM PC from a faulting RIP.
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
    bitmask: &[u8],
    jump_table: &[u32],
    arena_base_va: u64,
    ctx_va: u64,
    mem_cycles: u8,
    helpers: HelperFns,
) -> &'static CompiledImage {
    // SAFETY: single-threaded guest.
    let map = unsafe { &mut *CACHE.inner.get() };
    if !map.contains_key(image_hash) {
        // ---- compute region sizes and offsets --------------------------
        let bb_size = page_round_up_min1(bitmask.len());
        let jt_size = page_round_up_min1(core::mem::size_of_val(jump_table));
        // Dispatch table sized at worst-case (one i32 per code byte) so
        // every PC index lands in range; only the prefix produced by
        // compile is filled, rest stays zero.
        let dispatch_size = page_round_up_min1(code.len() * core::mem::size_of::<i32>());

        let bb_offset = 0usize;
        let jt_offset = bb_offset + bb_size;
        let dispatch_offset = jt_offset + jt_size;
        let jit_offset = dispatch_offset + dispatch_size;
        // jit_va is the absolute VA where the JIT region will be mapped;
        // codegen embeds this for its internal jump resolution.
        let jit_va = arena_base_va + jit_offset as u64;

        // ---- run codegen ----------------------------------------------
        let compiler = Compiler::new(bitmask, jump_table, helpers, code.len(), jit_va, mem_cycles);
        let CompileResult {
            native_code,
            dispatch_table,
            trap_table,
            exit_label_offset,
        } = compiler.compile(code, bitmask);

        let jit_size = page_round_up_min1(native_code.len());
        let tramp_offset = jit_offset + jit_size;
        let tramp_size = PAGE_SIZE; // 26 bytes; one page is plenty.

        let total = tramp_offset + tramp_size;

        // ---- allocate arena --------------------------------------------
        let mut arena = PageBuf::new(total).expect("PageBuf alloc for Image arena");

        // ---- fill BB / JT / DISPATCH / JIT / TRAMP into arena ----------
        let buf = arena.as_mut_slice();
        // BB
        buf[bb_offset..bb_offset + bitmask.len()].copy_from_slice(bitmask);
        // JT
        let jt_bytes_len = core::mem::size_of_val(jump_table);
        // Reinterpret &[u32] as &[u8] for the memcpy.
        let jt_ptr = jump_table.as_ptr() as *const u8;
        // SAFETY: jt_ptr is valid for jt_bytes_len bytes (jump_table
        // length × size_of::<u32>).
        let jt_slice = unsafe { core::slice::from_raw_parts(jt_ptr, jt_bytes_len) };
        buf[jt_offset..jt_offset + jt_bytes_len].copy_from_slice(jt_slice);
        // DISPATCH
        let dispatch_bytes_len = core::mem::size_of_val(dispatch_table.as_slice());
        let dispatch_ptr = dispatch_table.as_ptr() as *const u8;
        // SAFETY: dispatch_ptr is valid for dispatch_bytes_len bytes.
        let dispatch_slice =
            unsafe { core::slice::from_raw_parts(dispatch_ptr, dispatch_bytes_len) };
        buf[dispatch_offset..dispatch_offset + dispatch_bytes_len].copy_from_slice(dispatch_slice);
        // JIT
        buf[jit_offset..jit_offset + native_code.len()].copy_from_slice(&native_code);
        // TRAMP — 26 bytes encoding the per-Image entry sequence.
        //   mov rdi, ctx_va     ; 48 BF <imm64>  (10)
        //   mov rax, jit_va     ; 48 B8 <imm64>  (10)
        //   call rax            ; FF D0          (2)
        //   int 0x81            ; CD 81          (2)
        //   ud2                 ; 0F 0B          (2)
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

        // ---- build the template PD ------------------------------------
        // One PD covers 1 GiB of VA starting at `arena_base_va`; leaf
        // PTEs point at each 4 KiB arena page with the appropriate
        // permission (RO for BB/JT/DISPATCH, RX for JIT/TRAMP).
        let arena_pa = arena.pa();
        let mut template = TemplatePT::new().expect("TemplatePT alloc");
        let ro_end = jit_offset; // bytes covered by RO range (BB+JT+DISPATCH)
        let arena_total = total;
        let mut off = 0usize;
        while off < arena_total {
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
                bb_offset,
                jt_offset,
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
    // SAFETY: present; BTreeMap entries don't move once inserted.
    map.get(image_hash).expect("inserted above")
}
