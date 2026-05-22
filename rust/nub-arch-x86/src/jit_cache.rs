//! Per-image JIT code cache.
//!
//! `Compiler::compile` emits native x86-64 bytes whose RIP-relative
//! references hard-code the per-invocation VA layout: `CTX_VA` (4 GiB),
//! `JIT_VA_M` (META_BASE + 64 MiB), `BB_VA_M`, `JT_VA_M`,
//! `DISPATCH_VA_M`. Those VAs are *constants* in this crate, so the
//! compiled bytes are reusable across every ring-3 entry — the JIT
//! page-table sets up the same layout each time. Only the per-frame
//! memory (CTX page, mem region, stack, PT skeleton) changes.
//!
//! Caching the compile result keyed by `image_hash` (the `Cap::Image`
//! content hash) lets the recursive-spawn bench reuse one compile pass
//! across thousands of CALLs of the same Image. Without the cache,
//! `Compiler::compile` runs once per invocation (~100–500 µs per
//! call) and dwarfs the ~10 µs ring-3 context switch we're trying to
//! measure.

#![cfg(target_os = "none")]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cell::UnsafeCell;

use javm_recompiler_x86::codegen::{CompileResult, Compiler, HelperFns};

use javm_cap::CapHash;

/// One cached compile result, retained by `image_hash`.
///
/// The fields mirror [`CompileResult`] but live in long-term storage.
/// Each ring-3 entry copies `native` into the per-invocation user-RX
/// page and `dispatch_table` into the user-RO dispatch page. The
/// `trap_table` is consulted by `jit_pf_handler` to translate native
/// offsets back to PVM PCs on page faults; we hand a borrowed slice
/// to the handler via static atomics.
pub struct CompiledImage {
    pub native: Vec<u8>,
    pub dispatch_table: Vec<i32>,
    pub trap_table: Vec<(u32, u32)>,
    pub exit_label_offset: u32,
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

/// Look up the compile cache by `image_hash`. On miss, run
/// `Compiler::compile` and insert the result. Returns a `'static`
/// borrow into the cache entry — caller may freely read `native`,
/// `dispatch_table`, `trap_table`, `exit_label_offset` for the
/// duration of the invocation.
///
/// # Safety
///
/// Hyperlight serialises host calls, so concurrent access is not
/// possible. The returned reference is valid until the cache entry is
/// evicted; in V1 we never evict, so the borrow lifetime is
/// effectively `'static`.
pub fn get_or_compile(
    image_hash: &CapHash,
    code: &[u8],
    bitmask: &[u8],
    jump_table: &[u32],
    jit_va_m: u64,
    mem_cycles: u8,
    helpers: HelperFns,
) -> &'static CompiledImage {
    // SAFETY: single-threaded guest. Reentrant access from inside the
    // closure below is impossible because `Compiler::compile` doesn't
    // call back into this module.
    let map = unsafe { &mut *CACHE.inner.get() };
    if !map.contains_key(image_hash) {
        let compiler = Compiler::new(
            bitmask,
            jump_table,
            helpers,
            code.len(),
            jit_va_m,
            mem_cycles,
        );
        let CompileResult {
            native_code,
            dispatch_table,
            trap_table,
            exit_label_offset,
        } = compiler.compile(code, bitmask);
        map.insert(
            *image_hash,
            CompiledImage {
                native: native_code,
                dispatch_table,
                trap_table,
                exit_label_offset,
            },
        );
    }
    // SAFETY: just inserted (or already present); BTreeMap never
    // moves entries by value once allocated through the global
    // allocator, so the reference is stable for the cache's lifetime.
    map.get(image_hash).expect("inserted above")
}

/// Diagnostic: number of cached images. Useful for tests that assert
/// the cache is being hit.
#[allow(dead_code)]
pub fn cached_count() -> usize {
    // SAFETY: single-threaded guest.
    let map = unsafe { &*CACHE.inner.get() };
    map.len()
}
