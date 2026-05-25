//! Guest-side cap directory + boot info publishing.
//!
//! ## DIRECTORY
//!
//! The cap directory is a `Mutex<HashMap<CapHash, Box<Cap>>>` that
//! lives entirely in the guest's talc heap. The host populates it
//! via the [`FN_ID_NUB_PUT_CAP`](nub_arch_x86_abi::FN_ID_NUB_PUT_CAP)
//! RPC: ship a [`WireCap`](javm_cap::wire::WireCap) payload, the
//! guest decodes + computes `cap_hash` + inserts.
//!
//! The directory is initialised with a const-seeded
//! `foldhash::fast::FixedState` so both host (when it later
//! dereferences the directory via the `BOOT_INFO`-published VA) and
//! guest hash to the same buckets.
//!
//! ## BootInfo
//!
//! At boot the guest writes the directory's VA (the *inner*
//! HashMap's VA, not the wrapping Mutex's) into [`BOOT_INFO`], a
//! `static mut BootInfo` placed in the `.boot_info` linker section.
//! The host reads the section from the kernel ELF after sandbox
//! startup to learn where to find the cap directory.
//!
//! ## Legacy
//!
//! `init_guest_cache` (returning a shared-memory `Cache` handle) is
//! retained for backward compatibility with code that still calls
//! into the old shared-cache path — it errors at runtime if invoked
//! because Commit 1 broke the underlying allocator-sharing
//! assumption. Commit 5 deletes the shared-cache module wholesale;
//! at that point this shim goes too.

#![cfg(target_os = "none")]

use core::sync::atomic::{AtomicBool, Ordering};

use core::sync::atomic::AtomicU64;

use allocate::Global;
use allocate::collections::HashMap;
use foldhash::fast::FixedState;
use javm_cap::cap::{Cap, CapHash, CapRef};
use nub_arch_x86_abi::BootInfo;
use nub_host_common::cache::{Cache, STATE_CACHE_GPA, STATE_CACHE_SIZE, STATE_CACHE_VA};
use spin::Mutex;

use crate::paging::{Perm, install_persistent_kernel_mapping};

/// Per-cache hasher seed. Pinned at a constant so the host's
/// future direct-dereference reader (via `BootInfo.directory_va`)
/// agrees on bucket assignments. Any value works; using the magic
/// for symmetry with BootInfo makes diagnostics easier.
const DIRECTORY_HASHER_SEED: u64 = 0x4A41_525F_4449_5230; // "JAR_DIR0"

/// Heap-resident cap directory. Populated by the host via the
/// `put_cap` RPC; queried by the in-kernel CALL/HALT loop in
/// [`crate::call_loop`].
///
/// The const-fn `HashMap::with_hasher_in` lets us avoid runtime
/// `OnceLock` machinery — the directory is ready before
/// `hyperlight_main` runs.
pub static DIRECTORY: Mutex<HashMap<CapHash, alloc::boxed::Box<Cap>, FixedState, Global>> =
    Mutex::new(HashMap::with_hasher_in(
        FixedState::with_seed(DIRECTORY_HASHER_SEED),
        Global,
    ));

/// Per-RPC transient instances (`derive_spawn` results, the
/// kernel-derived sub-VMs). Keyed by [`CapRef`] allocated via
/// [`NEXT_REF`]. Not visible to the host; lives only as long as the
/// owning call-loop frames hold their refs.
///
/// V0: the map is never cleared — entries accumulate within a single
/// RPC and are dropped when the call-loop tears down. The host can't
/// see them anyway. A future commit can add an RPC-scoped reset.
pub static INSTANCES: Mutex<HashMap<CapRef, alloc::boxed::Box<Cap>, FixedState, Global>> =
    Mutex::new(HashMap::with_hasher_in(
        FixedState::with_seed(DIRECTORY_HASHER_SEED ^ 1),
        Global,
    ));

/// Monotonic ref allocator. CapRef 0 is reserved (matches
/// `CacheDirectory`'s convention).
pub static NEXT_REF: AtomicU64 = AtomicU64::new(1);

/// Allocate a fresh `CapRef`, insert `cap` into [`INSTANCES`] under
/// the new ref, and return the ref.
pub fn publish_transient_instance(cap: Cap) -> CapRef {
    let r = NEXT_REF.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let mut map = INSTANCES.lock();
    map.insert(r, alloc::boxed::Box::new(cap));
    r
}

/// `BootInfo` placed in the `.boot_info` linker section. Initialised
/// at link time with the magic and reserved fields; the
/// `directory_va` slot is patched at boot by [`init_directory_va`].
///
/// `static mut` because we patch one field at boot — the host
/// reads it post-boot via the section's symbol address (resolved
/// from the kernel ELF).
#[unsafe(link_section = ".boot_info")]
#[unsafe(no_mangle)]
pub static mut BOOT_INFO: BootInfo = BootInfo {
    magic: BootInfo::MAGIC,
    directory_va: 0,
    // Sentinel: hash of `Mutex<HashMap<CapHash, Box<Cap>, FixedState,
    // Global>>` type signature. Bumped when the directory shape
    // changes. Today the value is opaque — host just compares for
    // equality.
    directory_type_id: 0x0001,
    guest_va_base: 0x5000_0000_0000,
    _reserved: [0u64; 12],
};

/// Idempotent: write the VA of the inner HashMap into
/// `BOOT_INFO.directory_va`. Called once at guest boot (we do it
/// from the `put_cap` RPC's first call as a lazy hook — see
/// `nub-arch-x86/src/main.rs`).
pub fn init_directory_va() {
    static INITIALISED: AtomicBool = AtomicBool::new(false);
    if INITIALISED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    // SAFETY: we publish the VA of the directory's inner HashMap (the
    // value owned by the Mutex). Taking the lock first ensures no
    // concurrent mutation is in flight; we drop the guard immediately
    // so writes can resume. The host reader will take its own lock
    // before dereferencing.
    let va = {
        let guard = DIRECTORY.lock();
        let inner: &HashMap<_, _, _, _> = &guard;
        inner as *const _ as u64
    };
    // SAFETY: `BOOT_INFO` is `static mut` but we're the only writer
    // (single-threaded guest at boot) and the read side
    // (`directory_va` field) is loaded by the host only after
    // sandbox boot completes. The atomic guard ensures we run once.
    unsafe {
        let p = &raw mut BOOT_INFO;
        (*p).directory_va = va;
    }
}

// --- Legacy shared-cache shim ---

#[allow(dead_code)]
static CACHE_MAPPED: AtomicBool = AtomicBool::new(false);

/// Errors raised by guest-side `Cache` construction.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheErr {
    /// `install_persistent_kernel_mapping` couldn't add the region
    /// mapping.
    MapNotInstalled,
}

/// Idempotent: install the default cache mapping (`STATE_CACHE_VA →
/// STATE_CACHE_GPA`) in the active PML4 if not already done.
#[allow(dead_code)]
fn ensure_default_mapped() -> Result<(), CacheErr> {
    if CACHE_MAPPED.load(Ordering::Acquire) {
        return Ok(());
    }
    let perm = Perm::kernel_rw();
    // SAFETY: STATE_CACHE_VA / STATE_CACHE_GPA / size are agreed-upon
    // constants; the persistent kernel mapping is a one-time install
    // that the per-invocation page-table builder copies forward.
    unsafe {
        install_persistent_kernel_mapping(
            STATE_CACHE_VA,
            STATE_CACHE_GPA,
            STATE_CACHE_SIZE as u64,
            perm,
        )
        .ok_or(CacheErr::MapNotInstalled)?;
    }
    CACHE_MAPPED.store(true, Ordering::Release);
    Ok(())
}

/// Legacy shim: construct a guest-side shared-memory [`Cache`]
/// handle. Retained for the old `nub_invoke_cached` codepath until
/// Commit 5 deletes the shared-cache infrastructure.
///
/// After Commits 1+2, the shared cache no longer reliably carries
/// cap content — caps allocate from `Global` (= talc heap) rather
/// than from the cache region's talc. The call-loop has been
/// migrated to read from [`DIRECTORY`] instead; this shim only
/// survives because the function is invoked from the existing
/// `nub_invoke_cached` RPC handler.
#[allow(dead_code)]
pub fn init_guest_cache() -> Result<Cache, CacheErr> {
    ensure_default_mapped()?;
    // SAFETY: `ensure_default_mapped` just installed the mapping;
    // the host has initialised the `CacheHeader` at offset 0 of the
    // region before sharing it with us.
    Ok(unsafe { Cache::from_mapped_region() })
}
