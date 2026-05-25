//! Guest-side cap directory + boot info publishing.
//!
//! ## CACHE
//!
//! The cap store is a `Mutex<CacheDirectory<FixedState>>` that lives
//! entirely in the guest's talc heap. The host populates it via the
//! [`FN_ID_NUB_PUT_CAP`](nub_arch_x86_abi::FN_ID_NUB_PUT_CAP) RPC:
//! ship a [`WireCap`](javm_cap::wire::WireCap) payload, the guest
//! decodes + computes `cap_hash` + inserts via
//! [`CacheDirectory::put_cap`]. Kernel-derived sub-VM instances are
//! published via [`CacheDirectory::put_instance`], which allocates a
//! fresh [`CapRef`] from the directory's internal counter.
//!
//! The directory is initialised with a const-seeded
//! `foldhash::fast::FixedState` so both host (when it dereferences
//! the directory via the `BOOT_INFO`-published VA — see
//! `nub-host-kvm::guest_cache_reader`) and guest hash to the same
//! buckets.
//!
//! ## BootInfo
//!
//! At boot the guest writes the directory's VA (the *inner*
//! `CacheDirectory<FixedState>`'s VA, not the wrapping Mutex's) into
//! [`BOOT_INFO`], a `static mut BootInfo` placed in the `.boot_info`
//! linker section. The host reads the section from the kernel ELF
//! after sandbox startup to learn where to find the cap directory.

#![cfg(target_os = "none")]

use core::sync::atomic::{AtomicBool, Ordering};

use foldhash::fast::FixedState;
use javm_cap::cache::CacheDirectory;
use javm_cap::cap::{Cap, CapRef};
use nub_arch_x86_abi::BootInfo;
use spin::Mutex;

/// Per-cache hasher seed. Pinned at a constant so the host's
/// direct-dereference reader (via `BootInfo.directory_va`) agrees on
/// bucket assignments. Any value works; using the magic for symmetry
/// with BootInfo makes diagnostics easier.
const DIRECTORY_HASHER_SEED: u64 = 0x4A41_525F_4449_5230; // "JAR_DIR0"

/// Heap-resident cap directory + transient instance store. Populated by
/// the host via the `put_cap` RPC and by the kernel call loop via
/// `put_instance` for `derive_spawn`-created sub-VMs.
///
/// `CacheDirectory::new_const` is `const fn`, so the static initialiser
/// runs at link time — the cache is ready before `hyperlight_main`.
pub static CACHE: Mutex<CacheDirectory<FixedState>> = Mutex::new(CacheDirectory::new_const(
    FixedState::with_seed(DIRECTORY_HASHER_SEED),
    FixedState::with_seed(DIRECTORY_HASHER_SEED),
));

/// Allocate a fresh `CapRef`, insert `cap` into [`CACHE`]'s instances
/// tier, and return the ref.
///
/// Infallible: the underlying HashMap insert can't fail in the absence
/// of OOM (talc OOM panics rather than returning).
pub fn publish_transient_instance(cap: Cap) -> CapRef {
    let mut dir = CACHE.lock();
    dir.put_instance(cap).expect("put_instance: talc OOM")
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
    // Sentinel: hash of the published directory's type signature. Bumped
    // when the directory shape changes; today the value is opaque — the
    // host just compares for equality. Bumped to 0x0002 in Commit 3
    // when the guest's DIRECTORY+INSTANCES pair moved into a single
    // `CacheDirectory<FixedState>`.
    directory_type_id: 0x0002,
    guest_va_base: 0x5000_0000_0000,
    _reserved: [0u64; 12],
};

/// Idempotent: write the VA of the inner `CacheDirectory<FixedState>`
/// into `BOOT_INFO.directory_va`. Called once at guest boot (we do it
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
    // SAFETY: we publish the VA of the directory's inner
    // `CacheDirectory` (the value owned by the Mutex). Taking the lock
    // first ensures no concurrent mutation is in flight; we drop the
    // guard immediately so writes can resume. The host reader will
    // take its own lock before dereferencing.
    let va = {
        let guard = CACHE.lock();
        let inner: &CacheDirectory<FixedState> = &guard;
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
