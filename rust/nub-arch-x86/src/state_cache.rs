//! Guest-side cap directory + boot info publishing.
//!
//! ## CACHE
//!
//! The cap store is a `CacheDirectory<FixedState, CachedCap>` that lives entirely
//! in the guest's talc heap. The host populates blobs via the
//! [`FN_ID_NUB_PUT_CAP`](nub_arch_x86_abi::FN_ID_NUB_PUT_CAP) RPC:
//! ship a rkyv-archived `Cap` payload, the guest validates via
//! [`rkyv::access`], materialises via [`rkyv::deserialize`], and
//! inserts via [`CacheDirectory::put_cap`]. Kernel-derived sub-VM
//! instances are NOT published here — they live inline in their
//! parent frame's cnode as `CapHashOrRef::Owned` and move zero-copy
//! (see `call_loop`).
//!
//! `CacheDirectory` is interior-mutable (its inner `spin::Mutex`
//! serialises all public methods), so the static holds it directly
//! without an outer `Mutex<...>` wrapper.
//!
//! The directory is initialised with a const-seeded
//! `foldhash::fast::FixedState` so both host (when it dereferences
//! the directory via the `BOOT_INFO`-published VA — see
//! `nub-host-kvm::guest_cache_reader`) and guest hash to the same
//! buckets.
//!
//! ## BootInfo
//!
//! At boot the guest writes the directory's VA (the `CacheDirectory`
//! struct's address) into [`BOOT_INFO`], a `static mut BootInfo`
//! placed in the `.boot_info` linker section. The host reads the
//! section from the kernel ELF after sandbox startup to learn where
//! to find the cap directory.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use foldhash::fast::FixedState;
use javm_cap::cache::CacheDirectory;
use javm_cap::cap::Cap;
use nub_arch_x86_abi::BootInfo;

use crate::cached_cap::{CachedCap, CapCache};
use crate::personality::{GuestStore, ObjHash};

/// Per-cache hasher seed. Pinned at a constant so the host's
/// direct-dereference reader (via `BootInfo.directory_va`) agrees on
/// bucket assignments. Any value works; using the magic for symmetry
/// with BootInfo makes diagnostics easier.
const DIRECTORY_HASHER_SEED: u64 = 0x4A41_525F_4449_5230; // "JAR_DIR0"

/// Heap-resident cap directory. Populated by the host via the `put_cap` RPC
/// (content-addressed blobs). The kernel call loop no longer uses the
/// instances tier: `derive_spawn`'d sub-VMs live **inline** in their parent's
/// cnode as [`javm_cap::cache::CapHashOrRef::Owned`] and move zero-copy,
/// rather than being published as `CapRef`-keyed instances.
///
/// `CacheDirectory::new_const` is `const fn`, so the static initialiser
/// runs at link time — the cache is ready before `hyperlight_main`.
pub static CACHE: CacheDirectory<FixedState, CachedCap> = CacheDirectory::new_const(
    FixedState::with_seed(DIRECTORY_HASHER_SEED),
    FixedState::with_seed(DIRECTORY_HASHER_SEED),
);

/// The Javm personality's [`GuestStore`]: a stateless handle onto the
/// process-global [`CACHE`] directory + [`BOOT_INFO`] block.
pub struct JavmStore;

pub static JAVM_STORE: JavmStore = JavmStore;

impl GuestStore for JavmStore {
    /// Validate the rkyv-archived [`Cap`] payload via [`rkyv::access`]
    /// (zero-copy), materialise an owned `Cap` via [`rkyv::deserialize`],
    /// and insert it into [`CACHE`]. Error codes 1/2/3 (access /
    /// deserialize / put) are diagnostics only — the RPC wrapper maps any
    /// `Err` to the all-`0xFF` sentinel hash.
    fn put_object(&self, bytes: &[u8]) -> Result<ObjHash, u32> {
        let mut aligned = rkyv::util::AlignedVec::<16>::with_capacity(bytes.len());
        aligned.extend_from_slice(bytes);

        let archived = rkyv::access::<rkyv::Archived<Cap>, rkyv::rancor::Error>(aligned.as_slice())
            .map_err(|_| 1u32)?;
        let cap: Cap = rkyv::deserialize::<Cap, rkyv::rancor::Error>(archived).map_err(|_| 2u32)?;
        CACHE.put_cap(&cap).map_err(|_| 3u32)
    }

    fn sweep(&self) {
        CACHE.sweep_instances();
    }

    /// Drop every compiled-image artifact from [`CACHE`].
    ///
    /// Bench-only: each `CompiledImage`'s `Drop` releases its arena pages
    /// and template PD/PT pages, which is fine between invocations (no
    /// in-flight call references them). The next compile-cache miss will
    /// pay full recompile cost. Safe under Hyperlight serialisation; not
    /// meant for production paths.
    fn evict_jit(&self) {
        for (_, cap) in CACHE.iter_blobs() {
            let mut cache = cap.cache.lock();
            if matches!(&*cache, CapCache::Image(_)) {
                *cache = CapCache::None;
            }
        }
    }

    fn init_boot_info(&self) {
        init_directory_va();
    }

    /// Read the current [`BOOT_INFO`] block out as raw bytes.
    fn boot_info_bytes(&self) -> Vec<u8> {
        // SAFETY: `BOOT_INFO` is `static mut`; callers read it after the
        // `init_boot_info` hook ran, and we publish bytes out via a fresh
        // copy. Reads of a freshly-patched `directory_va` field are safe in
        // this single-threaded boot context.
        let info: BootInfo = unsafe {
            let p = &raw const BOOT_INFO;
            core::ptr::read(p)
        };
        let bytes = unsafe {
            core::slice::from_raw_parts(
                &info as *const BootInfo as *const u8,
                core::mem::size_of::<BootInfo>(),
            )
        };
        bytes.to_vec()
    }
}

/// `BootInfo` placed in the `.boot_info` linker section. Initialised
/// at link time with the magic and reserved fields; the
/// `directory_va` and `guest_va_base` slots are patched at boot by
/// [`init_directory_va`].
///
/// `static mut` because we patch two fields at boot — the host reads
/// them post-boot via the section's symbol address (resolved from
/// the kernel ELF).
#[unsafe(link_section = ".boot_info")]
#[unsafe(no_mangle)]
pub static mut BOOT_INFO: BootInfo = BootInfo {
    magic: BootInfo::MAGIC,
    directory_va: 0,
    // Sentinel: hash of the published directory's type signature.
    // Bumped to 0x0004 when the guest resident directory payload changed from
    // `Arc<Cap>` to `Arc<CachedCap>`.
    directory_type_id: 0x0004,
    // Patched at boot from `kernel_base_va() - KERNEL_OFFSET`.
    guest_va_base: 0,
    _reserved: [0u64; 12],
};

unsafe extern "C" {
    /// Linker symbol; PIE-relocated at load time to the kernel's
    /// actual runtime base GVA. See `paging.rs` for context.
    safe static _kernel_start: u8;
}

/// Idempotent: write the VA of [`CACHE`] into `BOOT_INFO.directory_va`
/// and the kernel's actual runtime base into `BOOT_INFO.guest_va_base`.
/// Called once at guest boot (we do it from the `put_cap` RPC's first
/// call as a lazy hook — see `nub-arch-x86/src/main.rs`).
pub fn init_directory_va() {
    static INITIALISED: AtomicBool = AtomicBool::new(false);
    if INITIALISED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    let va = &CACHE as *const CacheDirectory<FixedState, CachedCap> as u64;
    let kernel_base = &_kernel_start as *const u8 as u64;
    let guest_va_base = kernel_base - nub_host_common::layout::KERNEL_OFFSET;
    // SAFETY: `BOOT_INFO` is `static mut` but we're the only writer
    // (single-threaded guest at boot) and the read side is loaded
    // by the host only after sandbox boot completes. The atomic
    // guard ensures we run once.
    unsafe {
        let p = &raw mut BOOT_INFO;
        (*p).directory_va = va;
        (*p).guest_va_base = guest_va_base;
    }
}
