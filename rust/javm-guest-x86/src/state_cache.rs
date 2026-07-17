//! Guest-side cap directory.
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
//! The directory is guest-private: the host never dereferences it
//! (host/guest hashbrown deref is unsound — see
//! `nub-host-kvm::MultiUseSandbox::published_blobs`) and only tracks
//! published hashes on its own side.

use foldhash::fast::FixedState;
use javm_cap::cache::CacheDirectory;
use javm_cap::cap::Cap;

use crate::cached_cap::{CachedCap, CapCache};
use nub_arch_x86::personality::{GuestStore, ObjHash};

/// Per-cache hasher seed. A const seed (rather than a boot-time random
/// one) is required only because `CacheDirectory::new_const` runs at
/// link time; the value itself is arbitrary — nothing outside the
/// guest hashes into this table. ("JAR_DIR0" in ASCII, for
/// recognisability in memory dumps.)
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
/// process-global [`CACHE`] directory.
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
}
