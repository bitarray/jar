//! Shared-memory cache header.
//!
//! [`CacheHeader`] is the fixed-offset, page-aligned struct living at
//! the start of the cache region. It owns:
//!
//! - The talc allocator (with its own internal spinlock).
//! - A spinlock-guarded [`javm_cap::CacheDirectory`] that holds the
//!   two HashMaps (blobs by `CapHash`, instances by `CapRef`).
//!
//! The talc heap covers everything past `size_of::<CacheHeader>()`
//! (rounded up to a 4 KiB page by `#[repr(align(4096))]`).
//!
//! The directory's HashMaps embed a `foldhash::fast::FixedState`
//! seeded per cache region (host pulls 16 bytes from `getrandom`),
//! so host and guest hash to identical buckets but adversarially
//! constructed cap content can't precompute collisions across runs.

use allocate::talc::{CacheTalcLock, Mutex, RawSpinlock, TalcAlloc, new_cache_talc_lock};
use foldhash::fast::FixedState;
use javm_cap::CacheDirectory;

/// The `CacheDirectory` flavour stored in shared memory. Hashbrown's
/// `HashMap` embeds the `FixedState` seed inline, so the seed lives
/// in the shared region and is read by both host and guest through
/// the same struct.
pub type SharedCacheDirectory = CacheDirectory<FixedState, TalcAlloc>;

/// Spin-locked directory; the lock never contends in V0 (Hyperlight
/// serialises host↔guest), but it makes mutation honest about the
/// access model and is one CAS per uncontended op.
pub type LockedDirectory = Mutex<RawSpinlock, SharedCacheDirectory>;

#[repr(align(4096))]
pub struct CacheHeader {
    /// Talc + its own internal spinlock. `Talck` impls
    /// `allocator_api2::alloc::Allocator` so `&CacheTalcLock` (=
    /// `TalcAlloc`) is the allocator handle used by every shared-cache
    /// allocation.
    pub talc: CacheTalcLock,
    /// The cap directory. Stored under a separate spinlock so HashMap
    /// mutations don't have to hold the talc lock across HashMap-level
    /// reasoning (the talc lock is reentered for individual allocations
    /// during HashMap resize internally).
    pub directory: LockedDirectory,
}

impl CacheHeader {
    /// Size of the header rounded up to its 4 KiB alignment. The talc
    /// heap should begin at `region_base + CacheHeader::SIZE`.
    pub const SIZE: usize = {
        let s = core::mem::size_of::<Self>();
        let align = core::mem::align_of::<Self>();
        s.div_ceil(align) * align
    };

    /// Placement-initialise a `CacheHeader` at `ptr`. After this
    /// returns, `ptr` is a fully-constructed `CacheHeader` with:
    /// - talc lock initialised (no heap claimed yet — caller does so
    ///   via `(*ptr).talc.lock().claim(span)`);
    /// - directory with empty HashMaps, hasher seeded by `seed`,
    ///   allocator handle pointing at the embedded talc lock.
    ///
    /// # Safety
    ///
    /// `ptr` must point to a writable region of at least
    /// [`Self::SIZE`] bytes, aligned to 4096. The memory must not be
    /// concurrently accessed. The caller asserts the region is pinned
    /// in memory for the resulting `&'static CacheHeader`'s lifetime
    /// (in practice: the mmap region lives for the process lifetime).
    pub unsafe fn init_at(ptr: *mut CacheHeader, seed: u64) -> &'static CacheHeader {
        unsafe {
            // Phase 1: write the talc lock. `Talck::new` is const and
            // doesn't allocate, so this is just a store of the struct's
            // initial bytes.
            core::ptr::addr_of_mut!((*ptr).talc).write(new_cache_talc_lock());

            // Phase 2: take a `'static` borrow of the talc lock we just
            // initialised. The `'static` lifetime is the standard
            // pinned-mapping fiction — see allocate::talc::TalcAlloc
            // docs.
            let alloc: TalcAlloc = &*core::ptr::addr_of!((*ptr).talc);

            // Phase 3: construct the directory in place. Empty HashMaps
            // don't allocate yet, so we don't need the talc heap claimed
            // before this point.
            let dir = Mutex::new(CacheDirectory::with_hasher_in(
                FixedState::with_seed(seed),
                alloc,
            ));
            core::ptr::addr_of_mut!((*ptr).directory).write(dir);

            // SAFETY: caller asserts the region is pinned; `&*ptr` is a
            // valid `&'static CacheHeader` under that contract.
            &*ptr
        }
    }
}
