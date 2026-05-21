//! Guest-side state-cache plumbing.
//!
//! At boot we install a kernel-mode mapping for the host's state
//! cache region (`STATE_CACHE_VA → STATE_CACHE_GPA`, 1 GiB, no USER
//! bit) so kernel-mode RPC dispatchers can read cache memory by
//! offset. Persistent — survives across per-invocation page-table
//! rebuilds via the shallow-PML4-copy mechanism in
//! [`crate::paging::PageTable::new`].
//!
//! Host and guest both map the region at the same VA
//! ([`STATE_CACHE_VA`]) via `MAP_FIXED_NOREPLACE` on the host side,
//! which means every pointer the host wrote inside the region is
//! directly dereferenceable here. The directory at
//! [`CACHE_DIRECTORY_OFFSET`] holds `(CapHash, entry_va)` pairs that
//! resolve cap-hash queries into a `&CacheEntry<TalcAlloc>` we can
//! walk by pointer.

#![cfg(target_os = "none")]

extern crate alloc;

use alloc::vec::Vec;
use allocator_api2::alloc::Allocator;
use allocator_api2::boxed::Box as ABox;
use core::cell::UnsafeCell;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering};

use javm_cap::cap::Cap;
use javm_cap::entry::CacheEntry;
use nub_host_common::cache::{
    CACHE_DIRECTORY_OFFSET, CacheDirectory, CacheTalcLock, STATE_CACHE_GPA, STATE_CACHE_SIZE,
    STATE_CACHE_VA, TalcAlloc,
};

use crate::paging::{Perm, install_persistent_kernel_mapping};

static CACHE_MAPPED: AtomicBool = AtomicBool::new(false);

/// Per-RPC tracker of guest-published cap entries so we can clear
/// them at end of dispatch. The guest writes new caps into the
/// host-visible `CacheDirectory` for the duration of one
/// `nub_invoke_cached` call (e.g., children minted by in-kernel
/// `derive_spawn`); they're cleared before the RPC returns so the
/// host doesn't see stale "scratch" entries.
struct ScratchTracker {
    entries: Vec<(usize, NonNull<CacheEntry<TalcAlloc>>)>,
}

/// SAFETY: single-threaded guest (Hyperlight serialises calls).
unsafe impl Sync for ScratchTracker {}

struct ScratchCell {
    inner: UnsafeCell<ScratchTracker>,
}

/// SAFETY: single-threaded guest.
unsafe impl Sync for ScratchCell {}

static SCRATCH: ScratchCell = ScratchCell {
    inner: UnsafeCell::new(ScratchTracker {
        entries: Vec::new(),
    }),
};

/// Idempotent: install the cache mapping in the active PML4 if not
/// already done. Called lazily from the first `nub_invoke_cached`
/// dispatch. Boot path doesn't depend on cache, so we defer until
/// first use.
pub fn ensure_mapped() -> Result<(), &'static str> {
    if CACHE_MAPPED.load(Ordering::Acquire) {
        return Ok(());
    }
    let perm = Perm::kernel_rw();
    unsafe {
        install_persistent_kernel_mapping(
            STATE_CACHE_VA,
            STATE_CACHE_GPA,
            STATE_CACHE_SIZE as u64,
            perm,
        )
        .ok_or("install_persistent_kernel_mapping failed")?;
    }
    CACHE_MAPPED.store(true, Ordering::Release);
    Ok(())
}

/// Read-only view into the cache's `CacheDirectory`.
fn directory_ptr() -> *const CacheDirectory {
    (STATE_CACHE_VA + CACHE_DIRECTORY_OFFSET as u64) as *const CacheDirectory
}

/// Look up a blob (content-addressed cap) by hash. Returns a borrowed
/// reference to the `CacheEntry` living in cache memory.
///
/// # Safety
///
/// The returned reference borrows from the cache region. Callers must
/// ensure the cap isn't unpublished (decref to zero) while the
/// reference is live. V1 uses per-call `pin/unpin` on the host side
/// to enforce this.
pub fn lookup_blob<A: Allocator + Clone>(hash: &[u8; 32]) -> Option<&'static CacheEntry<A>> {
    ensure_mapped().ok()?;
    let dir = directory_ptr();
    // SAFETY: dir is a live pointer; find_blob just scans the array.
    let (_, slot_ptr) = unsafe { CacheDirectory::find_blob(dir, hash) }?;
    let va = unsafe { (*slot_ptr).entry_va };
    if va == 0 {
        return None;
    }
    // SAFETY: the host wrote a valid CacheEntry<TalcAlloc> at this VA;
    // host VA == guest VA so the pointer is directly dereferenceable.
    Some(unsafe { &*(va as *const CacheEntry<A>) })
}

/// Resolve an instance ref to its `CacheEntry`.
#[allow(dead_code)]
pub fn lookup_instance<A: Allocator + Clone>(ref_id: u64) -> Option<&'static CacheEntry<A>> {
    ensure_mapped().ok()?;
    let dir = directory_ptr();
    let (_, slot_ptr) = unsafe { CacheDirectory::find_instance(dir, ref_id) }?;
    let va = unsafe { (*slot_ptr).entry_va };
    if va == 0 {
        return None;
    }
    Some(unsafe { &*(va as *const CacheEntry<A>) })
}

/// Convenience: resolve a blob hash directly to its inner `Cap`.
pub fn lookup_cap(hash: &[u8; 32]) -> Option<&'static Cap<TalcAlloc>> {
    lookup_blob::<TalcAlloc>(hash).map(|e| &e.cap)
}

/// `TalcAlloc` handle pointing at the shared cache region's lock at
/// `STATE_CACHE_VA + 0`. Cheap to obtain (just wraps a pointer).
#[allow(dead_code)]
pub fn talc_alloc() -> TalcAlloc {
    ensure_mapped().expect("cache mapping");
    let lock_ptr =
        NonNull::new(STATE_CACHE_VA as *mut CacheTalcLock).expect("STATE_CACHE_VA is non-null");
    // SAFETY: the host's `Cache<TalcAlloc>` lives at the same VA and
    // already `claim`ed the lock; we share the same lock instance.
    unsafe { TalcAlloc::from_raw(lock_ptr) }
}

/// Publish a `Cap<TalcAlloc>` to the shared cache region by writing
/// a fresh `CacheEntry<TalcAlloc>` to the talc heap and recording
/// `(hash, entry_va)` in the host-visible `CacheDirectory`.
///
/// Tracks the published entry in [`SCRATCH`] so [`clear_scratch`]
/// can free + zero the directory slot at end of RPC.
///
/// V1: the host's `Cache<TalcAlloc>` BTreeMap is NOT updated — the
/// guest's view is via the directory only. The host doesn't query
/// guest-published caps mid-RPC (Hyperlight serialises calls), and
/// the cleanup at end-of-RPC ensures no stale entries leak across
/// invocations.
#[allow(dead_code)]
pub fn publish_blob(hash: [u8; 32], cap: Cap<TalcAlloc>) -> Result<(), &'static str> {
    let alloc = talc_alloc();
    let entry = CacheEntry::new(cap);
    let boxed = ABox::try_new_in(entry, alloc).map_err(|_| "publish_blob: alloc failed")?;
    // Leak the Box so the cache owns the entry; the pointer is
    // recorded in `SCRATCH` and freed in `clear_scratch`.
    let entry_ptr: *mut CacheEntry<TalcAlloc> = ABox::into_raw(boxed);
    let entry_nn = NonNull::new(entry_ptr).expect("just allocated");
    let entry_va = entry_ptr as u64;

    let dir_ptr = (STATE_CACHE_VA + CACHE_DIRECTORY_OFFSET as u64) as *mut CacheDirectory;
    // SAFETY: directory ptr is in the persistent kernel mapping.
    let idx = unsafe { CacheDirectory::first_empty_blob(dir_ptr) }
        .ok_or("publish_blob: directory full")?;
    // SAFETY: idx < MAX_BLOB_SLOTS; directory ptr is valid.
    unsafe {
        let slot = CacheDirectory::blob_slot_ptr(dir_ptr, idx);
        (*slot).hash = hash;
        (*slot).entry_va = entry_va;
        (*dir_ptr).blob_count_incr();
    }

    // Record for cleanup at end of RPC.
    // SAFETY: single-threaded guest.
    let tracker = unsafe { &mut *SCRATCH.inner.get() };
    tracker.entries.push((idx, entry_nn));
    Ok(())
}

/// Clear all entries this RPC published via [`publish_blob`]. Walks
/// the scratch tracker, zeroes each directory slot, and frees the
/// `CacheEntry` storage on the shared talc heap. Idempotent.
#[allow(dead_code)]
pub fn clear_scratch() {
    let alloc = talc_alloc();
    let dir_ptr = (STATE_CACHE_VA + CACHE_DIRECTORY_OFFSET as u64) as *mut CacheDirectory;

    // SAFETY: single-threaded guest.
    let tracker = unsafe { &mut *SCRATCH.inner.get() };
    for (idx, entry_ptr) in tracker.entries.drain(..) {
        // SAFETY: idx is < MAX_BLOB_SLOTS; we wrote (hash, entry_va)
        // when publishing.
        unsafe {
            let slot = CacheDirectory::blob_slot_ptr(dir_ptr, idx);
            (*slot).hash = [0u8; 32];
            (*slot).entry_va = 0;
            (*dir_ptr).blob_count_decr();
        }
        // SAFETY: we allocated this CacheEntry via `ABox::try_new_in`
        // in `publish_blob` and leaked it; reconstruct + drop frees
        // it through the same TalcAlloc.
        unsafe {
            let boxed = ABox::from_raw_in(entry_ptr.as_ptr(), alloc);
            drop(boxed);
        }
    }
}
