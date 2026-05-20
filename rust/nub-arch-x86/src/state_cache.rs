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

use allocator_api2::alloc::Allocator;
use core::sync::atomic::{AtomicBool, Ordering};

use javm_cap::talc::cap::Cap;
use javm_cap::talc::entry::CacheEntry;
use nub_host_common::cache::{
    CACHE_DIRECTORY_OFFSET, CacheDirectory, STATE_CACHE_GPA, STATE_CACHE_SIZE, STATE_CACHE_VA,
    TalcAlloc,
};

use crate::paging::{Perm, install_persistent_kernel_mapping};

static CACHE_MAPPED: AtomicBool = AtomicBool::new(false);

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
pub fn lookup_instance<A: Allocator + Clone>(
    ref_id: u64,
) -> Option<&'static CacheEntry<A>> {
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
