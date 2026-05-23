//! `CacheHandle<T>` — refcount-bumping pointer to a cache entry that
//! does NOT own the slab.
//!
//! Distinct from [`super::Aarc`] in one key respect: an `Aarc<T, A>`'s
//! `Drop` deallocates the slab on the last reference (matching
//! `Arc<T>`'s semantics). A `CacheHandle<T>` only manipulates the
//! refcount — storage is owned by the cache (host: `TBox` in a
//! `BTreeMap`; guest: shared-memory directory entry pointing at a
//! talc-heap allocation), and the cache decides when refcount==0
//! entries should be reclaimed.
//!
//! This is the right shape for the in-kernel guest path: a
//! `KernelFrame` holds a handle on its `Cap::Image` blob, the
//! refcount bump pins the blob against eviction, but the frame
//! shouldn't be responsible for freeing the entry — that's the
//! cache's job.
//!
//! Reuses the [`AarcRefCounted`] trait so any type with an embedded
//! `AtomicU32` refcount can be handle-wrapped.

use core::ops::Deref;
use core::ptr::NonNull;
use core::sync::atomic::Ordering;

use super::talc_arc::AarcRefCounted;

/// Refcount-bumping handle to a `T` whose storage is owned by the
/// cache. Clone bumps refcount; Drop decrements but does NOT free.
pub struct CacheHandle<T: AarcRefCounted> {
    ptr: NonNull<T>,
}

// SAFETY: a `CacheHandle` is a refcounted pointer to a shared `T`;
// thread-safety is inherited from `T` and from `AtomicU32`.
unsafe impl<T: AarcRefCounted + Send + Sync> Send for CacheHandle<T> {}
unsafe impl<T: AarcRefCounted + Send + Sync> Sync for CacheHandle<T> {}

impl<T: AarcRefCounted> CacheHandle<T> {
    /// Acquire a handle to an existing entry; bumps refcount by 1.
    ///
    /// # Safety
    ///
    /// `ptr` must point at a valid `T` that outlives the handle and
    /// every clone made from it. The cache (owner of the slab) must
    /// keep the entry resident at least until refcount drops back to
    /// where it was before this call.
    #[inline]
    pub unsafe fn acquire(ptr: NonNull<T>) -> Self {
        // SAFETY: caller asserts `ptr` is live.
        unsafe {
            (*ptr.as_ptr()).refcount().fetch_add(1, Ordering::Relaxed);
        }
        Self { ptr }
    }

    /// Construct a handle WITHOUT bumping refcount. Used when the
    /// caller has already accounted for this handle's refcount
    /// (e.g., during cache publish where the entry starts at
    /// refcount=1 and the publisher hands its initial reference to
    /// the handle).
    ///
    /// # Safety
    ///
    /// Same lifetime invariant as [`Self::acquire`]. Additionally,
    /// the caller must have already incremented the refcount by 1 to
    /// account for this handle, or be transferring a pre-existing
    /// count to the handle.
    #[inline]
    pub unsafe fn from_raw_no_bump(ptr: NonNull<T>) -> Self {
        Self { ptr }
    }

    /// Current refcount (loaded with Acquire ordering).
    #[inline]
    pub fn refcount(&self) -> u32 {
        // SAFETY: ptr is valid for the lifetime of this handle.
        unsafe { (*self.ptr.as_ptr()).refcount().load(Ordering::Acquire) }
    }

    /// Raw pointer to the underlying `T`. Useful for handing the VA
    /// to other cache-API entry points without taking an additional
    /// refcount.
    #[inline]
    pub fn as_ptr(&self) -> *mut T {
        self.ptr.as_ptr()
    }
}

impl<T: AarcRefCounted> Clone for CacheHandle<T> {
    fn clone(&self) -> Self {
        // SAFETY: ptr is valid for the lifetime of this handle.
        unsafe {
            (*self.ptr.as_ptr())
                .refcount()
                .fetch_add(1, Ordering::Relaxed);
        }
        Self { ptr: self.ptr }
    }
}

impl<T: AarcRefCounted> Drop for CacheHandle<T> {
    fn drop(&mut self) {
        // SAFETY: ptr is valid for the lifetime of this handle.
        // Storage is NOT freed here — the cache reclaims entries when
        // it observes refcount==0 (out of band).
        unsafe {
            (*self.ptr.as_ptr())
                .refcount()
                .fetch_sub(1, Ordering::Release);
        }
    }
}

impl<T: AarcRefCounted> Deref for CacheHandle<T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: ptr is valid for the lifetime of this handle.
        unsafe { &*self.ptr.as_ptr() }
    }
}

impl<T: AarcRefCounted + core::fmt::Debug> core::fmt::Debug for CacheHandle<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("CacheHandle")
            .field(&self.refcount())
            .field(&&**self)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicU32;

    #[repr(C)]
    struct Counted {
        refcount: AtomicU32,
        payload: u64,
    }
    impl AarcRefCounted for Counted {
        fn refcount(&self) -> &AtomicU32 {
            &self.refcount
        }
    }

    /// Helper: simulate the cache by leaking a `Box` so the entry
    /// stays live for the test's duration.
    fn make_entry(payload: u64, initial_count: u32) -> NonNull<Counted> {
        let boxed = alloc::boxed::Box::new(Counted {
            refcount: AtomicU32::new(initial_count),
            payload,
        });
        NonNull::new(alloc::boxed::Box::into_raw(boxed)).expect("non-null")
    }

    /// Helper: free the simulated cache entry after the test.
    /// Reconstructs the `Box` from the raw pointer and drops it.
    unsafe fn drop_entry(ptr: NonNull<Counted>) {
        // SAFETY: caller passes a pointer obtained from `make_entry`.
        unsafe {
            drop(alloc::boxed::Box::from_raw(ptr.as_ptr()));
        }
    }

    #[test]
    fn acquire_bumps_refcount() {
        // Cache pre-publishes with refcount=1.
        let ptr = make_entry(42, 1);
        // Lookup acquires; refcount → 2.
        let h = unsafe { CacheHandle::acquire(ptr) };
        assert_eq!(h.refcount(), 2);
        assert_eq!(h.payload, 42);
        drop(h);
        // Back to 1 (the cache's published count).
        assert_eq!(
            unsafe { (*ptr.as_ptr()).refcount.load(Ordering::Acquire) },
            1
        );
        unsafe { drop_entry(ptr) };
    }

    #[test]
    fn clone_bumps_drop_decrements() {
        let ptr = make_entry(7, 1);
        let a = unsafe { CacheHandle::acquire(ptr) };
        assert_eq!(a.refcount(), 2);
        let b = a.clone();
        let c = a.clone();
        assert_eq!(a.refcount(), 4);
        drop(b);
        assert_eq!(a.refcount(), 3);
        drop(c);
        assert_eq!(a.refcount(), 2);
        drop(a);
        assert_eq!(
            unsafe { (*ptr.as_ptr()).refcount.load(Ordering::Acquire) },
            1
        );
        unsafe { drop_entry(ptr) };
    }

    #[test]
    fn drop_does_not_free_storage() {
        // Pre-publish at refcount=1, acquire to refcount=2, drop both —
        // the entry remains live (the cache, not the handle, owns the
        // slab). We verify by reading payload after all handles drop.
        let ptr = make_entry(99, 1);
        let h = unsafe { CacheHandle::acquire(ptr) };
        assert_eq!(h.payload, 99);
        drop(h);
        // Refcount went 1 → 2 → 1; storage still live.
        assert_eq!(unsafe { (*ptr.as_ptr()).payload }, 99);
        assert_eq!(
            unsafe { (*ptr.as_ptr()).refcount.load(Ordering::Acquire) },
            1
        );
        unsafe { drop_entry(ptr) };
    }

    #[test]
    fn from_raw_no_bump_does_not_change_count() {
        // Caller publishes at refcount=1 and transfers that initial
        // reference to a handle without bumping again.
        let ptr = make_entry(13, 1);
        let h = unsafe { CacheHandle::from_raw_no_bump(ptr) };
        assert_eq!(h.refcount(), 1);
        drop(h);
        // Drop decremented; entry should now be at refcount=0, which
        // signals to the cache that it can reclaim — but the storage
        // itself is still live (cache hasn't run reclaim yet).
        assert_eq!(
            unsafe { (*ptr.as_ptr()).refcount.load(Ordering::Acquire) },
            0
        );
        unsafe { drop_entry(ptr) };
    }
}
