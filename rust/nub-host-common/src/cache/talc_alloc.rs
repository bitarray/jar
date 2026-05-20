//! `TalcAlloc`: an `allocator_api2::alloc::Allocator` newtype that
//! delegates to a [`CacheTalcLock`] living at a fixed pointer.
//!
//! This lets us use stock `allocator_api2::{vec::Vec, boxed::Box}` to
//! own cap content inside the cache region. `TalcAlloc` is `Copy`, so
//! parameterising every Cap variant by it (`Cap<TalcAlloc>`) is free —
//! the allocator handle is just `NonNull<CacheTalcLock>` under the
//! hood, and every Vec/Box stores one copy.
//!
//! For host-private (non-cache) cap usage, callers stick with the
//! default `Cap<Global>` — `TalcAlloc` only appears at the cache
//! boundary.

use core::ptr::NonNull;

use allocator_api2::alloc::{AllocError, Allocator};

use super::talc_box::CacheTalcLock;

/// Reference to the cache's talc instance. Cheap to clone (Copy).
///
/// # Safety
///
/// The pointer must reference a live, `claim`ed `CacheTalcLock`. The
/// host's `Cache` is responsible for keeping the lock alive at least
/// as long as any `TalcAlloc` derived from it.
#[derive(Clone, Copy, Debug)]
pub struct TalcAlloc {
    talc: NonNull<CacheTalcLock>,
}

// The pointer is process-local but the talc *lock* (the spinlock
// inside `CacheTalcLock`) is what serialises concurrent allocations,
// so the wrapper itself is Send + Sync.
unsafe impl Send for TalcAlloc {}
unsafe impl Sync for TalcAlloc {}

impl TalcAlloc {
    /// Wrap a raw pointer to a `CacheTalcLock`.
    ///
    /// # Safety
    ///
    /// `talc` must point at a live, `claim`ed `CacheTalcLock` that
    /// outlives every allocation made through the returned allocator.
    pub const unsafe fn from_raw(talc: NonNull<CacheTalcLock>) -> Self {
        Self { talc }
    }

    /// Pointer back to the underlying `CacheTalcLock`. Useful for
    /// hand-rolled primitives (e.g. `TalcArc`) that bypass the
    /// `Allocator` trait but still need to free against the same lock.
    #[inline]
    pub fn as_lock(&self) -> NonNull<CacheTalcLock> {
        self.talc
    }
}

unsafe impl Allocator for TalcAlloc {
    fn allocate(&self, layout: core::alloc::Layout) -> Result<NonNull<[u8]>, AllocError> {
        // talc 5.x: `Talc::allocate` returns `Option<NonNull<u8>>`,
        // `deallocate` takes a raw `*mut u8`. Convert at the boundary.
        let raw = unsafe { (*self.talc.as_ptr()).lock().allocate(layout) }.ok_or(AllocError)?;
        Ok(NonNull::slice_from_raw_parts(raw, layout.size()))
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: core::alloc::Layout) {
        unsafe {
            (*self.talc.as_ptr())
                .lock()
                .deallocate(ptr.as_ptr(), layout);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use allocator_api2::boxed::Box;
    use allocator_api2::vec::Vec;
    use talc::source::Manual;

    struct Arena {
        _backing: alloc::vec::Vec<u8>,
        talc: alloc::boxed::Box<CacheTalcLock>,
    }
    impl Arena {
        fn new(size: usize) -> Self {
            let backing = alloc::vec![0u8; size];
            let talc = alloc::boxed::Box::new(CacheTalcLock::new(Manual));
            let base = backing.as_ptr() as *mut u8;
            unsafe {
                let _ = talc.lock().claim(base, size).expect("claim");
            }
            Self {
                _backing: backing,
                talc,
            }
        }
        fn alloc(&self) -> TalcAlloc {
            unsafe { TalcAlloc::from_raw(NonNull::from(&*self.talc)) }
        }
    }

    #[test]
    fn vec_with_talc_alloc_round_trips() {
        let arena = Arena::new(64 * 1024);
        let alloc = arena.alloc();

        let mut v: Vec<u32, TalcAlloc> = Vec::new_in(alloc);
        for i in 0..16 {
            v.push(i * 3);
        }
        assert_eq!(v.len(), 16);
        for (i, &x) in v.iter().enumerate() {
            assert_eq!(x as usize, i * 3);
        }
    }

    #[test]
    fn box_with_talc_alloc_round_trips() {
        let arena = Arena::new(64 * 1024);
        let alloc = arena.alloc();

        let b: Box<[u64; 4], TalcAlloc> = Box::new_in([10, 20, 30, 40], alloc);
        assert_eq!(*b, [10, 20, 30, 40]);
    }

    #[test]
    fn freed_memory_is_reclaimed() {
        let arena = Arena::new(8 * 1024);
        let alloc = arena.alloc();
        // Repeated alloc-drop cycles should not exhaust the heap.
        for _ in 0..1024 {
            let _v: Vec<u8, TalcAlloc> = Vec::with_capacity_in(256, alloc);
        }
    }
}
