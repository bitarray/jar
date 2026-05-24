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
/// host's `HostCache` is responsible for keeping the lock alive at
/// least as long as any `TalcAlloc` derived from it.
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
