//! `TalcAlloc`: the bridge from a `talc::TalcLock` to
//! `core::alloc::Allocator`.

use core::alloc::{AllocError, Allocator, Layout};
use core::ptr::NonNull;

/// Re-exported from `talc::source::Manual` so consumers can construct
/// a [`CacheTalcLock`] without a direct dep on talc.
pub use talc::source::Manual;

/// Concrete TalcLock flavor used by the shared state-cache region.
/// `spinning_top::RawSpinlock` for serialisation, `Manual` source for
/// claim-based initial allocation.
pub type CacheTalcLock = talc::TalcLock<spinning_top::RawSpinlock, Manual>;

/// `Copy` allocator handle that delegates to a [`CacheTalcLock`]
/// living at a fixed pointer.
///
/// # Safety
///
/// The pointer must reference a live, `claim`-ed [`CacheTalcLock`].
/// The caller is responsible for keeping the lock alive at least as
/// long as any `TalcAlloc` derived from it.
#[derive(Clone, Copy, Debug)]
pub struct TalcAlloc {
    talc: NonNull<CacheTalcLock>,
}

// SAFETY: the underlying lock provides interior serialisation; the
// handle itself is just a pointer.
unsafe impl Send for TalcAlloc {}
unsafe impl Sync for TalcAlloc {}

impl TalcAlloc {
    /// Wrap a raw pointer to a [`CacheTalcLock`].
    ///
    /// # Safety
    ///
    /// `talc` must point at a live, `claim`-ed `CacheTalcLock` that
    /// outlives every allocation made through the returned allocator.
    #[inline]
    pub const unsafe fn from_raw(talc: NonNull<CacheTalcLock>) -> Self {
        Self { talc }
    }

    /// Pointer back to the underlying [`CacheTalcLock`].
    #[inline]
    pub fn as_lock(&self) -> NonNull<CacheTalcLock> {
        self.talc
    }
}

// SAFETY: `talc 5.x` `TalcLock` serialises concurrent allocations
// through its inner spinlock. The pointer is non-null and points at a
// live lock (caller obligation enforced via `from_raw`).
unsafe impl Allocator for TalcAlloc {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let raw = unsafe { (*self.talc.as_ptr()).lock().allocate(layout) }.ok_or(AllocError)?;
        Ok(NonNull::slice_from_raw_parts(raw, layout.size()))
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        unsafe {
            (*self.talc.as_ptr())
                .lock()
                .deallocate(ptr.as_ptr(), layout);
        }
    }
}
