//! `TalcArray<T>`: owned `[T]` slab allocated from a [`CacheTalcLock`].
//!
//! Generalises [`super::talc_box::TalcSlice`] to non-byte element
//! types. Drop runs `drop_in_place` over every element, then frees the
//! backing slab against the underlying talc.
//!
//! Used for the cap-shape arrays in `javm-cap` — `CNodeCap.slots`,
//! `ImageCap.endpoints`, `DataCap` paged pages, etc.

use alloc::alloc::Layout;
use core::ptr::NonNull;

use super::talc_box::CacheTalcLock;

/// An owned `[T]` slab inside the cache region.
///
/// Element invariants are the same as for `Box<[T]>`:
/// - `ptr` is aligned for `T`.
/// - The first `len` elements are valid `T` values.
/// - The backing allocation has `Layout::array::<T>(len)`.
///
/// Zero-length arrays don't allocate; `ptr` is `NonNull::dangling()`
/// and Drop is a no-op for the backing storage. Element destructors
/// (none, since `len == 0`) still run vacuously.
pub struct TalcArray<T> {
    ptr: NonNull<T>,
    len: usize,
    talc: NonNull<CacheTalcLock>,
}

unsafe impl<T: Send> Send for TalcArray<T> {}
unsafe impl<T: Sync> Sync for TalcArray<T> {}

impl<T> TalcArray<T> {
    /// Allocate space for `len` `T`s from `talc`, leaving the slab
    /// uninitialised. Caller must initialise every element before
    /// dropping or reading.
    ///
    /// Returns `None` if the layout overflows or the allocator
    /// refuses the request.
    ///
    /// # Safety
    ///
    /// `talc` must point at a live, properly-claimed [`CacheTalcLock`]
    /// that outlives the returned array. Caller must initialise the
    /// `len` elements before any read or drop.
    pub unsafe fn new_uninit_in(len: usize, talc: NonNull<CacheTalcLock>) -> Option<Self> {
        if len == 0 {
            return Some(Self {
                ptr: NonNull::dangling(),
                len: 0,
                talc,
            });
        }
        let layout = Layout::array::<T>(len).ok()?;
        let raw = unsafe { (*talc.as_ptr()).lock().allocate(layout)? };
        let ptr = raw.cast::<T>();
        Some(Self { ptr, len, talc })
    }

    /// Allocate space for `len` `T`s and zero the backing memory.
    /// Safe to call for any `T` whose all-zero bit pattern is a valid
    /// value (numeric types, `#[repr(C)]` structs of such).
    ///
    /// # Safety
    ///
    /// Same as [`Self::new_uninit_in`], plus the requirement that
    /// the all-zero pattern be a valid `T`.
    pub unsafe fn new_zeroed_in(len: usize, talc: NonNull<CacheTalcLock>) -> Option<Self> {
        let arr = unsafe { Self::new_uninit_in(len, talc)? };
        if len > 0 {
            unsafe {
                core::ptr::write_bytes(arr.ptr.as_ptr(), 0, len);
            }
        }
        Some(arr)
    }

    /// Allocate space for `values.len()` `T`s and bitwise-copy the
    /// values in. Requires `T: Copy` so the source's destructors
    /// don't run while the slab still references them.
    ///
    /// # Safety
    ///
    /// `talc` must point at a live, properly-claimed [`CacheTalcLock`]
    /// that outlives the returned array.
    pub unsafe fn copy_from_in(values: &[T], talc: NonNull<CacheTalcLock>) -> Option<Self>
    where
        T: Copy,
    {
        let arr = unsafe { Self::new_uninit_in(values.len(), talc)? };
        if !values.is_empty() {
            unsafe {
                core::ptr::copy_nonoverlapping(values.as_ptr(), arr.ptr.as_ptr(), values.len());
            }
        }
        Some(arr)
    }

    /// View the array as a slice.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    /// View the array as a mutable slice.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    /// Raw pointer to the first element. Stable across the lifetime
    /// of `self` (talc never relocates allocations).
    #[inline]
    pub fn as_ptr(&self) -> *mut T {
        self.ptr.as_ptr()
    }

    /// The cache VA the underlying slab lives at. Returns the dangling
    /// pointer for zero-length arrays — callers handle that case
    /// explicitly (no slab to point at).
    #[inline]
    pub fn va(&self) -> u64 {
        self.ptr.as_ptr() as u64
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl<T> Drop for TalcArray<T> {
    fn drop(&mut self) {
        if self.len == 0 {
            return;
        }
        // Drop every element in place.
        for i in 0..self.len {
            unsafe {
                core::ptr::drop_in_place(self.ptr.as_ptr().add(i));
            }
        }
        // Free the backing slab. If the layout is somehow invalid we
        // leak rather than risk UB.
        if let Ok(layout) = Layout::array::<T>(self.len) {
            unsafe {
                (*self.talc.as_ptr())
                    .lock()
                    .deallocate(self.ptr.as_ptr().cast::<u8>(), layout);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::talc_box::CacheTalcLock;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use talc::source::Manual;

    /// One-shot talc instance backed by a heap-allocated arena.
    /// Reused across the small-scale TalcArray tests.
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
        fn ptr(&self) -> NonNull<CacheTalcLock> {
            NonNull::from(&*self.talc)
        }
    }

    #[test]
    fn zero_length_is_no_op() {
        let arena = Arena::new(64 * 1024);
        let arr: TalcArray<u64> = unsafe { TalcArray::new_uninit_in(0, arena.ptr()) }.unwrap();
        assert_eq!(arr.len(), 0);
        assert!(arr.is_empty());
        assert_eq!(arr.as_slice().len(), 0);
        drop(arr); // must not panic / UB
    }

    #[test]
    fn copy_from_round_trips() {
        let arena = Arena::new(64 * 1024);
        let src: [u64; 4] = [11, 22, 33, 44];
        let arr = unsafe { TalcArray::copy_from_in(&src, arena.ptr()) }.unwrap();
        assert_eq!(arr.as_slice(), &src);
    }

    #[test]
    fn mut_slice_writes_through() {
        let arena = Arena::new(64 * 1024);
        let mut arr: TalcArray<u32> =
            unsafe { TalcArray::new_zeroed_in(8, arena.ptr()) }.unwrap();
        for (i, slot) in arr.as_mut_slice().iter_mut().enumerate() {
            *slot = i as u32 * 7;
        }
        assert_eq!(arr.as_slice(), &[0, 7, 14, 21, 28, 35, 42, 49]);
    }

    #[test]
    fn drop_runs_element_destructors() {
        struct Bumper<'a>(&'a AtomicUsize);
        impl Drop for Bumper<'_> {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }

        let counter = AtomicUsize::new(0);
        let arena = Arena::new(64 * 1024);
        let arr: TalcArray<Bumper> =
            unsafe { TalcArray::new_uninit_in(3, arena.ptr()) }.unwrap();
        for i in 0..3 {
            unsafe {
                arr.as_ptr().add(i).write(Bumper(&counter));
            }
        }
        drop(arr);
        assert_eq!(counter.load(Ordering::Relaxed), 3);
    }
}
