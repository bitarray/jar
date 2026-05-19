//! Hand-rolled `Box`/`[u8]` analogues that allocate from a
//! [`CacheTalcLock`] instance living at a fixed location.
//!
//! Why hand-rolled and not `Box<T, A: Allocator>`? With `allocator-api2`
//! the `Allocator` reference (`&TalcLock`) needs a lifetime, and the
//! TalcLock itself lives at offset 0 of the cache region — which is
//! owned by the same struct that holds the boxes. That's a
//! self-referencing struct, painful to express in safe Rust. Carrying
//! a raw `NonNull<TalcLock>` sidesteps the lifetime virus; the
//! correctness obligation is that the cache region (and therefore
//! the TalcLock at its offset 0) outlives every box pointing at it.
//! That's enforced by Drop ordering inside the host's `Cache` struct.

use alloc::alloc::Layout;
use core::marker::PhantomData;
use core::ptr::NonNull;

use spinning_top::RawSpinlock;
use talc::source::Manual;

/// Concrete TalcLock flavor we use for the state cache.
pub type CacheTalcLock = talc::TalcLock<RawSpinlock, Manual>;

/// A value of type `T` allocated inside the cache region. Drop runs
/// `T`'s destructor and frees the slab against the underlying talc.
pub struct TalcBox<T: ?Sized> {
    ptr: NonNull<T>,
    talc: NonNull<CacheTalcLock>,
    layout: Layout,
    _marker: PhantomData<T>,
}

// Send/Sync are not auto-derived through NonNull. The host side is
// single-threaded today; if multi-threading lands later we'd revisit.
unsafe impl<T: ?Sized + Send> Send for TalcBox<T> {}
unsafe impl<T: ?Sized + Sync> Sync for TalcBox<T> {}

impl<T> TalcBox<T> {
    /// Allocate space for a `T` from `talc` and move `value` into it.
    ///
    /// # Safety
    ///
    /// `talc` must point at a live, properly-claimed `CacheTalcLock`
    /// that outlives the returned box.
    pub unsafe fn new_in(value: T, talc: NonNull<CacheTalcLock>) -> Option<Self> {
        let layout = Layout::new::<T>();
        let raw = unsafe { (*talc.as_ptr()).lock().allocate(layout)? };
        let ptr = raw.cast::<T>();
        unsafe {
            ptr.as_ptr().write(value);
        }
        Some(Self {
            ptr,
            talc,
            layout,
            _marker: PhantomData,
        })
    }

    /// Pointer to the value in cache memory.
    #[inline]
    pub fn as_ptr(&self) -> *mut T {
        self.ptr.as_ptr()
    }

    /// The cache VA the underlying slab lives at — what the host
    /// writes into [`IndexSlot`](super::IndexSlot) for the guest.
    #[inline]
    pub fn va(&self) -> u64 {
        self.ptr.as_ptr() as u64
    }
}

impl<T: ?Sized> Drop for TalcBox<T> {
    fn drop(&mut self) {
        unsafe {
            core::ptr::drop_in_place(self.ptr.as_ptr());
            (*self.talc.as_ptr())
                .lock()
                .deallocate(self.ptr.as_ptr().cast::<u8>(), self.layout);
        }
    }
}

/// A `[u8]` slab allocated inside the cache region. Specialised
/// because the common case (code, ro, rw bytes) doesn't need to
/// drop_in_place — just free the bytes.
pub struct TalcSlice {
    ptr: NonNull<u8>,
    len: usize,
    talc: NonNull<CacheTalcLock>,
}

unsafe impl Send for TalcSlice {}
unsafe impl Sync for TalcSlice {}

impl TalcSlice {
    /// Allocate `bytes.len()` bytes from `talc` and copy `bytes` in.
    ///
    /// # Safety
    ///
    /// `talc` must point at a live, properly-claimed `CacheTalcLock`
    /// that outlives the returned slice.
    pub unsafe fn copy_from(bytes: &[u8], talc: NonNull<CacheTalcLock>) -> Option<Self> {
        let mut slice = unsafe { Self::zeroed(bytes.len(), talc)? };
        slice.as_mut_slice().copy_from_slice(bytes);
        Some(slice)
    }

    /// Allocate `len` zero-initialised bytes from `talc`. Returns
    /// `None` if the allocation fails.
    ///
    /// # Safety
    ///
    /// `talc` must point at a live, properly-claimed `CacheTalcLock`
    /// that outlives the returned slice.
    pub unsafe fn zeroed(len: usize, talc: NonNull<CacheTalcLock>) -> Option<Self> {
        // Zero-sized: return a 1-byte allocation so as_ptr is valid;
        // talc requires non-zero alloc. Common case `len == 0` would
        // produce a slice with `len == 0` and a benign 1-byte tail.
        // To avoid the special case in callers, allocate len.max(1).
        let alloc_len = len.max(1);
        let layout = Layout::from_size_align(alloc_len, 1).ok()?;
        let raw = unsafe { (*talc.as_ptr()).lock().allocate(layout)? };
        let ptr = raw.cast::<u8>();
        unsafe {
            core::ptr::write_bytes(ptr.as_ptr(), 0, alloc_len);
        }
        Some(Self { ptr, len, talc })
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

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

impl Drop for TalcSlice {
    fn drop(&mut self) {
        // Allocation was sized to `len.max(1)`; mirror it on free.
        let alloc_len = self.len.max(1);
        // unwrap: alloc_len >= 1 with align 1; cannot overflow.
        let layout = Layout::from_size_align(alloc_len, 1).expect("talc-slice layout");
        unsafe {
            (*self.talc.as_ptr())
                .lock()
                .deallocate(self.ptr.as_ptr(), layout);
        }
    }
}
