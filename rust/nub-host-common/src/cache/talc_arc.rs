//! `Aarc<T, A>`: a hand-rolled `Arc<T>` parameterised over an
//! `allocator_api2::alloc::Allocator`.
//!
//! `T` must implement [`AarcRefCounted`] to expose an `AtomicU32`
//! refcount field at a known location. Drop atomically decrements;
//! the last drop runs `T`'s destructor and frees the slab through
//! the captured allocator.
//!
//! Why not stock `alloc::sync::Arc`? Two reasons:
//!
//! 1. Stock `Arc` allocates from the global Rust allocator. The
//!    state-cache region uses its own `CacheTalcLock` instance;
//!    putting an `Arc<T>` whose header is in the global heap but
//!    payload is in talc memory (or vice versa) would deadlock the
//!    cache layout.
//! 2. `allocator_api2` ships `Vec<T, A>` and `Box<T, A>` on stable
//!    but not `Arc<T, A>` — that's a much harder primitive
//!    (refcounted ArcInner layout, weak refs, etc.). For our DataCap
//!    page sharing we need exactly one specific shape: refcount +
//!    content, alloc-backed, no weaks.
//!
//! `Aarc<T, A>` is the minimum we need: one `NonNull<T>` + an
//! allocator handle + a refcount living inside `T` + Drop that
//! returns the slab through the allocator. Used by
//! `javm-cap::cap::PageRef<A>` to share DataCap page bytes between
//! CoW clones.

use allocator_api2::alloc::{AllocError, Allocator, Layout};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, Ordering, fence};

use super::talc_alloc::TalcAlloc;

/// Trait implemented by types that carry their own `AtomicU32`
/// refcount field. Required to live inside [`Aarc`].
pub trait AarcRefCounted {
    fn refcount(&self) -> &AtomicU32;
}

/// Shared, reference-counted handle to a `T` allocated through an
/// `allocator_api2::Allocator`. Cheap to clone (one atomic
/// increment); Drop atomically decrements and frees on the last
/// reference.
pub struct Aarc<T: AarcRefCounted, A: Allocator + Clone> {
    ptr: NonNull<T>,
    alloc: A,
}

// SAFETY: the layout of T + A is plain data; thread-safety follows
// from T's refcount being atomic and A being Send/Sync per impl.
unsafe impl<T: AarcRefCounted + Send + Sync, A: Allocator + Clone + Send> Send for Aarc<T, A> {}
unsafe impl<T: AarcRefCounted + Send + Sync, A: Allocator + Clone + Sync> Sync for Aarc<T, A> {}

impl<T: AarcRefCounted + core::fmt::Debug, A: Allocator + Clone> core::fmt::Debug for Aarc<T, A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Aarc").field(self.get()).finish()
    }
}

impl<T: AarcRefCounted, A: Allocator + Clone> Aarc<T, A> {
    /// Allocate space for a `T` through `alloc`, move `value` in,
    /// and return a handle.
    ///
    /// **The caller must construct `value` with `refcount` already
    /// initialised to `1`.** `Aarc::new_in` doesn't touch the
    /// refcount field, so we honour whatever the caller wrote.
    pub fn new_in(value: T, alloc: A) -> Result<Self, AllocError> {
        debug_assert_eq!(
            value.refcount().load(Ordering::Relaxed),
            1,
            "Aarc::new_in expects value.refcount() == 1",
        );
        let layout = Layout::new::<T>();
        let raw = alloc.allocate(layout)?;
        let ptr = raw.cast::<T>();
        unsafe {
            ptr.as_ptr().write(value);
        }
        Ok(Self { ptr, alloc })
    }

    /// Current refcount. Mostly useful in tests and `make_mut`-style
    /// branches.
    #[inline]
    pub fn refcount(&self) -> u32 {
        unsafe { (*self.ptr.as_ptr()).refcount().load(Ordering::Acquire) }
    }

    /// Shared reference to the inner `T`.
    #[inline]
    pub fn get(&self) -> &T {
        unsafe { &*self.ptr.as_ptr() }
    }

    /// Mutable reference to the inner `T`. Caller is responsible
    /// for confirming exclusive access (e.g. by checking
    /// `self.refcount() == 1`).
    ///
    /// # Safety
    ///
    /// The caller must guarantee no other `Aarc` references the
    /// same `T` for the duration of the returned reference's
    /// lifetime.
    pub unsafe fn as_mut_unchecked(&mut self) -> &mut T {
        unsafe { &mut *self.ptr.as_ptr() }
    }

    /// Raw pointer to the underlying `T`. Useful for embedding the
    /// VA in the cache directory.
    #[inline]
    pub fn as_ptr(&self) -> *mut T {
        self.ptr.as_ptr()
    }
}

impl<T: AarcRefCounted + Clone, A: Allocator + Clone> Aarc<T, A> {
    /// Return `&mut T`. If we're the sole owner (refcount == 1) the
    /// caller mutates in place. Otherwise we deep-clone `T` into a
    /// fresh `Aarc` slab, replace `*this` with that fresh handle, and
    /// let the original Aarc drop (refcount on the original entry
    /// decrements by 1; other holders keep observing the original).
    ///
    /// Returns `Err(AllocError)` if the clone path can't allocate;
    /// the original `*this` is left untouched in that case.
    ///
    /// Single-threaded model: relaxed load is sufficient because no
    /// other thread is concurrently bumping the refcount.
    pub fn make_mut(this: &mut Self) -> Result<&mut T, AllocError> {
        if this.get().refcount().load(Ordering::Relaxed) == 1 {
            // SAFETY: sole owner; no aliasing.
            return Ok(unsafe { this.as_mut_unchecked() });
        }
        let cloned: T = this.get().clone();
        cloned.refcount().store(1, Ordering::Relaxed);
        let new_aarc = Aarc::new_in(cloned, this.alloc.clone())?;
        let _old = core::mem::replace(this, new_aarc);
        // SAFETY: `this` now references the fresh sole-owner slab.
        Ok(unsafe { this.as_mut_unchecked() })
    }
}

impl<T: AarcRefCounted, A: Allocator + Clone> Clone for Aarc<T, A> {
    fn clone(&self) -> Self {
        unsafe {
            (*self.ptr.as_ptr())
                .refcount()
                .fetch_add(1, Ordering::Relaxed);
        }
        Self {
            ptr: self.ptr,
            alloc: self.alloc.clone(),
        }
    }
}

impl<T: AarcRefCounted, A: Allocator + Clone> Drop for Aarc<T, A> {
    fn drop(&mut self) {
        let prev = unsafe {
            (*self.ptr.as_ptr())
                .refcount()
                .fetch_sub(1, Ordering::Release)
        };
        if prev != 1 {
            return;
        }
        fence(Ordering::Acquire);
        unsafe {
            core::ptr::drop_in_place(self.ptr.as_ptr());
            self.alloc.deallocate(
                NonNull::new_unchecked(self.ptr.as_ptr().cast::<u8>()),
                Layout::new::<T>(),
            );
        }
    }
}

/// Alias for the talc-backed variant — the common case in the
/// shared-memory state cache.
pub type TalcArc<T> = Aarc<T, TalcAlloc>;

/// Alias retained from the earlier hand-rolled API; downstream may
/// still import this name.
pub trait TalcRefCounted: AarcRefCounted {}
impl<T: AarcRefCounted> TalcRefCounted for T {}
