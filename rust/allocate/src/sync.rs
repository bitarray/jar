//! `Arc<T, A>` — atomically reference-counted handle backed by `A`.
//!
//! Non-intrusive: the refcount lives in a heap-allocated `ArcInner<T>`
//! header (8 bytes), not on the payload `T`. Mirrors std `Arc`'s
//! shape (`new_in`, `strong_count`, `get_mut`, `make_mut`, `as_ptr`,
//! `ptr_eq`, `allocator`, `Deref<Target = T>`, `Clone`, `Drop`). No
//! `Weak` — none of the workspace's current consumers want one.
//!
//! `allocator-api2` 0.2 does not ship an `Arc`, so we write our own
//! against the api2 `Allocator` trait.

use crate::{Allocator, Global};
use core::marker::PhantomData;
use core::ops::Deref;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering, fence};

struct ArcInner<T: ?Sized> {
    strong: AtomicUsize,
    data: T,
}

/// Atomically reference-counted handle to a `T` allocated by `A`.
pub struct Arc<T: ?Sized, A: Allocator + Clone = Global> {
    ptr: NonNull<ArcInner<T>>,
    alloc: A,
    _marker: PhantomData<ArcInner<T>>,
}

// Send/Sync mirror std `Arc<T, A>`: T must be Send+Sync because clones
// of the Arc can move T to other threads (via the Arc) and share it.
unsafe impl<T: ?Sized + Sync + Send, A: Allocator + Clone + Send> Send for Arc<T, A> {}
unsafe impl<T: ?Sized + Sync + Send, A: Allocator + Clone + Sync> Sync for Arc<T, A> {}

impl<T> Arc<T, Global> {
    /// Allocate space for a `T` from `Global` and move `value` in.
    #[inline]
    pub fn new(value: T) -> Self {
        Self::new_in(value, Global)
    }
}

impl<T, A: Allocator + Clone> Arc<T, A> {
    /// Allocate space for a `T` from `alloc` and move `value` in.
    pub fn new_in(value: T, alloc: A) -> Self {
        let layout = core::alloc::Layout::new::<ArcInner<T>>();
        let raw = alloc
            .allocate(layout)
            .unwrap_or_else(|_| handle_alloc_error(layout));
        let ptr = raw.cast::<ArcInner<T>>();
        // SAFETY: `ptr` is a fresh allocation sized for `ArcInner<T>`
        // and aligned to it.
        unsafe {
            core::ptr::write(
                ptr.as_ptr(),
                ArcInner {
                    strong: AtomicUsize::new(1),
                    data: value,
                },
            );
        }
        Self {
            ptr,
            alloc,
            _marker: PhantomData,
        }
    }
}

impl<T: ?Sized, A: Allocator + Clone> Arc<T, A> {
    #[inline]
    fn inner(&self) -> &ArcInner<T> {
        // SAFETY: `ptr` is always a valid initialised `ArcInner<T>`
        // for the Arc's lifetime (allocated in `new_in`, freed in
        // `Drop` when the last strong ref dies).
        unsafe { self.ptr.as_ref() }
    }

    /// Current strong-reference count.
    #[inline]
    pub fn strong_count(this: &Self) -> usize {
        this.inner().strong.load(Ordering::Acquire)
    }

    /// Mutable reference iff this is the unique strong owner.
    #[inline]
    pub fn get_mut(this: &mut Self) -> Option<&mut T> {
        if Self::strong_count(this) == 1 {
            // SAFETY: strong == 1 and we hold `&mut Self`, so no other
            // Arc<T, A> can be aliasing the inner data.
            Some(unsafe { &mut (*this.ptr.as_ptr()).data })
        } else {
            None
        }
    }

    /// Raw pointer to the inner `T`. The Arc remains the owner.
    #[inline]
    pub fn as_ptr(this: &Self) -> *const T {
        // SAFETY: inner is always live for the Arc's lifetime.
        unsafe { core::ptr::addr_of!((*this.ptr.as_ptr()).data) }
    }

    /// Pointer-equality test.
    #[inline]
    pub fn ptr_eq(this: &Self, other: &Self) -> bool {
        core::ptr::addr_eq(this.ptr.as_ptr(), other.ptr.as_ptr())
    }

    /// Borrow the underlying allocator.
    #[inline]
    pub fn allocator(this: &Self) -> &A {
        &this.alloc
    }
}

impl<T: Clone, A: Allocator + Clone> Arc<T, A> {
    /// Return `&mut T`. If this is the sole strong owner, mutate in
    /// place; otherwise deep-clone the `T` into a fresh `Arc` slab,
    /// replace `*this` with the fresh handle, and let the original
    /// `Arc` drop.
    ///
    /// Panics on allocation failure in the clone path.
    pub fn make_mut(this: &mut Self) -> &mut T {
        if Self::strong_count(this) != 1 {
            let cloned = this.inner().data.clone();
            *this = Self::new_in(cloned, this.alloc.clone());
        }
        // SAFETY: strong == 1 (either because it already was, or
        // because we just replaced `*this` with a fresh Arc whose
        // strong starts at 1) and we hold `&mut Self`.
        unsafe { &mut (*this.ptr.as_ptr()).data }
    }
}

impl<T: ?Sized, A: Allocator + Clone> Deref for Arc<T, A> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        &self.inner().data
    }
}

impl<T: ?Sized, A: Allocator + Clone> Clone for Arc<T, A> {
    fn clone(&self) -> Self {
        // Relaxed is fine: the Arc we're cloning already synchronises
        // with anyone who might observe the new strong count, and the
        // bumped count can't underflow because *this Arc keeps it ≥ 1.
        let old = self.inner().strong.fetch_add(1, Ordering::Relaxed);
        // Saturation guard: refcount overflow is a hard error. std Arc
        // aborts; we panic (no_std-friendly via core::panic).
        if old > isize::MAX as usize {
            arc_overflow();
        }
        Self {
            ptr: self.ptr,
            alloc: self.alloc.clone(),
            _marker: PhantomData,
        }
    }
}

impl<T: ?Sized, A: Allocator + Clone> Drop for Arc<T, A> {
    fn drop(&mut self) {
        // Release the strong ref. If we weren't last, nothing more to
        // do; another thread will run the destructor.
        if self.inner().strong.fetch_sub(1, Ordering::Release) != 1 {
            return;
        }
        // Synchronise with all previous Releases so we observe the
        // final state of the payload before dropping it.
        fence(Ordering::Acquire);

        let layout = core::alloc::Layout::for_value(self.inner());
        // SAFETY: we are the last strong reference; the payload is
        // valid and uniquely owned by us, so dropping it in place is
        // sound. The allocation came from `self.alloc` (via `new_in`)
        // with this exact layout.
        unsafe {
            core::ptr::drop_in_place(&raw mut (*self.ptr.as_ptr()).data);
            self.alloc.deallocate(self.ptr.cast::<u8>(), layout);
        }
    }
}

impl<T: ?Sized + core::fmt::Debug, A: Allocator + Clone> core::fmt::Debug for Arc<T, A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(&self.inner().data, f)
    }
}

#[cold]
#[inline(never)]
fn handle_alloc_error(_layout: core::alloc::Layout) -> ! {
    // Mirror std behaviour: allocation failure inside Arc::new_in is
    // unrecoverable. Callers who care about fallibility should use
    // try_*_in on Box / Vec directly; Arc has no try-form in std and
    // we follow suit.
    panic!("Arc: allocation failed");
}

#[cold]
#[inline(never)]
fn arc_overflow() -> ! {
    panic!("Arc: strong refcount overflowed isize::MAX");
}
