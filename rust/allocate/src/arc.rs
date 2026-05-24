//! `Arc<T, A>` — newtype wrapper around `alloc::sync::Arc<T, A>`.
//!
//! Refcount lives in the std `ArcInner` header (8 bytes strong + 8
//! bytes weak), not on the payload `T`. That replaces our
//! hand-rolled `Aarc<T, A>` pattern that required `T:
//! AarcRefCounted`.

use crate::{Allocator, Global};
use core::ops::Deref;

/// Atomically reference-counted handle to a `T` allocated by `A`.
///
/// Stable-name newtype wrapper around `alloc::sync::Arc<T, A>`. The
/// inner std `Arc<T, A>` requires nightly to name; this wrapper hides
/// that so downstream stays on stable Rust.
pub struct Arc<T: ?Sized, A: Allocator + Clone = Global> {
    inner: alloc::sync::Arc<T, A>,
}

/// Weak reference to an [`Arc`]. Re-wrapped from `alloc::sync::Weak`.
pub struct Weak<T: ?Sized, A: Allocator + Clone = Global> {
    inner: alloc::sync::Weak<T, A>,
}

impl<T> Arc<T, Global> {
    /// Allocate space for a `T` from `Global` and move `value` in.
    #[inline]
    pub fn new(value: T) -> Self {
        Self {
            inner: alloc::sync::Arc::new(value),
        }
    }
}

impl<T, A: Allocator + Clone> Arc<T, A> {
    /// Allocate space for a `T` from `alloc` and move `value` in.
    #[inline]
    pub fn new_in(value: T, alloc: A) -> Self {
        Self {
            inner: alloc::sync::Arc::new_in(value, alloc),
        }
    }
}

impl<T: ?Sized, A: Allocator + Clone> Arc<T, A> {
    /// Current strong-reference count.
    #[inline]
    pub fn strong_count(this: &Self) -> usize {
        alloc::sync::Arc::strong_count(&this.inner)
    }

    /// Current weak-reference count (excluding the implicit "strong"
    /// edge).
    #[inline]
    pub fn weak_count(this: &Self) -> usize {
        alloc::sync::Arc::weak_count(&this.inner)
    }

    /// Mutable reference iff this is the unique strong owner and no
    /// weak references exist.
    #[inline]
    pub fn get_mut(this: &mut Self) -> Option<&mut T> {
        alloc::sync::Arc::get_mut(&mut this.inner)
    }

    /// Raw pointer to the inner `T`. The Arc remains the owner.
    #[inline]
    pub fn as_ptr(this: &Self) -> *const T {
        alloc::sync::Arc::as_ptr(&this.inner)
    }

    /// Borrow the underlying allocator.
    #[inline]
    pub fn allocator(this: &Self) -> &A {
        alloc::sync::Arc::allocator(&this.inner)
    }

    /// Make a weak reference.
    #[inline]
    pub fn downgrade(this: &Self) -> Weak<T, A> {
        Weak {
            inner: alloc::sync::Arc::downgrade(&this.inner),
        }
    }

    /// Pointer-equality test.
    #[inline]
    pub fn ptr_eq(this: &Self, other: &Self) -> bool {
        alloc::sync::Arc::ptr_eq(&this.inner, &other.inner)
    }
}

impl<T: Clone, A: Allocator + Clone> Arc<T, A> {
    /// Return `&mut T`. If this is the sole strong owner with no
    /// weak refs, mutate in place; otherwise deep-clone the `T` into
    /// a fresh `Arc` slab, replace `*this` with the fresh handle, and
    /// let the original `Arc` drop.
    ///
    /// Panics on allocation failure in the clone path.
    #[inline]
    pub fn make_mut(this: &mut Self) -> &mut T {
        alloc::sync::Arc::make_mut(&mut this.inner)
    }
}

impl<T: ?Sized, A: Allocator + Clone> Deref for Arc<T, A> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T: ?Sized, A: Allocator + Clone> Clone for Arc<T, A> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T: ?Sized + core::fmt::Debug, A: Allocator + Clone> core::fmt::Debug for Arc<T, A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(&self.inner, f)
    }
}

impl<T: ?Sized, A: Allocator + Clone> Weak<T, A> {
    #[inline]
    pub fn upgrade(&self) -> Option<Arc<T, A>> {
        self.inner.upgrade().map(|inner| Arc { inner })
    }
}

impl<T: ?Sized, A: Allocator + Clone> Clone for Weak<T, A> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}
