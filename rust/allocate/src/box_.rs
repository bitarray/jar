//! `Box<T, A>` — newtype wrapper around `alloc::boxed::Box<T, A>`.

use crate::{Allocator, Global};
use core::ops::{Deref, DerefMut};

/// Owning, single-pointer handle to a `T` allocated by `A`.
///
/// Stable-name newtype wrapper around `alloc::boxed::Box<T, A>`. The
/// inner std `Box<T, A>` requires nightly to name; this wrapper hides
/// that so downstream stays on stable Rust.
pub struct Box<T: ?Sized, A: Allocator = Global> {
    inner: alloc::boxed::Box<T, A>,
}

impl<T> Box<T, Global> {
    /// Allocate space for a `T` from `Global` and move `value` in.
    #[inline]
    pub fn new(value: T) -> Self {
        Self {
            inner: alloc::boxed::Box::new(value),
        }
    }
}

impl<T, A: Allocator> Box<T, A> {
    /// Allocate space for a `T` from `alloc` and move `value` in.
    #[inline]
    pub fn new_in(value: T, alloc: A) -> Self {
        Self {
            inner: alloc::boxed::Box::new_in(value, alloc),
        }
    }

    /// Fallible `new_in`.
    #[inline]
    pub fn try_new_in(value: T, alloc: A) -> Result<Self, crate::AllocError> {
        alloc::boxed::Box::try_new_in(value, alloc).map(|inner| Self { inner })
    }
}

impl<T: ?Sized, A: Allocator> Box<T, A> {
    /// Consume `self` and return the raw pointer + allocator.
    ///
    /// The caller becomes responsible for freeing the allocation via
    /// [`Box::from_raw_in`].
    #[inline]
    pub fn into_raw_with_allocator(b: Self) -> (*mut T, A) {
        alloc::boxed::Box::into_raw_with_allocator(b.inner)
    }

    /// Re-wrap a raw pointer previously obtained from
    /// [`Box::into_raw_with_allocator`].
    ///
    /// # Safety
    ///
    /// `ptr` must have come from a `Box<T, A>` with the same `alloc`,
    /// and must not have been freed.
    #[inline]
    pub unsafe fn from_raw_in(ptr: *mut T, alloc: A) -> Self {
        Self {
            inner: unsafe { alloc::boxed::Box::from_raw_in(ptr, alloc) },
        }
    }

    /// Consume `self` and return the raw pointer (without recovering
    /// the allocator). The allocator's lifetime is left to the caller.
    #[inline]
    pub fn into_raw(b: Self) -> *mut T {
        let (ptr, _alloc) = alloc::boxed::Box::into_raw_with_allocator(b.inner);
        ptr
    }

    /// Borrow the underlying allocator.
    #[inline]
    pub fn allocator(b: &Self) -> &A {
        alloc::boxed::Box::allocator(&b.inner)
    }
}

impl<T: ?Sized, A: Allocator> Deref for Box<T, A> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T: ?Sized, A: Allocator> DerefMut for Box<T, A> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: ?Sized, A: Allocator + Default> Default for Box<T, A>
where
    alloc::boxed::Box<T, A>: Default,
{
    fn default() -> Self {
        Self {
            inner: alloc::boxed::Box::default(),
        }
    }
}

impl<T: ?Sized + core::fmt::Debug, A: Allocator> core::fmt::Debug for Box<T, A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(&self.inner, f)
    }
}
