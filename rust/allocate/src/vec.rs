//! `Vec<T, A>` — newtype wrapper around `alloc::vec::Vec<T, A>`.

use crate::{Allocator, Global};
use core::ops::{Deref, DerefMut, Index, IndexMut};
use core::slice::SliceIndex;

/// Heap-allocated growable array of `T`, allocated by `A`.
///
/// Stable-name newtype wrapper around `alloc::vec::Vec<T, A>`. The
/// inner std `Vec<T, A>` requires nightly to name; this wrapper hides
/// that so downstream stays on stable Rust.
///
/// Implements [`Deref<Target = [T]>`][core::ops::Deref] / `DerefMut`,
/// so slice methods (`.iter()`, `.get()`, `.first()`, `.last()`,
/// `.split_at()`, `.as_ptr()`, …) work transparently.
pub struct Vec<T, A: Allocator = Global> {
    inner: alloc::vec::Vec<T, A>,
}

impl<T> Vec<T, Global> {
    /// Empty vector that allocates from `Global` on first push.
    #[inline]
    pub const fn new() -> Self {
        Self {
            inner: alloc::vec::Vec::new(),
        }
    }
}

impl<T, A: Allocator> Vec<T, A> {
    /// Empty vector that allocates from `alloc` on first push.
    #[inline]
    pub const fn new_in(alloc: A) -> Self {
        Self {
            inner: alloc::vec::Vec::new_in(alloc),
        }
    }

    /// Empty vector with capacity for at least `cap` items, allocated
    /// from `alloc` up front.
    #[inline]
    pub fn with_capacity_in(cap: usize, alloc: A) -> Self {
        Self {
            inner: alloc::vec::Vec::with_capacity_in(cap, alloc),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    #[inline]
    pub fn push(&mut self, value: T) {
        self.inner.push(value);
    }

    #[inline]
    pub fn pop(&mut self) -> Option<T> {
        self.inner.pop()
    }

    #[inline]
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    #[inline]
    pub fn truncate(&mut self, len: usize) {
        self.inner.truncate(len);
    }

    #[inline]
    pub fn reserve(&mut self, additional: usize) {
        self.inner.reserve(additional);
    }

    #[inline]
    pub fn swap_remove(&mut self, index: usize) -> T {
        self.inner.swap_remove(index)
    }

    #[inline]
    pub fn extend_from_slice(&mut self, other: &[T])
    where
        T: Clone,
    {
        self.inner.extend_from_slice(other);
    }

    /// Borrow the underlying allocator.
    #[inline]
    pub fn allocator(&self) -> &A {
        self.inner.allocator()
    }

    /// Resize the vector by repeating `value`.
    #[inline]
    pub fn resize(&mut self, new_len: usize, value: T)
    where
        T: Clone,
    {
        self.inner.resize(new_len, value);
    }

    /// Borrow the vec's bytes as a slice.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        self.inner.as_slice()
    }

    /// Mutably borrow the vec's bytes as a slice.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        self.inner.as_mut_slice()
    }
}

impl<T, A: Allocator> Deref for Vec<T, A> {
    type Target = [T];
    #[inline]
    fn deref(&self) -> &[T] {
        self.inner.as_slice()
    }
}

impl<T, A: Allocator> DerefMut for Vec<T, A> {
    #[inline]
    fn deref_mut(&mut self) -> &mut [T] {
        self.inner.as_mut_slice()
    }
}

impl<T, I: SliceIndex<[T]>, A: Allocator> Index<I> for Vec<T, A> {
    type Output = I::Output;
    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        Index::index(&**self, index)
    }
}

impl<T, I: SliceIndex<[T]>, A: Allocator> IndexMut<I> for Vec<T, A> {
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        IndexMut::index_mut(&mut **self, index)
    }
}

impl<T: Clone, A: Allocator + Clone> Clone for Vec<T, A> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T: core::fmt::Debug, A: Allocator> core::fmt::Debug for Vec<T, A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self.as_slice(), f)
    }
}

impl<T, A: Allocator + Default> Default for Vec<T, A> {
    fn default() -> Self {
        Self::new_in(A::default())
    }
}

impl<T, A: Allocator> Extend<T> for Vec<T, A> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        self.inner.extend(iter);
    }
}

impl<'a, T: 'a + Copy, A: Allocator> Extend<&'a T> for Vec<T, A> {
    fn extend<I: IntoIterator<Item = &'a T>>(&mut self, iter: I) {
        self.inner.extend(iter);
    }
}

impl<'a, T, A: Allocator> IntoIterator for &'a Vec<T, A> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter()
    }
}

impl<'a, T, A: Allocator> IntoIterator for &'a mut Vec<T, A> {
    type Item = &'a mut T;
    type IntoIter = core::slice::IterMut<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter_mut()
    }
}

impl<T, A: Allocator> IntoIterator for Vec<T, A> {
    type Item = T;
    type IntoIter = alloc::vec::IntoIter<T, A>;
    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<T: PartialEq, A: Allocator, A2: Allocator> PartialEq<Vec<T, A2>> for Vec<T, A> {
    fn eq(&self, other: &Vec<T, A2>) -> bool {
        **self == **other
    }
}

impl<T: PartialEq, A: Allocator> PartialEq<[T]> for Vec<T, A> {
    fn eq(&self, other: &[T]) -> bool {
        **self == *other
    }
}

impl<T: Eq, A: Allocator> Eq for Vec<T, A> {}
