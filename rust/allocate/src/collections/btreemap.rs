//! `BTreeMap<K, V, A>` — newtype wrapper around
//! `alloc::collections::BTreeMap<K, V, A>`.

use crate::{Allocator, Global};
use core::borrow::Borrow;

/// Ordered map backed by a B-tree.
///
/// Stable-name newtype wrapper around
/// `alloc::collections::BTreeMap<K, V, A>`. The 3-parameter form is
/// nightly-only, so the wrapper hides it from downstream callers.
pub struct BTreeMap<K, V, A: Allocator + Clone = Global> {
    inner: alloc::collections::BTreeMap<K, V, A>,
}

impl<K, V> BTreeMap<K, V, Global> {
    /// Empty heap-backed map.
    pub fn new() -> Self {
        Self {
            inner: alloc::collections::BTreeMap::new_in(Global),
        }
    }
}

impl<K, V, A: Allocator + Clone> BTreeMap<K, V, A> {
    /// Empty map that allocates from `alloc`.
    pub fn new_in(alloc: A) -> Self {
        Self {
            inner: alloc::collections::BTreeMap::new_in(alloc),
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
    pub fn iter(&self) -> alloc::collections::btree_map::Iter<'_, K, V> {
        self.inner.iter()
    }

    #[inline]
    pub fn iter_mut(&mut self) -> alloc::collections::btree_map::IterMut<'_, K, V> {
        self.inner.iter_mut()
    }
}

impl<K: Ord, V, A: Allocator + Clone> BTreeMap<K, V, A> {
    #[inline]
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.inner.insert(key, value)
    }

    #[inline]
    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: ?Sized + Ord,
    {
        self.inner.get(key)
    }

    #[inline]
    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: ?Sized + Ord,
    {
        self.inner.get_mut(key)
    }

    #[inline]
    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: ?Sized + Ord,
    {
        self.inner.contains_key(key)
    }

    #[inline]
    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: ?Sized + Ord,
    {
        self.inner.remove(key)
    }
}

impl<K, V> Default for BTreeMap<K, V, Global> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: core::fmt::Debug, V: core::fmt::Debug, A: Allocator + Clone> core::fmt::Debug
    for BTreeMap<K, V, A>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(&self.inner, f)
    }
}
