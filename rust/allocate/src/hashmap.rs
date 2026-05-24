//! `HashMap<K, V, A>` — newtype wrapper around
//! `hashbrown::HashMap<K, V, S, A>` (with hashbrown's `nightly`
//! feature enabled so it uses `core::alloc::Allocator` directly).

use crate::{Allocator, Global};
use core::borrow::Borrow;
use core::hash::{BuildHasher, Hash};

/// Default hasher (hashbrown's [`foldhash`]).
pub type DefaultHashBuilder = hashbrown::DefaultHashBuilder;

/// SwissTable hash map.
///
/// Stable-name newtype wrapper around
/// `hashbrown::HashMap<K, V, S, A>` (built with hashbrown's
/// `nightly` feature, so its `A` is `core::alloc::Allocator`).
pub struct HashMap<K, V, A: Allocator = Global, S = DefaultHashBuilder> {
    inner: hashbrown::HashMap<K, V, S, A>,
}

impl<K, V> HashMap<K, V, Global, DefaultHashBuilder> {
    /// Empty heap-backed map.
    #[inline]
    pub fn new() -> Self {
        Self {
            inner: hashbrown::HashMap::new(),
        }
    }

    /// Empty heap-backed map with capacity for at least `cap` items.
    #[inline]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            inner: hashbrown::HashMap::with_capacity(cap),
        }
    }
}

impl<K, V, A: Allocator> HashMap<K, V, A, DefaultHashBuilder> {
    /// Empty map that allocates from `alloc`.
    #[inline]
    pub fn new_in(alloc: A) -> Self {
        Self {
            inner: hashbrown::HashMap::new_in(alloc),
        }
    }

    /// Empty map with capacity for at least `cap` items, allocated
    /// from `alloc` up front.
    #[inline]
    pub fn with_capacity_in(cap: usize, alloc: A) -> Self {
        Self {
            inner: hashbrown::HashMap::with_capacity_in(cap, alloc),
        }
    }
}

impl<K, V, A: Allocator, S> HashMap<K, V, A, S> {
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
    pub fn iter(&self) -> hashbrown::hash_map::Iter<'_, K, V> {
        self.inner.iter()
    }

    #[inline]
    pub fn iter_mut(&mut self) -> hashbrown::hash_map::IterMut<'_, K, V> {
        self.inner.iter_mut()
    }

    #[inline]
    pub fn allocator(&self) -> &A {
        self.inner.allocator()
    }
}

impl<K, V, A, S> HashMap<K, V, A, S>
where
    K: Eq + Hash,
    A: Allocator,
    S: BuildHasher,
{
    #[inline]
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.inner.insert(key, value)
    }

    #[inline]
    pub fn get<Q>(&self, k: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        self.inner.get(k)
    }

    #[inline]
    pub fn get_mut<Q>(&mut self, k: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        self.inner.get_mut(k)
    }

    #[inline]
    pub fn contains_key<Q>(&self, k: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        self.inner.contains_key(k)
    }

    #[inline]
    pub fn remove<Q>(&mut self, k: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        self.inner.remove(k)
    }
}

impl<K, V> Default for HashMap<K, V, Global, DefaultHashBuilder> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: core::fmt::Debug, V: core::fmt::Debug, A: Allocator, S> core::fmt::Debug
    for HashMap<K, V, A, S>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(&self.inner, f)
    }
}
