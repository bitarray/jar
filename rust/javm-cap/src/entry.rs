//! `CacheEntry<A>` — refcounted wrapper around a [`Cap`] for
//! storage in `Cache::{blobs, instances}`.
//!
//! The refcount tracks how many slots in other caps reference this
//! entry. Decrement at mutation time follows the `Arc::make_mut`
//! protocol (see plan): if `prev == 1` we have sole ownership and
//! can move-promote, otherwise we shallow-clone into a fresh
//! instance entry.

use allocator_api2::alloc::{Allocator, Global};
use core::sync::atomic::AtomicU32;

use nub_talc_util::AarcRefCounted;

use super::cap::Cap;

pub struct CacheEntry<A: Allocator + Clone = Global> {
    pub refcount: AtomicU32,
    pub cap: Cap<A>,
}

impl<A: Allocator + Clone> CacheEntry<A> {
    /// Construct a fresh entry with refcount initialised to 1.
    pub fn new(cap: Cap<A>) -> Self {
        Self {
            refcount: AtomicU32::new(1),
            cap,
        }
    }
}

impl<A: Allocator + Clone> AarcRefCounted for CacheEntry<A> {
    fn refcount(&self) -> &AtomicU32 {
        &self.refcount
    }
}
