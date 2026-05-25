//! `CacheEntry` — refcounted wrapper around a [`Cap`] for storage
//! in `CacheDirectory::{blobs, instances}`.
//!
//! The refcount tracks how many slots in other caps reference this
//! entry. Decrement at mutation time follows the `Arc::make_mut`
//! protocol: if `prev == 1` we have sole ownership and can
//! move-promote, otherwise we shallow-clone into a fresh instance
//! entry.

use core::sync::atomic::AtomicU32;

use super::cap::Cap;

pub struct CacheEntry {
    pub refcount: AtomicU32,
    pub cap: Cap,
}

impl CacheEntry {
    /// Construct a fresh entry with refcount initialised to 1.
    pub fn new(cap: Cap) -> Self {
        Self {
            refcount: AtomicU32::new(1),
            cap,
        }
    }
}
