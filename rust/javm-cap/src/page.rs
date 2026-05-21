//! `PageSlot<A>` and `PageRef<A>` — DataCap page storage.
//!
//! Each page is owned by the DataCap that holds it. Sharing across
//! DataCap CoW clones is done via [`PageRef`], a refcounted handle
//! over [`PageBytes`] backed by the caller-supplied allocator. The
//! cache subsystem doesn't index pages by hash — pages aren't
//! first-class caps. They're internal to the DataCap layer.

use allocator_api2::alloc::{Allocator, Global};
use allocator_api2::vec::Vec;
use core::sync::atomic::AtomicU32;

use nub_host_common::cache::{Aarc, AarcRefCounted};

use super::cap::CapHash;

/// Sparse representation of a paged DataCap's pages. `Empty` is the
/// canonical zero page; `Loaded` holds a refcounted byte slab;
/// `Missing` records the page's content hash so a host callback can
/// later resolve it (V1: never observed — we always pre-publish).
#[derive(Clone, Debug)]
pub enum PageSlot<A: Allocator + Clone = Global> {
    Empty,
    Loaded(PageRef<A>),
    Missing(CapHash),
}

/// Hand-rolled `Arc<PageBytes>` backed by an arbitrary allocator.
/// Aliases the generic `Aarc` from `nub-host-common` for cap-layer
/// readability.
pub type PageRef<A> = Aarc<PageBytes<A>, A>;

/// One page's bytes plus metadata. The `refcount` is what the
/// `Aarc` machinery uses to manage sharing.
#[derive(Debug)]
pub struct PageBytes<A: Allocator + Clone = Global> {
    pub refcount: AtomicU32,
    pub hash: CapHash,
    pub bytes: Vec<u8, A>,
}

impl<A: Allocator + Clone> AarcRefCounted for PageBytes<A> {
    fn refcount(&self) -> &AtomicU32 {
        &self.refcount
    }
}
