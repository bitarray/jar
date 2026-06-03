//! `DataViewCap` — a copy-on-write overlay over an immutable Backing DataCap.
//!
//! A View covers its Backing **1:1** (there is no offset / window / `set_offset`
//! — programs roam large state by mapping/unmapping bounded dense DataCaps, not
//! by sliding a window). `overlay` holds the CoW'd pages in the same dense
//! group storage a [`DataCap`] uses ([`super::data::DataGroup`] /
//! `RadixMap<DataGroup, 4>`), so the recompiler maps overlay pages by the same
//! per-slab physical address it uses for backing pages.
//!
//! ## Mutability split (in-flight identity vs settled content)
//!
//! A View is the **mutable** working form of a data object; a [`DataCap`] is the
//! **immutable** settled form. This mirrors `InstanceCap` (a mutable identity
//! that settles to a content blob):
//!
//! - [`DataViewCap::hash_tree_root`] is a cheap **provenance** root —
//!   `merkleize([htr(size), backing_root, overlay_root], 3)` — O(overlay), the
//!   identity of "this backing, shadowed by exactly these CoW'd pages". It is
//!   *not* equal to the effective content's flat merkle (the View only holds the
//!   backing by hash, so it cannot recompute the backing's per-page roots).
//! - [`DataViewCap::settle`] folds the overlay into a fresh immutable
//!   [`DataCap`] whose `hash_tree_root` *is* the effective size-scaled flat
//!   merkle — the canonical content commitment that enters consensus state.
//!
//! ## Why the overlay stores zero-writes explicitly (binding)
//!
//! Unlike [`DataCap`], the overlay does **not** canonically trim a page written
//! to all-zeros down to [`PageSlot::Empty`]. A zero-write must *shadow* a
//! possibly-nonzero backing page, so it is stored as a present
//! [`PageSlot::Loaded`] (a zero page hashes to `zero_hash(7)`, distinct from an
//! absent page's `[0; 32]`). This keeps the provenance root **binding**: two
//! Views over the same backing with different effective content always differ at
//! `overlay_root` — same root ⟹ same dirty-page set and contents ⟹ same
//! effective content. A page is "dirty" iff it is present (`Loaded`/`Missing`)
//! in the overlay; no separate, desync-prone dirty set is kept.

use alloc::sync::Arc;
use alloc::vec::Vec;

use ssz::digest::Digest;
use ssz::digest::typenum::U32;
use ssz::merkle::merkleize;
use ssz::{HashTreeRoot, MissingOr, RadixMap};

use super::data::{
    DataCap, DataGroup, GROUP_KEY_BYTES, GROUP_PAGES, GROUP_SIZE, PAGE_SIZE, PageResolution,
};
use super::page::{PageBytes, PageSlot};
use crate::cache::CapHashOrRef;

/// Sparse CoW overlay storage: the same dense 2 MiB group map a [`DataCap`] uses.
pub type ViewOverlay = RadixMap<DataGroup, GROUP_KEY_BYTES>;

/// A 1:1 copy-on-write overlay over an immutable Backing [`DataCap`].
#[derive(Clone, Debug, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct DataViewCap {
    /// The immutable backing. `Hash` once settled; `Ref` while a kernel-derived
    /// backing is in flight (settled before hashing, like
    /// `InstanceCap::root_cnode`).
    pub backing: CapHashOrRef,
    /// Logical byte length; copied from the backing at construction and never
    /// changes (the View covers the backing 1:1). Always a [`PAGE_SIZE`]
    /// multiple. Committed in the provenance root.
    pub size: u64,
    /// CoW'd pages, stored exactly like `DataCap::groups`. A page present here
    /// shadows the backing; zero-writes are stored explicitly (see module docs).
    pub overlay: ViewOverlay,
}

impl DataViewCap {
    /// A fresh, clean View over `backing` (no overlaid pages). `size` is the
    /// backing's logical size.
    pub fn new(backing: CapHashOrRef, size: u64) -> Self {
        Self {
            backing,
            size,
            overlay: ViewOverlay::new(),
        }
    }

    /// Borrow the overlay page slot at **absolute page index** `i`; an absent /
    /// out-of-range page reads as [`PageSlot::Empty`] (clean — defers to the
    /// backing). Mirrors [`DataCap::page_slot`] against the overlay storage.
    #[inline]
    pub fn overlay_page_slot(&self, i: usize) -> &PageSlot {
        let g = (i / GROUP_PAGES) as u32;
        let p = i % GROUP_PAGES;
        match self.overlay.get(&DataCap::group_key(g)) {
            Some(MissingOr::Materialized(group)) => group.page(p),
            _ => &PageSlot::Empty,
        }
    }

    /// Is page `i` overlaid (CoW'd)? A page is dirty iff it is present in the
    /// overlay — `Empty` slots / absent groups are clean (defer to the backing).
    #[inline]
    pub fn is_dirty(&self, i: usize) -> bool {
        matches!(
            self.overlay_page_slot(i),
            PageSlot::Loaded(_) | PageSlot::Missing(_)
        )
    }

    /// Resolve the page at absolute index `i`: the overlay page if dirty, else
    /// the `backing`'s page. Both engines call this so their materialized
    /// contents are byte-identical.
    pub fn effective_page_at<'a>(&'a self, i: usize, backing: &'a DataCap) -> PageResolution<'a> {
        if self.is_dirty(i) {
            match self.overlay_page_slot(i) {
                PageSlot::Loaded(pr) => PageResolution::Bytes(&pr.bytes),
                PageSlot::Missing(h) => PageResolution::Missing(*h),
                // Unreachable given `is_dirty`, but resolve safely.
                PageSlot::Empty => PageResolution::Zero,
            }
        } else {
            backing.page_at((i as u64) * PAGE_SIZE as u64)
        }
    }

    /// Copy-on-write the page containing absolute offset `off` with up to
    /// [`PAGE_SIZE`] `content` bytes (zero-padded tail). The page is stored
    /// **explicitly** as a present `Loaded` slab — even all-zero content — so it
    /// shadows the backing and keeps the provenance root binding (see module
    /// docs). This is the frame-exit fold primitive and the interp write
    /// boundary.
    ///
    /// Panics (debug) if `off >= self.size`.
    pub fn write_page(&mut self, off: u64, content: &[u8]) {
        debug_assert!(off < self.size, "DataViewCap::write_page: offset past size");
        let g = (off / GROUP_SIZE as u64) as u32;
        let p = ((off / PAGE_SIZE as u64) % GROUP_PAGES as u64) as usize;
        let key = DataCap::group_key(g);
        let mut pages = match self.overlay.get(&key) {
            Some(MissingOr::Materialized(grp)) => grp.pages.clone(),
            Some(MissingOr::Missing(_)) => {
                unreachable!("DataViewCap overlay never Missing a group")
            }
            None => Vec::new(),
        };
        if pages.len() <= p {
            pages.resize(p + 1, PageSlot::Empty);
        }
        // Store unconditionally (no zero-trim): a zero-write must shadow the
        // backing, so the page stays present.
        pages[p] = PageSlot::Loaded(Arc::new(PageBytes::from_content(content)));
        self.overlay
            .insert(key, MissingOr::Materialized(DataGroup { pages }));
    }

    /// Settle the View into a fresh immutable [`DataCap`]: clone the backing and
    /// fold every overlaid page in via the canonical [`DataCap::put_page`] CoW
    /// fold. The result's `hash_tree_root` is the effective size-scaled flat
    /// merkle — the content commitment a copy / post-instance settle publishes.
    pub fn settle(&self, backing: &DataCap) -> DataCap {
        debug_assert_eq!(
            backing.content_len(),
            self.size,
            "DataViewCap::settle: backing size mismatch"
        );
        let mut out = backing.clone();
        let page_count = (self.size / PAGE_SIZE as u64) as usize;
        for i in 0..page_count {
            match self.overlay_page_slot(i) {
                PageSlot::Loaded(pr) => out.put_page(i as u64 * PAGE_SIZE as u64, &pr.bytes),
                // A `Missing` overlay page would need cold-load to settle; V1
                // never mints one.
                PageSlot::Missing(_) => {
                    unreachable!(
                        "DataViewCap::settle: Missing overlay page (cold-load unsupported)"
                    )
                }
                PageSlot::Empty => {}
            }
        }
        out
    }
}

impl HashTreeRoot for DataViewCap {
    fn hash_tree_root<D: Digest<OutputSize = U32>>(&self) -> [u8; 32] {
        debug_assert!(
            self.size.is_multiple_of(PAGE_SIZE as u64),
            "DataViewCap::hash_tree_root: size must be a PAGE_SIZE multiple"
        );
        // Provenance root: { size, backing-hash, overlay-radix-root }. O(overlay)
        // — the View holds the backing by hash, so it commits the backing's hash
        // rather than recomputing its per-page roots. Sits under the `Cap` union
        // selector (5), which domain-separates an empty overlay's `[0; 32]`
        // radix root from a raw zero summary.
        let size_root = self.size.hash_tree_root::<D>();
        let backing_root = self.backing.hash_tree_root::<D>();
        let overlay_root = self.overlay.hash_tree_root::<D>();
        merkleize::<D>(&[size_root, backing_root, overlay_root], 3)
    }
}
