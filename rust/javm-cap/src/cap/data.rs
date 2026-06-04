//! `DataCap` — backing (immutable dense page slab) + copy-on-write overlay.
//!
//! A `DataCap` is `{ backing: Arc<PageSlab>, overlay }`:
//!
//! - [`PageSlab`] is the **immutable backing**: a *dense* runtime-sized vector
//!   of pages (index `i` is absolute page `i`), `Arc`-shared so `MGMT_COPY` is
//!   one refcount bump. It is **not** a sparse `RadixMap` of 2 MiB groups and
//!   **not** raw bytes — it is a custom SSZ page-vector whose `hash_tree_root`
//!   merkleizes the page roots at the **exact runtime depth** `ceil_log2(page_count)`
//!   (`page_count = size / PAGE_SIZE`). `ssz::List<T, N>` / `Vector` fix `N` at
//!   compile time; a cap's `page_count` is a runtime value, so `PageSlab` is a
//!   bespoke type reusing [`ssz::merkle::merkleize`] with `limit = page_count`.
//! - `overlay` is the **copy-on-write working layer**: the pages this cap has
//!   modified since the backing settled, keyed by absolute page index. A page
//!   present in the overlay *shadows* the backing; a clean cap has an empty
//!   overlay and is identical to its backing. During execution the engines
//!   write dirty pages straight into the overlay (no separate dirty-page list);
//!   at settle [`DataCap::flush`] folds the overlay into a fresh `PageSlab`.
//!
//! Earlier drafts split this across a separate `DataCap` (immutable, sparse
//! groups) and `DataViewCap` (backing-by-hash + overlay). They are now **one
//! type**: `DataViewCap == DataCap`.
//!
//! ## The cap root (flat, size-scaled) — defined only on a *flushed* cap
//!
//! `hash_tree_root` is the SSZ 2-field container `{ size, pages }`:
//!
//! ```text
//! cap_root   = merkleize([ htr(size), pages_root ], 2)            // depth-1 container
//! pages_root = merkleize([ page(0)..page(page_count) ], page_count) // = PageSlab::hash_tree_root
//! page_count = size / PAGE_SIZE
//! ```
//!
//! The cap root is **only defined when the `overlay` is empty** — the backing is
//! the hashable, content-addressed form; the overlay is transient working state.
//! Hashing a cap with a non-empty overlay is a usage error (it panics, like
//! hashing a cap graph that still holds an unresolved `Ref`): callers
//! [`flush`](DataCap::flush) first. The engines' read path
//! ([`page_slot`](DataCap::page_slot) / [`page_at`](DataCap::page_at)) and the
//! zero-copy slot return read *effective* bytes without hashing.
//!
//! The pages-root tracks the cap's *actual* size (depth `ceil_log2(page_count)`),
//! not a fixed compile-time capacity: ≤ 256 pages (≤ 1 MiB) is shallower than
//! depth 9; a 4 GiB cap is depth 20. `size` is committed in the cap's own root
//! (the first container field) because SSZ merkleization is not self-describing.
//!
//! ## Page-alignment invariant
//!
//! Each present page is a [`PageSlot::Loaded`] holding a refcounted
//! [`PageBytes`] whose `bytes` is a **`PAGE_SIZE`-aligned** 4 KiB slab
//! ([`alloc_page_aligned_zeroed`]) — load-bearing because the x86 recompiler
//! resolves each page's physical address from its slab pointer and maps it
//! directly into a ring-3 page table. This holds for backing *and* overlay pages.

use core::alloc::Layout;

use alloc::alloc::alloc_zeroed;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use ssz::HashTreeRoot;
use ssz::digest::Digest;
use ssz::digest::typenum::U32;
use ssz::merkle::merkleize;

use super::CapHash;
use super::page::{PageBytes, PageSlot};

/// Cap-level page size. Mirrors the architecture's 4 KiB page (must match
/// `nub_arch_x86::paging::PAGE_SIZE` for direct PT mapping to work).
pub const PAGE_SIZE: usize = 4096;

/// Pages per 2 MiB group (`512 = 2^9`). Kept as the natural large-page /
/// 2 MiB-cluster unit (architecture-portable large page; the read-only gas
/// materialization unit), even though storage is no longer group-chunked.
pub const GROUP_PAGES: usize = 512;

/// 2 MiB span in bytes (`512 * 4096 = 1 << 21`).
pub const GROUP_SIZE: usize = GROUP_PAGES * PAGE_SIZE;

/// The dense immutable backing of a [`DataCap`]: a custom runtime-sized SSZ
/// vector of pages.
///
/// `pages[i]` is absolute page `i`; trailing [`PageSlot::Empty`] pages may be
/// omitted (so `pages.len() <= page_count`), and an out-of-range index reads as
/// `Empty` (zero) — the merkle pads them back via the zero-hash table. The
/// `hash_tree_root` is `merkleize(page_roots, page_count)` at runtime depth.
#[derive(Clone, Debug, Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct PageSlab {
    /// Logical byte length; always a [`PAGE_SIZE`] multiple. `page_count =
    /// size / PAGE_SIZE`.
    pub size: u64,
    /// Dense page storage indexed by absolute page (trailing `Empty` trimmed).
    pub pages: Vec<PageSlot>,
}

impl PageSlab {
    /// An empty slab (size 0, no pages).
    pub fn empty() -> Self {
        PageSlab {
            size: 0,
            pages: Vec::new(),
        }
    }

    /// Number of logical pages (`size / PAGE_SIZE`).
    #[inline]
    pub fn page_count(&self) -> usize {
        (self.size / PAGE_SIZE as u64) as usize
    }

    /// Borrow page `i` (absolute). Out-of-range / trimmed-tail reads as
    /// [`PageSlot::Empty`].
    #[inline]
    pub fn page(&self, i: usize) -> &PageSlot {
        self.pages.get(i).unwrap_or(&PageSlot::Empty)
    }

    /// Fold up to [`PAGE_SIZE`] `content` bytes into absolute page index `p`,
    /// **canonically**: all-zero content stores the [`PageSlot::Empty`] sentinel
    /// (no allocation), any other content a fresh `PAGE_SIZE`-aligned
    /// [`PageSlot::Loaded`] slab. Grows the dense vector as needed, then trims
    /// trailing `Empty` so the layout is unique.
    fn put_page_idx(&mut self, p: usize, content: &[u8]) {
        if self.pages.len() <= p {
            self.pages.resize(p + 1, PageSlot::Empty);
        }
        self.pages[p] = if content.iter().all(|&b| b == 0) {
            PageSlot::Empty
        } else {
            PageSlot::Loaded(Arc::new(PageBytes::from_content(content)))
        };
        while matches!(self.pages.last(), Some(PageSlot::Empty)) {
            self.pages.pop();
        }
    }

    /// Build a slab from contiguous `content`, logical size at least
    /// `target_size` (rounded up to a page boundary, minimum one page). All-zero
    /// pages become [`PageSlot::Empty`] (sparse).
    fn from_bytes_sized(content: &[u8], target_size: u64) -> Self {
        let size = target_size
            .max(content.len() as u64)
            .next_multiple_of(PAGE_SIZE as u64)
            .max(PAGE_SIZE as u64);
        let total_pages = (size / PAGE_SIZE as u64) as usize;
        let mut pages: Vec<PageSlot> = Vec::new();
        let mut last_nonempty: Option<usize> = None;
        for p in 0..total_pages {
            let off = p * PAGE_SIZE;
            let lo = off.min(content.len());
            let hi = (off + PAGE_SIZE).min(content.len());
            let slice = &content[lo..hi];
            if slice.iter().all(|&b| b == 0) {
                pages.push(PageSlot::Empty);
            } else {
                pages.push(PageSlot::Loaded(Arc::new(PageBytes::from_content(slice))));
                last_nonempty = Some(p);
            }
        }
        match last_nonempty {
            Some(last) => pages.truncate(last + 1),
            None => pages.clear(),
        }
        PageSlab { size, pages }
    }
}

impl HashTreeRoot for PageSlab {
    /// The `pages` field root: the flat size-scaled page merkle at exact depth
    /// `ceil_log2(page_count)`. Empty/absent pages contribute `[0;32]`, folded
    /// by the merkle zero-hash table.
    fn hash_tree_root<D: Digest<OutputSize = U32>>(&self) -> [u8; 32] {
        let page_count = self.page_count();
        let leaves: Vec<[u8; 32]> = (0..page_count)
            .map(|i| self.page(i).hash_tree_root::<D>())
            .collect();
        merkleize::<D>(&leaves, page_count.max(1))
    }
}

/// Data cap: an `Arc`-shared immutable [`PageSlab`] backing plus a copy-on-write
/// overlay of modified pages. The cap identity (when flushed) is the flat
/// size-scaled `{ size, pages }` merkle (see the module docs).
#[derive(Clone, Debug, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct DataCap {
    /// Immutable backing, shared across a `MGMT_COPY` lineage by `Arc`.
    pub backing: Arc<PageSlab>,
    /// Copy-on-write modified pages (absolute page index → page). Empty for a
    /// clean / settled cap. A present entry shadows the backing; zero-writes are
    /// stored explicitly (a present [`PageSlot::Loaded`]) so they shadow a
    /// possibly-nonzero backing page.
    pub overlay: BTreeMap<u32, PageSlot>,
}

impl HashTreeRoot for DataCap {
    fn hash_tree_root<D: Digest<OutputSize = U32>>(&self) -> [u8; 32] {
        // The cap root is defined only on a flushed (overlay-empty) cap; the
        // backing is the content-addressed form. Hashing an overlay-bearing cap
        // is a usage error (mirrors hashing a graph with an unresolved Ref):
        // callers `flush()` first.
        assert!(
            self.overlay.is_empty(),
            "DataCap::hash_tree_root: cap has a non-empty CoW overlay; flush() before hashing"
        );
        debug_assert!(
            self.backing.size.is_multiple_of(PAGE_SIZE as u64),
            "DataCap::hash_tree_root: size must be a PAGE_SIZE multiple"
        );
        // 2-field SSZ container `{ size, pages }`.
        let size_root = self.backing.size.hash_tree_root::<D>();
        let pages_root = self.backing.hash_tree_root::<D>();
        merkleize::<D>(&[size_root, pages_root], 2)
    }
}

/// Resolution of a single page within a [`DataCap`], shared by both engines so
/// they materialize byte-identically.
#[derive(Clone, Copy, Debug)]
pub enum PageResolution<'a> {
    /// Canonical zero page (absent / `Empty`): reads as zero; a write
    /// copies-on-write a fresh page.
    Zero,
    /// A materialized, `PAGE_SIZE`-aligned page slab.
    Bytes(&'a [u8]),
    /// An elided page known only by its content hash: a faulting access is a
    /// PVM page fault. V1 never mints this.
    Missing(CapHash),
}

impl DataCap {
    /// An empty `DataCap`: logical size 0, no pages, no overlay.
    pub fn empty() -> Self {
        DataCap {
            backing: Arc::new(PageSlab::empty()),
            overlay: BTreeMap::new(),
        }
    }

    /// Total logical content size in bytes (always a [`PAGE_SIZE`] multiple).
    pub fn content_len(&self) -> u64 {
        self.backing.size
    }

    /// Number of logical pages.
    #[inline]
    pub fn page_count(&self) -> usize {
        self.backing.page_count()
    }

    /// Is page `i` overlaid (CoW'd)? A page is dirty iff it is present in the
    /// overlay (`Empty` slots / absent entries are clean — defer to the backing).
    #[inline]
    pub fn is_dirty(&self, i: usize) -> bool {
        matches!(
            self.overlay.get(&(i as u32)),
            Some(PageSlot::Loaded(_) | PageSlot::Missing(_))
        )
    }

    /// Borrow the **effective** page slot at absolute page index `i`: the
    /// overlay page if dirty, else the backing page. Both engines resolve a
    /// page's physical address from the returned [`PageSlot::Loaded`] slab.
    #[inline]
    pub fn page_slot(&self, i: usize) -> &PageSlot {
        match self.overlay.get(&(i as u32)) {
            Some(slot @ (PageSlot::Loaded(_) | PageSlot::Missing(_))) => slot,
            _ => self.backing.page(i),
        }
    }

    /// Resolve the **effective** page containing byte offset `off` (need not be
    /// page-aligned). Both engines call this so their materialized page contents
    /// are identical.
    pub fn page_at(&self, off: u64) -> PageResolution<'_> {
        let i = (off / PAGE_SIZE as u64) as usize;
        match self.page_slot(i) {
            PageSlot::Loaded(pr) => PageResolution::Bytes(&pr.bytes),
            PageSlot::Missing(h) => PageResolution::Missing(*h),
            PageSlot::Empty => PageResolution::Zero,
        }
    }

    /// Copy `out.len()` logical bytes starting at byte offset `start` into
    /// `out` (effective content), fully defining every byte: materialized pages
    /// are copied; `Zero` pages read as zero.
    ///
    /// # Panics
    ///
    /// Panics on a [`PageResolution::Missing`] page — elided content known only
    /// by hash is **not** zero, and the recompiler hard-faults on it; silently
    /// zero-filling would fork consensus. V1 never mints `Missing`.
    pub fn copy_into(&self, start: u64, out: &mut [u8]) {
        let mut done = 0usize;
        while done < out.len() {
            let off = start + done as u64;
            let page_off = (off % PAGE_SIZE as u64) as usize;
            let take = (PAGE_SIZE - page_off).min(out.len() - done);
            match self.page_at(off) {
                PageResolution::Bytes(bytes) => {
                    let avail = bytes.len().saturating_sub(page_off);
                    let n = avail.min(take);
                    out[done..done + n].copy_from_slice(&bytes[page_off..page_off + n]);
                    out[done + n..done + take].fill(0);
                }
                PageResolution::Zero => {
                    out[done..done + take].fill(0);
                }
                PageResolution::Missing(h) => {
                    panic!(
                        "DataCap::copy_into: Missing page at offset {off} (hash \
                         {:02x?}..) — host reads of elided pages are unsupported \
                         (would fork vs the engine's page fault)",
                        &h[..4],
                    );
                }
            }
            done += take;
        }
    }

    /// Overwrite the **backing** page containing absolute offset `off` with up
    /// to [`PAGE_SIZE`] content bytes (zero-padded tail), canonically. This is
    /// the **construction / settle** primitive (it mutates the backing via
    /// `Arc::make_mut`, so it is O(slab) on a shared backing — only use it while
    /// building a fresh cap). Copy-on-write *during execution* goes through
    /// [`write_page`](Self::write_page) (the overlay) instead.
    ///
    /// Panics (debug) if `off >= self.content_len()`.
    pub fn put_page(&mut self, off: u64, content: &[u8]) {
        debug_assert!(
            off < self.content_len(),
            "DataCap::put_page: offset past logical size"
        );
        let p = (off / PAGE_SIZE as u64) as usize;
        Arc::make_mut(&mut self.backing).put_page_idx(p, content);
    }

    /// Copy-on-write the **overlay** page containing absolute offset `off` with
    /// up to [`PAGE_SIZE`] `content` bytes (zero-padded tail). The page is stored
    /// **explicitly** as a present `Loaded` slab — even all-zero content — so it
    /// shadows the backing. This is the execution write boundary.
    ///
    /// Panics (debug) if `off >= self.content_len()`.
    pub fn write_page(&mut self, off: u64, content: &[u8]) {
        debug_assert!(
            off < self.content_len(),
            "DataCap::write_page: offset past logical size"
        );
        let p = (off / PAGE_SIZE as u64) as u32;
        self.overlay.insert(
            p,
            PageSlot::Loaded(Arc::new(PageBytes::from_content(content))),
        );
    }

    /// Insert an already-built overlay page slot at absolute page index `p`
    /// (move, no copy). The slab is page-aligned by construction; used by the
    /// engines' CoW path to hand a freshly-written page to the cap directly.
    pub fn insert_overlay_page(&mut self, p: u32, slot: PageSlot) {
        self.overlay.insert(p, slot);
    }

    /// Place every effective page of `src` into this cap's **backing** starting
    /// at absolute byte offset `dst_off` (page-aligned): backing page
    /// `dst_off/PAGE_SIZE + i` becomes a clone of `src.page_slot(i)` — an `Arc`
    /// refcount bump, **not** a byte copy. Pages beyond this cap's extent are
    /// dropped (clamped, mirroring the interpreter's `off < extent` fold guard).
    ///
    /// This is the **page-sharing** instance-memory composer: a fresh Instance
    /// `mem` built by placing an Image's mapped `Cap::Data` sources shares those
    /// sources' physical pages, so N sub-VMs spawned from one Image all map the
    /// same read-only frames and each CoWs (into its overlay) only the pages it
    /// writes — the shared backing is never mutated. Effective bytes are
    /// identical to the copying `put_page` fold; only the allocation is shared.
    pub fn place_shared(&mut self, dst_off: u64, src: &DataCap) {
        debug_assert!(
            dst_off.is_multiple_of(PAGE_SIZE as u64),
            "place_shared: dst_off must be page-aligned"
        );
        let base = (dst_off / PAGE_SIZE as u64) as usize;
        let total_pages = self.backing.page_count();
        let slab = Arc::make_mut(&mut self.backing);
        for i in 0..src.page_count() {
            let dst = base + i;
            if dst >= total_pages {
                break; // clamp to this cap's logical extent
            }
            if slab.pages.len() <= dst {
                slab.pages.resize(dst + 1, PageSlot::Empty);
            }
            slab.pages[dst] = src.page_slot(i).clone();
        }
        // Re-canonicalize: trim trailing `Empty` so the layout stays unique.
        while matches!(slab.pages.last(), Some(PageSlot::Empty)) {
            slab.pages.pop();
        }
    }

    /// Fold the overlay into a fresh, clean (overlay-empty) `DataCap` whose
    /// `hash_tree_root` is defined. Clones the backing and folds every overlaid
    /// page in via the canonical backing CoW. This is the settle / content-
    /// address primitive (it replaces the old `DataViewCap::settle`).
    pub fn flush(&self) -> DataCap {
        if self.overlay.is_empty() {
            return self.clone();
        }
        let mut backing = (*self.backing).clone();
        for (&p, slot) in &self.overlay {
            match slot {
                PageSlot::Loaded(pr) => backing.put_page_idx(p as usize, &pr.bytes),
                PageSlot::Empty => {}
                PageSlot::Missing(_) => {
                    unreachable!("DataCap::flush: Missing overlay page (cold-load unsupported)")
                }
            }
        }
        DataCap {
            backing: Arc::new(backing),
            overlay: BTreeMap::new(),
        }
    }

    /// Build a `DataCap` from contiguous `content`, sized to the next page
    /// boundary (at least one page). All-zero pages become [`PageSlot::Empty`].
    pub fn from_bytes(content: &[u8]) -> Self {
        Self::from_bytes_sized(content, content.len() as u64)
    }

    /// Build a `DataCap` from `content` with a logical size of at least
    /// `target_size` (rounded up to a page boundary, minimum one page).
    /// `content` fills the low bytes; the remainder is zero (sparse). The cap is
    /// clean (empty overlay).
    pub fn from_bytes_sized(content: &[u8], target_size: u64) -> Self {
        DataCap {
            backing: Arc::new(PageSlab::from_bytes_sized(content, target_size)),
            overlay: BTreeMap::new(),
        }
    }
}

/// Allocate a zero-filled `Vec<u8>` of `len` bytes (rounded up to the next page
/// boundary) with `PAGE_SIZE`-aligned backing storage. Page alignment is what
/// lets the kernel map the buffer directly into a ring-3 PT.
///
/// Panics if the allocator returns null (OOM) or the `Layout` overflows.
pub fn alloc_page_aligned_zeroed(len: usize) -> Vec<u8> {
    let padded = len.next_multiple_of(PAGE_SIZE).max(PAGE_SIZE);
    let layout =
        Layout::from_size_align(padded, PAGE_SIZE).expect("DataCap page-aligned layout overflow");
    // SAFETY: `padded > 0` so the `Layout` is non-zero; the std global
    // allocator is what `Vec` uses, so the buffer is `Vec::from_raw_parts`-safe.
    let ptr = unsafe { alloc_zeroed(layout) };
    if ptr.is_null() {
        alloc::alloc::handle_alloc_error(layout);
    }
    // SAFETY: non-null pointer to `padded` zeroed bytes, PAGE_SIZE-aligned;
    // capacity == len == padded, all bytes initialised (to zero).
    unsafe { Vec::from_raw_parts(ptr, padded, padded) }
}

/// Content hash of a single page: the SSZ `hash_tree_root` of the page as a
/// `ByteVector[PAGE_SIZE]` (zero-padded), under the cap digest (SHA-256). This
/// is the value a materialized page contributes to the cap merkle and the
/// precomputed [`PageBytes::hash`] kept by the substitution invariant.
pub fn page_content_hash(bytes: &[u8]) -> CapHash {
    let mut arr = [0u8; PAGE_SIZE];
    let n = bytes.len().min(PAGE_SIZE);
    arr[..n].copy_from_slice(&bytes[..n]);
    ssz::hash_tree_root(&arr)
}
