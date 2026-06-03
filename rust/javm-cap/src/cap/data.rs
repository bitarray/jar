//! `DataCap` — Data cap: a **dense** content-addressed page vector with a
//! **size-scaled flat merkle** root.
//!
//! A `DataCap` is `{ size, groups }`. `size` is the logical byte length
//! (always a [`PAGE_SIZE`] multiple); `groups` is the in-memory storage: a
//! sparse map of 2 MiB groups ([`DataGroup`] = up to 512 × 4 KiB pages),
//! keyed by big-endian `u32` group index. **The group map is a pure storage /
//! copy-on-write index — NOT a merkle node.**
//!
//! ## The cap root (flat, size-scaled)
//!
//! `hash_tree_root` is the SSZ 2-field container `{ size, pages-root }`:
//!
//! ```text
//! cap_root  = merkleize([ htr(size), pages_root ], 2)            // depth 1 container
//! pages_root = merkleize([ page_slot(0)..page_slot(page_count) ], page_count)
//! page_count = size / PAGE_SIZE
//! ```
//!
//! The pages-root merkleizes the **flat** vector of all page roots (absolute
//! page index `0..page_count`) with a **runtime limit = `page_count`**, so the
//! tree depth is `ceil_log2(page_count)` — it tracks the cap's *actual* size,
//! not a fixed compile-time capacity. A cap ≤ 256 pages (≤ 1 MiB) is shallower
//! than depth 9; 257–512 pages are depth 9 (the natural minimal height); a
//! 4 GiB cap is depth 20. There is **no explicit `Group` merkle level** — yet a
//! 2 MiB-aligned 512-page span is still a clean depth-9 *subtree* of the flat
//! tree (for `page_count > 512`, `next_pow2(page_count)` is a multiple of 512),
//! so per-2 MiB materialization, group-granular CoW, and group-subtree proofs
//! still align with the storage chunking.
//!
//! `size` is committed in the cap's **own** root (the first container field):
//! SSZ merkleization is not self-describing, so `page_count` cannot be
//! recovered from the pages-root alone and must not be deferred to a parent.
//! This makes the minimum cap depth 1 and distinguishes two caps with the same
//! present pages but different logical `size`.
//!
//! The cap is **dense**: every index `0..page_count` is a leaf. Absent / zero
//! pages are [`PageSlot::Empty`] (root `[0; 32]`, no allocation), folded by the
//! merkle zero-hash table — there is no sparse non-membership proof and the cap
//! is *charged* at its full declared `size`.
//!
//! ## Page-alignment invariant
//!
//! Each present page is a [`PageSlot::Loaded`] holding a refcounted
//! [`PageBytes`] whose `bytes` is a **`PAGE_SIZE`-aligned** 4 KiB slab
//! ([`alloc_page_aligned_zeroed`]) — load-bearing because the x86 recompiler
//! resolves each page's physical address from its slab pointer and maps it
//! directly into a ring-3 page table.

use core::alloc::Layout;

use alloc::alloc::alloc_zeroed;
use alloc::sync::Arc;
use alloc::vec::Vec;

use ssz::digest::Digest;
use ssz::digest::typenum::U32;
use ssz::merkle::merkleize;
use ssz::{HashTreeRoot, MissingOr, RadixMap};

use super::CapHash;
use super::page::{PageBytes, PageSlot};

/// Cap-level page size. Mirrors the architecture's 4 KiB page (must match
/// `nub_arch_x86::paging::PAGE_SIZE` for direct PT mapping to work).
pub const PAGE_SIZE: usize = 4096;

/// Pages per 2 MiB group (`512 = 2^9`).
pub const GROUP_PAGES: usize = 512;

/// 2 MiB group size in bytes (`512 * 4096 = 1 << 21`).
pub const GROUP_SIZE: usize = GROUP_PAGES * PAGE_SIZE;

/// Width of a storage group key: a big-endian `u32` group index.
pub const GROUP_KEY_BYTES: usize = 4;

/// In-memory storage index: a sparse map of 2 MiB groups keyed by big-endian
/// `u32` group index. This is **not** a merkle node — the cap root is the flat
/// size-scaled page merkle ([`DataCap::hash_tree_root`]); the map only provides
/// O(group-depth) page lookup and group-granular copy-on-write.
pub type DataGroups = RadixMap<DataGroup, GROUP_KEY_BYTES>;

/// One 2 MiB group: up to [`GROUP_PAGES`] pages, densely indexed by
/// page-within-group (holes are [`PageSlot::Empty`]). Trailing `Empty` pages
/// may be omitted (the cap merkle pads them back to zero), so the stored
/// `pages` length is `≤ GROUP_PAGES`. The group is the copy-on-write unit: a
/// `put_page` clones one group's `pages`, never the whole cap.
#[derive(Clone, Debug, Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct DataGroup {
    pub pages: Vec<PageSlot>,
}

impl DataGroup {
    /// Borrow page `p` (`0..GROUP_PAGES`); absent / out-of-range reads as
    /// [`PageSlot::Empty`].
    #[inline]
    pub fn page(&self, p: usize) -> &PageSlot {
        self.pages.get(p).unwrap_or(&PageSlot::Empty)
    }

    /// Depth-9 merkle root of this group's 512 page roots
    /// (`FixedVector<Page, 512>` semantics). This equals the corresponding
    /// 2 MiB-aligned subtree of the cap's flat merkle (for full, 512-page
    /// groups), so it is the per-group subtree root used by group-granular
    /// proofs and the (future) present-group fold of [`DataCap::hash_tree_root`].
    pub fn subtree_root<D: Digest<OutputSize = U32>>(&self) -> [u8; 32] {
        let roots: Vec<[u8; 32]> = self.pages.iter().map(|p| p.hash_tree_root::<D>()).collect();
        merkleize::<D>(&roots, GROUP_PAGES)
    }
}

/// A `DataGroup`'s value root is its depth-9 page subtree (see
/// [`DataGroup::subtree_root`]). This is **not** used by [`DataCap`]'s own merkle
/// (which is the flat size-scaled page tree over `page_slot`), only by a
/// `RadixMap<DataGroup, _>` root — e.g. the `DataViewCap` overlay's
/// `overlay_root`, where the group key + this subtree root bind the overlaid
/// page set.
impl HashTreeRoot for DataGroup {
    fn hash_tree_root<D: Digest<OutputSize = U32>>(&self) -> [u8; 32] {
        self.subtree_root::<D>()
    }
}

/// Data cap: a logical byte `size` plus the sparse group storage. The cap
/// identity is the flat size-scaled page merkle (see the module docs).
#[derive(Clone, Debug, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct DataCap {
    /// Logical byte length; always a [`PAGE_SIZE`] multiple.
    pub size: u64,
    /// Sparse 2 MiB group storage keyed by big-endian `u32` group index.
    pub groups: DataGroups,
}

impl HashTreeRoot for DataCap {
    fn hash_tree_root<D: Digest<OutputSize = U32>>(&self) -> [u8; 32] {
        debug_assert!(
            self.size.is_multiple_of(PAGE_SIZE as u64),
            "DataCap::hash_tree_root: size must be a PAGE_SIZE multiple"
        );
        let page_count = (self.size / PAGE_SIZE as u64) as usize;
        // Field 1 — the flat page merkle. Limit = page_count (NOT
        // leaves.len()), so depth = ceil_log2(page_count) and tracks the cap's
        // actual size. Empty/absent pages contribute [0;32], folded by the
        // merkle zero-hash table.
        //
        // TODO(perf): this materializes a length-`page_count` leaves vector,
        // which is O(page_count) even for a sparse-but-huge cap. Replace with a
        // present-group depth-9 subtree fold (O(present_pages + groups + depth))
        // and assert byte-equality against this oracle in tests.
        let leaves: Vec<[u8; 32]> = (0..page_count)
            .map(|i| self.page_slot(i).hash_tree_root::<D>())
            .collect();
        let pages_root = merkleize::<D>(&leaves, page_count.max(1));
        // Field 0 — `size` (a basic `u64`: 8 LE bytes in a 32-byte chunk).
        let size_root = self.size.hash_tree_root::<D>();
        // 2-field SSZ container `{ size, pages }` (depth-1 over the field roots).
        merkleize::<D>(&[size_root, pages_root], 2)
    }
}

/// Resolution of a single page within a [`DataCap`], shared by both engines so
/// they materialize byte-identically.
#[derive(Clone, Copy, Debug)]
pub enum PageResolution<'a> {
    /// Canonical zero page (absent group, `Empty` slot, or past a group's
    /// stored tail): reads as zero; a write copies-on-write a fresh page.
    Zero,
    /// A materialized, `PAGE_SIZE`-aligned page slab.
    Bytes(&'a [u8]),
    /// An elided page known only by its content hash: a faulting access is a
    /// PVM page fault. V1 never mints this.
    Missing(CapHash),
}

impl DataCap {
    /// Total logical content size in bytes (always a [`PAGE_SIZE`] multiple).
    pub fn content_len(&self) -> u64 {
        self.size
    }

    /// The big-endian `u32` storage key for group index `g`.
    #[inline]
    pub fn group_key(g: u32) -> [u8; GROUP_KEY_BYTES] {
        g.to_be_bytes()
    }

    /// Borrow the page slot at **absolute page index** `i`, crossing group
    /// boundaries (group `i / 512`, slot `i % 512`). Any miss — absent group,
    /// elided (`Missing`) group, or past a group's stored tail — reads as
    /// [`PageSlot::Empty`]. This is the flat-merkle leaf accessor.
    #[inline]
    pub fn page_slot(&self, i: usize) -> &PageSlot {
        let g = (i / GROUP_PAGES) as u32;
        let p = i % GROUP_PAGES;
        match self.groups.get(&Self::group_key(g)) {
            Some(MissingOr::Materialized(group)) => group.page(p),
            // V1 never mints a `Missing` group; a wholly-elided group has no
            // per-page roots, so the flat leaf reads as Empty (zero).
            _ => &PageSlot::Empty,
        }
    }

    /// Resolve the page containing byte offset `off` (need not be page-aligned).
    /// Both engines call this so their materialized page contents are identical.
    pub fn page_at(&self, off: u64) -> PageResolution<'_> {
        let g = (off / GROUP_SIZE as u64) as u32;
        let p = ((off / PAGE_SIZE as u64) % GROUP_PAGES as u64) as usize;
        match self.groups.get(&Self::group_key(g)) {
            Some(MissingOr::Materialized(group)) => match group.page(p) {
                PageSlot::Loaded(pr) => PageResolution::Bytes(&pr.bytes),
                PageSlot::Missing(h) => PageResolution::Missing(*h),
                PageSlot::Empty => PageResolution::Zero,
            },
            Some(MissingOr::Missing(h)) => PageResolution::Missing(*h),
            None => PageResolution::Zero,
        }
    }

    /// Copy `out.len()` logical bytes starting at byte offset `start` into
    /// `out`, fully defining every byte: materialized pages are copied; `Zero`
    /// pages read as zero.
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

    /// Overwrite the page containing absolute offset `off` with up to
    /// [`PAGE_SIZE`] content bytes (zero-padded tail), **canonically**: all-zero
    /// content stores the [`PageSlot::Empty`] sentinel (no allocation), any
    /// other content a fresh `PAGE_SIZE`-aligned [`PageSlot::Loaded`] slab.
    /// Grows the storage and the group's page vector as needed, then trims
    /// trailing `Empty` pages / removes an emptied group so the result is the
    /// unique canonical layout — identical to what [`Self::from_bytes`] yields.
    ///
    /// This is the copy-on-write fold primitive a `DataViewCap` overlay write
    /// goes through (see [`put_page_into`], shared with `DataViewCap::write_page`).
    ///
    /// Panics (debug) if `off >= self.size`.
    pub fn put_page(&mut self, off: u64, content: &[u8]) {
        debug_assert!(
            off < self.size,
            "DataCap::put_page: offset past logical size"
        );
        put_page_into(&mut self.groups, off, content);
    }

    /// Build a `DataCap` from contiguous `content`, sized to the next page
    /// boundary (at least one page). All-zero pages become [`PageSlot::Empty`].
    pub fn from_bytes(content: &[u8]) -> Self {
        Self::from_bytes_sized(content, content.len() as u64)
    }

    /// Build a `DataCap` from `content` with a logical size of at least
    /// `target_size` (rounded up to a page boundary, minimum one page).
    /// `content` fills the low bytes; the remainder is zero (sparse).
    pub fn from_bytes_sized(content: &[u8], target_size: u64) -> Self {
        let size = target_size
            .max(content.len() as u64)
            .next_multiple_of(PAGE_SIZE as u64)
            .max(PAGE_SIZE as u64);
        let num_groups = size.div_ceil(GROUP_SIZE as u64) as usize;
        let total_pages = (size / PAGE_SIZE as u64) as usize;

        let mut groups: DataGroups = RadixMap::new();
        for g in 0..num_groups {
            let mut pages: Vec<PageSlot> = Vec::new();
            let mut last_nonempty: Option<usize> = None;
            for p in 0..GROUP_PAGES {
                let page_idx = g * GROUP_PAGES + p;
                if page_idx >= total_pages {
                    break;
                }
                let off = page_idx * PAGE_SIZE;
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
            if let Some(last) = last_nonempty {
                pages.truncate(last + 1);
                groups.insert(
                    Self::group_key(g as u32),
                    MissingOr::Materialized(DataGroup { pages }),
                );
            }
        }
        DataCap { size, groups }
    }
}

/// Canonical copy-on-write page fold into group-chunked storage: write up to
/// [`PAGE_SIZE`] `content` bytes at absolute byte offset `off`, storing the
/// [`PageSlot::Empty`] sentinel for all-zero content (no allocation) or a fresh
/// `PAGE_SIZE`-aligned [`PageSlot::Loaded`] slab otherwise. Grows the group's
/// page vector as needed, then trims trailing `Empty` pages / removes an emptied
/// group so the result is the unique canonical layout (identical to what
/// [`DataCap::from_bytes`] yields for the same effective content).
///
/// Shared by [`DataCap::put_page`] and `DataViewCap::write_page` so a backing
/// cap and a view overlay fold pages identically.
pub fn put_page_into(groups: &mut DataGroups, off: u64, content: &[u8]) {
    let g = (off / GROUP_SIZE as u64) as u32;
    let p = ((off / PAGE_SIZE as u64) % GROUP_PAGES as u64) as usize;
    let key = DataCap::group_key(g);
    let mut pages = match groups.get(&key) {
        Some(MissingOr::Materialized(grp)) => grp.pages.clone(),
        Some(MissingOr::Missing(_)) => {
            unreachable!("put_page_into a Missing group")
        }
        None => Vec::new(),
    };
    if pages.len() <= p {
        pages.resize(p + 1, PageSlot::Empty);
    }
    pages[p] = if content.iter().all(|&b| b == 0) {
        PageSlot::Empty
    } else {
        PageSlot::Loaded(Arc::new(PageBytes::from_content(content)))
    };
    while matches!(pages.last(), Some(PageSlot::Empty)) {
        pages.pop();
    }
    if pages.is_empty() {
        groups.remove(&key);
    } else {
        groups.insert(key, MissingOr::Materialized(DataGroup { pages }));
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
