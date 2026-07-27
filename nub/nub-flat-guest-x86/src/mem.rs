//! Frame memory: page-aligned backing for the program's data extent,
//! plus a copy-on-write overlay.
//!
//! Each frame owns a private copy of the whole data extent, so the CoW
//! overlay is not strictly load-bearing here the way it is for a
//! personality that shares immutable pages between instances. It is
//! implemented faithfully anyway: the substrate's `#PF` handler drives
//! CoW through this trait, and short-circuiting it would mean the flat
//! personality exercised a different fault path from the real one — the
//! opposite of what a reference implementation is for.

use alloc::boxed::Box;
use alloc::vec::Vec;

use nub_arch_x86::paging::{self, PAGE_SIZE};
use nub_arch_x86::personality::{FrameMem, PageSource};

/// One page-aligned page of guest data.
#[repr(C, align(4096))]
pub struct Page(pub [u8; PAGE_SIZE]);

impl Page {
    fn zeroed() -> Box<Page> {
        Box::new(Page([0u8; PAGE_SIZE]))
    }
}

/// A frame's data memory: one page per data page, plus CoW overlay.
pub struct FlatMem {
    /// The initial image, one page each. Materialized eagerly because a
    /// flat program's extent is small (tens to hundreds of KiB) and this
    /// keeps `page_source` a pure lookup.
    backing: Vec<Box<Page>>,
    /// Pages written since entry. `None` = still reading the backing.
    overlay: Vec<Option<Box<Page>>>,
}

impl FlatMem {
    /// Build memory for a program's data extent from its flat image.
    ///
    /// `image` is `ProgramBlob::memory_image()` — exactly what the
    /// interpreter maps at `DATA_BASE`, so the two engines start from
    /// identical bytes.
    pub fn new(image: &[u8]) -> Self {
        let pages = image.len().div_ceil(PAGE_SIZE);
        let mut backing = Vec::with_capacity(pages);
        for i in 0..pages {
            let mut page = Page::zeroed();
            let start = i * PAGE_SIZE;
            let end = (start + PAGE_SIZE).min(image.len());
            page.0[..end - start].copy_from_slice(&image[start..end]);
            backing.push(page);
        }
        let mut overlay = Vec::with_capacity(pages);
        overlay.resize_with(pages, || None);
        FlatMem { backing, overlay }
    }

    pub fn pages(&self) -> usize {
        self.backing.len()
    }

    /// Effective bytes of page `idx`: the overlay if written, else the
    /// backing. Used to surface the scratchpad head after a halt.
    pub fn page_bytes(&self, idx: usize) -> Option<&[u8; PAGE_SIZE]> {
        match self.overlay.get(idx) {
            Some(Some(p)) => Some(&p.0),
            _ => self.backing.get(idx).map(|p| &p.0),
        }
    }
}

impl FrameMem for FlatMem {
    type CowPage = Box<Page>;

    fn page_source(&self, page_idx: usize) -> PageSource {
        // Overlay first, so a rebuilt runtime picks up prior writes.
        if let Some(Some(page)) = self.overlay.get(page_idx) {
            return match paging::va_to_pa(page.0.as_ptr() as u64) {
                Some(pa) => PageSource::Pa(pa),
                None => PageSource::Missing,
            };
        }
        match self.backing.get(page_idx) {
            Some(page) => match paging::va_to_pa(page.0.as_ptr() as u64) {
                Some(pa) => PageSource::Pa(pa),
                None => PageSource::Missing,
            },
            // Past the declared extent: a genuine PVM fault, not a zero
            // page. The interpreter faults here too.
            None => PageSource::Missing,
        }
    }

    fn overlay_has(&self, page_idx: u32) -> bool {
        matches!(self.overlay.get(page_idx as usize), Some(Some(_)))
    }

    fn alloc_cow_page(src: &[u8]) -> Option<(Self::CowPage, u64)> {
        debug_assert_eq!(src.len(), PAGE_SIZE);
        let mut page = Page::zeroed();
        page.0.copy_from_slice(src);
        let pa = paging::va_to_pa(page.0.as_ptr() as u64)?;
        Some((page, pa))
    }

    fn commit_overlay_page(&mut self, page_idx: u32, page: Self::CowPage) {
        if let Some(slot) = self.overlay.get_mut(page_idx as usize) {
            *slot = Some(page);
        }
    }
}
