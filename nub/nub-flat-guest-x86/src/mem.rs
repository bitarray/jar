//! Frame memory: a shared immutable backing image plus a per-frame
//! copy-on-write overlay.
//!
//! The backing is built **once, at publish time**, and every invocation
//! of that program reads the same pages. Isolation comes from the
//! overlay: a frame starts with an empty one, so it sees the pristine
//! image, and the first write to a page copies it privately. The next
//! invocation gets a fresh overlay and therefore a pristine image
//! again.
//!
//! Getting this wrong is expensive and quiet. Giving each frame its own
//! copy of the backing is also *correct* — and it makes frame setup
//! O(data extent) instead of O(pages), which for prime-sieve's 236 KiB
//! extent cost ~90 us of memcpy on every single invocation while
//! producing byte-identical results. It made the overlay redundant, so
//! nothing failed; the only symptom was the clock.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use nub_arch_x86::paging::{self, PAGE_SIZE};
use nub_arch_x86::personality::{FrameMem, PageSource};

use crate::store::PublishedProgram;

/// One page-aligned page of guest data.
#[repr(C, align(4096))]
pub struct Page(pub [u8; PAGE_SIZE]);

impl Page {
    pub fn zeroed() -> Box<Page> {
        Box::new(Page([0u8; PAGE_SIZE]))
    }

    /// Split `image` into page-aligned pages. Used once per program, at
    /// publish time.
    pub fn split(image: &[u8]) -> Vec<Box<Page>> {
        let mut pages = Vec::with_capacity(image.len().div_ceil(PAGE_SIZE));
        for chunk in image.chunks(PAGE_SIZE) {
            let mut page = Page::zeroed();
            page.0[..chunk.len()].copy_from_slice(chunk);
            pages.push(page);
        }
        pages
    }
}

/// A frame's view of its program's data: the shared image, plus the
/// pages this frame has written.
pub struct FlatMem {
    /// Keeps the shared backing alive for the frame's lifetime — the
    /// page table points straight at its physical pages.
    program: Arc<PublishedProgram>,
    /// Pages written since entry. `None` = still reading the backing.
    /// Allocating this is the whole of per-frame memory setup.
    overlay: Vec<Option<Box<Page>>>,
}

impl FlatMem {
    pub fn new(program: Arc<PublishedProgram>) -> Self {
        let pages = program.data_pages().len();
        let mut overlay = Vec::with_capacity(pages);
        overlay.resize_with(pages, || None);
        FlatMem { program, overlay }
    }

    pub fn pages(&self) -> usize {
        self.overlay.len()
    }

    /// Effective bytes of page `idx`: this frame's copy if it wrote one,
    /// else the shared backing. Used to surface the scratchpad head.
    pub fn page_bytes(&self, idx: usize) -> Option<&[u8; PAGE_SIZE]> {
        match self.overlay.get(idx) {
            Some(Some(p)) => Some(&p.0),
            _ => self.program.data_pages().get(idx).map(|p| &p.0),
        }
    }
}

impl FrameMem for FlatMem {
    type CowPage = Box<Page>;

    fn page_source(&self, page_idx: usize) -> PageSource {
        // Overlay first, so a rebuilt runtime picks up this frame's
        // prior writes rather than reverting to the shared image.
        let page = match self.overlay.get(page_idx) {
            Some(Some(page)) => &page.0,
            _ => match self.program.data_pages().get(page_idx) {
                Some(page) => &page.0,
                // Past the declared extent: a genuine PVM fault, not a
                // zero page. The interpreter faults here too.
                None => return PageSource::Missing,
            },
        };
        match paging::va_to_pa(page.as_ptr() as u64) {
            Some(pa) => PageSource::Pa(pa),
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
