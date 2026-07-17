//! Kernel-personality seam: what the generic guest kernel (`task`,
//! [`crate::jit_run`]) needs from a pluggable state/cap system. javm-cap is
//! one implementation ([`crate::call_loop`]). Exactly one personality per
//! guest binary (asserted in `jit_run::install_handlers`).

/// Content hash of a published state object (javm: `CapHash`). Local alias
/// for A2; unifies with `nub-kernel::ObjHash` at phase B.
pub type ObjHash = [u8; 32];

/// Persisted PVM register file width. Matches
/// [`crate::jit_run::ExitInfo::regs`] and `javm_cap::NUM_REGS`
/// (const-asserted in `call_loop`).
pub const NUM_REGS: usize = 13;

/// Source of a guest data page for materialization.
///
/// `Pa` = a live slab's physical address; `Zero` = shared zero page (the
/// substrate substitutes `ZERO_PAGE.pa()`); `Missing` = PVM fault.
pub enum PageSource {
    Pa(u64),
    Zero,
    Missing,
}

/// Paged frame memory the CoW #PF handler materializes from (javm:
/// `DataCap`). Implemented on a personality-owned type (javm:
/// `#[repr(transparent)] JavmMem(DataCap)`) so the impl survives the B1
/// crate split (orphan rule).
pub trait FrameMem: Sized {
    /// Privately-owned CoW page pending publication into the overlay
    /// (javm: `Arc<javm_cap::PageBytes>`).
    type CowPage;

    /// Source of data-extent page `page_idx` (index from the data base).
    fn page_source(&self, page_idx: usize) -> PageSource;

    /// Whether `page_idx` is privately CoW'd (present in the overlay).
    fn overlay_has(&self, page_idx: u32) -> bool;

    /// Allocate a page-aligned private copy of `src` (len ==
    /// `paging::PAGE_SIZE`); return it plus its physical address. Does NOT
    /// publish. Publication is separate so the substrate keeps the exact op
    /// order: alloc/copy → `pt_map_leaf` → `invlpg` → commit — a map failure
    /// after alloc leaves the overlay untouched.
    /// javm: `Arc<PageBytes::from_page_copy_unhashed>` + `paging::va_to_pa`.
    fn alloc_cow_page(src: &[u8]) -> Option<(Self::CowPage, u64)>;

    /// Publish a CoW'd page into the overlay at `page_idx`.
    fn commit_overlay_page(&mut self, page_idx: u32, page: Self::CowPage);
}
