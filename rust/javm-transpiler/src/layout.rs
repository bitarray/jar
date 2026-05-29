//! Shared program data-region layout for transpiler-emitted Images.
//!
//! [`ProgramLayout`] assigns `cap_index`, `base_page`, and `page_count`
//! to each DATA cap appearing in a transpiler-emitted Image. The
//! consumer is [`crate::linker::link_elf`], which uses
//! [`ProgramLayout::stack_top`] to compute the initial SP value baked
//! into every endpoint's
//! [`javm_cap::image::EndpointDef::initial_regs`]. The page-count and
//! base-page metadata also feed declarative `Image.memory_mappings`.
//!
//! Cap-index convention: 64 = CODE, 65 = stack, 66 = ro, 67 = rw,
//! 68 = heap. Data is laid out from [`javm_cap::layout::DATA_BASE`]
//! (256 MiB) upward and stacks linearly: stack lives at `[DATA_BASE,
//! DATA_BASE + stack_pages)`, ro at `[DATA_BASE + stack_pages, …)`,
//! etc. Code maps separately at [`CODE_BASE`].

/// Cap index of the CODE cap in transpiler-emitted blobs. Matches the
/// JAR `init_cap` field.
pub const CODE_CAP_INDEX: u8 = 64;
/// Cap index of the stack DATA cap.
pub const STACK_CAP_INDEX: u8 = 65;
/// Cap index of the read-only DATA cap (`.rodata`).
pub const RO_CAP_INDEX: u8 = 66;
/// Cap index of the read-write DATA cap (`.data` + `.bss`).
pub const RW_CAP_INDEX: u8 = 67;
/// Cap index of the heap DATA cap.
pub const HEAP_CAP_INDEX: u8 = 68;
/// PVM page size in bytes.
pub const PVM_PAGE_SIZE: u32 = 4096;

/// Guest virtual address where the code region is mapped read-only.
///
/// The canonical definition is the PVM2 ABI constant
/// [`javm_cap::layout::CODE_BASE`] (re-exported here for transpiler
/// call sites). Code occupies `[CODE_BASE, DATA_BASE)`; data regions
/// (stack/ro/rw/heap) occupy `[DATA_BASE, 4 GiB)` (see [`ProgramLayout`]).
/// The linker asserts code stays below [`DATA_BASE`] and the data
/// layout stays within the 4 GiB guest range.
pub use javm_cap::layout::CODE_BASE;
/// Re-exported PVM2 ABI layout constants (see [`javm_cap::layout`]).
pub use javm_cap::layout::{DATA_BASE, MAX_CODE_SIZE};

/// One DATA cap's layout: where it lives in the manifest and where it
/// maps in guest memory.
#[derive(Debug, Clone, Copy)]
pub struct DataCapEntry {
    pub cap_index: u8,
    pub base_page: u32,
    pub page_count: u32,
}

/// Full DATA-cap layout of a transpiler-emitted blob. `stack` is
/// always present; `ro`, `rw`, `heap` are present only when their
/// page count is non-zero. Args bytes are delivered separately
/// (kernel-allocated cap at bare-Frame slot 4), so they are not part
/// of the layout.
#[derive(Debug, Clone)]
pub struct ProgramLayout {
    pub stack: DataCapEntry,
    pub ro: Option<DataCapEntry>,
    pub rw: Option<DataCapEntry>,
    pub heap: Option<DataCapEntry>,
}

impl ProgramLayout {
    /// Compute the layout from per-region page counts. `stack_pages`
    /// must be ≥ 1 in any sane build, but the function does not enforce
    /// that. `ro_pages`, `rw_pages`, `heap_pages` of zero omit those
    /// caps entirely.
    pub fn compute(stack_pages: u32, ro_pages: u32, rw_pages: u32, heap_pages: u32) -> Self {
        // Data starts at DATA_BASE (256 MiB), above the code region.
        let mut next_page = javm_cap::layout::DATA_BASE / PVM_PAGE_SIZE;

        let stack = DataCapEntry {
            cap_index: STACK_CAP_INDEX,
            base_page: next_page,
            page_count: stack_pages,
        };
        next_page += stack_pages;

        let ro = if ro_pages > 0 {
            let e = DataCapEntry {
                cap_index: RO_CAP_INDEX,
                base_page: next_page,
                page_count: ro_pages,
            };
            next_page += ro_pages;
            Some(e)
        } else {
            None
        };

        let rw = if rw_pages > 0 {
            let e = DataCapEntry {
                cap_index: RW_CAP_INDEX,
                base_page: next_page,
                page_count: rw_pages,
            };
            next_page += rw_pages;
            Some(e)
        } else {
            None
        };

        let heap = if heap_pages > 0 {
            let e = DataCapEntry {
                cap_index: HEAP_CAP_INDEX,
                base_page: next_page,
                page_count: heap_pages,
            };
            Some(e)
        } else {
            None
        };

        Self {
            stack,
            ro,
            rw,
            heap,
        }
    }

    /// Iterate every DATA cap entry in cap-index (and base-page) order:
    /// stack, ro?, rw?, heap?.
    pub fn data_caps(&self) -> impl Iterator<Item = &DataCapEntry> + '_ {
        std::iter::once(&self.stack)
            .chain(self.ro.iter())
            .chain(self.rw.iter())
            .chain(self.heap.iter())
    }

    /// Top-of-stack address (initial SP). RISC-V SP grows downward, so
    /// the first push lands at `stack_top - 8`.
    pub fn stack_top(&self) -> u64 {
        (self.stack.base_page + self.stack.page_count) as u64 * PVM_PAGE_SIZE as u64
    }

    /// Total pages across all DATA caps in this layout.
    pub fn total_data_pages(&self) -> u32 {
        self.data_caps().map(|d| d.page_count).sum()
    }
}
