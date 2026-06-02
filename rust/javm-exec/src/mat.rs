//! Shared per-page memory-materialization (#3) state machine.
//!
//! Both engines drive this same state machine so they charge
//! bit-identical category-#3 gas (consensus determinism): the
//! interpreter does software first-touch accounting (no real unmap),
//! the x86 recompiler does the same accounting off hardware page-table
//! faults. See `~/docs/spec-staging/gas-cost.md` §3.
//!
//! The charge rules key strictly on the per-page [`PageState`] and the
//! static [`PageKind`] — never on the instruction — so a load-then-store
//! to one page charges identically regardless of engine. `page_in` is
//! charged at most once and `cow` at most once per page (per frame); the
//! only re-page-in is a `MGMT_MOVE`/`MGMT_DROP` slot eviction, which is a
//! block terminator.
//!
//! ## Read-only clusters
//!
//! Read-only ([`PageKind::PinnedCapRo`]) regions — the program's code and
//! pinned data caps — are materialized at **2 MiB cluster** granularity
//! ([`CLUSTER_SHIFT`], [`cluster_of`]): the first read anywhere in a
//! cluster pays a single [`PAGE_IN_COST`] and brings the whole cluster's
//! RO pages into the working set (the recompiler fault-arounds them — a
//! single 2 MiB large page where aligned + fully cap-backed, else the
//! cluster's 4 KiB pages; the interpreter just accounts the cluster). This
//! frames `page_in` as the O(1) *map* event (one fault, one mapping) — the
//! per-access data-movement latency is category #2 — so a large aligned RO
//! input materializes for one fault instead of 512, and the per-block
//! reserve is unchanged (a load still spans ≤ 2 clusters = ≤ 2 events).
//! Copy-on-write (RW) regions stay 4 KiB-granular (a write copies one
//! page). Both engines key on the same absolute cluster index, so they
//! charge identically.

use crate::gas_const::{COW_COST, PAGE_IN_COST};
use crate::mem::PAGE_SIZE;

/// log2 of the read-only materialization cluster size. `21` → 2 MiB, the
/// common large-page size on x86 (PDE), AArch64 (L2 block), and RISC-V
/// (megapage), so the clustered charge model is arch-portable.
/// TODO(gas-calibration): cluster size is subject to change.
pub const CLUSTER_SHIFT: u32 = 21;

/// Absolute 2 MiB cluster index of `addr` (`addr >> CLUSTER_SHIFT`). Both
/// engines key read-only cluster materialization on this, so a read-only
/// page pays `page_in` at most once per cluster, identically on each.
#[inline]
pub fn cluster_of(addr: u32) -> u32 {
    addr >> CLUSTER_SHIFT
}

/// Static per-page source kind, derived once from the Image's declared
/// memory mappings (pinned slot vs initial slot vs ephemeral / zero tail).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageKind {
    /// Sourced from a **pinned** cnode slot: read-only forever. A store
    /// is a hard fault, never a CoW.
    PinnedCapRo,
    /// Sourced from an **unpinned** (initial) slot: readable; the first
    /// write copies-on-write.
    UnpinnedCapCow,
    /// Declared mapping with no / empty source (ephemeral working area,
    /// or the zero-padded tail of an under-sized DataCap): reads see
    /// zero, the first write materializes a fresh zero page.
    EphemeralZero,
}

impl PageKind {
    /// One-byte tag for the per-page side arrays both engines keep.
    #[inline]
    pub fn as_u8(self) -> u8 {
        match self {
            PageKind::PinnedCapRo => 0,
            PageKind::UnpinnedCapCow => 1,
            PageKind::EphemeralZero => 2,
        }
    }

    /// Inverse of [`PageKind::as_u8`]. `None` for an undeclared page.
    #[inline]
    pub fn from_u8(v: u8) -> Option<PageKind> {
        match v {
            0 => Some(PageKind::PinnedCapRo),
            1 => Some(PageKind::UnpinnedCapCow),
            2 => Some(PageKind::EphemeralZero),
            _ => None,
        }
    }
}

/// Dynamic per-page first-touch state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum PageState {
    /// Never touched; the next read pages-in, the next write CoWs.
    #[default]
    NotPresent,
    /// Paged-in read-only (a read happened, or a pinned-cap page).
    PresentRo,
    /// CoW'd (a write happened): writable.
    PresentRw,
}

impl PageState {
    #[inline]
    pub fn as_u8(self) -> u8 {
        match self {
            PageState::NotPresent => 0,
            PageState::PresentRo => 1,
            PageState::PresentRw => 2,
        }
    }

    #[inline]
    pub fn from_u8(v: u8) -> PageState {
        match v {
            1 => PageState::PresentRo,
            2 => PageState::PresentRw,
            _ => PageState::NotPresent,
        }
    }
}

/// A write to a read-only (pinned) page — a permanent PVM2-level fault.
/// (Accesses outside any declared mapping are rejected by the caller
/// before reaching [`charge_for`].) Charge nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HardFault;

/// The category-#3 charge and resulting state for one page touch.
///
/// - first read (`NotPresent`)  → `PAGE_IN_COST`,            → `PresentRo`
/// - first write (`NotPresent`) → `PAGE_IN_COST + COW_COST`, → `PresentRw`
/// - write after read (`PresentRo`) → `COW_COST`,            → `PresentRw`
/// - already present for this access kind → `0`
/// - write to `PinnedCapRo` → [`HardFault`]
#[inline]
pub fn charge_for(
    state: PageState,
    kind: PageKind,
    is_write: bool,
) -> Result<(u64, PageState), HardFault> {
    if is_write && kind == PageKind::PinnedCapRo {
        return Err(HardFault);
    }
    Ok(match (state, is_write) {
        (PageState::NotPresent, false) => (PAGE_IN_COST, PageState::PresentRo),
        (PageState::NotPresent, true) => (PAGE_IN_COST + COW_COST, PageState::PresentRw),
        (PageState::PresentRo, true) => (COW_COST, PageState::PresentRw),
        (PageState::PresentRo, false) => (0, PageState::PresentRo),
        (PageState::PresentRw, _) => (0, PageState::PresentRw),
    })
}

/// The set of consensus 4 KiB pages a single `width`-byte access at
/// `addr` touches: the base page, plus the next page iff the access
/// straddles a page boundary. At most [`crate::gas_const::MAX_PAGES_PER_ACCESS`]
/// (= 2) pages. Pages are ordered **low → high** — the fixed order both
/// engines iterate, so the charged page set and total match exactly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageSet {
    pages: [u32; 2],
    len: u8,
}

impl PageSet {
    /// The page numbers (page-aligned base addresses), low → high.
    #[inline]
    pub fn as_slice(&self) -> &[u32] {
        &self.pages[..self.len as usize]
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len as usize
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Compute the page set for a `width`-byte access at `addr`. Keyed only
/// on `addr` and `width` so the recompiler (which learns `width` from a
/// compile-time side table) and the interpreter (which knows it from the
/// opcode) agree byte-for-byte. `width` must be in `1..=8`.
#[inline]
pub fn access_pages(addr: u32, width: u32) -> PageSet {
    let mask = PAGE_SIZE - 1;
    let base = addr & !mask;
    let off = addr & mask;
    // Straddles iff the last touched byte lands in the next page.
    if off + width > PAGE_SIZE {
        PageSet {
            pages: [base, base.wrapping_add(PAGE_SIZE)],
            len: 2,
        }
    } else {
        PageSet {
            pages: [base, 0],
            len: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_read_pays_page_in() {
        let (c, s) = charge_for(PageState::NotPresent, PageKind::UnpinnedCapCow, false).unwrap();
        assert_eq!(c, PAGE_IN_COST);
        assert_eq!(s, PageState::PresentRo);
    }

    #[test]
    fn first_write_pays_page_in_plus_cow() {
        let (c, s) = charge_for(PageState::NotPresent, PageKind::EphemeralZero, true).unwrap();
        assert_eq!(c, PAGE_IN_COST + COW_COST);
        assert_eq!(s, PageState::PresentRw);
    }

    #[test]
    fn write_after_read_pays_cow_only() {
        let (c, s) = charge_for(PageState::PresentRo, PageKind::UnpinnedCapCow, true).unwrap();
        assert_eq!(c, COW_COST);
        assert_eq!(s, PageState::PresentRw);
    }

    #[test]
    fn second_touch_is_free() {
        assert_eq!(
            charge_for(PageState::PresentRo, PageKind::UnpinnedCapCow, false).unwrap(),
            (0, PageState::PresentRo)
        );
        assert_eq!(
            charge_for(PageState::PresentRw, PageKind::EphemeralZero, true).unwrap(),
            (0, PageState::PresentRw)
        );
    }

    #[test]
    fn pinned_store_hard_faults_and_reads_are_free_after_first() {
        assert_eq!(
            charge_for(PageState::PresentRo, PageKind::PinnedCapRo, true),
            Err(HardFault)
        );
        // A read of a pinned page still pays page-in once, then is free.
        let (c, s) = charge_for(PageState::NotPresent, PageKind::PinnedCapRo, false).unwrap();
        assert_eq!((c, s), (PAGE_IN_COST, PageState::PresentRo));
    }

    #[test]
    fn access_pages_single_and_straddle() {
        // Aligned 8-byte: one page.
        let s = access_pages(0x1000, 8);
        assert_eq!(s.as_slice(), &[0x1000]);
        // 8-byte at offset 0xFFC: straddles into the next page.
        let s = access_pages(0x1FFC, 8);
        assert_eq!(s.as_slice(), &[0x1000, 0x2000]);
        // 4-byte at 0xFFE: straddles.
        let s = access_pages(0x1FFE, 4);
        assert_eq!(s.as_slice(), &[0x1000, 0x2000]);
        // 1-byte never straddles.
        let s = access_pages(0x1FFF, 1);
        assert_eq!(s.as_slice(), &[0x1000]);
        // 8-byte ending exactly at the boundary (offset 0xFF8): one page.
        let s = access_pages(0x1FF8, 8);
        assert_eq!(s.as_slice(), &[0x1000]);
    }
}
