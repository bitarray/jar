use javm_exec::gas_const::{COW_COST, PAGE_IN_COST};
use javm_exec::{Access, GasCounter, MapError, Mem, MemAccess, PAGE_SIZE, TouchFault, perm};

#[test]
fn read_u8_in_bounds() {
    let mut m = Mem::with_pages(1, perm::RW);
    m.write_u8(0x100, 0xAB);
    assert_eq!(m.read_u8(0x100), Some(0xAB));
}

#[test]
fn read_u8_out_of_bounds_returns_none() {
    let m = Mem::with_pages(1, perm::RW);
    assert_eq!(m.read_u8(PAGE_SIZE), None);
    assert_eq!(m.read_u8(u32::MAX), None);
}

#[test]
fn read_write_u32_le() {
    let mut m = Mem::with_pages(1, perm::RW);
    m.write_u32_le(0x10, 0xDEAD_BEEF);
    assert_eq!(m.read_u32_le(0x10), Some(0xDEAD_BEEF));
}

#[test]
fn unaligned_access_works() {
    let mut m = Mem::with_pages(1, perm::RW);
    m.write_u32_le(0x103, 0x1234_5678);
    assert_eq!(m.read_u32_le(0x103), Some(0x1234_5678));
}

#[test]
fn read_u32_straddling_end_returns_none() {
    let m = Mem::with_pages(1, perm::RW);
    // PAGE_SIZE - 2 → would read 4 bytes ending at PAGE_SIZE + 2, OOB.
    assert_eq!(m.read_u32_le(PAGE_SIZE - 2), None);
}

#[test]
fn ro_page_write_via_slow_path_faults() {
    let mut m = Mem::with_pages(1, perm::RO);
    let res = m.write(0, &[1]);
    assert!(matches!(res, Err(MemAccess::WriteProtected(_))));
}

#[test]
fn perm_of_page_after_set() {
    let m = Mem::with_pages(2, perm::RW);
    assert_eq!(m.perm_of(0), perm::RW);
    assert_eq!(m.perm_of(PAGE_SIZE), perm::RW);
    // Out of range
    assert_eq!(m.perm_of(2 * PAGE_SIZE), perm::NONE);
}

#[test]
fn slow_path_read_write_round_trip() {
    let mut m = Mem::with_pages(1, perm::RW);
    m.write(0, &[1, 2, 3, 4]).unwrap();
    assert_eq!(m.read(0, 4).unwrap(), vec![1, 2, 3, 4]);
}

#[test]
fn map_region_grows_buffer_and_sets_perms() {
    let mut m = Mem::new();
    m.map_region(
        2 * PAGE_SIZE as u64,
        2 * PAGE_SIZE as u64,
        Access::ReadWrite,
        None,
    )
    .unwrap();
    assert_eq!(m.flat_mem.len(), 4 * PAGE_SIZE as usize);
    // Pages 0..2 are unmapped; pages 2..4 are RW.
    assert_eq!(m.perm_of(0), perm::NONE);
    assert_eq!(m.perm_of(PAGE_SIZE), perm::NONE);
    assert_eq!(m.perm_of(2 * PAGE_SIZE), perm::RW);
    assert_eq!(m.perm_of(3 * PAGE_SIZE), perm::RW);
}

#[test]
fn map_region_copies_init_bytes_and_zero_fills_tail() {
    let mut m = Mem::new();
    m.map_region(
        0,
        PAGE_SIZE as u64,
        Access::ReadOnly,
        Some(&[0xAA, 0xBB, 0xCC]),
    )
    .unwrap();
    assert_eq!(m.flat_mem[0], 0xAA);
    assert_eq!(m.flat_mem[1], 0xBB);
    assert_eq!(m.flat_mem[2], 0xCC);
    assert_eq!(m.flat_mem[3], 0x00);
    assert_eq!(m.perm_of(0), perm::RO);
}

#[test]
fn map_region_truncates_oversize_init() {
    let mut m = Mem::new();
    let init = vec![0x77u8; (PAGE_SIZE as usize) * 3];
    // Only one page declared; init is bigger.
    m.map_region(0, PAGE_SIZE as u64, Access::ReadWrite, Some(&init))
        .unwrap();
    assert_eq!(m.flat_mem.len(), PAGE_SIZE as usize);
    assert_eq!(m.flat_mem[PAGE_SIZE as usize - 1], 0x77);
}

#[test]
fn map_region_rejects_unaligned_start() {
    let mut m = Mem::new();
    assert_eq!(
        m.map_region(123, PAGE_SIZE as u64, Access::ReadOnly, None),
        Err(MapError::UnalignedStart(123))
    );
}

#[test]
fn map_region_rejects_unaligned_size() {
    let mut m = Mem::new();
    assert_eq!(
        m.map_region(0, 123, Access::ReadOnly, None),
        Err(MapError::UnalignedSize(123))
    );
}

#[test]
fn map_region_overlapping_overwrites_perms() {
    let mut m = Mem::with_pages(2, perm::RO);
    m.map_region(0, 2 * PAGE_SIZE as u64, Access::ReadWrite, None)
        .unwrap();
    assert_eq!(m.perm_of(0), perm::RW);
    assert_eq!(m.perm_of(PAGE_SIZE), perm::RW);
}

// ---- Category-#3 first-touch (page-in / CoW) accounting -------------------

/// Gas spent by `f` against a fresh counter.
fn spent(initial: u64, f: impl FnOnce(&mut GasCounter)) -> u64 {
    let mut g = GasCounter::new(initial);
    f(&mut g);
    initial - g.remaining()
}

#[test]
fn first_read_charges_page_in_once() {
    let mut m = Mem::with_pages(2, perm::RW);
    // First read of page 0 pays page-in.
    assert_eq!(
        spent(10_000, |g| m.touch_read(0, 8, g).unwrap()),
        PAGE_IN_COST
    );
    // A second read of the same page is free (already present).
    assert_eq!(spent(10_000, |g| m.touch_read(0x40, 8, g).unwrap()), 0);
    // A read of a different page pays its own page-in.
    assert_eq!(
        spent(10_000, |g| m.touch_read(PAGE_SIZE, 4, g).unwrap()),
        PAGE_IN_COST
    );
}

#[test]
fn first_write_charges_page_in_plus_cow() {
    let mut m = Mem::with_pages(1, perm::RW);
    assert_eq!(
        spent(10_000, |g| m.touch_write(0x10, 8, g).unwrap()),
        PAGE_IN_COST + COW_COST
    );
    // Subsequent writes to the now-present-RW page are free.
    assert_eq!(spent(10_000, |g| m.touch_write(0x20, 8, g).unwrap()), 0);
}

#[test]
fn read_then_write_same_page_pays_page_in_then_cow_only() {
    // D-2: read-then-write must not double-charge page-in.
    let mut m = Mem::with_pages(1, perm::RW);
    assert_eq!(
        spent(10_000, |g| m.touch_read(0, 8, g).unwrap()),
        PAGE_IN_COST
    );
    // The page is PresentRo; a write CoWs it — COW only, no second page-in.
    assert_eq!(spent(10_000, |g| m.touch_write(0, 8, g).unwrap()), COW_COST);
    // And it is now PresentRw: further reads/writes are free.
    assert_eq!(spent(10_000, |g| m.touch_read(0, 8, g).unwrap()), 0);
    assert_eq!(spent(10_000, |g| m.touch_write(0, 8, g).unwrap()), 0);
}

#[test]
fn aligned_straddle_charges_both_pages() {
    // An 8-byte read crossing the page boundary pays page-in for both pages.
    let mut m = Mem::with_pages(2, perm::RW);
    assert_eq!(
        spent(10_000, |g| m.touch_read(PAGE_SIZE - 4, 8, g).unwrap()),
        2 * PAGE_IN_COST
    );
    // Both pages are now PresentRo; a straddling write CoWs both.
    assert_eq!(
        spent(10_000, |g| m.touch_write(PAGE_SIZE - 4, 8, g).unwrap()),
        2 * COW_COST
    );
}

#[test]
fn write_to_pinned_page_hard_faults_charging_nothing() {
    // A write to a read-only page is a hard fault; nothing is charged and
    // the page's state is unchanged.
    let mut m = Mem::with_pages(1, perm::RO);
    let mut g = GasCounter::new(10_000);
    assert_eq!(m.touch_write(0, 8, &mut g), Err(TouchFault));
    assert_eq!(g.remaining(), 10_000);
    // A read of the same pinned page is fine and pays page-in once.
    assert_eq!(
        spent(10_000, |g| m.touch_read(0, 8, g).unwrap()),
        PAGE_IN_COST
    );
}

#[test]
fn straddle_into_unmapped_hard_faults_all_or_nothing() {
    // D-3: an access whose base page is mapped but straddles into an
    // unmapped page faults wholesale — nothing is charged, and the mapped
    // page is NOT paged in (so a later in-range read still pays page-in).
    let mut m = Mem::with_pages(1, perm::RW); // only page 0 exists
    let mut g = GasCounter::new(10_000);
    assert_eq!(m.touch_read(PAGE_SIZE - 4, 8, &mut g), Err(TouchFault));
    assert_eq!(g.remaining(), 10_000);
    // Page 0 was not materialized by the failed straddle.
    assert_eq!(
        spent(10_000, |g| m.touch_read(0, 8, g).unwrap()),
        PAGE_IN_COST
    );
}

#[test]
fn unmapped_base_page_is_skipped_not_charged() {
    // An access wholly outside the declared buffer (e.g. a code-region PIC
    // load when the data buffer is based elsewhere) is skipped: no #3
    // charge, and the caller's load path resolves it.
    let mut m = Mem::with_pages(1, perm::RW);
    let mut g = GasCounter::new(10_000);
    // Address past the buffer: base page not declared → Ok, no charge.
    assert_eq!(m.touch_read(8 * PAGE_SIZE, 4, &mut g), Ok(()));
    assert_eq!(g.remaining(), 10_000);
}

// ---- CODE region (PinnedCapRo) #3 -----------------------------------------

#[test]
fn code_first_read_pages_in_then_free() {
    // A read of the declared code region pages it in once (PAGE_IN), then is
    // free; a write hard-faults (code is read-only), charging nothing.
    let mut m = Mem::new();
    m.set_code_region(0x40_0000, PAGE_SIZE); // one code page
    assert_eq!(
        spent(10_000, |g| m.touch_read(0x40_0000, 8, g).unwrap()),
        PAGE_IN_COST
    );
    assert_eq!(spent(10_000, |g| m.touch_read(0x40_0040, 8, g).unwrap()), 0);
    // A write to code hard-faults, charging nothing.
    let mut g = GasCounter::new(10_000);
    assert_eq!(m.touch_write(0x40_0000, 4, &mut g), Err(TouchFault));
    assert_eq!(g.remaining(), 10_000);
}

#[test]
fn ro_cluster_charges_page_in_once_for_whole_cluster() {
    // 16 read-only pages in one 2 MiB cluster: reading every page charges a
    // SINGLE page_in (cluster materialization), not 16 — mirroring the
    // recompiler's fault-around of the whole cluster on the first fault.
    let mut m = Mem::with_pages(16, perm::RO);
    let mut total = 0u64;
    for pg in 0..16u32 {
        total += spent(10_000, |g| m.touch_read(pg * PAGE_SIZE, 8, g).unwrap());
    }
    assert_eq!(total, PAGE_IN_COST);
}

#[test]
fn ro_cluster_straddle_charges_each_cluster() {
    // An RO read straddling a 2 MiB cluster boundary pays one page_in per
    // cluster (two here); re-reads are then free.
    const TWO_MIB: u32 = 1 << 21;
    let mut m = Mem::new();
    m.base = TWO_MIB - PAGE_SIZE;
    m.map_region(
        (TWO_MIB - PAGE_SIZE) as u64,
        (2 * PAGE_SIZE) as u64,
        Access::ReadOnly,
        None,
    )
    .unwrap();
    assert_eq!(
        spent(10_000, |g| m.touch_read(TWO_MIB - 4, 8, g).unwrap()),
        2 * PAGE_IN_COST
    );
    assert_eq!(
        spent(10_000, |g| m.touch_read(TWO_MIB - PAGE_SIZE, 8, g).unwrap()),
        0
    );
    assert_eq!(spent(10_000, |g| m.touch_read(TWO_MIB, 8, g).unwrap()), 0);
}

#[test]
fn rw_pages_stay_per_page_not_clustered() {
    // Writable (CoW) pages are NOT clustered: each page pays its own
    // page_in+cow, unchanged from the per-page model.
    let mut m = Mem::with_pages(4, perm::RW);
    let mut total = 0u64;
    for pg in 0..4u32 {
        total += spent(10_000, |g| m.touch_write(pg * PAGE_SIZE, 8, g).unwrap());
    }
    assert_eq!(total, 4 * (PAGE_IN_COST + COW_COST));
}

#[test]
fn code_data_adjacency_straddle_faults() {
    // The consensus-critical boundary: a code region whose top abuts the
    // data region (`code_top == data_base`, reachable with a maximal 252 MiB
    // code image). An 8-byte read straddling the last code page into the
    // first data page must fault WHOLESALE — charging nothing — on both
    // engines (base-page region dispatch is all-or-nothing), not materialize
    // across the boundary. Here code = [0x1000, 0x2000) abuts data at 0x2000.
    let mut m = Mem::new();
    m.base = 0x2000;
    m.map_region(0x2000, PAGE_SIZE as u64, Access::ReadWrite, None)
        .unwrap();
    m.set_code_region(0x1000, PAGE_SIZE); // code_top == 0x2000 == data base
    let mut g = GasCounter::new(10_000);
    // 8-byte read at 0x1FFC straddles code page 0x1000 → data page 0x2000.
    assert_eq!(m.touch_read(0x2000 - 4, 8, &mut g), Err(TouchFault));
    assert_eq!(g.remaining(), 10_000); // all-or-nothing: charged nothing
    // Sanity: a read wholly inside each region still charges its own page-in.
    assert_eq!(
        spent(10_000, |g| m.touch_read(0x1000, 8, g).unwrap()),
        PAGE_IN_COST
    );
    assert_eq!(
        spent(10_000, |g| m.touch_read(0x2000, 8, g).unwrap()),
        PAGE_IN_COST
    );
}
