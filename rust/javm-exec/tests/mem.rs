use javm_exec::{Access, MapError, Mem, MemAccess, PAGE_SIZE, perm};

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
