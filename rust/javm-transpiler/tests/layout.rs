//! The cnode-slot convention for transpiler-emitted Images.
//!
//! Region *geometry* is `nub_program::Regions`' business and is tested
//! in `nub-program`; what this crate owns is the slot each region's
//! `Cap::Data` is filed under.

use javm_transpiler::layout::*;
use nub_program::RegionKind;

#[test]
fn each_region_kind_maps_to_its_conventional_slot() {
    assert_eq!(cap_index(RegionKind::Stack), STACK_CAP_INDEX);
    assert_eq!(cap_index(RegionKind::Ro), RO_CAP_INDEX);
    assert_eq!(cap_index(RegionKind::Rw), RW_CAP_INDEX);
    assert_eq!(cap_index(RegionKind::Heap), HEAP_CAP_INDEX);
}

/// Distinct slots, and above the low range a guest's own cnode uses.
#[test]
fn slots_are_distinct_and_in_the_reserved_range() {
    let slots = [STACK_CAP_INDEX, RO_CAP_INDEX, RW_CAP_INDEX, HEAP_CAP_INDEX];
    let mut sorted = slots.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), slots.len(), "cap indices must be distinct");
    assert!(slots.iter().all(|&s| s >= 64));
}

#[test]
fn abi_constants_are_re_exported_from_nub_program() {
    assert_eq!(CODE_BASE, nub_program::abi::CODE_BASE);
    assert_eq!(DATA_BASE, nub_program::abi::DATA_BASE);
    assert_eq!(MAX_CODE_SIZE, DATA_BASE - CODE_BASE);
    assert_eq!(PVM_PAGE_SIZE, nub_program::abi::PAGE_SIZE);
}
