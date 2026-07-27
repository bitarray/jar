//! Region geometry and blob invariants.

use nub_program::abi::{DATA_BASE, PAGE_SIZE};
use nub_program::{Endpoint, InvalidProgram, ProgramBlob, RegionKind, Regions};
use std::collections::BTreeMap;

fn endpoints() -> BTreeMap<u8, Endpoint> {
    BTreeMap::from([(
        0,
        Endpoint {
            entry_pc: 0x20,
            arg_registers: 0,
            arg_meta: 0,
            initial_regs: BTreeMap::from([(1, 0x1000_4000)]),
        },
    )])
}

#[test]
fn regions_lay_out_from_data_base_in_kind_order() {
    let r = Regions {
        stack_pages: 4,
        ro_pages: 2,
        rw_pages: 3,
        heap_pages: 16,
    };
    let got: Vec<_> = r
        .iter()
        .map(|x| (x.kind, x.base_page, x.page_count))
        .collect();
    let base = DATA_BASE / PAGE_SIZE;
    assert_eq!(
        got,
        vec![
            (RegionKind::Stack, base, 4),
            (RegionKind::Ro, base + 4, 2),
            (RegionKind::Rw, base + 6, 3),
            (RegionKind::Heap, base + 9, 16),
        ]
    );
}

/// Consumers that pack a content-addressed arena in insertion order
/// depend on this order; a reorder would silently change their output.
#[test]
fn region_iteration_order_is_stack_ro_rw_heap() {
    let r = Regions {
        stack_pages: 1,
        ro_pages: 1,
        rw_pages: 1,
        heap_pages: 1,
    };
    let kinds: Vec<_> = r.iter().map(|x| x.kind).collect();
    assert_eq!(
        kinds,
        vec![
            RegionKind::Stack,
            RegionKind::Ro,
            RegionKind::Rw,
            RegionKind::Heap
        ]
    );
}

#[test]
fn empty_regions_are_omitted_and_occupy_no_address_space() {
    let r = Regions {
        stack_pages: 2,
        ro_pages: 0,
        rw_pages: 5,
        heap_pages: 0,
    };
    let got: Vec<_> = r.iter().map(|x| (x.kind, x.base_page)).collect();
    let base = DATA_BASE / PAGE_SIZE;
    assert_eq!(
        got,
        vec![(RegionKind::Stack, base), (RegionKind::Rw, base + 2)]
    );
    assert_eq!(r.get(RegionKind::Ro), None);
    assert_eq!(r.total_pages(), 7);
    assert_eq!(r.data_extent(), 7 * u64::from(PAGE_SIZE));
}

#[test]
fn stack_top_is_the_end_of_the_stack_region() {
    let r = Regions {
        stack_pages: 4,
        ro_pages: 9,
        rw_pages: 9,
        heap_pages: 9,
    };
    assert_eq!(
        r.stack_top(),
        u64::from(DATA_BASE) + 4 * u64::from(PAGE_SIZE)
    );
}

#[test]
fn new_zero_extends_backing_buffers_to_whole_pages() {
    let regions = Regions {
        stack_pages: 1,
        ro_pages: 2,
        rw_pages: 1,
        heap_pages: 0,
    };
    let blob = ProgramBlob::new(vec![0x13; 8], regions, vec![0xAB; 10], vec![], endpoints())
        .expect("valid");
    assert_eq!(blob.ro_data.len(), 2 * PAGE_SIZE as usize);
    assert_eq!(blob.rw_data.len(), PAGE_SIZE as usize);
    assert_eq!(&blob.ro_data[..10], &[0xAB; 10]);
    assert!(blob.ro_data[10..].iter().all(|&b| b == 0));
}

#[test]
fn memory_image_places_each_region_at_its_offset() {
    let regions = Regions {
        stack_pages: 1,
        ro_pages: 1,
        rw_pages: 1,
        heap_pages: 1,
    };
    let blob =
        ProgramBlob::new(vec![], regions, vec![0xAA], vec![0xBB], endpoints()).expect("valid");
    let image = blob.memory_image();
    assert_eq!(image.len(), 4 * PAGE_SIZE as usize);
    let page = PAGE_SIZE as usize;
    assert_eq!(image[0], 0); // stack: zero
    assert_eq!(image[page], 0xAA); // ro
    assert_eq!(image[2 * page], 0xBB); // rw
    assert_eq!(image[3 * page], 0); // heap: zero
}

#[test]
fn rejects_a_program_with_no_endpoints() {
    let err =
        ProgramBlob::new(vec![], Regions::default(), vec![], vec![], BTreeMap::new()).unwrap_err();
    assert_eq!(err, InvalidProgram::NoEndpoints);
}

#[test]
fn rejects_code_that_would_overlap_data_base() {
    let len = nub_program::abi::MAX_CODE_SIZE as usize + 1;
    let err = ProgramBlob::new(
        vec![0; len],
        Regions {
            stack_pages: 1,
            ..Default::default()
        },
        vec![],
        vec![],
        endpoints(),
    )
    .unwrap_err();
    assert_eq!(err, InvalidProgram::CodeTooLarge { len });
}

#[test]
fn rejects_data_past_the_four_gib_guest_range() {
    let regions = Regions {
        stack_pages: u32::MAX / PAGE_SIZE,
        ro_pages: 0,
        rw_pages: 0,
        heap_pages: 0,
    };
    let err = ProgramBlob::new(vec![], regions, vec![], vec![], endpoints()).unwrap_err();
    assert!(matches!(err, InvalidProgram::DataOutOfRange { .. }));
}

/// `validate` must catch a hand-built blob that skipped `new`.
#[test]
fn validate_catches_a_region_length_mismatch() {
    let blob = ProgramBlob {
        code: vec![],
        regions: Regions {
            stack_pages: 1,
            ro_pages: 2,
            rw_pages: 0,
            heap_pages: 0,
        },
        ro_data: vec![0; 7],
        rw_data: vec![],
        endpoints: endpoints(),
    };
    assert_eq!(
        blob.validate().unwrap_err(),
        InvalidProgram::RegionLengthMismatch {
            kind: RegionKind::Ro,
            expected: 2 * PAGE_SIZE as usize,
            actual: 7,
        }
    );
}
