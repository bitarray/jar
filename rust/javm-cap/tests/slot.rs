use javm_cap::{SlotIdx, SlotPath};

#[test]
fn slot_idx_fits_within_size_log() {
    assert!(SlotIdx(0).fits(0)); // 2^0 = 1 slot; idx 0 fits
    assert!(!SlotIdx(1).fits(0)); // doesn't fit
    assert!(SlotIdx(255).fits(8)); // 2^8 = 256
    assert!(!SlotIdx(256).fits(8));
    assert!(SlotIdx(255).fits(16));
    assert!(SlotIdx(u32::MAX).fits(32));
}

#[test]
fn slot_idx_conversions() {
    assert_eq!(SlotIdx::from(7u8).get(), 7);
    assert_eq!(SlotIdx::from(1000u16).get(), 1000);
    assert_eq!(SlotIdx(42).as_usize(), 42);
}

#[test]
fn slot_path_root_single_step() {
    let p = SlotPath::root(SlotIdx(7));
    assert!(p.is_root_slot());
    assert_eq!(p.target(), SlotIdx(7));
    assert_eq!(p.prefix(), &[]);
}

#[test]
fn slot_path_nested() {
    let p = SlotPath::new(vec![SlotIdx(7), SlotIdx(3), SlotIdx(12)]).unwrap();
    assert!(!p.is_root_slot());
    assert_eq!(p.target(), SlotIdx(12));
    assert_eq!(p.prefix(), &[SlotIdx(7), SlotIdx(3)]);
}

#[test]
fn slot_path_empty_rejected() {
    assert!(SlotPath::new(vec![]).is_err());
}

#[test]
fn slot_path_equality_by_value() {
    let a = SlotPath::root(SlotIdx(5));
    let b = SlotPath::new(vec![SlotIdx(5)]).unwrap();
    assert_eq!(a, b);
}
