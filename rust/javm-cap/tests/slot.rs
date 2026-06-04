use javm_cap::{Key, SlotPath, key_from_regs, key_to_regs};

#[test]
fn key_regs_round_trip() {
    // Pack/unpack a meter_key / quota_key through the unit handle's registers.
    for bytes in [
        vec![],
        vec![0u8],
        vec![7u8],
        vec![1u8, 2, 3, 4, 5, 6, 7, 8], // full MAX_KEY_LEN
        vec![0xFF, 0x00, 0xFF],
    ] {
        let key = Key::from(&bytes[..]);
        let (packed, len) = key_to_regs(&key);
        assert_eq!(key_from_regs(packed, len), key, "round trip for {bytes:?}");
    }
}

#[test]
fn key_to_regs_rejects_oversized_key() {
    let too_long = Key::from(&[1u8; 9][..]); // 9 > MAX_KEY_LEN (8)
    let r = std::panic::catch_unwind(|| key_to_regs(&too_long));
    assert!(r.is_err(), "a >8-byte key must not pack into one register");
}

#[test]
fn slot_key_from_byte_is_single_byte() {
    let k = Key::from(7u8);
    assert_eq!(k.as_slice(), &[7u8]);
    assert_eq!(k.diag_id(), 7);
    assert!(!k.is_empty());
}

#[test]
fn slot_key_from_bytes_multi() {
    let k = Key::from(&[1u8, 2, 3][..]);
    assert_eq!(k.as_slice(), &[1u8, 2, 3]);
    // diag_id folds a multi-byte key to its first byte (diagnostics only).
    assert_eq!(k.diag_id(), 1);
}

#[test]
fn slot_key_byte_vs_empty_distinct() {
    // The empty key and the 1-byte `[0]` key are different logical keys.
    let zero_byte = Key::from(0u8);
    let empty = Key::from(&[][..]);
    assert!(!zero_byte.is_empty());
    assert!(empty.is_empty());
    assert_ne!(zero_byte, empty);
}

#[test]
fn slot_key_ord_is_lexicographic() {
    // `Key` is a BTreeMap key in the host `Image`; ordering must be
    // lexicographic-by-byte (shorter prefix sorts first).
    assert!(Key::from(1u8) < Key::from(2u8));
    assert!(Key::from(&[1u8][..]) < Key::from(&[1u8, 0][..]));
}

#[test]
fn slot_path_root_single_step() {
    let p = SlotPath::root(Key::from(7u8));
    assert!(p.is_root_slot());
    assert_eq!(p.target(), Some(&Key::from(7u8)));
    assert_eq!(p.prefix(), &[] as &[Key]);
    assert_eq!(p.len(), 1);
}

#[test]
fn slot_path_nested() {
    let p = SlotPath::new([Key::from(7u8), Key::from(3u8), Key::from(12u8)]).unwrap();
    assert!(!p.is_root_slot());
    assert_eq!(p.target(), Some(&Key::from(12u8)));
    assert_eq!(p.prefix(), &[Key::from(7u8), Key::from(3u8)]);
    assert_eq!(p.steps().len(), 3);
}

#[test]
fn slot_path_empty_rejected() {
    assert!(SlotPath::new(core::iter::empty()).is_err());
}

#[test]
fn slot_path_equality_by_value() {
    let a = SlotPath::root(Key::from(5u8));
    let b = SlotPath::new([Key::from(5u8)]).unwrap();
    assert_eq!(a, b);
}

#[test]
fn slot_key_ssz_matches_vec_u8() {
    // `Key`'s SSZ wire/hash form must be identical to `Vec<u8>` of the
    // same bytes (it forwards through `#[ssz(transparent)]` to the
    // `SmallVec` impl, which mirrors `Vec`).
    use ssz::{Encode, hash_tree_root};
    for bytes in [vec![], vec![7u8], vec![1u8, 2, 3, 4, 5]] {
        let key = Key::from(&bytes[..]);
        assert_eq!(key.as_ssz_bytes(), bytes.as_ssz_bytes());
        assert_eq!(hash_tree_root(&key), hash_tree_root(&bytes));
    }
}

#[test]
fn slot_path_ssz_roundtrip() {
    use ssz::{Decode, Encode};
    let p = SlotPath::new([Key::from(7u8), Key::from(&[9u8, 9][..])]).unwrap();
    let bytes = p.as_ssz_bytes();
    let back = SlotPath::from_ssz_bytes(&bytes).unwrap();
    assert_eq!(p, back);
}
