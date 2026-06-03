use javm_cap::{SlotKey, SlotPath};

#[test]
fn slot_key_from_byte_is_single_byte() {
    let k = SlotKey::from(7u8);
    assert_eq!(k.as_slice(), &[7u8]);
    assert_eq!(k.diag_id(), 7);
    assert!(!k.is_empty());
}

#[test]
fn slot_key_from_bytes_multi() {
    let k = SlotKey::from(&[1u8, 2, 3][..]);
    assert_eq!(k.as_slice(), &[1u8, 2, 3]);
    // diag_id folds a multi-byte key to its first byte (diagnostics only).
    assert_eq!(k.diag_id(), 1);
}

#[test]
fn slot_key_byte_vs_empty_distinct() {
    // The empty key and the 1-byte `[0]` key are different logical keys.
    let zero_byte = SlotKey::from(0u8);
    let empty = SlotKey::from(&[][..]);
    assert!(!zero_byte.is_empty());
    assert!(empty.is_empty());
    assert_ne!(zero_byte, empty);
}

#[test]
fn slot_key_ord_is_lexicographic() {
    // `SlotKey` is a BTreeMap key in the host `Image`; ordering must be
    // lexicographic-by-byte (shorter prefix sorts first).
    assert!(SlotKey::from(1u8) < SlotKey::from(2u8));
    assert!(SlotKey::from(&[1u8][..]) < SlotKey::from(&[1u8, 0][..]));
}

#[test]
fn slot_path_root_single_step() {
    let p = SlotPath::root(SlotKey::from(7u8));
    assert!(p.is_root_slot());
    assert_eq!(p.target(), Some(&SlotKey::from(7u8)));
    assert_eq!(p.prefix(), &[] as &[SlotKey]);
    assert_eq!(p.len(), 1);
}

#[test]
fn slot_path_nested() {
    let p = SlotPath::new([SlotKey::from(7u8), SlotKey::from(3u8), SlotKey::from(12u8)]).unwrap();
    assert!(!p.is_root_slot());
    assert_eq!(p.target(), Some(&SlotKey::from(12u8)));
    assert_eq!(p.prefix(), &[SlotKey::from(7u8), SlotKey::from(3u8)]);
    assert_eq!(p.steps().len(), 3);
}

#[test]
fn slot_path_empty_rejected() {
    assert!(SlotPath::new(core::iter::empty()).is_err());
}

#[test]
fn slot_path_equality_by_value() {
    let a = SlotPath::root(SlotKey::from(5u8));
    let b = SlotPath::new([SlotKey::from(5u8)]).unwrap();
    assert_eq!(a, b);
}

#[test]
fn slot_key_ssz_matches_vec_u8() {
    // `SlotKey`'s SSZ wire/hash form must be identical to `Vec<u8>` of the
    // same bytes (it forwards through `#[ssz(transparent)]` to the
    // `SmallVec` impl, which mirrors `Vec`).
    use ssz::{Encode, hash_tree_root};
    for bytes in [vec![], vec![7u8], vec![1u8, 2, 3, 4, 5]] {
        let key = SlotKey::from(&bytes[..]);
        assert_eq!(key.as_ssz_bytes(), bytes.as_ssz_bytes());
        assert_eq!(hash_tree_root(&key), hash_tree_root(&bytes));
    }
}

#[test]
fn slot_path_ssz_roundtrip() {
    use ssz::{Decode, Encode};
    let p = SlotPath::new([SlotKey::from(7u8), SlotKey::from(&[9u8, 9][..])]).unwrap();
    let bytes = p.as_ssz_bytes();
    let back = SlotPath::from_ssz_bytes(&bytes).unwrap();
    assert_eq!(p, back);
}
