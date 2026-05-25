use sha2::Sha256;
use ssz::{Bitlist, Bitvector, Decode, Encode, HashTreeRoot};

#[test]
fn bitvector_set_get() {
    let mut bv: Bitvector<10> = Bitvector::default();
    bv.set(0, true);
    bv.set(9, true);
    assert!(bv.get(0));
    assert!(!bv.get(1));
    assert!(bv.get(9));
}

#[test]
fn bitvector_round_trip() {
    let mut bv: Bitvector<10> = Bitvector::default();
    bv.set(0, true);
    bv.set(3, true);
    bv.set(9, true);
    let bytes = bv.as_ssz_bytes();
    let decoded = Bitvector::<10>::from_ssz_bytes(&bytes).unwrap();
    assert_eq!(bv, decoded);
}

#[test]
fn bitvector_rejects_excess_bits() {
    // N=4, but high nibble has a set bit
    let raw = [0b00010000u8];
    assert!(Bitvector::<4>::from_slice(&raw).is_err());
}

#[test]
fn bitlist_empty_round_trip() {
    let bl: Bitlist<256> = Bitlist::new();
    let bytes = bl.as_ssz_bytes();
    // Empty bitlist: sentinel bit at position 0 → byte 0x01.
    assert_eq!(bytes, vec![0x01]);
    let decoded = Bitlist::<256>::from_ssz_bytes(&bytes).unwrap();
    assert_eq!(bl, decoded);
    assert_eq!(decoded.len(), 0);
}

#[test]
fn bitlist_round_trip() {
    let bits = [true, false, true, true, false, true, false, false, true];
    let bl: Bitlist<256> = Bitlist::from_bits(&bits).unwrap();
    let bytes = bl.as_ssz_bytes();
    let decoded = Bitlist::<256>::from_ssz_bytes(&bytes).unwrap();
    assert_eq!(bl, decoded);
    assert_eq!(decoded.len(), 9);
    for (i, b) in bits.iter().enumerate() {
        assert_eq!(decoded.get(i as u64), Some(*b));
    }
}

#[test]
fn bitlist_hash_matches_after_round_trip() {
    let bits = [true, false, true, false, true];
    let bl: Bitlist<256> = Bitlist::from_bits(&bits).unwrap();
    let h1 = bl.hash_tree_root::<Sha256>();
    let bytes = bl.as_ssz_bytes();
    let bl2 = Bitlist::<256>::from_ssz_bytes(&bytes).unwrap();
    let h2 = bl2.hash_tree_root::<Sha256>();
    assert_eq!(h1, h2);
}
