use javm_cap::Blake2b256;
use javm_cap::Hash;

#[test]
fn empty_hash_is_deterministic() {
    let h1 = Blake2b256::hash(b"");
    let h2 = Blake2b256::hash(b"");
    assert_eq!(h1, h2);
}

#[test]
fn different_inputs_different_hashes() {
    assert_ne!(Blake2b256::hash(b"hello"), Blake2b256::hash(b"world"));
    assert_ne!(Blake2b256::hash(b"a"), Blake2b256::hash(b"b"));
}

#[test]
fn hash_pair_matches_hash_of_concat() {
    let a: &[u8] = b"foo";
    let b: &[u8] = b"barbaz";
    let mut joined = Vec::new();
    joined.extend_from_slice(a);
    joined.extend_from_slice(b);
    assert_eq!(Blake2b256::hash_pair(a, b), Blake2b256::hash(&joined));
}

#[test]
fn hash_pair_empty_matches_single() {
    let a: &[u8] = b"";
    let b: &[u8] = b"only";
    assert_eq!(Blake2b256::hash_pair(a, b), Blake2b256::hash(b"only"));
}
