use sha2::Sha256;
use ssz::merkle::{ceil_log2, hash_pair};
use ssz::{merkleize, zero_hash};

#[test]
fn zero_hash_depth_0_is_zero() {
    assert_eq!(zero_hash::<Sha256>(0), [0u8; 32]);
}

#[test]
fn zero_hash_depth_1_is_h00() {
    let expected = hash_pair::<Sha256>(&[0u8; 32], &[0u8; 32]);
    assert_eq!(zero_hash::<Sha256>(1), expected);
}

#[test]
fn merkleize_single_chunk_returns_chunk() {
    let chunk = [0xAAu8; 32];
    assert_eq!(merkleize::<Sha256>(&[chunk], 1), chunk);
}

#[test]
fn merkleize_two_chunks() {
    let a = [0xAAu8; 32];
    let b = [0xBBu8; 32];
    let expected = hash_pair::<Sha256>(&a, &b);
    assert_eq!(merkleize::<Sha256>(&[a, b], 2), expected);
}

#[test]
fn merkleize_empty_with_limit_zero_is_zero_chunk() {
    assert_eq!(merkleize::<Sha256>(&[], 0), [0u8; 32]);
}

#[test]
fn merkleize_padded_with_zero_hashes() {
    // 3 chunks → padded to 4. Right-subtree right leaf is zero_hash(0).
    let a = [1u8; 32];
    let b = [2u8; 32];
    let c = [3u8; 32];
    let left = hash_pair::<Sha256>(&a, &b);
    let right = hash_pair::<Sha256>(&c, &[0u8; 32]);
    let root = hash_pair::<Sha256>(&left, &right);
    assert_eq!(merkleize::<Sha256>(&[a, b, c], 4), root);
}

#[test]
fn pack_bytes_pads_tail_with_zeros() {
    let chunks = ssz::pack_bytes(&[1, 2, 3]);
    assert_eq!(chunks.len(), 1);
    let mut expected = [0u8; 32];
    expected[0] = 1;
    expected[1] = 2;
    expected[2] = 3;
    assert_eq!(chunks[0], expected);
}

#[test]
fn merkleize_huge_limit_finishes_fast() {
    // Regression: previous algorithm was O(padded_len), so a 4-billion
    // limit would try to allocate a 2-billion-entry Vec. Now O(depth).
    // limit = 1 << 32 → padded_len = 2^32, depth = 32 hash operations
    // after the initial input fold. Should complete in microseconds.
    let chunk = [0xAAu8; 32];
    let root = merkleize::<Sha256>(&[chunk], 1usize << 32);

    // Equivalent: a single real leaf in a depth-32 tree; sibling at
    // each level is zero_hash(d).
    let mut current = chunk;
    for d in 0..32 {
        current = hash_pair::<Sha256>(&current, &zero_hash::<Sha256>(d));
    }
    assert_eq!(root, current);
}

#[test]
fn merkleize_empty_with_large_limit_is_zero_subtree() {
    // Empty input, limit = 1024 → root must be zero_hash(10) without
    // materializing 1024 zero leaves.
    let root = merkleize::<Sha256>(&[], 1024);
    assert_eq!(root, zero_hash::<Sha256>(10));
}

#[test]
fn merkleize_three_chunks_with_large_limit() {
    // 3 chunks, limit = 16 → padded_len = 16, depth = 4.
    let a = [1u8; 32];
    let b = [2u8; 32];
    let c = [3u8; 32];
    let root = merkleize::<Sha256>(&[a, b, c], 16);

    // Compute by hand. Level 0 has [a, b, c]; level 1 has
    // [H(a,b), H(c, zero_h0)]; level 2 has [H(L1[0], L1[1])];
    // level 3 has [H(L2[0], zero_h2)]; level 4 has [H(L3[0], zero_h3)].
    let l1_0 = hash_pair::<Sha256>(&a, &b);
    let l1_1 = hash_pair::<Sha256>(&c, &zero_hash::<Sha256>(0));
    let l2_0 = hash_pair::<Sha256>(&l1_0, &l1_1);
    let l3_0 = hash_pair::<Sha256>(&l2_0, &zero_hash::<Sha256>(2));
    let l4_0 = hash_pair::<Sha256>(&l3_0, &zero_hash::<Sha256>(3));
    assert_eq!(root, l4_0);
}

#[test]
fn ceil_log2_examples() {
    assert_eq!(ceil_log2(0), 0);
    assert_eq!(ceil_log2(1), 0);
    assert_eq!(ceil_log2(2), 1);
    assert_eq!(ceil_log2(3), 2);
    assert_eq!(ceil_log2(4), 2);
    assert_eq!(ceil_log2(5), 3);
    assert_eq!(ceil_log2(8), 3);
    assert_eq!(ceil_log2(9), 4);
}
