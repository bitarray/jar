//! `RadixMap<V, KEY_BYTES>` — canonical-root, binding, wire, and rkyv tests.
//!
//! The value type is `[u8; 32]` so that `value_root == value bytes`
//! (a single SSZ chunk merkleizes to itself), letting tests construct exact
//! leaf/branch preimages and mount the binding-break forgery the design must
//! defeat.

use proptest::prelude::*;
use sha2::Sha256;
use ssz::radix::{
    BRANCH_TAG, EMPTY, LEAF_TAG, RadixProof, RadixTerminal, RadixVerdict, bit, branch_hash,
    leaf_hash, verify,
};
use ssz::{HashTreeRoot, MissingOr, RadixMap};

type V = [u8; 32];

fn mat(b: [u8; 32]) -> MissingOr<V> {
    MissingOr::Materialized(b)
}

/// Independent reference root: a filter-based recursion (not the
/// `partition_point`-on-sorted-slice the implementation uses), so it
/// cross-checks the impl's structure. Catches any algorithm/prose drift.
fn ref_root<const KB: usize>(entries: &[([u8; KB], [u8; 32])], depth: usize) -> [u8; 32] {
    match entries.len() {
        0 => EMPTY,
        1 => leaf_hash::<Sha256>(&entries[0].0, &entries[0].1),
        _ => {
            if depth >= KB * 8 {
                return leaf_hash::<Sha256>(&entries[0].0, &entries[0].1);
            }
            let l: Vec<_> = entries
                .iter()
                .filter(|(k, _)| bit(k, depth) == 0)
                .cloned()
                .collect();
            let r: Vec<_> = entries
                .iter()
                .filter(|(k, _)| bit(k, depth) == 1)
                .cloned()
                .collect();
            branch_hash::<Sha256>(&ref_root(&l, depth + 1), &ref_root(&r, depth + 1))
        }
    }
}

#[test]
fn empty_map_root_is_zero() {
    let m: RadixMap<V, 8> = RadixMap::new();
    assert_eq!(m.hash_tree_root::<Sha256>(), EMPTY);
    assert!(m.is_empty());
    assert_eq!(m.len(), 0);
}

#[test]
fn single_entry_is_a_leaf() {
    let key = [0xABu8; 8];
    let val = [0xCDu8; 32];
    let mut m: RadixMap<V, 8> = RadixMap::new();
    m.insert(key, mat(val));
    // A lone key is a single leaf (shallow), regardless of key bits.
    assert_eq!(
        m.hash_tree_root::<Sha256>(),
        leaf_hash::<Sha256>(&key, &val)
    );
}

#[test]
fn two_entries_diverging_at_bit_0() {
    let k0 = [0x00u8; 8]; // bit 0 = 0
    let mut k1 = [0x00u8; 8];
    k1[0] = 0x80; // bit 0 = 1
    let v0 = [0x11u8; 32];
    let v1 = [0x22u8; 32];
    let mut m: RadixMap<V, 8> = RadixMap::new();
    m.insert(k1, mat(v1)); // insert out of order; sorted storage normalizes
    m.insert(k0, mat(v0));
    let expect = branch_hash::<Sha256>(
        &leaf_hash::<Sha256>(&k0, &v0),
        &leaf_hash::<Sha256>(&k1, &v1),
    );
    assert_eq!(m.hash_tree_root::<Sha256>(), expect);
}

#[test]
fn two_entries_diverging_at_last_bit() {
    // KEY_BYTES = 1 → 8 bits. Keys 0x00 and 0x01 share bits 0..6, diverge at
    // bit 7 (the LSB). The shared 7-bit prefix is materialized as a chain of
    // one-sided branches with EMPTY siblings, terminating in a 2-leaf branch.
    let k0 = [0x00u8; 1];
    let k1 = [0x01u8; 1];
    let v0 = [0x11u8; 32];
    let v1 = [0x22u8; 32];
    let mut m: RadixMap<V, 1> = RadixMap::new();
    m.insert(k0, mat(v0));
    m.insert(k1, mat(v1));

    // Build the expected root bottom-up: 7 one-sided branches (left child
    // populated, right EMPTY) above a final 2-leaf branch.
    let mut acc = branch_hash::<Sha256>(
        &leaf_hash::<Sha256>(&k0, &v0),
        &leaf_hash::<Sha256>(&k1, &v1),
    );
    for _ in 0..7 {
        acc = branch_hash::<Sha256>(&acc, &EMPTY);
    }
    assert_eq!(m.hash_tree_root::<Sha256>(), acc);
    assert_eq!(
        m.hash_tree_root::<Sha256>(),
        ref_root::<1>(&[(k0, v0), (k1, v1)], 0)
    );
}

#[test]
fn missing_or_substitution_preserves_root() {
    // A Missing(value_root) leaf hashes identically to a Materialized leaf.
    let key = [0x07u8; 8];
    let val = [0x42u8; 32];
    let h = val; // value_root of [u8;32] is the bytes themselves
    let mut a: RadixMap<V, 8> = RadixMap::new();
    a.insert(key, MissingOr::Materialized(val));
    let mut b: RadixMap<V, 8> = RadixMap::new();
    b.insert(key, MissingOr::Missing(h));
    assert_eq!(a.hash_tree_root::<Sha256>(), b.hash_tree_root::<Sha256>());
}

#[test]
fn domains_are_distinct() {
    // empty / leaf / branch occupy distinct hash domains.
    let l = leaf_hash::<Sha256>(&[0u8; 8], &[0u8; 32]);
    let b = branch_hash::<Sha256>(&[0u8; 32], &[0u8; 32]);
    assert_ne!(l, EMPTY);
    assert_ne!(b, EMPTY);
    assert_ne!(l, b);
    assert_eq!(LEAF_TAG, 0x00);
    assert_eq!(BRANCH_TAG, 0x01);
}

#[test]
fn binding_tag_defeats_leaf_branch_confusion() {
    // The fatal break the design must close: for KEY_BYTES <= 32 a bare
    // `hash_pair` leaf would be byte-identical to a branch, so the one-entry
    // map {(H_L, Missing(H_R))} would share a root with the two-entry branch
    // branch(leaf(k0,v0), leaf(k1,v1)). With distinct leaf/branch tags it does
    // not, under collision resistance alone.
    let k0 = [0x00u8; 32]; // bit 0 = 0
    let mut k1 = [0x00u8; 32];
    k1[0] = 0x80; // bit 0 = 1
    let v0 = [0x11u8; 32];
    let v1 = [0x22u8; 32];

    let mut honest: RadixMap<V, 32> = RadixMap::new();
    honest.insert(k0, mat(v0));
    honest.insert(k1, mat(v1));
    let root = honest.hash_tree_root::<Sha256>();

    let h_l = leaf_hash::<Sha256>(&k0, &v0);
    let h_r = leaf_hash::<Sha256>(&k1, &v1);
    // Structure check: root is exactly the tagged branch of the two leaves.
    assert_eq!(root, branch_hash::<Sha256>(&h_l, &h_r));

    // Attacker forgery attempt: present H_L as a 32-byte key and Missing(H_R)
    // as its value. Its leaf = D(LEAF_TAG || H_L || H_R); the honest root =
    // D(BRANCH_TAG || H_L || H_R). The differing tag byte makes them unequal.
    let mut forged: RadixMap<V, 32> = RadixMap::new();
    forged.insert(h_l, MissingOr::Missing(h_r));
    let forged_root = forged.hash_tree_root::<Sha256>();
    assert_eq!(forged_root, leaf_hash::<Sha256>(&h_l, &h_r));
    assert_ne!(forged_root, root, "leaf/branch tag must defeat the forgery");
}

#[test]
fn radix_root_differs_from_list_root() {
    // Dense != Vector: a RadixMap root is not byte-equal to an SSZ List root
    // over the same value roots (tagged + key-committed nodes, no mix_in_length).
    let mut m: RadixMap<V, 8> = RadixMap::new();
    m.insert([0u8; 8], mat([1u8; 32]));
    m.insert([1u8; 8], mat([2u8; 32]));
    let list: ssz::List<V, 1024> = ssz::List::from_slice(&[[1u8; 32], [2u8; 32]]).unwrap();
    assert_ne!(
        m.hash_tree_root::<Sha256>(),
        list.hash_tree_root::<Sha256>()
    );
}

#[test]
fn order_independent_root() {
    let entries: Vec<([u8; 4], [u8; 32])> = (0u32..40)
        .map(|i| {
            let k = (i.wrapping_mul(2654435761)).to_be_bytes();
            let mut v = [0u8; 32];
            v[..4].copy_from_slice(&i.to_le_bytes());
            (k, v)
        })
        .collect();

    let mut forward: RadixMap<V, 4> = RadixMap::new();
    for (k, v) in &entries {
        forward.insert(*k, mat(*v));
    }
    let mut reverse: RadixMap<V, 4> = RadixMap::new();
    for (k, v) in entries.iter().rev() {
        reverse.insert(*k, mat(*v));
    }
    assert_eq!(
        forward.hash_tree_root::<Sha256>(),
        reverse.hash_tree_root::<Sha256>()
    );
    assert_eq!(
        forward.hash_tree_root::<Sha256>(),
        ref_root::<4>(&entries, 0)
    );
}

#[test]
fn get_insert_remove() {
    let mut m: RadixMap<V, 4> = RadixMap::new();
    assert_eq!(m.get(&[1, 2, 3, 4]), None);
    assert_eq!(m.insert([1, 2, 3, 4], mat([9u8; 32])), None);
    assert!(matches!(m.get(&[1, 2, 3, 4]), Some(MissingOr::Materialized(b)) if *b == [9u8; 32]));
    // Overwrite returns the old value.
    let old = m.insert([1, 2, 3, 4], mat([8u8; 32]));
    assert!(matches!(old, Some(MissingOr::Materialized(b)) if b == [9u8; 32]));
    assert_eq!(m.len(), 1);
    let removed = m.remove(&[1, 2, 3, 4]);
    assert!(removed.is_some());
    assert_eq!(m.get(&[1, 2, 3, 4]), None);
    assert!(m.is_empty());
}

#[test]
fn encode_decode_roundtrip() {
    let mut m: RadixMap<V, 8> = RadixMap::new();
    for i in 0u64..25 {
        let k = (i.wrapping_mul(0x9E3779B97F4A7C15)).to_be_bytes();
        let mut v = [0u8; 32];
        v[..8].copy_from_slice(&i.to_le_bytes());
        // Mix Materialized and Missing values.
        if i % 3 == 0 {
            m.insert(k, MissingOr::Missing(v));
        } else {
            m.insert(k, mat(v));
        }
    }
    let bytes = ssz::Encode::as_ssz_bytes(&m);
    let decoded = <RadixMap<V, 8> as ssz::Decode>::from_ssz_bytes(&bytes).expect("decode");
    assert_eq!(m, decoded);
    // Hash survives the roundtrip.
    assert_eq!(
        m.hash_tree_root::<Sha256>(),
        decoded.hash_tree_root::<Sha256>()
    );
}

#[test]
fn empty_map_encode_decode() {
    let m: RadixMap<V, 8> = RadixMap::new();
    let bytes = ssz::Encode::as_ssz_bytes(&m);
    // entries_offset (4) only.
    assert_eq!(bytes, 4u32.to_le_bytes());
    let decoded = <RadixMap<V, 8> as ssz::Decode>::from_ssz_bytes(&bytes).expect("decode");
    assert!(decoded.is_empty());
}

#[test]
fn decode_rejects_bad_entries_offset() {
    // entries_offset must be 4.
    let mut bytes = 5u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&[0u8; 8]);
    assert!(<RadixMap<V, 8> as ssz::Decode>::from_ssz_bytes(&bytes).is_err());
}

#[test]
fn decode_rejects_unsorted_keys() {
    // Hand-build a 2-entry list with descending keys; decode must reject.
    let mut m: RadixMap<V, 8> = RadixMap::new();
    m.insert([0u8; 8], mat([1u8; 32]));
    m.insert([1u8; 8], mat([2u8; 32]));
    let mut bytes = ssz::Encode::as_ssz_bytes(&m);
    // Swap the two keys' bytes in place to make them descending. Locate the
    // two entry containers via the offset table (entries list begins at 4).
    // Entry container layout: [key(8)][value_offset(4)][MissingOr payload].
    // The offset table is at [4..4+2*4]; each entry has key at its container
    // start. Rather than parse, just corrupt: set first key to 0xFF.. so it
    // is no longer < second key.
    // entries_offset=4; offset table starts at byte 4; first entry container
    // starts at 4 + first_offset. We instead rebuild bytes with a known bad
    // ordering by re-encoding manually is overkill — assert the simpler
    // duplicate-key rejection below; here flip the leading entry's first key
    // byte to 0xFF (> second key's 0x00), breaking ascending order.
    // The first entry's key starts right after the 2*4-byte offset table:
    // payload base = 4 (entries_offset) + 0 (we read first offset relative to
    // list). Compute it from the encoding.
    let first_off = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize; // = 8
    let entry0_key = 4 + first_off; // absolute index of entry 0's key byte 0
    bytes[entry0_key] = 0xFF;
    assert!(<RadixMap<V, 8> as ssz::Decode>::from_ssz_bytes(&bytes).is_err());
}

#[test]
fn rkyv_roundtrip_and_canonicalizes() {
    let mut m: RadixMap<V, 8> = RadixMap::new();
    for i in 0u64..16 {
        let k = (i.wrapping_mul(0x9E3779B97F4A7C15)).to_be_bytes();
        let mut v = [0u8; 32];
        v[..8].copy_from_slice(&i.to_le_bytes());
        m.insert(k, mat(v));
    }
    let aligned = rkyv::to_bytes::<rkyv::rancor::Error>(&m).expect("rkyv encode");
    let archived =
        rkyv::access::<rkyv::Archived<RadixMap<V, 8>>, rkyv::rancor::Error>(aligned.as_slice())
            .expect("rkyv access");
    let back: RadixMap<V, 8> = rkyv::deserialize::<RadixMap<V, 8>, rkyv::rancor::Error>(archived)
        .expect("rkyv deserialize");
    assert_eq!(m, back);
    assert_eq!(
        m.hash_tree_root::<Sha256>(),
        back.hash_tree_root::<Sha256>()
    );
}

// --------------------------------------------------------------------------
// Proofs
// --------------------------------------------------------------------------

/// A small KB=2 map exercising membership, Empty non-membership, and
/// DivergingLeaf non-membership terminals.
fn proof_fixture() -> RadixMap<V, 2> {
    let mut m: RadixMap<V, 2> = RadixMap::new();
    m.insert([0x00, 0x00], mat([0xA0u8; 32]));
    m.insert([0x00, 0x01], mat([0xA1u8; 32]));
    m.insert([0x80, 0x00], mat([0xB0u8; 32]));
    m
}

#[test]
fn membership_proof_verifies() {
    let m = proof_fixture();
    let root = m.hash_tree_root::<Sha256>();
    for key in [[0x00u8, 0x00], [0x00, 0x01], [0x80, 0x00]] {
        let p = m.prove::<Sha256>(&key);
        assert!(matches!(p.terminal, RadixTerminal::Leaf { .. }));
        assert_eq!(
            verify::<Sha256, V, 2>(&root, &key, &p),
            Some(RadixVerdict::Present)
        );
    }
}

#[test]
fn non_membership_empty_terminal() {
    let m = proof_fixture();
    let root = m.hash_tree_root::<Sha256>();
    // 0x4000: bit0=0 routes into the {0x0000,0x0001} cluster, then diverges
    // into an EMPTY sibling.
    let key = [0x40u8, 0x00];
    let p = m.prove::<Sha256>(&key);
    assert!(matches!(p.terminal, RadixTerminal::Empty));
    assert_eq!(
        verify::<Sha256, V, 2>(&root, &key, &p),
        Some(RadixVerdict::Absent)
    );
}

#[test]
fn non_membership_diverging_leaf() {
    let m = proof_fixture();
    let root = m.hash_tree_root::<Sha256>();
    // 0x8001: bit0=1 routes to the lone {0x8000} leaf — a diverging leaf.
    let key = [0x80u8, 0x01];
    let p = m.prove::<Sha256>(&key);
    assert!(matches!(p.terminal, RadixTerminal::DivergingLeaf { .. }));
    assert_eq!(
        verify::<Sha256, V, 2>(&root, &key, &p),
        Some(RadixVerdict::Absent)
    );
}

#[test]
fn non_membership_against_empty_and_single_maps() {
    // Empty map: any key is absent (Empty terminal at depth 0).
    let empty: RadixMap<V, 2> = RadixMap::new();
    let er = empty.hash_tree_root::<Sha256>();
    let p = empty.prove::<Sha256>(&[0x12, 0x34]);
    assert!(matches!(p.terminal, RadixTerminal::Empty));
    assert_eq!(
        verify::<Sha256, V, 2>(&er, &[0x12, 0x34], &p),
        Some(RadixVerdict::Absent)
    );

    // Single-key map: a different key is a DivergingLeaf at depth 0.
    let mut single: RadixMap<V, 2> = RadixMap::new();
    single.insert([0xAA, 0xBB], mat([7u8; 32]));
    let sr = single.hash_tree_root::<Sha256>();
    let p = single.prove::<Sha256>(&[0xAA, 0xBC]);
    assert!(matches!(p.terminal, RadixTerminal::DivergingLeaf { .. }));
    assert_eq!(
        verify::<Sha256, V, 2>(&sr, &[0xAA, 0xBC], &p),
        Some(RadixVerdict::Absent)
    );
    // ...and membership of the present key.
    let pm = single.prove::<Sha256>(&[0xAA, 0xBB]);
    assert_eq!(
        verify::<Sha256, V, 2>(&sr, &[0xAA, 0xBB], &pm),
        Some(RadixVerdict::Present)
    );
}

#[test]
fn verify_rejects_tampered_and_malformed_proofs() {
    let m = proof_fixture();
    let root = m.hash_tree_root::<Sha256>();
    let key = [0x00u8, 0x00];
    let good = m.prove::<Sha256>(&key);

    // Tamper a sibling hash.
    if !good.siblings.is_empty() {
        let mut bad = good.clone();
        bad.siblings[0].1[0] ^= 0xFF;
        assert_eq!(verify::<Sha256, V, 2>(&root, &key, &bad), None);
    }

    // term_depth beyond KEY_BITS.
    let mut bad = good.clone();
    bad.term_depth = 17;
    assert_eq!(verify::<Sha256, V, 2>(&root, &key, &bad), None);

    // Sibling level >= term_depth.
    let mut bad = good.clone();
    bad.siblings.push((bad.term_depth, [9u8; 32]));
    assert_eq!(verify::<Sha256, V, 2>(&root, &key, &bad), None);

    // Wrong root.
    let mut wrong = root;
    wrong[0] ^= 0xFF;
    assert_eq!(verify::<Sha256, V, 2>(&wrong, &key, &good), None);

    // DivergingLeaf whose other_key == queried key is rejected.
    let bad = RadixProof::<V, 2> {
        term_depth: 0,
        siblings: Vec::new(),
        terminal: RadixTerminal::DivergingLeaf {
            other_key: key,
            other_value_root: [0u8; 32],
        },
    };
    assert_eq!(verify::<Sha256, V, 2>(&root, &key, &bad), None);
}

#[test]
fn verify_rejects_binding_break_forgery() {
    // The Attack-2 forgery, at the proof layer: forge a membership proof for
    // key = H_L (a leaf hash) claiming value Missing(H_R), against the honest
    // two-key map root = branch(H_L, H_R). The tag mismatch must reject it.
    let k0 = [0x00u8; 32];
    let mut k1 = [0x00u8; 32];
    k1[0] = 0x80;
    let v0 = [0x11u8; 32];
    let v1 = [0x22u8; 32];
    let mut honest: RadixMap<V, 32> = RadixMap::new();
    honest.insert(k0, mat(v0));
    honest.insert(k1, mat(v1));
    let root = honest.hash_tree_root::<Sha256>();

    let h_l = leaf_hash::<Sha256>(&k0, &v0);
    let h_r = leaf_hash::<Sha256>(&k1, &v1);
    let forged = RadixProof::<V, 32> {
        term_depth: 0,
        siblings: Vec::new(),
        terminal: RadixTerminal::Leaf {
            value: MissingOr::Missing(h_r),
        },
    };
    // verify recomputes leaf_hash(H_L, H_R) = D(0x00||H_L||H_R) != root.
    assert_eq!(verify::<Sha256, V, 32>(&root, &h_l, &forged), None);
}

proptest! {
    /// For a random map and random queries, prove+verify always returns the
    /// correct verdict (Present iff the key is in the map), and a present
    /// key's proof does not verify against a different (absent) key.
    #[test]
    fn proofs_sound_and_complete(
        raw in proptest::collection::vec(
            (proptest::array::uniform2(any::<u8>()), proptest::array::uniform32(any::<u8>())),
            1..40usize,
        ),
        queries in proptest::collection::vec(proptest::array::uniform2(any::<u8>()), 1..20usize),
    ) {
        let mut m: RadixMap<V, 2> = RadixMap::new();
        for (k, v) in &raw {
            m.insert(*k, mat(*v));
        }
        let root = m.hash_tree_root::<Sha256>();

        for q in &queries {
            let present = m.get(q).is_some();
            let p = m.prove::<Sha256>(q);
            let want = if present { RadixVerdict::Present } else { RadixVerdict::Absent };
            prop_assert_eq!(verify::<Sha256, V, 2>(&root, q, &p), Some(want));
        }

        // A member's proof must not verify for any different key.
        let member_key = raw[0].0;
        let mp = m.prove::<Sha256>(&member_key);
        for q in &queries {
            if q.as_slice() != member_key.as_slice() {
                prop_assert_ne!(
                    verify::<Sha256, V, 2>(&root, q, &mp),
                    Some(RadixVerdict::Present)
                );
            }
        }
    }
}

proptest! {
    /// Random maps (incl. duplicate keys and adversarially-close keys) match
    /// the independent filter-based reference oracle, are insertion-order
    /// independent, and survive SSZ + rkyv roundtrips.
    #[test]
    fn random_maps_match_oracle_and_roundtrip(
        raw in proptest::collection::vec(
            (proptest::array::uniform3(any::<u8>()), proptest::array::uniform32(any::<u8>())),
            0..60usize,
        ),
        shuffle_seed in any::<u64>(),
    ) {
        // Dedup keeping last value (matches `insert` overwrite semantics).
        let mut dedup: std::collections::BTreeMap<[u8; 3], [u8; 32]> = std::collections::BTreeMap::new();
        for (k, v) in &raw {
            dedup.insert(*k, *v);
        }
        let set: Vec<([u8; 3], [u8; 32])> = dedup.iter().map(|(k, v)| (*k, *v)).collect();

        let mut m: RadixMap<V, 3> = RadixMap::new();
        for (k, v) in &raw {
            m.insert(*k, mat(*v));
        }
        prop_assert_eq!(m.len(), set.len());

        // Matches the independent oracle.
        let root = m.hash_tree_root::<Sha256>();
        prop_assert_eq!(root, ref_root::<3>(&set, 0));

        // Insertion-order independent: shuffle and rebuild.
        let mut order: Vec<usize> = (0..raw.len()).collect();
        // Simple deterministic shuffle (Fisher-Yates with an LCG).
        let mut s = shuffle_seed | 1;
        for i in (1..order.len()).rev() {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let j = (s >> 33) as usize % (i + 1);
            order.swap(i, j);
        }
        let mut shuffled: RadixMap<V, 3> = RadixMap::new();
        for &idx in &order {
            let (k, v) = raw[idx];
            shuffled.insert(k, mat(v));
        }
        // NB: with duplicate keys, "last value wins" depends on order, so only
        // compare roots when keys are unique (set.len() == raw.len()).
        if set.len() == raw.len() {
            prop_assert_eq!(shuffled.hash_tree_root::<Sha256>(), root);
        }

        // SSZ roundtrip.
        let bytes = ssz::Encode::as_ssz_bytes(&m);
        let decoded = <RadixMap<V, 3> as ssz::Decode>::from_ssz_bytes(&bytes).expect("decode");
        prop_assert_eq!(decoded.hash_tree_root::<Sha256>(), root);

        // rkyv roundtrip.
        let aligned = rkyv::to_bytes::<rkyv::rancor::Error>(&m).expect("rkyv encode");
        let archived =
            rkyv::access::<rkyv::Archived<RadixMap<V, 3>>, rkyv::rancor::Error>(aligned.as_slice())
                .expect("rkyv access");
        let back: RadixMap<V, 3> =
            rkyv::deserialize::<RadixMap<V, 3>, rkyv::rancor::Error>(archived).expect("rkyv deser");
        prop_assert_eq!(back.hash_tree_root::<Sha256>(), root);
    }
}
