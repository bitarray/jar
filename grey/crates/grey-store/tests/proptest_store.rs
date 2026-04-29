//! Property-based roundtrip tests for grey-store.

use grey_types::header::{Block, Extrinsic, Header, UnsignedHeader};
use grey_types::testing::arb_hash;
use grey_types::{BandersnatchSignature, Hash};
use proptest::prelude::*;

fn temp_store() -> (grey_store::Store, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = grey_store::Store::open(dir.path().join("test.redb")).unwrap();
    (store, dir)
}

/// Strategy for a minimal Block with arbitrary header fields.
fn arb_block() -> impl Strategy<Value = Block> {
    (
        prop::array::uniform32(any::<u8>()), // parent_hash
        prop::array::uniform32(any::<u8>()), // state_root
        prop::array::uniform32(any::<u8>()), // extrinsic_hash
        any::<u32>(),                        // timeslot
        any::<u16>(),                        // author_index
        any::<u8>(),                         // vrf fill byte
        any::<u8>(),                         // seal fill byte
    )
        .prop_map(
            |(parent, state, ext_hash, slot, author, vrf_byte, seal_byte)| Block {
                header: Header {
                    data: UnsignedHeader {
                        parent_hash: Hash(parent),
                        state_root: Hash(state),
                        extrinsic_hash: Hash(ext_hash),
                        timeslot: slot,
                        epoch_marker: None,
                        tickets_marker: None,
                        author_index: author,
                        vrf_signature: BandersnatchSignature([vrf_byte; 96]),
                        offenders_marker: vec![],
                    },
                    seal: BandersnatchSignature([seal_byte; 96]),
                },
                extrinsic: Extrinsic::default(),
            },
        )
}

proptest! {
    /// put_block then get_block returns a block with identical header fields.
    #[test]
    fn block_roundtrip(block in arb_block()) {
        let (store, _dir) = temp_store();
        let hash = store.put_block(&block).unwrap();
        let got = store.get_block(&hash).unwrap();
        prop_assert_eq!(got.header.timeslot, block.header.timeslot);
        prop_assert_eq!(got.header.author_index, block.header.author_index);
        prop_assert_eq!(got.header.parent_hash.0, block.header.parent_hash.0);
        prop_assert_eq!(got.header.state_root.0, block.header.state_root.0);
        prop_assert_eq!(got.header.extrinsic_hash.0, block.header.extrinsic_hash.0);
        prop_assert_eq!(got.header.vrf_signature.0, block.header.vrf_signature.0);
        prop_assert_eq!(got.header.seal.0, block.header.seal.0);
    }

    /// put_block then get_block_by_slot returns the same block.
    #[test]
    fn block_slot_index_roundtrip(block in arb_block()) {
        let (store, _dir) = temp_store();
        let hash = store.put_block(&block).unwrap();

        let got_hash = store.get_block_hash_by_slot(block.header.timeslot).unwrap();
        prop_assert_eq!(got_hash.0, hash.0);

        let got = store.get_block_by_slot(block.header.timeslot).unwrap();
        prop_assert_eq!(got.header.timeslot, block.header.timeslot);
        prop_assert_eq!(got.header.parent_hash.0, block.header.parent_hash.0);
    }

    /// set_head then get_head returns the same hash and slot.
    #[test]
    fn head_roundtrip(hash in arb_hash(), slot in any::<u32>()) {
        let (store, _dir) = temp_store();
        store.set_head(&hash, slot).unwrap();
        let (got_hash, got_slot) = store.get_head().unwrap();
        prop_assert_eq!(got_hash.0, hash.0);
        prop_assert_eq!(got_slot, slot);
    }

    /// set_finalized then get_finalized returns the same hash and slot.
    #[test]
    fn finalized_roundtrip(hash in arb_hash(), slot in any::<u32>()) {
        let (store, _dir) = temp_store();
        store.set_finalized(&hash, slot).unwrap();
        let (got_hash, got_slot) = store.get_finalized().unwrap();
        prop_assert_eq!(got_hash.0, hash.0);
        prop_assert_eq!(got_slot, slot);
    }

    /// put_chunk then get_chunk returns the same data.
    #[test]
    fn chunk_roundtrip(
        hash in arb_hash(),
        idx in 0u16..1024,
        data in proptest::collection::vec(any::<u8>(), 0..8192),
    ) {
        let (store, _dir) = temp_store();
        store.put_chunk(&hash, idx, &data).unwrap();
        let got = store.get_chunk(&hash, idx).unwrap();
        prop_assert_eq!(got, data);
    }

    /// delete_chunks_for_report removes all stored chunks.
    #[test]
    fn delete_chunks_removes_all(
        hash in arb_hash(),
        count in 1u16..16,
    ) {
        let (store, _dir) = temp_store();
        let data = vec![0xAB; 100];
        for i in 0..count {
            store.put_chunk(&hash, i, &data).unwrap();
        }
        let deleted = store.delete_chunks_for_report(&hash).unwrap();
        prop_assert_eq!(deleted, count as u32);
        // All chunks should be gone
        for i in 0..count {
            prop_assert!(store.get_chunk(&hash, i).is_err());
        }
    }

    /// has_block returns true after put_block and false for unknown hashes.
    #[test]
    fn has_block_consistency(block in arb_block()) {
        let (store, _dir) = temp_store();
        let unknown = Hash([0xFF; 32]);
        prop_assert!(!store.has_block(&unknown).unwrap());

        let hash = store.put_block(&block).unwrap();
        prop_assert!(store.has_block(&hash).unwrap());
    }
}
