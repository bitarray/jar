//! Property-based tests for erasure coding encode/recover roundtrip.

use grey_erasure::{ErasureParams, encode, recover};
use proptest::prelude::*;

const TINY: ErasureParams = ErasureParams::TINY; // 2 data, 6 total

/// Generate random data of 1-512 bytes.
fn arb_data() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..=512)
}

proptest! {
    #[test]
    fn encode_recover_roundtrip_all_data_shards(data in arb_data()) {
        let chunks = encode(&TINY, &data).expect("encode should succeed");

        // Using all data shards (indices 0..2) for recovery
        let indexed: Vec<(Vec<u8>, usize)> = chunks[..2]
            .iter()
            .enumerate()
            .map(|(i, c)| (c.clone(), i))
            .collect();

        let recovered = recover(&TINY, &indexed, data.len()).expect("recover should succeed");
        prop_assert_eq!(&recovered, &data);
    }

    #[test]
    fn encode_recover_with_parity_shards(data in arb_data()) {
        let chunks = encode(&TINY, &data).expect("encode should succeed");

        // Drop first data shard, use shard 1 (data) + shard 2 (first parity)
        let indexed: Vec<(Vec<u8>, usize)> = vec![
            (chunks[1].clone(), 1),
            (chunks[2].clone(), 2),
        ];

        let recovered = recover(&TINY, &indexed, data.len()).expect("recover should succeed");
        prop_assert_eq!(&recovered, &data);
    }

    #[test]
    fn encode_produces_correct_shard_count(data in arb_data()) {
        let chunks = encode(&TINY, &data).expect("encode should succeed");
        prop_assert_eq!(chunks.len(), 6); // 2 data + 4 recovery
    }

    #[test]
    fn all_shards_same_size(data in arb_data()) {
        let chunks = encode(&TINY, &data).expect("encode should succeed");
        let first_len = chunks[0].len();
        for (i, chunk) in chunks.iter().enumerate() {
            prop_assert_eq!(
                chunk.len(),
                first_len,
                "shard {} has different size ({} vs {})",
                i,
                chunk.len(),
                first_len
            );
        }
    }
}

// Recovery from any k-of-n shards is expensive (15 pairs per iteration),
// so use fewer proptest cases.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]

    /// Recovery succeeds using any combination of data_shards out of total_shards.
    /// For TINY (2 data, 6 total), tests all C(6,2)=15 pairs per input.
    #[test]
    fn recover_from_any_k_shards(data in arb_data()) {
        let chunks = encode(&TINY, &data).expect("encode should succeed");
        let k = TINY.data_shards; // 2
        let n = TINY.total_shards; // 6

        // Try every combination of k shards from n
        for i in 0..n {
            for j in (i + 1)..n {
                let indexed: Vec<(Vec<u8>, usize)> = vec![
                    (chunks[i].clone(), i),
                    (chunks[j].clone(), j),
                ];
                let recovered = recover(&TINY, &indexed, data.len())
                    .unwrap_or_else(|e| panic!(
                        "recover failed with shards ({}, {}): {:?}", i, j, e
                    ));
                prop_assert_eq!(
                    &recovered, &data,
                    "recovery mismatch with shards ({}, {})", i, j
                );
            }
        }

        // Also verify that k-1 shards (just 1) is not enough
        let single: Vec<(Vec<u8>, usize)> = vec![(chunks[0].clone(), 0)];
        let result = recover(&TINY, &single, data.len());
        prop_assert!(
            result.is_err(),
            "recovery with fewer than k={} shards should fail", k
        );
    }
}
