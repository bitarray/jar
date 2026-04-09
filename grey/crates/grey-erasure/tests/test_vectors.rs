//! Test vectors for Reed-Solomon erasure coding (Appendix H).

use grey_erasure::{ErasureParams, encode, recover};

#[derive(serde::Deserialize)]
struct ErasureTestVector {
    data: String,
    shards: Vec<String>,
}

fn decode_hex(s: &str) -> Vec<u8> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).unwrap()
}

fn run_encode_test(params: &ErasureParams, json_str: &str) {
    let tv: ErasureTestVector = serde_json::from_str(json_str).unwrap();
    let data = decode_hex(&tv.data);
    let expected_shards: Vec<Vec<u8>> = tv.shards.iter().map(|s| decode_hex(s)).collect();

    assert_eq!(
        expected_shards.len(),
        params.total_shards,
        "test vector shard count mismatch: expected {}, got {}",
        params.total_shards,
        expected_shards.len()
    );

    let actual_shards = encode(params, &data).unwrap();

    assert_eq!(
        actual_shards.len(),
        expected_shards.len(),
        "shard count mismatch"
    );
    for (i, (actual, expected)) in actual_shards.iter().zip(&expected_shards).enumerate() {
        assert_eq!(
            actual,
            expected,
            "shard {i} mismatch:\n  got:      {}\n  expected: {}",
            hex::encode(actual),
            hex::encode(expected)
        );
    }
}

fn run_recover_test(params: &ErasureParams, json_str: &str) {
    let tv: ErasureTestVector = serde_json::from_str(json_str).unwrap();
    let data = decode_hex(&tv.data);
    let all_shards: Vec<Vec<u8>> = tv.shards.iter().map(|s| decode_hex(s)).collect();

    // Test recovery using only recovery (parity) shards — worst case.
    // Take exactly data_shards recovery shards from the parity portion.
    let chunks: Vec<(Vec<u8>, usize)> = all_shards
        .iter()
        .enumerate()
        .skip(params.data_shards) // skip original shards
        .take(params.data_shards) // take data_shards parity shards
        .map(|(i, s)| (s.clone(), i))
        .collect();

    let recovered = recover(params, &chunks, data.len()).unwrap();
    assert_eq!(
        recovered,
        data,
        "recovery mismatch:\n  got:      {}\n  expected: {}",
        hex::encode(&recovered),
        hex::encode(&data)
    );
}

/// Generate an encode + recover test pair for a given variant and vector file.
macro_rules! erasure_tests {
    ($encode_name:ident, $recover_name:ident, $params:expr, $path:expr) => {
        #[test]
        fn $encode_name() {
            run_encode_test(&$params, include_str!($path));
        }

        #[test]
        fn $recover_name() {
            run_recover_test(&$params, include_str!($path));
        }
    };
}

// Tiny variant (6 shards)
erasure_tests!(
    test_tiny_ec_3_encode,
    test_tiny_ec_3_recover,
    ErasureParams::TINY,
    "../../../../spec/tests/vectors/erasure/ec-3.gp072_tiny.json"
);
erasure_tests!(
    test_tiny_ec_32_encode,
    test_tiny_ec_32_recover,
    ErasureParams::TINY,
    "../../../../spec/tests/vectors/erasure/ec-32.gp072_tiny.json"
);
erasure_tests!(
    test_tiny_ec_100_encode,
    test_tiny_ec_100_recover,
    ErasureParams::TINY,
    "../../../../spec/tests/vectors/erasure/ec-100.gp072_tiny.json"
);
erasure_tests!(
    test_tiny_ec_4096_encode,
    test_tiny_ec_4096_recover,
    ErasureParams::TINY,
    "../../../../spec/tests/vectors/erasure/ec-4096.gp072_tiny.json"
);
erasure_tests!(
    test_tiny_ec_4104_encode,
    test_tiny_ec_4104_recover,
    ErasureParams::TINY,
    "../../../../spec/tests/vectors/erasure/ec-4104.gp072_tiny.json"
);
erasure_tests!(
    test_tiny_ec_10000_encode,
    test_tiny_ec_10000_recover,
    ErasureParams::TINY,
    "../../../../spec/tests/vectors/erasure/ec-10000.gp072_tiny.json"
);

// Full variant (1023 shards)
erasure_tests!(
    test_full_ec_3_encode,
    test_full_ec_3_recover,
    ErasureParams::FULL,
    "../../../../spec/tests/vectors/erasure/ec-3.gp072_full.json"
);
erasure_tests!(
    test_full_ec_32_encode,
    test_full_ec_32_recover,
    ErasureParams::FULL,
    "../../../../spec/tests/vectors/erasure/ec-32.gp072_full.json"
);
erasure_tests!(
    test_full_ec_100_encode,
    test_full_ec_100_recover,
    ErasureParams::FULL,
    "../../../../spec/tests/vectors/erasure/ec-100.gp072_full.json"
);
erasure_tests!(
    test_full_ec_4096_encode,
    test_full_ec_4096_recover,
    ErasureParams::FULL,
    "../../../../spec/tests/vectors/erasure/ec-4096.gp072_full.json"
);
erasure_tests!(
    test_full_ec_4104_encode,
    test_full_ec_4104_recover,
    ErasureParams::FULL,
    "../../../../spec/tests/vectors/erasure/ec-4104.gp072_full.json"
);
erasure_tests!(
    test_full_ec_10000_encode,
    test_full_ec_10000_recover,
    ErasureParams::FULL,
    "../../../../spec/tests/vectors/erasure/ec-10000.gp072_full.json"
);
