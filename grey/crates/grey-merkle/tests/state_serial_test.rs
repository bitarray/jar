//! Tests for state serialization T(σ) against JAR block test vectors.

use grey_merkle::compute_state_root_from_kvs;
use grey_merkle::state_serial::{deserialize_state, serialize_state_with_opaque};
use grey_types::config::Config;

fn decode_hex(s: &str) -> Vec<u8> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).expect("bad hex")
}

fn load_block_pre_state(path: &str) -> (Vec<([u8; 31], Vec<u8>)>, String) {
    let json_str = std::fs::read_to_string(path).expect("failed to read block input JSON");
    let data: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    let pre = &data["pre_state"];

    let expected_root = pre["state_root"].as_str().unwrap().to_string();

    let kvs: Vec<([u8; 31], Vec<u8>)> = pre["keyvals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            let key_bytes = decode_hex(entry["key"].as_str().unwrap());
            let mut key = [0u8; 31];
            key.copy_from_slice(&key_bytes);
            let val_bytes = decode_hex(entry["value"].as_str().unwrap());
            (key, val_bytes)
        })
        .collect();

    (kvs, expected_root)
}

#[test]
fn test_deserialize_initial_state() {
    let (kvs, _) = load_block_pre_state(
        "../../res/spec/tests/vectors/blocks/fallback/block-00000001.input.gp072_tiny.json",
    );
    let config = Config::tiny();

    let (state, opaque) = deserialize_state(&kvs, &config).expect("deserialization failed");

    // Verify basic properties of the tiny genesis state
    assert_eq!(state.timeslot, 0);
    assert_eq!(state.auth_pool.len(), 2); // C=2 cores
    assert_eq!(state.pending_validators.len(), 6); // V=6
    assert_eq!(state.current_validators.len(), 6);
    assert_eq!(state.previous_validators.len(), 6);
    assert_eq!(state.pending_reports.len(), 2); // C=2
    assert!(state.pending_reports[0].is_none());
    assert!(state.pending_reports[1].is_none());
    assert_eq!(state.recent_blocks.headers.len(), 1);
    assert_eq!(state.judgments.good.len(), 0);
    assert_eq!(state.judgments.bad.len(), 0);
    assert!(state.services.contains_key(&0));
    assert_eq!(state.privileged_services.manager, 0);
    assert_eq!(state.privileged_services.assigner.len(), 2); // C=2

    // Check service account for bootstrap service
    let svc = &state.services[&0];
    assert_eq!(svc.balance, u64::MAX);

    // Opaque entries should exist
    assert!(opaque.len() > 0, "expected some opaque service data");
}

#[test]
fn test_roundtrip_initial_state() {
    let (kvs, _) = load_block_pre_state(
        "../../res/spec/tests/vectors/blocks/fallback/block-00000001.input.gp072_tiny.json",
    );
    let config = Config::tiny();

    let (state, opaque) = deserialize_state(&kvs, &config).expect("deserialization failed");

    // Re-serialize
    let re_kvs = serialize_state_with_opaque(&state, &config, &opaque);

    // Compare key-value pairs
    assert_eq!(
        re_kvs.len(),
        kvs.len(),
        "KV count mismatch: got {} expected {}",
        re_kvs.len(),
        kvs.len()
    );

    for (i, ((re_key, re_val), (orig_key, orig_val))) in
        re_kvs.iter().zip(kvs.iter()).enumerate()
    {
        assert_eq!(
            re_key, orig_key,
            "Key mismatch at entry {i}: got {} expected {}",
            hex::encode(re_key),
            hex::encode(orig_key)
        );
        assert_eq!(
            re_val, orig_val,
            "Value mismatch at entry {i} (key {}): got {} bytes expected {} bytes\n  got: {}\n  exp: {}",
            hex::encode(re_key),
            re_val.len(),
            orig_val.len(),
            hex::encode(&re_val[..re_val.len().min(80)]),
            hex::encode(&orig_val[..orig_val.len().min(80)])
        );
    }
}

#[test]
fn test_state_root_matches_expected() {
    let (kvs, expected_root_hex) = load_block_pre_state(
        "../../res/spec/tests/vectors/blocks/fallback/block-00000001.input.gp072_tiny.json",
    );

    let expected_bytes = decode_hex(&expected_root_hex);
    let mut expected = [0u8; 32];
    expected.copy_from_slice(&expected_bytes);

    let root = compute_state_root_from_kvs(&kvs);

    assert_eq!(
        root.0, expected,
        "State root mismatch:\n  computed: {}\n  expected: {}",
        hex::encode(root.0),
        hex::encode(expected)
    );
}
