//! Shared test utilities for STF test vectors.
#![allow(dead_code)]

use grey_types::work::{AvailabilitySpec, RefinementContext, WorkDigest, WorkReport, WorkResult};
use grey_types::validator::ValidatorKey;
use grey_types::{
    BandersnatchPublicKey, BlsPublicKey, Ed25519PublicKey, Ed25519Signature, Hash, ServiceId,
};
use std::collections::BTreeMap;

/// Decode a 0x-prefixed hex string to bytes. Panics on invalid input.
pub fn decode_hex(s: &str) -> Vec<u8> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).expect("bad hex")
}

/// Parse a Hash from a hex string.
pub fn hash_from_hex(s: &str) -> Hash {
    Hash::from_hex(s)
}

/// Parse an Ed25519PublicKey from a hex string.
pub fn ed25519_from_hex(s: &str) -> Ed25519PublicKey {
    Ed25519PublicKey::from_hex(s)
}

/// Parse an Ed25519Signature from a hex string.
pub fn sig_from_hex(s: &str) -> Ed25519Signature {
    Ed25519Signature::from_hex(s)
}

/// Parse a BandersnatchPublicKey from a hex string.
pub fn bandersnatch_from_hex(s: &str) -> BandersnatchPublicKey {
    BandersnatchPublicKey::from_hex(s)
}

/// Parse a WorkResult from a JSON value.
pub fn parse_work_result(v: &serde_json::Value) -> WorkResult {
    if let Some(ok) = v.get("ok") {
        WorkResult::Ok(decode_hex(ok.as_str().unwrap()))
    } else if v.get("out_of_gas").is_some() {
        WorkResult::OutOfGas
    } else if v.get("panic").is_some() {
        WorkResult::Panic
    } else if v.get("bad_exports").is_some() {
        WorkResult::BadExports
    } else if v.get("bad_code").is_some() {
        WorkResult::BadCode
    } else if v.get("code_oversize").is_some() {
        WorkResult::CodeOversize
    } else {
        panic!("unknown work result: {v}");
    }
}

/// Parse a WorkReport from a JSON value.
pub fn parse_work_report(json: &serde_json::Value) -> WorkReport {
    let ps = &json["package_spec"];
    let ctx = &json["context"];

    let segment_root_lookup: BTreeMap<Hash, Hash> = json["segment_root_lookup"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                hash_from_hex(entry["work_package_hash"].as_str().unwrap()),
                hash_from_hex(entry["segment_tree_root"].as_str().unwrap()),
            )
        })
        .collect();

    let results: Vec<WorkDigest> = json["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            let rl = &d["refine_load"];
            WorkDigest {
                service_id: d["service_id"].as_u64().unwrap() as ServiceId,
                code_hash: hash_from_hex(d["code_hash"].as_str().unwrap()),
                payload_hash: hash_from_hex(d["payload_hash"].as_str().unwrap()),
                accumulate_gas: d["accumulate_gas"].as_u64().unwrap(),
                result: parse_work_result(&d["result"]),
                gas_used: rl["gas_used"].as_u64().unwrap(),
                imports_count: rl["imports"].as_u64().unwrap() as u16,
                extrinsics_count: rl["extrinsic_count"].as_u64().unwrap() as u16,
                extrinsics_size: rl["extrinsic_size"].as_u64().unwrap() as u32,
                exports_count: rl["exports"].as_u64().unwrap() as u16,
            }
        })
        .collect();

    WorkReport {
        package_spec: AvailabilitySpec {
            package_hash: hash_from_hex(ps["hash"].as_str().unwrap()),
            bundle_length: ps["length"].as_u64().unwrap() as u32,
            erasure_root: hash_from_hex(ps["erasure_root"].as_str().unwrap()),
            exports_root: hash_from_hex(ps["exports_root"].as_str().unwrap()),
            exports_count: ps["exports_count"].as_u64().unwrap() as u16,
        },
        context: RefinementContext {
            anchor: hash_from_hex(ctx["anchor"].as_str().unwrap()),
            state_root: hash_from_hex(ctx["state_root"].as_str().unwrap()),
            beefy_root: hash_from_hex(ctx["beefy_root"].as_str().unwrap()),
            lookup_anchor: hash_from_hex(ctx["lookup_anchor"].as_str().unwrap()),
            lookup_anchor_timeslot: ctx["lookup_anchor_slot"].as_u64().unwrap() as u32,
            prerequisites: ctx["prerequisites"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| hash_from_hex(h.as_str().unwrap()))
                .collect(),
        },
        core_index: json["core_index"].as_u64().unwrap() as u16,
        authorizer_hash: hash_from_hex(json["authorizer_hash"].as_str().unwrap()),
        auth_gas_used: json["auth_gas_used"].as_u64().unwrap(),
        auth_output: decode_hex(json["auth_output"].as_str().unwrap()),
        segment_root_lookup,
        results,
    }
}

/// Load a JAR split-format test vector pair into a merged JSON value.
/// JAR vectors are split into `{stem}.input.gp072_tiny.json` (containing `{input, pre_state}`)
/// and `{stem}.output.gp072_tiny.json` (containing `{output, post_state}`).
/// Returns a Value with all four keys at top level, matching the W3F single-file format.
pub fn load_jar_test(dir: &str, stem: &str) -> serde_json::Value {
    let variant = "jar080_tiny";
    let input_path = format!("{dir}/{stem}.input.{variant}.json");
    let output_path = format!("{dir}/{stem}.output.{variant}.json");

    let input_content = std::fs::read_to_string(&input_path)
        .unwrap_or_else(|e| panic!("failed to read {input_path}: {e}"));
    let output_content = std::fs::read_to_string(&output_path)
        .unwrap_or_else(|e| panic!("failed to read {output_path}: {e}"));

    let mut input_json: serde_json::Value =
        serde_json::from_str(&input_content).unwrap_or_else(|e| panic!("failed to parse {input_path}: {e}"));
    let output_json: serde_json::Value =
        serde_json::from_str(&output_content).unwrap_or_else(|e| panic!("failed to parse {output_path}: {e}"));

    let map = input_json.as_object_mut().unwrap();
    for (k, v) in output_json.as_object().unwrap() {
        map.insert(k.clone(), v.clone());
    }

    input_json
}

/// Discover all test stems for a given category directory (gp072_tiny variant).
/// Returns stems sorted alphabetically.
pub fn discover_test_stems(dir: &str) -> Vec<String> {
    let variant = "jar080_tiny";
    let suffix = format!(".input.{variant}.json");
    let mut stems = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("failed to read dir {dir}: {e}")) {
        let name = entry.unwrap().file_name().into_string().unwrap();
        if let Some(stem) = name.strip_suffix(&suffix) {
            stems.push(stem.to_string());
        }
    }
    stems.sort();
    stems
}

/// Parse a ValidatorKey from a JSON value.
pub fn parse_validator(v: &serde_json::Value) -> ValidatorKey {
    let bandersnatch = bandersnatch_from_hex(v["bandersnatch"].as_str().unwrap());
    let ed25519 = ed25519_from_hex(v["ed25519"].as_str().unwrap());

    let bls_bytes = decode_hex(v["bls"].as_str().unwrap());
    let mut bls = [0u8; 144];
    bls.copy_from_slice(&bls_bytes);

    let meta_bytes = decode_hex(v["metadata"].as_str().unwrap());
    let mut metadata = [0u8; 128];
    metadata.copy_from_slice(&meta_bytes);

    ValidatorKey {
        bandersnatch,
        ed25519,
        bls: BlsPublicKey(bls),
        metadata,
    }
}
