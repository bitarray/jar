//! Shared test utilities for STF test vectors.
#![allow(dead_code)]

use grey_types::config::Config;
use grey_types::state::PendingReport;
use grey_types::validator::ValidatorKey;
use grey_types::work::{AvailabilitySpec, RefinementContext, WorkDigest, WorkReport, WorkResult};
use grey_types::{
    BandersnatchPublicKey, BlsPublicKey, Ed25519PublicKey, Ed25519Signature, Hash, ServiceId,
};
use std::collections::BTreeMap;
use std::path::Path;

/// Discover test vector file stems in a directory matching `*.input.jar1.json`.
///
/// Returns a sorted list of stems (the filename prefix before `.input.jar1.json`).
/// Convenience wrapper for `discover_test_stems_variant` with the default "jar1" variant.
pub fn discover_test_stems(dir: &str) -> Vec<String> {
    discover_test_stems_variant(dir, "jar1")
}

/// Discover test vector file stems in a directory matching `*.input.{variant}.json`.
///
/// Returns a sorted list of stems (the filename prefix before `.input.{variant}.json`).
pub fn discover_test_stems_variant(dir: &str, variant: &str) -> Vec<String> {
    let suffix = format!(".input.{variant}.json");
    let mut stems: Vec<String> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("failed to read dir {dir}: {e}"))
        .filter_map(|entry| {
            let name = entry.ok()?.file_name().into_string().ok()?;
            name.strip_suffix(&suffix).map(String::from)
        })
        .collect();
    stems.sort();
    stems
}

/// Load and parse a JSON file, panicking with a descriptive message on failure.
pub fn load_json(path: &str) -> serde_json::Value {
    let contents =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
    serde_json::from_str(&contents).unwrap_or_else(|e| panic!("failed to parse {path}: {e}"))
}

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

/// Resolve blob_file/code_blob_file references in a JSON value.
/// Reads files relative to `base_dir`, computes blake2b hash.
pub fn resolve_blob_files(json: &mut serde_json::Value, base_dir: &Path) {
    let accounts = match json
        .pointer_mut("/pre_state/accounts")
        .and_then(|v| v.as_array_mut())
    {
        Some(a) => a,
        None => return,
    };
    for acct in accounts.iter_mut() {
        let data = match acct.get_mut("data") {
            Some(d) => d,
            None => continue,
        };
        // Resolve code_blob_file in service
        if let Some(svc) = data.get_mut("service")
            && let Some(path) = svc
                .get("code_blob_file")
                .and_then(|v| v.as_str())
                .map(String::from)
        {
            let bytes = std::fs::read(base_dir.join(&path))
                .unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
            let hash = grey_crypto::blake2b_256(&bytes);
            svc.as_object_mut()
                .unwrap()
                .insert("code_hash".to_string(), serde_json::json!(hash.to_string()));
        }
        // Resolve blob_file in preimage_blobs
        if let Some(blobs) = data
            .get_mut("preimage_blobs")
            .and_then(|v| v.as_array_mut())
        {
            for item in blobs.iter_mut() {
                if let Some(path) = item
                    .get("blob_file")
                    .and_then(|v| v.as_str())
                    .map(String::from)
                {
                    let bytes = std::fs::read(base_dir.join(&path))
                        .unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
                    let hash = grey_crypto::blake2b_256(&bytes);
                    *item = serde_json::json!({
                        "hash": hash.to_string(),
                        "blob": format!("0x{}", hex::encode(&bytes)),
                    });
                }
            }
        }
    }
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
        .map(|arr| {
            arr.iter()
                .map(|entry| {
                    (
                        hash_from_hex(entry["work_package_hash"].as_str().unwrap()),
                        hash_from_hex(entry["segment_tree_root"].as_str().unwrap()),
                    )
                })
                .collect()
        })
        .unwrap_or_default();

    let results: Vec<WorkDigest> = json["results"]
        .as_array()
        .map(|arr| {
            arr.iter()
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
                .collect()
        })
        .unwrap_or_default();

    WorkReport {
        package_spec: AvailabilitySpec {
            package_hash: hash_from_hex(ps["hash"].as_str().unwrap()),
            bundle_length: ps["length"].as_u64().unwrap_or(0) as u32,
            erasure_root: ps["erasure_root"]
                .as_str()
                .map(hash_from_hex)
                .unwrap_or_default(),
            exports_root: ps["exports_root"]
                .as_str()
                .map(hash_from_hex)
                .unwrap_or_default(),
            exports_count: ps["exports_count"].as_u64().unwrap_or(0) as u16,
            erasure_shards: ps["erasure_shards"]
                .as_u64()
                .unwrap_or(Config::full().validators_count as u64)
                as u16,
        },
        context: RefinementContext {
            anchor: ctx["anchor"]
                .as_str()
                .map(hash_from_hex)
                .unwrap_or_default(),
            state_root: ctx["state_root"]
                .as_str()
                .map(hash_from_hex)
                .unwrap_or_default(),
            beefy_root: ctx["beefy_root"]
                .as_str()
                .map(hash_from_hex)
                .unwrap_or_default(),
            lookup_anchor: ctx["lookup_anchor"]
                .as_str()
                .map(hash_from_hex)
                .unwrap_or_default(),
            lookup_anchor_timeslot: ctx["lookup_anchor_slot"].as_u64().unwrap_or(0) as u32,
            prerequisites: ctx["prerequisites"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .map(|h| hash_from_hex(h.as_str().unwrap()))
                        .collect()
                })
                .unwrap_or_default(),
        },
        core_index: json["core_index"].as_u64().unwrap_or(0) as u16,
        authorizer_hash: json["authorizer_hash"]
            .as_str()
            .map(hash_from_hex)
            .unwrap_or_default(),
        auth_gas_used: json["auth_gas_used"].as_u64().unwrap_or(0),
        auth_output: json["auth_output"]
            .as_str()
            .map(decode_hex)
            .unwrap_or_default(),
        segment_root_lookup,
        results,
    }
}

/// Load a JAR split-format test vector pair into a merged JSON value.
/// JAR vectors are split into `{stem}.input.gp072_tiny.json` (containing `{input, pre_state}`)
/// and `{stem}.output.gp072_tiny.json` (containing `{output, post_state}`).
/// Returns a Value with all four keys at top level, matching the W3F single-file format.
pub fn load_jar_test(dir: &str, stem: &str) -> serde_json::Value {
    let variant = "jar1";
    let input_path = format!("{dir}/{stem}.input.{variant}.json");
    let output_path = format!("{dir}/{stem}.output.{variant}.json");

    let input_content = std::fs::read_to_string(&input_path)
        .unwrap_or_else(|e| panic!("failed to read {input_path}: {e}"));
    let output_content = std::fs::read_to_string(&output_path)
        .unwrap_or_else(|e| panic!("failed to read {output_path}: {e}"));

    let mut input_json: serde_json::Value = serde_json::from_str(&input_content)
        .unwrap_or_else(|e| panic!("failed to parse {input_path}: {e}"));
    resolve_blob_files(&mut input_json, Path::new(dir));
    let output_json: serde_json::Value = serde_json::from_str(&output_content)
        .unwrap_or_else(|e| panic!("failed to parse {output_path}: {e}"));

    let map = input_json.as_object_mut().unwrap();
    for (k, v) in output_json.as_object().unwrap() {
        map.insert(k.clone(), v.clone());
    }

    input_json
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

/// Parse a pending reports array (ρ) from JSON.
/// Each element is either null (empty slot) or a report with timeout.
pub fn parse_pending_reports(json: &serde_json::Value) -> Vec<Option<PendingReport>> {
    json.as_array()
        .unwrap()
        .iter()
        .map(|v| {
            if v.is_null() {
                None
            } else {
                Some(PendingReport {
                    report: parse_work_report(&v["report"]),
                    timeslot: v["timeout"].as_u64().unwrap() as u32,
                })
            }
        })
        .collect()
}

/// Generate a `#[test]` that discovers all test vector stems in `$dir` and runs
/// each through `$runner(dir, stem)`.  Replaces 8 identical `test_*_discover_all`
/// functions across the STF test files.
#[macro_export]
macro_rules! discover_all_test {
    ($dir:expr, $runner:path) => {
        #[test]
        fn discover_all() {
            let stems = common::discover_test_stems($dir);
            assert!(!stems.is_empty(), "no test vectors found in {}", $dir);
            for stem in &stems {
                $runner($dir, stem);
            }
        }
    };
}

/// Generate a named test that runs a single STF test vector through a runner function.
///
/// Usage: `stf_test!(test_name, "vector-stem", DIR, run_my_test);`
#[macro_export]
macro_rules! stf_test {
    ($name:ident, $stem:expr, $dir:expr, $runner:path) => {
        #[test]
        fn $name() {
            $runner($dir, $stem);
        }
    };
}

/// Like `stf_test!` but also applies `#[traced_test]` for tracing-test log capture.
///
/// Usage: `stf_test_traced!(test_name, "vector-stem", DIR, run_my_test);`
#[macro_export]
macro_rules! stf_test_traced {
    ($name:ident, $stem:expr, $dir:expr, $runner:path) => {
        #[tracing_test::traced_test]
        #[test]
        fn $name() {
            $runner($dir, $stem);
        }
    };
}
