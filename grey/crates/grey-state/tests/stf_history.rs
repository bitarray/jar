//! STF test vectors for history sub-transition (Section 7).

mod common;

use common::{discover_test_stems, hash_from_hex};
use grey_state::history::{update_history, HistoryInput};
use grey_types::Hash;
use grey_types::state::{RecentBlockInfo, RecentBlocks};
use std::collections::BTreeMap;

/// Parse RecentBlockInfo from JSON.
fn block_info_from_json(json: &serde_json::Value) -> RecentBlockInfo {
    let mut reported = BTreeMap::new();
    for r in json["reported"].as_array().unwrap() {
        let hash = hash_from_hex(r["hash"].as_str().unwrap());
        let exports_root = hash_from_hex(r["exports_root"].as_str().unwrap());
        reported.insert(hash, exports_root);
    }

    RecentBlockInfo {
        header_hash: hash_from_hex(json["header_hash"].as_str().unwrap()),
        accumulation_root: hash_from_hex(json["beefy_root"].as_str().unwrap()),
        state_root: hash_from_hex(json["state_root"].as_str().unwrap()),
        reported_packages: reported,
    }
}

/// Parse RecentBlocks from JSON.
fn recent_blocks_from_json(json: &serde_json::Value) -> RecentBlocks {
    let headers: Vec<RecentBlockInfo> = json["history"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| block_info_from_json(v))
        .collect();

    let peaks: Vec<Option<Hash>> = json["mmr"]["peaks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            if v.is_null() {
                None
            } else {
                Some(hash_from_hex(v.as_str().unwrap()))
            }
        })
        .collect();

    RecentBlocks {
        headers,
        accumulation_log: peaks,
    }
}

/// Run a single history STF test vector.
fn run_history_test(dir: &str, stem: &str) {
    let json = common::load_jar_test(dir, stem);
    let path = format!("{dir}/{stem}");

    let input_json = &json["input"];
    let pre = &json["pre_state"]["beta"];
    let post = &json["post_state"]["beta"];

    // Parse input
    let input = HistoryInput {
        header_hash: hash_from_hex(input_json["header_hash"].as_str().unwrap()),
        parent_state_root: hash_from_hex(input_json["parent_state_root"].as_str().unwrap()),
        accumulate_root: hash_from_hex(input_json["accumulate_root"].as_str().unwrap()),
        work_packages: input_json["work_packages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|wp| {
                (
                    hash_from_hex(wp["hash"].as_str().unwrap()),
                    hash_from_hex(wp["exports_root"].as_str().unwrap()),
                )
            })
            .collect(),
    };

    // Parse pre-state
    let mut recent_blocks = recent_blocks_from_json(pre);

    // Apply transition
    update_history(&mut recent_blocks, &input);

    // Parse expected post-state
    let expected = recent_blocks_from_json(post);

    // Compare headers
    assert_eq!(
        recent_blocks.headers.len(),
        expected.headers.len(),
        "history length mismatch in {}",
        path
    );
    for (i, (got, exp)) in recent_blocks
        .headers
        .iter()
        .zip(expected.headers.iter())
        .enumerate()
    {
        assert_eq!(
            got.header_hash, exp.header_hash,
            "header_hash mismatch at index {} in {}",
            i, path
        );
        assert_eq!(
            got.state_root, exp.state_root,
            "state_root mismatch at index {} in {}",
            i, path
        );
        assert_eq!(
            got.accumulation_root, exp.accumulation_root,
            "accumulation_root (beefy_root) mismatch at index {} in {}",
            i, path
        );
        assert_eq!(
            got.reported_packages, exp.reported_packages,
            "reported_packages mismatch at index {} in {}",
            i, path
        );
    }

    // Compare MMR peaks
    assert_eq!(
        recent_blocks.accumulation_log, expected.accumulation_log,
        "MMR peaks mismatch in {}",
        path
    );
}

const DIR: &str = "../../res/spec/tests/vectors/history";

#[test]
fn test_stf_history_1() {
    run_history_test(DIR, "progress_blocks_history-1");
}

#[test]
fn test_stf_history_2() {
    run_history_test(DIR, "progress_blocks_history-2");
}

#[test]
fn test_stf_history_3() {
    run_history_test(DIR, "progress_blocks_history-3");
}

#[test]
fn test_stf_history_4() {
    run_history_test(DIR, "progress_blocks_history-4");
}

#[test]
fn test_history_discover_all() {
    let stems = discover_test_stems(DIR);
    for stem in &stems {
        run_history_test(DIR, stem);
    }
}
