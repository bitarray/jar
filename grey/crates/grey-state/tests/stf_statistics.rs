//! STF test vectors for statistics sub-transition (Section 13).

mod common;

use common::{decode_hex, discover_test_stems, ed25519_from_hex, hash_from_hex, parse_work_report, sig_from_hex};
use grey_state::statistics;
use grey_types::header::*;
use grey_types::state::{ValidatorRecord, ValidatorStatistics};
use std::collections::BTreeMap;

/// Parse an Extrinsic from JSON (for statistics tests, we just need the structure).
fn extrinsic_from_json(json: &serde_json::Value) -> Extrinsic {
    Extrinsic {
        tickets: json["tickets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| TicketProof {
                attempt: t["attempt"].as_u64().unwrap() as u8,
                proof: decode_hex(t["signature"].as_str().unwrap()),
            })
            .collect(),
        preimages: json["preimages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                (
                    p["requester"].as_u64().unwrap() as u32,
                    decode_hex(p["blob"].as_str().unwrap()),
                )
            })
            .collect(),
        guarantees: json["guarantees"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| Guarantee {
                report: parse_work_report(&g["report"]),
                timeslot: g["slot"].as_u64().unwrap() as u32,
                credentials: g["signatures"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|s| {
                        (
                            s["validator_index"].as_u64().unwrap() as u16,
                            sig_from_hex(s["signature"].as_str().unwrap()),
                        )
                    })
                    .collect(),
            })
            .collect(),
        assurances: json["assurances"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| Assurance {
                anchor: hash_from_hex(a["anchor"].as_str().unwrap()),
                bitfield: decode_hex(a["bitfield"].as_str().unwrap()),
                validator_index: a["validator_index"].as_u64().unwrap() as u16,
                signature: sig_from_hex(a["signature"].as_str().unwrap()),
            })
            .collect(),
        disputes: {
            let d = &json["disputes"];
            DisputesExtrinsic {
                verdicts: d["verdicts"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| Verdict {
                        report_hash: hash_from_hex(v["target"].as_str().unwrap()),
                        age: v["age"].as_u64().unwrap() as u32,
                        judgments: v["votes"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|j| Judgment {
                                is_valid: j["vote"].as_bool().unwrap(),
                                validator_index: j["index"].as_u64().unwrap() as u16,
                                signature: sig_from_hex(j["signature"].as_str().unwrap()),
                            })
                            .collect(),
                    })
                    .collect(),
                culprits: d["culprits"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|c| Culprit {
                        report_hash: hash_from_hex(c["target"].as_str().unwrap()),
                        validator_key: ed25519_from_hex(c["key"].as_str().unwrap()),
                        signature: sig_from_hex(c["signature"].as_str().unwrap()),
                    })
                    .collect(),
                faults: d["faults"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|f| Fault {
                        report_hash: hash_from_hex(f["target"].as_str().unwrap()),
                        is_valid: f["vote"].as_bool().unwrap(),
                        validator_key: ed25519_from_hex(f["key"].as_str().unwrap()),
                        signature: sig_from_hex(f["signature"].as_str().unwrap()),
                    })
                    .collect(),
            }
        },
    }
}

/// Parse ValidatorRecord from JSON.
fn validator_record_from_json(json: &serde_json::Value) -> ValidatorRecord {
    serde_json::from_value(json.clone()).expect("failed to parse ValidatorRecord")
}

/// Run a single statistics STF test vector.
fn run_statistics_test(dir: &str, stem: &str) {
    let json = common::load_jar_test(dir, stem);
    let path = format!("{dir}/{stem}");

    let input = &json["input"];
    let pre = &json["pre_state"];
    let post = &json["post_state"];

    // Parse input
    let new_slot = input["slot"].as_u64().unwrap() as u32;
    let author_index = input["author_index"].as_u64().unwrap() as u16;
    let extrinsic = extrinsic_from_json(&input["extrinsic"]);

    // Parse pre-state
    let prior_slot = pre["slot"].as_u64().unwrap() as u32;
    let pre_curr: Vec<ValidatorRecord> = pre["vals_curr_stats"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| validator_record_from_json(v))
        .collect();
    let pre_last: Vec<ValidatorRecord> = pre["vals_last_stats"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| validator_record_from_json(v))
        .collect();

    let mut stats = ValidatorStatistics {
        current: pre_curr,
        last: pre_last,
        core_stats: vec![],
        service_stats: BTreeMap::new(),
    };

    // Apply transition using tiny config
    let config = grey_types::config::Config::tiny();
    let incoming_reports: Vec<&grey_types::work::WorkReport> = extrinsic.guarantees.iter().map(|g| &g.report).collect();
    statistics::update_statistics(&config, &mut stats, prior_slot, new_slot, author_index, &extrinsic, &incoming_reports, &[], &std::collections::BTreeMap::new());

    // Parse expected post-state
    let expected_curr: Vec<ValidatorRecord> = post["vals_curr_stats"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| validator_record_from_json(v))
        .collect();
    let expected_last: Vec<ValidatorRecord> = post["vals_last_stats"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| validator_record_from_json(v))
        .collect();

    // Compare
    assert_eq!(
        stats.current, expected_curr,
        "current stats mismatch in {}",
        path
    );
    assert_eq!(
        stats.last, expected_last,
        "last stats mismatch in {}",
        path
    );
}

const DIR: &str = "../../res/spec/tests/vectors/statistics";

#[test]
fn test_stf_statistics_empty_extrinsic() {
    run_statistics_test(DIR, "stats_with_empty_extrinsic-1");
}

#[test]
fn test_stf_statistics_some_extrinsic() {
    run_statistics_test(DIR, "stats_with_some_extrinsic-1");
}

#[test]
fn test_stf_statistics_epoch_change() {
    run_statistics_test(DIR, "stats_with_epoch_change-1");
}

#[test]
fn test_statistics_discover_all() {
    let stems = discover_test_stems(DIR);
    for stem in &stems {
        run_statistics_test(DIR, stem);
    }
}
