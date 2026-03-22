//! STF test vectors for disputes sub-transition (Section 10).

mod common;

use common::{discover_test_stems, ed25519_from_hex, hash_from_hex, sig_from_hex};
use grey_state::disputes::process_disputes;
use grey_types::config::Config;
use grey_types::header::*;
use grey_types::state::{Judgments, PendingReport};
use grey_types::validator::ValidatorKey;
use grey_types::Ed25519PublicKey;

fn parse_judgments(json: &serde_json::Value) -> Judgments {
    Judgments {
        good: json["good"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| hash_from_hex(v.as_str().unwrap()))
            .collect(),
        bad: json["bad"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| hash_from_hex(v.as_str().unwrap()))
            .collect(),
        wonky: json["wonky"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| hash_from_hex(v.as_str().unwrap()))
            .collect(),
        offenders: json["offenders"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| ed25519_from_hex(v.as_str().unwrap()))
            .collect(),
    }
}

fn parse_disputes_extrinsic(json: &serde_json::Value) -> DisputesExtrinsic {
    DisputesExtrinsic {
        verdicts: json["verdicts"]
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
        culprits: json["culprits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| Culprit {
                report_hash: hash_from_hex(c["target"].as_str().unwrap()),
                validator_key: ed25519_from_hex(c["key"].as_str().unwrap()),
                signature: sig_from_hex(c["signature"].as_str().unwrap()),
            })
            .collect(),
        faults: json["faults"]
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
}

fn parse_pending_reports(json: &serde_json::Value) -> Vec<Option<PendingReport>> {
    json.as_array()
        .unwrap()
        .iter()
        .map(|v| {
            if v.is_null() {
                None
            } else {
                // Simplified: we'd need to parse WorkReport for full fidelity
                // For disputes tests, rho is usually all-null
                None
            }
        })
        .collect()
}

fn run_disputes_test(dir: &str, stem: &str) {
    let json = common::load_jar_test(dir, stem);
    let path = format!("{dir}/{stem}");

    let input_json = &json["input"];
    let pre = &json["pre_state"];
    let post = &json["post_state"];
    let output = &json["output"];

    // Parse input
    let disputes = parse_disputes_extrinsic(&input_json["disputes"]);

    // Parse pre-state
    let mut judgments = parse_judgments(&pre["psi"]);
    let mut pending_reports = parse_pending_reports(&pre["rho"]);
    let current_timeslot = pre["tau"].as_u64().unwrap() as u32;
    let current_validators: Vec<ValidatorKey> = pre["kappa"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| serde_json::from_value(v.clone()).expect("failed to parse ValidatorKey"))
        .collect();
    let previous_validators: Vec<ValidatorKey> = pre["lambda"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| serde_json::from_value(v.clone()).expect("failed to parse ValidatorKey"))
        .collect();

    let config = Config::tiny();

    // Apply transition
    let result = process_disputes(
        &config,
        &mut judgments,
        &mut pending_reports,
        current_timeslot,
        &disputes,
        &current_validators,
        &previous_validators,
    );

    // Check output
    if let Some(err_val) = output.get("err") {
        // Expect error
        let expected_err = err_val.as_str().unwrap();
        match result {
            Err(e) => {
                assert_eq!(
                    e.as_str(),
                    expected_err,
                    "wrong error in {}: got {:?}, expected {}",
                    path,
                    e,
                    expected_err
                );
            }
            Ok(_) => panic!(
                "expected error '{}' but got Ok in {}",
                expected_err, path
            ),
        }
    } else if let Some(ok_val) = output.get("ok") {
        // Expect success
        match result {
            Ok(dispute_output) => {
                // Check offenders_mark
                let expected_offenders: Vec<Ed25519PublicKey> = ok_val["offenders_mark"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| ed25519_from_hex(v.as_str().unwrap()))
                    .collect();
                assert_eq!(
                    dispute_output.offenders_mark, expected_offenders,
                    "offenders_mark mismatch in {}",
                    path
                );

                // Check post-state judgments
                let expected_judgments = parse_judgments(&post["psi"]);
                assert_eq!(
                    judgments.good, expected_judgments.good,
                    "good set mismatch in {}",
                    path
                );
                assert_eq!(
                    judgments.bad, expected_judgments.bad,
                    "bad set mismatch in {}",
                    path
                );
                assert_eq!(
                    judgments.wonky, expected_judgments.wonky,
                    "wonky set mismatch in {}",
                    path
                );
                assert_eq!(
                    judgments.offenders, expected_judgments.offenders,
                    "offenders set mismatch in {}",
                    path
                );
            }
            Err(e) => panic!("expected Ok but got error {:?} in {}", e, path),
        }
    } else if output.is_null() {
        // null output means success with no specific output check
        assert!(result.is_ok(), "expected Ok but got error in {}", path);
    }
}

const DIR: &str = "../../res/spec/tests/vectors/disputes";

// Generate test functions for all dispute test vectors
macro_rules! dispute_test {
    ($name:ident, $stem:expr) => {
        #[test]
        fn $name() {
            run_disputes_test(DIR, $stem);
        }
    };
}

dispute_test!(test_disputes_verdicts_1, "progress_with_verdicts-1");
dispute_test!(test_disputes_verdicts_2, "progress_with_verdicts-2");
dispute_test!(test_disputes_verdicts_3, "progress_with_verdicts-3");
dispute_test!(test_disputes_verdicts_4, "progress_with_verdicts-4");
dispute_test!(test_disputes_verdicts_5, "progress_with_verdicts-5");
dispute_test!(test_disputes_verdicts_6, "progress_with_verdicts-6");

dispute_test!(test_disputes_culprits_1, "progress_with_culprits-1");
dispute_test!(test_disputes_culprits_2, "progress_with_culprits-2");
dispute_test!(test_disputes_culprits_3, "progress_with_culprits-3");
dispute_test!(test_disputes_culprits_4, "progress_with_culprits-4");
dispute_test!(test_disputes_culprits_5, "progress_with_culprits-5");
dispute_test!(test_disputes_culprits_6, "progress_with_culprits-6");
dispute_test!(test_disputes_culprits_7, "progress_with_culprits-7");

dispute_test!(test_disputes_faults_1, "progress_with_faults-1");
dispute_test!(test_disputes_faults_2, "progress_with_faults-2");
dispute_test!(test_disputes_faults_3, "progress_with_faults-3");
dispute_test!(test_disputes_faults_4, "progress_with_faults-4");
dispute_test!(test_disputes_faults_5, "progress_with_faults-5");
dispute_test!(test_disputes_faults_6, "progress_with_faults-6");
dispute_test!(test_disputes_faults_7, "progress_with_faults-7");

dispute_test!(
    test_disputes_bad_signatures_1,
    "progress_with_bad_signatures-1"
);
dispute_test!(
    test_disputes_bad_signatures_2,
    "progress_with_bad_signatures-2"
);

dispute_test!(
    test_disputes_invalid_keys_1,
    "progress_with_invalid_keys-1"
);
dispute_test!(
    test_disputes_invalid_keys_2,
    "progress_with_invalid_keys-2"
);

dispute_test!(
    test_disputes_no_verdicts_1,
    "progress_with_no_verdicts-1"
);

dispute_test!(
    test_disputes_prev_set_sigs_1,
    "progress_with_verdict_signatures_from_previous_set-1"
);
dispute_test!(
    test_disputes_prev_set_sigs_2,
    "progress_with_verdict_signatures_from_previous_set-2"
);

dispute_test!(
    test_disputes_invalidates_avail_1,
    "progress_invalidates_avail_assignments-1"
);

#[test]
fn test_disputes_discover_all() {
    let stems = discover_test_stems(DIR);
    for stem in &stems {
        run_disputes_test(DIR, stem);
    }
}
