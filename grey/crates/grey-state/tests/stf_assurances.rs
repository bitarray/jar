//! STF test vectors for assurances sub-transition (Section 11.2).

mod common;

use common::{decode_hex, hash_from_hex, parse_pending_reports, sig_from_hex};
use grey_state::assurances::process_assurances;
use grey_types::config::Config;
use grey_types::header::Assurance;
use grey_types::validator::ValidatorKey;

fn run_assurances_test(dir: &str, stem: &str) {
    let json = common::load_jar_test(dir, stem);
    let path = format!("{dir}/{stem}");

    let input = &json["input"];
    let pre = &json["pre_state"];
    let output = &json["output"];

    // Parse input
    let assurances: Vec<Assurance> = input["assurances"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| Assurance {
            anchor: hash_from_hex(a["anchor"].as_str().unwrap()),
            bitfield: decode_hex(a["bitfield"].as_str().unwrap()),
            validator_index: a["validator_index"].as_u64().unwrap() as u16,
            signature: sig_from_hex(a["signature"].as_str().unwrap()),
        })
        .collect();

    let current_timeslot = input["slot"].as_u64().unwrap() as u32;
    let parent_hash = hash_from_hex(input["parent"].as_str().unwrap());

    // Parse pre-state
    let mut pending_reports = parse_pending_reports(&pre["avail_assignments"]);
    let current_validators: Vec<ValidatorKey> = pre["curr_validators"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| serde_json::from_value(v.clone()).expect("failed to parse ValidatorKey"))
        .collect();

    let config = Config::full();

    // Apply transition
    let result = process_assurances(
        &config,
        &mut pending_reports,
        &assurances,
        current_timeslot,
        parent_hash,
        &current_validators,
    );

    // Check output
    if let Some(err_val) = output.get("err") {
        let expected_err = err_val.as_str().unwrap();
        match result {
            Err(e) => assert_eq!(
                e.as_str(),
                expected_err,
                "wrong error in {}: got {:?}",
                path,
                e
            ),
            Ok(_) => panic!("expected error '{}' but got Ok in {}", expected_err, path),
        }
    } else if let Some(ok_val) = output.get("ok") {
        match result {
            Ok(assurance_output) => {
                let expected_reported_count = ok_val["reported"].as_array().unwrap().len();
                assert_eq!(
                    assurance_output.reported.len(),
                    expected_reported_count,
                    "reported count mismatch in {}",
                    path
                );

                // Verify post-state pending reports
                let expected_pending =
                    parse_pending_reports(&json["post_state"]["avail_assignments"]);
                assert_eq!(
                    pending_reports.len(),
                    expected_pending.len(),
                    "pending reports length mismatch in {}",
                    path
                );
                for (i, (got, exp)) in pending_reports
                    .iter()
                    .zip(expected_pending.iter())
                    .enumerate()
                {
                    match (got, exp) {
                        (None, None) => {}
                        (Some(g), Some(e)) => {
                            assert_eq!(
                                g.report.core_index, e.report.core_index,
                                "core_index mismatch at {} in {}",
                                i, path
                            );
                        }
                        _ => panic!(
                            "pending report mismatch at core {} in {}: got {:?}, expected {:?}",
                            i,
                            path,
                            got.is_some(),
                            exp.is_some()
                        ),
                    }
                }
            }
            Err(e) => panic!("expected Ok but got error {:?} in {}", e, path),
        }
    }
}

const DIR: &str = "../../../spec/tests/vectors/assurances";

stf_test!(
    test_assurances_no_assurances,
    "no_assurances-1",
    DIR,
    run_assurances_test
);
stf_test!(
    test_assurances_some,
    "some_assurances-1",
    DIR,
    run_assurances_test
);
stf_test!(
    test_assurances_stale_report,
    "no_assurances_with_stale_report-1",
    DIR,
    run_assurances_test
);
stf_test!(
    test_assurances_for_stale,
    "assurances_for_stale_report-1",
    DIR,
    run_assurances_test
);
stf_test!(
    test_assurances_bad_signature,
    "assurances_with_bad_signature-1",
    DIR,
    run_assurances_test
);
stf_test!(
    test_assurances_bad_validator_index,
    "assurances_with_bad_validator_index-1",
    DIR,
    run_assurances_test
);
stf_test!(
    test_assurances_not_engaged_core,
    "assurance_for_not_engaged_core-1",
    DIR,
    run_assurances_test
);
stf_test!(
    test_assurances_bad_attestation_parent,
    "assurance_with_bad_attestation_parent-1",
    DIR,
    run_assurances_test
);
stf_test!(
    test_assurances_not_sorted_1,
    "assurers_not_sorted_or_unique-1",
    DIR,
    run_assurances_test
);
stf_test!(
    test_assurances_not_sorted_2,
    "assurers_not_sorted_or_unique-2",
    DIR,
    run_assurances_test
);

discover_all_test!(DIR, run_assurances_test);
