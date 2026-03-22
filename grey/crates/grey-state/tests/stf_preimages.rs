//! STF test vectors for preimages sub-transition (Section 12, eq 12.35-12.38).

mod common;

use common::{decode_hex, discover_test_stems, hash_from_hex};
use grey_state::preimages::{process_preimages, PreimageAccountData, PreimageServiceRecord};
use grey_types::{Hash, ServiceId, Timeslot};
use std::collections::{BTreeMap, BTreeSet};

fn run_preimages_test(dir: &str, stem: &str) {
    let json = common::load_jar_test(dir, stem);
    let path = format!("{dir}/{stem}");

    // Parse input
    let input_json = &json["input"];
    let slot = input_json["slot"].as_u64().unwrap() as Timeslot;
    let preimages: Vec<(ServiceId, Vec<u8>)> = input_json["preimages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            let requester = p["requester"].as_u64().unwrap() as ServiceId;
            let blob = decode_hex(p["blob"].as_str().unwrap());
            (requester, blob)
        })
        .collect();

    // Parse pre-state accounts
    let pre = &json["pre_state"];
    let mut accounts: BTreeMap<ServiceId, PreimageAccountData> = BTreeMap::new();

    for acct in pre["accounts"].as_array().unwrap() {
        let id = acct["id"].as_u64().unwrap() as ServiceId;
        let data = &acct["data"];

        let mut blobs = BTreeMap::new();
        for blob_entry in data["preimage_blobs"].as_array().unwrap() {
            let hash = hash_from_hex(blob_entry["hash"].as_str().unwrap());
            let blob = decode_hex(blob_entry["blob"].as_str().unwrap());
            blobs.insert(hash, blob);
        }

        let mut requests = BTreeMap::new();
        for req in data["preimage_requests"].as_array().unwrap() {
            let hash = hash_from_hex(req["key"]["hash"].as_str().unwrap());
            let length = req["key"]["length"].as_u64().unwrap() as u32;
            let timeslots: Vec<Timeslot> = req["value"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_u64().unwrap() as Timeslot)
                .collect();
            requests.insert((hash, length), timeslots);
        }

        accounts.insert(id, PreimageAccountData { blobs, requests });
    }

    // Parse expected output
    let output = &json["output"];
    let expected_error = output.get("err").and_then(|e| e.as_str());

    // Run the transition
    let result = process_preimages(&mut accounts, &preimages, slot);

    if let Some(err_code) = expected_error {
        let err = result.expect_err(&format!(
            "expected error '{}' but got Ok in {}",
            err_code, path
        ));
        assert_eq!(
            err.as_str(),
            err_code,
            "error code mismatch in {}: got '{}', expected '{}'",
            path,
            err.as_str(),
            err_code
        );
    } else {
        let stats = result.expect(&format!("expected Ok but got error in {}", path));

        // Verify post-state accounts
        let post = &json["post_state"];
        for acct in post["accounts"].as_array().unwrap() {
            let id = acct["id"].as_u64().unwrap() as ServiceId;
            let data = &acct["data"];
            let account = accounts.get(&id).unwrap_or_else(|| {
                panic!("missing account {} in post-state of {}", id, path)
            });

            // Check preimage_blobs (output may only have hashes, not full blob data)
            let expected_blob_hashes: BTreeSet<Hash> = data["preimage_blobs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|b| hash_from_hex(b["hash"].as_str().unwrap()))
                .collect();
            let got_blob_hashes: BTreeSet<Hash> = account.blobs.keys().cloned().collect();

            assert_eq!(
                got_blob_hashes, expected_blob_hashes,
                "preimage_blobs hash set mismatch for service {} in {}",
                id, path
            );

            // Check preimage_requests
            let expected_requests: BTreeMap<(Hash, u32), Vec<Timeslot>> = data
                ["preimage_requests"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| {
                    let hash = hash_from_hex(r["key"]["hash"].as_str().unwrap());
                    let length = r["key"]["length"].as_u64().unwrap() as u32;
                    let timeslots: Vec<Timeslot> = r["value"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_u64().unwrap() as Timeslot)
                        .collect();
                    ((hash, length), timeslots)
                })
                .collect();

            assert_eq!(
                account.requests, expected_requests,
                "preimage_requests mismatch for service {} in {}",
                id, path
            );
        }

        // Verify per-service statistics (optional in jar080 output)
        let empty_arr = vec![];
        let expected_stats_json = post["statistics"].as_array().unwrap_or(&empty_arr);
        let mut expected_stats: BTreeMap<ServiceId, PreimageServiceRecord> = BTreeMap::new();
        for s in expected_stats_json {
            let id = s["id"].as_u64().unwrap() as ServiceId;
            let record = &s["record"];
            expected_stats.insert(
                id,
                PreimageServiceRecord {
                    provided_count: record["provided_count"].as_u64().unwrap() as u32,
                    provided_size: record["provided_size"].as_u64().unwrap(),
                },
            );
        }

        // Only compare if expected statistics are present in the output
        if !expected_stats.is_empty() {
            assert_eq!(
                stats, expected_stats,
                "service statistics mismatch in {}",
                path
            );
        }
    }
}

const DIR: &str = "../../res/spec/tests/vectors/preimages";

macro_rules! preimage_test {
    ($name:ident, $stem:expr) => {
        #[test]
        fn $name() {
            run_preimages_test(DIR, $stem);
        }
    };
}

preimage_test!(test_preimage_needed_1, "preimage_needed-1");
preimage_test!(test_preimage_needed_2, "preimage_needed-2");
preimage_test!(test_preimage_not_needed_1, "preimage_not_needed-1");
preimage_test!(test_preimage_not_needed_2, "preimage_not_needed-2");
preimage_test!(test_preimages_order_check_1, "preimages_order_check-1");
preimage_test!(test_preimages_order_check_2, "preimages_order_check-2");
preimage_test!(test_preimages_order_check_3, "preimages_order_check-3");
preimage_test!(test_preimages_order_check_4, "preimages_order_check-4");

#[test]
fn test_preimages_discover_all() {
    let stems = discover_test_stems(DIR);
    for stem in &stems {
        run_preimages_test(DIR, stem);
    }
}
