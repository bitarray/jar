//! STF test vectors for authorizations sub-transition (Section 8).

mod common;

use common::hash_from_hex;
use grey_state::authorizations::{AuthorizationInput, update_authorizations};
use grey_types::Hash;
use grey_types::config::Config;

fn run_authorizations_test(dir: &str, stem: &str) {
    let json = common::load_jar_test(dir, stem);
    let path = format!("{dir}/{stem}");

    let input_json = &json["input"];
    let pre = &json["pre_state"];
    let post = &json["post_state"];

    // Parse input
    let slot = input_json["slot"].as_u64().unwrap() as u32;
    let auths: Vec<(u16, Hash)> = input_json["auths"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            (
                a["core"].as_u64().unwrap() as u16,
                hash_from_hex(a["auth_hash"].as_str().unwrap()),
            )
        })
        .collect();

    // Parse pre-state pools and queues
    let mut auth_pools: Vec<Vec<Hash>> = pre["auth_pools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pool| {
            pool.as_array()
                .unwrap()
                .iter()
                .map(|h| hash_from_hex(h.as_str().unwrap()))
                .collect()
        })
        .collect();

    let auth_queues: Vec<Vec<Hash>> = pre["auth_queues"]
        .as_array()
        .unwrap()
        .iter()
        .map(|queue| {
            queue
                .as_array()
                .unwrap()
                .iter()
                .map(|h| hash_from_hex(h.as_str().unwrap()))
                .collect()
        })
        .collect();

    // Apply transition
    let config = Config::full();
    let input = AuthorizationInput { slot, auths };
    update_authorizations(&config, &mut auth_pools, &auth_queues, &input);

    // Parse expected post-state
    let expected_pools: Vec<Vec<Hash>> = post["auth_pools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pool| {
            pool.as_array()
                .unwrap()
                .iter()
                .map(|h| hash_from_hex(h.as_str().unwrap()))
                .collect()
        })
        .collect();

    // Compare
    assert_eq!(
        auth_pools.len(),
        expected_pools.len(),
        "pool count mismatch in {}",
        path
    );
    for (core, (got, exp)) in auth_pools.iter().zip(expected_pools.iter()).enumerate() {
        assert_eq!(got, exp, "auth pool mismatch for core {} in {}", core, path);
    }
}

const DIR: &str = "../../../spec/tests/vectors/authorizations";

stf_test!(
    test_stf_authorizations_1,
    "progress_authorizations-1",
    DIR,
    run_authorizations_test
);
stf_test!(
    test_stf_authorizations_2,
    "progress_authorizations-2",
    DIR,
    run_authorizations_test
);
stf_test!(
    test_stf_authorizations_3,
    "progress_authorizations-3",
    DIR,
    run_authorizations_test
);

discover_all_test!(DIR, run_authorizations_test);
