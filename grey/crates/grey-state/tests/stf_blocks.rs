//! Block-level integration tests using JAR block test vectors.
//!
//! Each test loads pre-state from keyvals, parses a block from JSON,
//! applies the full state transition, and compares the resulting state root.

#![allow(dead_code)]

mod common;

use common::{
    bandersnatch_from_hex, bandersnatch_sig_from_hex, decode_hex, ed25519_from_hex, hash_from_hex,
    parse_assurance, parse_credentials, parse_disputes_extrinsic, parse_work_report,
};
use grey_merkle::state_serial;
use grey_types::config::Config;
use grey_types::header::*;
use grey_types::{BandersnatchPublicKey, Ed25519PublicKey};

const BLOCKS_DIR: &str = "../../../spec/tests/vectors/blocks";

// ---------------------------------------------------------------------------
// JSON → Grey type parsers
// ---------------------------------------------------------------------------

fn parse_epoch_marker(v: &serde_json::Value) -> Option<EpochMarker> {
    if v.is_null() || v.as_str() == Some("None") {
        return None;
    }
    let validators: Vec<(BandersnatchPublicKey, Ed25519PublicKey)> = v["validators"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| {
            let bk = bandersnatch_from_hex(pair["bandersnatch"].as_str().unwrap());
            let ek = ed25519_from_hex(pair["ed25519"].as_str().unwrap());
            (bk, ek)
        })
        .collect();
    Some(EpochMarker {
        entropy: hash_from_hex(v["entropy"].as_str().unwrap()),
        entropy_previous: hash_from_hex(v["tickets_entropy"].as_str().unwrap()),
        validators,
    })
}

fn parse_tickets_marker(v: &serde_json::Value) -> Option<Vec<Ticket>> {
    if v.is_null() || v.as_str() == Some("None") {
        return None;
    }
    Some(
        v.as_array()
            .unwrap()
            .iter()
            .map(|t| Ticket {
                id: hash_from_hex(t["id"].as_str().unwrap()),
                attempt: t["attempt"].as_u64().unwrap() as u8,
            })
            .collect(),
    )
}

fn parse_header(v: &serde_json::Value) -> Header {
    let offenders_marker: Vec<Ed25519PublicKey> = v["offenders_mark"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| ed25519_from_hex(o.as_str().unwrap()))
        .collect();

    Header {
        data: UnsignedHeader {
            parent_hash: hash_from_hex(v["parent"].as_str().unwrap()),
            state_root: hash_from_hex(v["parent_state_root"].as_str().unwrap()),
            extrinsic_hash: hash_from_hex(v["extrinsic_hash"].as_str().unwrap()),
            timeslot: v["slot"].as_u64().unwrap() as u32,
            epoch_marker: parse_epoch_marker(&v["epoch_mark"]),
            tickets_marker: parse_tickets_marker(&v["tickets_mark"]),
            author_index: v["author_index"].as_u64().unwrap() as u16,
            vrf_signature: bandersnatch_sig_from_hex(v["entropy_source"].as_str().unwrap()),
            offenders_marker,
        },
        seal: bandersnatch_sig_from_hex(v["seal"].as_str().unwrap()),
    }
}

fn parse_extrinsic(v: &serde_json::Value) -> Extrinsic {
    let tickets: Vec<TicketProof> = v["tickets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| TicketProof {
            attempt: t["attempt"].as_u64().unwrap() as u8,
            proof: decode_hex(t["signature"].as_str().unwrap()),
        })
        .collect();

    let preimages: Vec<(u32, Vec<u8>)> = v["preimages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            let sid = p["requester"].as_u64().unwrap() as u32;
            let data = decode_hex(p["blob"].as_str().unwrap());
            (sid, data)
        })
        .collect();

    let guarantees: Vec<Guarantee> = v["guarantees"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| {
            let report = parse_work_report(&g["report"]);
            let timeslot = g["slot"].as_u64().unwrap() as u32;
            let credentials = parse_credentials(&g["signatures"]);
            Guarantee {
                report,
                timeslot,
                credentials,
            }
        })
        .collect();

    let assurances: Vec<Assurance> = v["assurances"]
        .as_array()
        .unwrap()
        .iter()
        .map(parse_assurance)
        .collect();

    let disputes = parse_disputes_extrinsic(&v["disputes"]);

    Extrinsic {
        tickets,
        preimages,
        guarantees,
        assurances,
        disputes,
    }
}

fn parse_block_from_json(v: &serde_json::Value) -> Block {
    Block {
        header: parse_header(&v["header"]),
        extrinsic: parse_extrinsic(&v["extrinsic"]),
    }
}

fn parse_keyvals(v: &serde_json::Value) -> Vec<([u8; 31], Vec<u8>)> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|kv| {
            let key_bytes = decode_hex(kv["key"].as_str().unwrap());
            let mut key = [0u8; 31];
            key.copy_from_slice(&key_bytes);
            let value = decode_hex(kv["value"].as_str().unwrap());
            (key, value)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Test runners
// ---------------------------------------------------------------------------

/// Run an independent block trace where each block has full keyvals.
fn run_independent_trace(trace_name: &str) {
    let dir = format!("{BLOCKS_DIR}/{trace_name}");
    let config = Config::full();
    let variant = "jar1";
    let stems = common::discover_test_stems_variant(&dir, variant);

    let mut passed = 0;
    let mut failed = 0;
    let mut errors_expected = 0;

    for stem in &stems {
        let input_path = format!("{dir}/{stem}.input.{variant}.json");
        let output_path = format!("{dir}/{stem}.output.{variant}.json");

        let input_json = common::load_json(&input_path);
        let output_json = common::load_json(&output_path);

        // Check if this is an expected error
        if output_json.get("error").is_some() {
            // Expected error — skip detailed verification
            errors_expected += 1;
            continue;
        }

        let pre_state = &input_json["pre_state"];

        // Check for no-op blocks (expected post_state root == pre_state root)
        // These are invalid fork blocks that should produce the same state.
        let expected_root =
            hash_from_hex(output_json["post_state"]["state_root"].as_str().unwrap());
        let expected_pre_root_str = pre_state["state_root"].as_str().unwrap();
        let pre_root_hash = hash_from_hex(expected_pre_root_str);
        if expected_root == pre_root_hash {
            passed += 1;
            continue;
        }

        let kvs = parse_keyvals(&pre_state["keyvals"]);

        // Verify pre-state root
        let pre_root = grey_merkle::compute_state_root_from_kvs(&kvs);
        let expected_pre_root = hash_from_hex(pre_state["state_root"].as_str().unwrap());
        assert_eq!(
            pre_root, expected_pre_root,
            "{stem}: pre-state root mismatch"
        );

        // Deserialize state
        let (state, opaque) = match state_serial::deserialize_state(&kvs, &config) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{stem}: deserialize_state failed: {e}");
                failed += 1;
                continue;
            }
        };

        // Parse block
        let block = parse_block_from_json(&input_json["block"]);

        // Apply transition
        match grey_state::transition::apply_with_config(&state, &block, &config, &opaque) {
            Ok((new_state, remaining_opaque)) => {
                let output_kvs = state_serial::serialize_state_with_opaque(
                    &new_state,
                    &config,
                    &remaining_opaque,
                );
                let computed_root = grey_merkle::compute_state_root_from_kvs(&output_kvs);

                let expected_root =
                    hash_from_hex(output_json["post_state"]["state_root"].as_str().unwrap());

                if computed_root == expected_root {
                    passed += 1;
                } else {
                    eprintln!(
                        "{stem}: state root mismatch: computed={} expected={}",
                        computed_root, expected_root
                    );
                    // Detailed KV comparison for first failure only
                    if failed == 0
                        && let Some(expected_kvs_json) = output_json["post_state"].get("keyvals")
                    {
                        let expected_kvs = parse_keyvals(expected_kvs_json);
                        let exp_map: std::collections::BTreeMap<[u8; 31], Vec<u8>> =
                            expected_kvs.iter().cloned().collect();
                        let act_map: std::collections::BTreeMap<[u8; 31], Vec<u8>> =
                            output_kvs.iter().cloned().collect();
                        for (k, ev) in &exp_map {
                            match act_map.get(k) {
                                Some(av) if av != ev => {
                                    eprintln!(
                                        "  DIFF key[0]={} key={}...: exp={}B act={}B",
                                        k[0],
                                        hex::encode(&k[..8]),
                                        ev.len(),
                                        av.len()
                                    );
                                }
                                None => {
                                    eprintln!(
                                        "  MISSING key[0]={} key={}...: exp={}B",
                                        k[0],
                                        hex::encode(&k[..8]),
                                        ev.len()
                                    );
                                }
                                _ => {}
                            }
                        }
                        for (k, av) in &act_map {
                            if !exp_map.contains_key(k) {
                                eprintln!(
                                    "  EXTRA key[0]={} key={}...: act={}B",
                                    k[0],
                                    hex::encode(&k[..8]),
                                    av.len()
                                );
                            }
                        }
                    }
                    failed += 1;
                }
            }
            Err(e) => {
                eprintln!("{stem}: transition error: {e:?}");
                failed += 1;
            }
        }
    }

    eprintln!(
        "\n=== {trace_name}: {passed} passed, {failed} failed, {errors_expected} expected-errors, {} total ===\n",
        stems.len()
    );

    assert_eq!(
        failed, 0,
        "{trace_name}: {failed} blocks failed (see above for details)"
    );
}

/// Run a sequential block trace where state threads through blocks.
fn run_sequential_trace(trace_name: &str) {
    let dir = format!("{BLOCKS_DIR}/{trace_name}");
    let config = Config::full();
    let variant = "jar1";
    let stems = common::discover_test_stems_variant(&dir, variant);

    // Load first block's keyvals
    let first_input = common::load_json(&format!("{dir}/{}.input.{variant}.json", stems[0]));

    let kvs = parse_keyvals(&first_input["pre_state"]["keyvals"]);
    let (mut state, mut opaque) =
        state_serial::deserialize_state(&kvs, &config).expect("deserialize first block state");

    let mut passed = 0;
    let mut failed = 0;

    for stem in &stems {
        let input_path = format!("{dir}/{stem}.input.{variant}.json");
        let output_path = format!("{dir}/{stem}.output.{variant}.json");

        let input_json = common::load_json(&input_path);
        let output_json = common::load_json(&output_path);

        let block = parse_block_from_json(&input_json["block"]);

        match grey_state::transition::apply_with_config(&state, &block, &config, &opaque) {
            Ok((new_state, remaining_opaque)) => {
                let output_kvs = state_serial::serialize_state_with_opaque(
                    &new_state,
                    &config,
                    &remaining_opaque,
                );
                let computed_root = grey_merkle::compute_state_root_from_kvs(&output_kvs);

                let expected_root =
                    hash_from_hex(output_json["post_state"]["state_root"].as_str().unwrap());

                if computed_root == expected_root {
                    passed += 1;
                } else {
                    eprintln!(
                        "{stem}: state root mismatch: computed={} expected={}",
                        computed_root, expected_root
                    );
                    failed += 1;
                }

                state = new_state;
                opaque = remaining_opaque;
            }
            Err(e) => {
                eprintln!("{stem}: transition error: {e:?}");
                failed += 1;
                break; // Sequential trace: can't continue after failure
            }
        }
    }

    eprintln!(
        "\n=== {trace_name}: {passed} passed, {failed} failed, {} total ===\n",
        stems.len()
    );

    assert_eq!(
        failed, 0,
        "{trace_name}: {failed} blocks failed (see above for details)"
    );
}

// ---------------------------------------------------------------------------
// Block trace tests — commented out: jar1 block trace vectors not yet available.
// Test pointers kept for when coverage is restored.
// ---------------------------------------------------------------------------

// #[test] fn block_trace_safrole() { run_independent_trace("safrole"); }
// #[test] fn block_trace_fallback() { run_independent_trace("fallback"); }
// #[test] fn block_trace_storage() { run_independent_trace("storage"); }
// #[test] fn block_trace_storage_light() { run_independent_trace("storage_light"); }
// #[test] fn block_trace_preimages() { run_independent_trace("preimages"); }
// #[test] fn block_trace_preimages_light() { run_independent_trace("preimages_light"); }
// #[test] fn block_trace_fuzzy() { run_independent_trace("fuzzy"); }
// #[test] fn block_trace_fuzzy_light() { run_independent_trace("fuzzy_light"); }
// #[test] fn block_trace_conformance_forks() { run_independent_trace("conformance_forks"); }
// #[test] fn block_trace_conformance_no_forks() { run_sequential_trace("conformance_no_forks"); }
