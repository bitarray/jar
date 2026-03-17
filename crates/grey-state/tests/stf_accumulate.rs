//! STF test vectors for the accumulate sub-transition (Section 12).

mod common;

use common::{decode_hex, discover_test_stems, hash_from_hex, load_jar_test, parse_work_report};
use grey_state::accumulate::{
    AccPrivileges, AccServiceAccount, AccServiceStats, AccumulateInput, AccumulateState,
    ReadyRecord, process_accumulate,
};
use grey_types::config::Config;
use grey_types::{Hash, ServiceId, Timeslot};
use javm::Gas;
use std::collections::BTreeMap;
use tracing_test::traced_test;

fn parse_ready_record(v: &serde_json::Value) -> ReadyRecord {
    ReadyRecord {
        report: parse_work_report(&v["report"]),
        dependencies: v["dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| hash_from_hex(h.as_str().unwrap()))
            .collect(),
    }
}

fn parse_service_account(v: &serde_json::Value) -> (ServiceId, AccServiceAccount) {
    let id = v["id"].as_u64().unwrap() as ServiceId;
    let data = &v["data"];
    let svc = &data["service"];

    let mut storage = BTreeMap::new();
    for item in data["storage"].as_array().unwrap() {
        let key = decode_hex(item["key"].as_str().unwrap());
        let value = decode_hex(item["value"].as_str().unwrap());
        storage.insert(key, value);
    }

    let mut preimage_lookup = BTreeMap::new();
    for item in data["preimage_blobs"].as_array().unwrap() {
        let hash = hash_from_hex(item["hash"].as_str().unwrap());
        let blob = decode_hex(item["blob"].as_str().unwrap());
        preimage_lookup.insert(hash, blob);
    }

    let mut preimage_info = BTreeMap::new();
    for item in data["preimage_requests"].as_array().unwrap() {
        let hash = hash_from_hex(item["key"]["hash"].as_str().unwrap());
        let length = item["key"]["length"].as_u64().unwrap() as u32;
        let slots: Vec<Timeslot> = item["value"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_u64().unwrap() as Timeslot)
            .collect();
        preimage_info.insert((hash, length), slots);
    }

    let account = AccServiceAccount {
        version: svc["version"].as_u64().unwrap() as u8,
        code_hash: hash_from_hex(svc["code_hash"].as_str().unwrap()),
        balance: svc["balance"].as_u64().unwrap(),
        min_item_gas: svc["min_item_gas"].as_u64().unwrap() as Gas,
        min_memo_gas: svc["min_memo_gas"].as_u64().unwrap() as Gas,
        bytes: svc["bytes"].as_u64().unwrap(),
        deposit_offset: svc["deposit_offset"].as_u64().unwrap(),
        items: svc["items"].as_u64().unwrap(),
        creation_slot: svc["creation_slot"].as_u64().unwrap() as Timeslot,
        last_accumulation_slot: svc["last_accumulation_slot"].as_u64().unwrap() as Timeslot,
        parent_service: svc["parent_service"].as_u64().unwrap() as ServiceId,
        storage,
        preimage_lookup,
        preimage_info,
        opaque_data: std::collections::BTreeMap::new(),
    };

    (id, account)
}

fn parse_privileges(v: &serde_json::Value) -> AccPrivileges {
    AccPrivileges {
        bless: v["bless"].as_u64().unwrap() as ServiceId,
        assign: v["assign"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_u64().unwrap() as ServiceId)
            .collect(),
        designate: v["designate"].as_u64().unwrap() as ServiceId,
        register: v["register"].as_u64().unwrap() as ServiceId,
        always_acc: v["always_acc"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| {
                let sid = entry["service"].as_u64().unwrap() as ServiceId;
                let gas = entry["gas"].as_u64().unwrap() as Gas;
                (sid, gas)
            })
            .collect(),
    }
}

fn parse_statistics(v: &serde_json::Value) -> Vec<(ServiceId, AccServiceStats)> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            let id = entry["id"].as_u64().unwrap() as ServiceId;
            let r = &entry["record"];
            let stats = AccServiceStats {
                provided_count: r["provided_count"].as_u64().unwrap() as u32,
                provided_size: r["provided_size"].as_u64().unwrap(),
                refinement_count: r["refinement_count"].as_u64().unwrap() as u32,
                refinement_gas_used: r["refinement_gas_used"].as_u64().unwrap() as Gas,
                imports: r["imports"].as_u64().unwrap() as u32,
                extrinsic_count: r["extrinsic_count"].as_u64().unwrap() as u32,
                extrinsic_size: r["extrinsic_size"].as_u64().unwrap(),
                exports: r["exports"].as_u64().unwrap() as u32,
                accumulate_count: r["accumulate_count"].as_u64().unwrap() as u32,
                accumulate_gas_used: r["accumulate_gas_used"].as_u64().unwrap() as Gas,
            };
            (id, stats)
        })
        .collect()
}

fn parse_state(v: &serde_json::Value) -> AccumulateState {
    let ready_queue: Vec<Vec<ReadyRecord>> = v["ready_queue"]
        .as_array()
        .unwrap()
        .iter()
        .map(|slot| {
            slot.as_array()
                .unwrap()
                .iter()
                .map(|rr| parse_ready_record(rr))
                .collect()
        })
        .collect();

    let accumulated: Vec<Vec<Hash>> = v["accumulated"]
        .as_array()
        .unwrap()
        .iter()
        .map(|slot| {
            slot.as_array()
                .unwrap()
                .iter()
                .map(|h| hash_from_hex(h.as_str().unwrap()))
                .collect()
        })
        .collect();

    let accounts: BTreeMap<ServiceId, AccServiceAccount> = v["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| parse_service_account(a))
        .collect();

    AccumulateState {
        slot: v["slot"].as_u64().unwrap() as Timeslot,
        entropy: hash_from_hex(v["entropy"].as_str().unwrap()),
        ready_queue,
        accumulated,
        privileges: parse_privileges(&v["privileges"]),
        statistics: parse_statistics(&v["statistics"]),
        accounts,
        auth_queues: None,
        pending_validators: None,
    }
}

fn parse_input(v: &serde_json::Value) -> AccumulateInput {
    AccumulateInput {
        slot: v["slot"].as_u64().unwrap() as Timeslot,
        reports: v["reports"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| parse_work_report(r))
            .collect(),
    }
}

fn run_accumulate_test(dir: &str, stem: &str) {
    let json = load_jar_test(dir, stem);
    let path = format!("{dir}/{stem}");

    let config = Config::tiny();
    let input = parse_input(&json["input"]);
    let mut state = parse_state(&json["pre_state"]);
    let expected_state = parse_state(&json["post_state"]);

    let expected_output = hash_from_hex(json["output"]["ok"].as_str().unwrap());

    let result = process_accumulate(&config, &mut state, &input);
    let output_hash = result.hash;

    // Compare output hash
    assert_eq!(
        output_hash, expected_output,
        "output hash mismatch in {path}\n  got:      {}\n  expected: {}",
        hex::encode(output_hash.0),
        hex::encode(expected_output.0)
    );

    // Compare slot
    assert_eq!(
        state.slot, expected_state.slot,
        "slot mismatch in {path}"
    );

    // Compare accumulated
    assert_eq!(
        state.accumulated.len(),
        expected_state.accumulated.len(),
        "accumulated length mismatch in {path}"
    );
    for (i, (got, exp)) in state
        .accumulated
        .iter()
        .zip(expected_state.accumulated.iter())
        .enumerate()
    {
        assert_eq!(
            got, exp,
            "accumulated[{i}] mismatch in {path}\n  got:      {got:?}\n  expected: {exp:?}"
        );
    }

    // Compare ready_queue
    assert_eq!(
        state.ready_queue.len(),
        expected_state.ready_queue.len(),
        "ready_queue length mismatch in {path}"
    );
    for (i, (got, exp)) in state
        .ready_queue
        .iter()
        .zip(expected_state.ready_queue.iter())
        .enumerate()
    {
        assert_eq!(
            got.len(),
            exp.len(),
            "ready_queue[{i}] length mismatch in {path}: got {} expected {}",
            got.len(),
            exp.len()
        );
        for (j, (g, e)) in got.iter().zip(exp.iter()).enumerate() {
            assert_eq!(
                g.report.package_spec.package_hash,
                e.report.package_spec.package_hash,
                "ready_queue[{i}][{j}] report package_hash mismatch in {path}"
            );
            assert_eq!(
                g.dependencies, e.dependencies,
                "ready_queue[{i}][{j}] dependencies mismatch in {path}"
            );
        }
    }

    // Compare privileges
    assert_eq!(
        state.privileges.bless, expected_state.privileges.bless,
        "privileges.bless mismatch in {path}"
    );
    assert_eq!(
        state.privileges.assign, expected_state.privileges.assign,
        "privileges.assign mismatch in {path}"
    );
    assert_eq!(
        state.privileges.designate, expected_state.privileges.designate,
        "privileges.designate mismatch in {path}"
    );

    // Compare statistics
    assert_eq!(
        state.statistics.len(),
        expected_state.statistics.len(),
        "statistics length mismatch in {path}: got {} expected {}",
        state.statistics.len(),
        expected_state.statistics.len()
    );
    for ((got_id, got_stats), (exp_id, exp_stats)) in
        state.statistics.iter().zip(expected_state.statistics.iter())
    {
        assert_eq!(got_id, exp_id, "statistics id mismatch in {path}");
        assert_eq!(
            got_stats.accumulate_count, exp_stats.accumulate_count,
            "statistics[{got_id}].accumulate_count mismatch in {path}"
        );
        assert_eq!(
            got_stats.accumulate_gas_used, exp_stats.accumulate_gas_used,
            "statistics[{got_id}].accumulate_gas_used mismatch in {path}: got {} expected {}",
            got_stats.accumulate_gas_used, exp_stats.accumulate_gas_used
        );
    }

    // Compare accounts
    assert_eq!(
        state.accounts.len(),
        expected_state.accounts.len(),
        "accounts count mismatch in {path}: got {} expected {}",
        state.accounts.len(),
        expected_state.accounts.len()
    );
    for (sid, exp_acc) in &expected_state.accounts {
        let got_acc = state
            .accounts
            .get(sid)
            .unwrap_or_else(|| panic!("missing account {sid} in {path}"));
        assert_eq!(
            got_acc.balance, exp_acc.balance,
            "account[{sid}].balance mismatch in {path}: got {} expected {}",
            got_acc.balance, exp_acc.balance
        );
        assert_eq!(
            got_acc.bytes, exp_acc.bytes,
            "account[{sid}].bytes mismatch in {path}: got {} expected {}",
            got_acc.bytes, exp_acc.bytes
        );
        assert_eq!(
            got_acc.items, exp_acc.items,
            "account[{sid}].items mismatch in {path}: got {} expected {}",
            got_acc.items, exp_acc.items
        );
        assert_eq!(
            got_acc.last_accumulation_slot, exp_acc.last_accumulation_slot,
            "account[{sid}].last_accumulation_slot mismatch in {path}"
        );
        assert_eq!(
            got_acc.storage, exp_acc.storage,
            "account[{sid}].storage mismatch in {path}"
        );
    }
}

const DIR: &str = "../../res/spec/tests/vectors/accumulate";

#[traced_test]
#[test]
fn test_no_available_reports_1() {
    run_accumulate_test(DIR, "no_available_reports-1");
}

#[traced_test]
#[test]
fn test_queues_are_shifted_1() {
    run_accumulate_test(DIR, "queues_are_shifted-1");
}

#[traced_test]
#[test]
fn test_queues_are_shifted_2() {
    run_accumulate_test(DIR, "queues_are_shifted-2");
}

#[traced_test]
#[test]
fn test_process_one_immediate_report_1() {
    run_accumulate_test(DIR, "process_one_immediate_report-1");
}

#[traced_test]
#[test]
fn test_ready_queue_editing_1() {
    run_accumulate_test(DIR, "ready_queue_editing-1");
}

#[traced_test]
#[test]
fn test_ready_queue_editing_2() {
    run_accumulate_test(DIR, "ready_queue_editing-2");
}

#[traced_test]
#[test]
fn test_ready_queue_editing_3() {
    run_accumulate_test(DIR, "ready_queue_editing-3");
}

#[traced_test]
#[test]
fn test_enqueue_and_unlock_simple_1() {
    run_accumulate_test(DIR, "enqueue_and_unlock_simple-1");
}

#[traced_test]
#[test]
fn test_enqueue_and_unlock_simple_2() {
    run_accumulate_test(DIR, "enqueue_and_unlock_simple-2");
}

#[traced_test]
#[test]
fn test_enqueue_and_unlock_chain_1() {
    run_accumulate_test(DIR, "enqueue_and_unlock_chain-1");
}

#[traced_test]
#[test]
fn test_enqueue_and_unlock_chain_2() {
    run_accumulate_test(DIR, "enqueue_and_unlock_chain-2");
}

#[traced_test]
#[test]
fn test_enqueue_and_unlock_chain_3() {
    run_accumulate_test(DIR, "enqueue_and_unlock_chain-3");
}

#[traced_test]
#[test]
fn test_enqueue_and_unlock_chain_4() {
    run_accumulate_test(DIR, "enqueue_and_unlock_chain-4");
}

#[traced_test]
#[test]
fn test_enqueue_self_referential_1() {
    run_accumulate_test(DIR, "enqueue_self_referential-1");
}

#[traced_test]
#[test]
fn test_enqueue_self_referential_2() {
    run_accumulate_test(DIR, "enqueue_self_referential-2");
}

#[traced_test]
#[test]
fn test_enqueue_self_referential_3() {
    run_accumulate_test(DIR, "enqueue_self_referential-3");
}

#[traced_test]
#[test]
fn test_enqueue_self_referential_4() {
    run_accumulate_test(DIR, "enqueue_self_referential-4");
}

#[traced_test]
#[test]
fn test_enqueue_and_unlock_with_sr_lookup_1() {
    run_accumulate_test(DIR, "enqueue_and_unlock_with_sr_lookup-1");
}

#[traced_test]
#[test]
fn test_enqueue_and_unlock_with_sr_lookup_2() {
    run_accumulate_test(DIR, "enqueue_and_unlock_with_sr_lookup-2");
}

#[traced_test]
#[test]
fn test_enqueue_and_unlock_chain_wraps_1() {
    run_accumulate_test(DIR, "enqueue_and_unlock_chain_wraps-1");
}

#[traced_test]
#[test]
fn test_enqueue_and_unlock_chain_wraps_2() {
    run_accumulate_test(DIR, "enqueue_and_unlock_chain_wraps-2");
}

#[traced_test]
#[test]
fn test_enqueue_and_unlock_chain_wraps_3() {
    run_accumulate_test(DIR, "enqueue_and_unlock_chain_wraps-3");
}

#[traced_test]
#[test]
fn test_enqueue_and_unlock_chain_wraps_4() {
    run_accumulate_test(DIR, "enqueue_and_unlock_chain_wraps-4");
}

#[traced_test]
#[test]
fn test_enqueue_and_unlock_chain_wraps_5() {
    run_accumulate_test(DIR, "enqueue_and_unlock_chain_wraps-5");
}

#[traced_test]
#[test]
fn test_accumulate_ready_queued_reports_1() {
    run_accumulate_test(DIR, "accumulate_ready_queued_reports-1");
}

#[traced_test]
#[test]
fn test_same_code_different_services_1() {
    run_accumulate_test(DIR, "same_code_different_services-1");
}

#[traced_test]
#[test]
fn test_work_for_ejected_service_1() {
    run_accumulate_test(DIR, "work_for_ejected_service-1");
}

#[traced_test]
#[test]
fn test_work_for_ejected_service_2() {
    run_accumulate_test(DIR, "work_for_ejected_service-2");
}

#[traced_test]
#[test]
fn test_work_for_ejected_service_3() {
    run_accumulate_test(DIR, "work_for_ejected_service-3");
}

#[traced_test]
#[test]
fn test_transfer_for_ejected_service_1() {
    run_accumulate_test(DIR, "transfer_for_ejected_service-1");
}

#[traced_test]
#[test]
fn test_accumulate_discover_all() {
    let stems = discover_test_stems(DIR);
    for stem in &stems {
        run_accumulate_test(DIR, stem);
    }
}
