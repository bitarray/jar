//! STF test vectors for the Safrole sub-transition (Section 6).

mod common;

use common::{
    bandersnatch_from_hex, decode_hex, discover_test_stems, ed25519_from_hex, hash_from_hex,
    load_jar_test, parse_validator,
};
use grey_state::safrole::{self, SafroleInput, SafroleState};
use grey_types::config::Config;
use grey_types::header::{Ticket, TicketProof};
use grey_types::state::SealKeySeries;
use grey_types::validator::ValidatorKey;
use grey_types::{BandersnatchRingRoot, Hash};

fn parse_validators(arr: &serde_json::Value) -> Vec<ValidatorKey> {
    arr.as_array()
        .unwrap()
        .iter()
        .map(|v| parse_validator(v))
        .collect()
}

fn parse_tickets(arr: &serde_json::Value) -> Vec<Ticket> {
    arr.as_array()
        .unwrap()
        .iter()
        .map(|t| Ticket {
            id: hash_from_hex(t["id"].as_str().unwrap()),
            attempt: t["attempt"].as_u64().unwrap() as u8,
        })
        .collect()
}

fn parse_seal_key_series(v: &serde_json::Value) -> SealKeySeries {
    if let Some(keys) = v.get("keys") {
        SealKeySeries::Fallback(
            keys.as_array()
                .unwrap()
                .iter()
                .map(|k| bandersnatch_from_hex(k.as_str().unwrap()))
                .collect(),
        )
    } else if let Some(tickets) = v.get("tickets") {
        SealKeySeries::Tickets(parse_tickets(tickets))
    } else {
        panic!("gamma_s must have 'keys' or 'tickets' field");
    }
}

fn parse_state(s: &serde_json::Value) -> SafroleState {
    let eta = [
        hash_from_hex(s["eta"][0].as_str().unwrap()),
        hash_from_hex(s["eta"][1].as_str().unwrap()),
        hash_from_hex(s["eta"][2].as_str().unwrap()),
        hash_from_hex(s["eta"][3].as_str().unwrap()),
    ];

    let offenders = s["post_offenders"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| ed25519_from_hex(o.as_str().unwrap()))
        .collect();

    SafroleState {
        tau: s["tau"].as_u64().unwrap() as u32,
        eta,
        lambda: parse_validators(&s["lambda"]),
        kappa: parse_validators(&s["kappa"]),
        gamma_k: parse_validators(&s["gamma_k"]),
        iota: parse_validators(&s["iota"]),
        gamma_a: parse_tickets(&s["gamma_a"]),
        gamma_s: parse_seal_key_series(&s["gamma_s"]),
        gamma_z: BandersnatchRingRoot::from_hex(s["gamma_z"].as_str().unwrap()),
        offenders,
    }
}

fn parse_input(input: &serde_json::Value) -> SafroleInput {
    let extrinsic: Vec<TicketProof> = input["extrinsic"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tp| {
            let sig_bytes = decode_hex(tp["signature"].as_str().unwrap());
            TicketProof {
                attempt: tp["attempt"].as_u64().unwrap() as u8,
                proof: sig_bytes,
            }
        })
        .collect();

    SafroleInput {
        slot: input["slot"].as_u64().unwrap() as u32,
        entropy: hash_from_hex(input["entropy"].as_str().unwrap()),
        extrinsic,
    }
}

/// Compare two SafroleState instances.
fn assert_state_eq(got: &SafroleState, expected: &SafroleState, path: &str) {
    assert_eq!(got.tau, expected.tau, "tau mismatch in {}", path);

    for i in 0..4 {
        assert_eq!(
            got.eta[i], expected.eta[i],
            "eta[{}] mismatch in {}",
            i, path
        );
    }

    assert_validators_eq(&got.lambda, &expected.lambda, "lambda", path);
    assert_validators_eq(&got.kappa, &expected.kappa, "kappa", path);
    assert_validators_eq(&got.gamma_k, &expected.gamma_k, "gamma_k", path);
    assert_validators_eq(&got.iota, &expected.iota, "iota", path);

    assert_eq!(
        got.gamma_a.len(),
        expected.gamma_a.len(),
        "gamma_a length mismatch in {}",
        path
    );
    for (i, (g, e)) in got.gamma_a.iter().zip(expected.gamma_a.iter()).enumerate() {
        assert_eq!(g.id, e.id, "gamma_a[{}].id mismatch in {}", i, path);
        assert_eq!(
            g.attempt, e.attempt,
            "gamma_a[{}].attempt mismatch in {}",
            i, path
        );
    }

    assert_seal_key_series_eq(&got.gamma_s, &expected.gamma_s, path);

    assert_eq!(
        got.gamma_z, expected.gamma_z,
        "gamma_z mismatch in {}\nGot:      {}\nExpected: {}",
        path,
        hex::encode(got.gamma_z.0),
        hex::encode(expected.gamma_z.0)
    );
}

fn assert_validators_eq(
    got: &[ValidatorKey],
    expected: &[ValidatorKey],
    name: &str,
    path: &str,
) {
    assert_eq!(
        got.len(),
        expected.len(),
        "{} length mismatch in {}",
        name,
        path
    );
    for (i, (g, e)) in got.iter().zip(expected.iter()).enumerate() {
        assert_eq!(
            g.bandersnatch, e.bandersnatch,
            "{}[{}].bandersnatch mismatch in {}",
            name, i, path
        );
        assert_eq!(
            g.ed25519, e.ed25519,
            "{}[{}].ed25519 mismatch in {}",
            name, i, path
        );
    }
}

fn assert_seal_key_series_eq(got: &SealKeySeries, expected: &SealKeySeries, path: &str) {
    match (got, expected) {
        (SealKeySeries::Fallback(g), SealKeySeries::Fallback(e)) => {
            assert_eq!(
                g.len(),
                e.len(),
                "gamma_s fallback length mismatch in {}",
                path
            );
            for (i, (gk, ek)) in g.iter().zip(e.iter()).enumerate() {
                assert_eq!(
                    gk, ek,
                    "gamma_s fallback key[{}] mismatch in {}",
                    i, path
                );
            }
        }
        (SealKeySeries::Tickets(g), SealKeySeries::Tickets(e)) => {
            assert_eq!(
                g.len(),
                e.len(),
                "gamma_s tickets length mismatch in {}",
                path
            );
            for (i, (gt, et)) in g.iter().zip(e.iter()).enumerate() {
                assert_eq!(
                    gt.id, et.id,
                    "gamma_s ticket[{}].id mismatch in {}",
                    i, path
                );
                assert_eq!(
                    gt.attempt, et.attempt,
                    "gamma_s ticket[{}].attempt mismatch in {}",
                    i, path
                );
            }
        }
        (SealKeySeries::Fallback(_), SealKeySeries::Tickets(_)) => {
            panic!("gamma_s type mismatch: got Fallback, expected Tickets in {}", path);
        }
        (SealKeySeries::Tickets(_), SealKeySeries::Fallback(_)) => {
            panic!("gamma_s type mismatch: got Tickets, expected Fallback in {}", path);
        }
    }
}

fn make_ring_vrf_verifier(
    ring_size: usize,
) -> impl Fn(&TicketProof, &BandersnatchRingRoot, &Hash, u8) -> Option<Hash> {
    move |tp: &TicketProof, gamma_z: &BandersnatchRingRoot, eta2: &Hash, attempt: u8| {
        let ticket_id_bytes = grey_crypto::bandersnatch::verify_ticket(
            ring_size,
            &gamma_z.0,
            &eta2.0,
            attempt,
            &tp.proof,
        )?;
        Some(Hash(ticket_id_bytes))
    }
}

fn run_safrole_test(dir: &str, stem: &str) {
    let json = load_jar_test(dir, stem);
    let path = format!("{dir}/{stem}");

    let input = parse_input(&json["input"]);
    let pre_state = parse_state(&json["pre_state"]);
    let expected_post = parse_state(&json["post_state"]);

    let config = Config::tiny();

    let ring_size = pre_state.gamma_k.len();
    let verifier = make_ring_vrf_verifier(ring_size);
    let result = safrole::process_safrole(&config, &input, &pre_state, Some(&verifier));

    let output = &json["output"];

    if let Some(err) = output.get("err") {
        // Expected error
        let expected_err = err.as_str().unwrap();
        match result {
            Err(e) => {
                assert_eq!(
                    e.as_str(),
                    expected_err,
                    "error mismatch in {}: got {}, expected {}",
                    path,
                    e.as_str(),
                    expected_err
                );
            }
            Ok(_) => panic!("expected error '{}' but got Ok in {}", expected_err, path),
        }
        // On error, state should be unchanged
        assert_state_eq(&pre_state, &expected_post, &path);
    } else {
        // Expected success
        let ok = &output["ok"];
        let output_result = result.unwrap_or_else(|e| {
            panic!("expected Ok but got error '{}' in {}", e.as_str(), path);
        });

        // Check epoch mark
        if ok["epoch_mark"].is_null() {
            assert!(
                output_result.epoch_mark.is_none(),
                "expected no epoch_mark in {}",
                path
            );
        } else {
            let em = output_result
                .epoch_mark
                .as_ref()
                .unwrap_or_else(|| panic!("expected epoch_mark in {}", path));
            let expected_em = &ok["epoch_mark"];

            assert_eq!(
                em.entropy,
                hash_from_hex(expected_em["entropy"].as_str().unwrap()),
                "epoch_mark.entropy mismatch in {}",
                path
            );
            assert_eq!(
                em.tickets_entropy,
                hash_from_hex(expected_em["tickets_entropy"].as_str().unwrap()),
                "epoch_mark.tickets_entropy mismatch in {}",
                path
            );

            let expected_validators = expected_em["validators"].as_array().unwrap();
            assert_eq!(
                em.validators.len(),
                expected_validators.len(),
                "epoch_mark validators length mismatch in {}",
                path
            );
            for (i, (g, e)) in em
                .validators
                .iter()
                .zip(expected_validators.iter())
                .enumerate()
            {
                assert_eq!(
                    g.0,
                    bandersnatch_from_hex(e["bandersnatch"].as_str().unwrap()),
                    "epoch_mark validator[{}].bandersnatch mismatch in {}",
                    i,
                    path
                );
                assert_eq!(
                    g.1,
                    ed25519_from_hex(e["ed25519"].as_str().unwrap()),
                    "epoch_mark validator[{}].ed25519 mismatch in {}",
                    i,
                    path
                );
            }
        }

        // Check tickets mark
        if ok["tickets_mark"].is_null() {
            assert!(
                output_result.tickets_mark.is_none(),
                "expected no tickets_mark in {}",
                path
            );
        } else {
            let tm = output_result
                .tickets_mark
                .as_ref()
                .unwrap_or_else(|| panic!("expected tickets_mark in {}", path));
            let expected_tm = ok["tickets_mark"].as_array().unwrap();

            assert_eq!(
                tm.len(),
                expected_tm.len(),
                "tickets_mark length mismatch in {}",
                path
            );
            for (i, (g, e)) in tm.iter().zip(expected_tm.iter()).enumerate() {
                assert_eq!(
                    g.id,
                    hash_from_hex(e["id"].as_str().unwrap()),
                    "tickets_mark[{}].id mismatch in {}",
                    i,
                    path
                );
                assert_eq!(
                    g.attempt,
                    e["attempt"].as_u64().unwrap() as u8,
                    "tickets_mark[{}].attempt mismatch in {}",
                    i,
                    path
                );
            }
        }

        // Check post-state
        assert_state_eq(&output_result.state, &expected_post, &path);
    }
}

const DIR: &str = "../../res/spec/tests/vectors/safrole";

macro_rules! safrole_test {
    ($name:ident, $stem:expr) => {
        #[test]
        fn $name() {
            run_safrole_test(DIR, $stem);
        }
    };
}

// Non-ticket tests (no Ring VRF needed)
safrole_test!(
    test_safrole_no_tickets_1,
    "enact-epoch-change-with-no-tickets-1"
);
safrole_test!(
    test_safrole_no_tickets_2,
    "enact-epoch-change-with-no-tickets-2"
);
safrole_test!(
    test_safrole_no_tickets_3,
    "enact-epoch-change-with-no-tickets-3"
);
safrole_test!(
    test_safrole_no_tickets_4,
    "enact-epoch-change-with-no-tickets-4"
);
safrole_test!(
    test_safrole_padding_1,
    "enact-epoch-change-with-padding-1"
);
safrole_test!(
    test_safrole_skip_epochs_1,
    "skip-epochs-1"
);
safrole_test!(
    test_safrole_skip_epoch_tail_1,
    "skip-epoch-tail-1"
);

// Ticket tests that fail before VRF (no Ring VRF needed)
safrole_test!(
    test_safrole_bad_ticket_attempt,
    "publish-tickets-no-mark-1"
);
safrole_test!(
    test_safrole_unexpected_ticket,
    "publish-tickets-no-mark-7"
);
safrole_test!(
    test_safrole_no_tickets_in_sealing_phase,
    "publish-tickets-no-mark-8"
);

// Ticket tests (with real Bandersnatch Ring VRF verification)
safrole_test!(
    test_safrole_tickets_ok_1,
    "publish-tickets-no-mark-2"
);
safrole_test!(
    test_safrole_tickets_duplicate,
    "publish-tickets-no-mark-3"
);
safrole_test!(
    test_safrole_tickets_bad_order,
    "publish-tickets-no-mark-4"
);
safrole_test!(
    test_safrole_tickets_bad_proof,
    "publish-tickets-no-mark-5"
);
safrole_test!(
    test_safrole_tickets_ok_2,
    "publish-tickets-no-mark-6"
);
safrole_test!(
    test_safrole_tickets_epoch_mark,
    "publish-tickets-no-mark-9"
);
safrole_test!(
    test_safrole_with_mark_1,
    "publish-tickets-with-mark-1"
);
safrole_test!(
    test_safrole_with_mark_2,
    "publish-tickets-with-mark-2"
);
safrole_test!(
    test_safrole_with_mark_3,
    "publish-tickets-with-mark-3"
);
safrole_test!(
    test_safrole_with_mark_4,
    "publish-tickets-with-mark-4"
);
safrole_test!(
    test_safrole_with_mark_5,
    "publish-tickets-with-mark-5"
);

#[test]
fn test_safrole_discover_all() {
    let stems = discover_test_stems(DIR);
    for stem in &stems {
        run_safrole_test(DIR, stem);
    }
}
