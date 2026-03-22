//! Random JSON input generation per sub-transition.
//!
//! Generates valid-shaped JSON that can be parsed by Jar's FromJson instances.
//! The values are random but structurally correct.

use crate::Rng;
use serde_json::{json, Value};

// Tiny config constants (matching Jar test vectors)
const V_TINY: usize = 6;
const C_TINY: usize = 2;
const E_TINY: usize = 12;
const N_TICKETS: usize = 3;

fn gen_hash(rng: &mut Rng) -> Value {
    Value::String(rng.gen_hex(32))
}

fn gen_signature_ed25519(rng: &mut Rng) -> Value {
    Value::String(rng.gen_hex(64))
}

fn gen_bandersnatch_key(rng: &mut Rng) -> Value {
    Value::String(rng.gen_hex(32))
}

fn gen_bls_key(rng: &mut Rng) -> Value {
    Value::String(rng.gen_hex(144))
}

fn gen_metadata(rng: &mut Rng) -> Value {
    Value::String(rng.gen_hex(128))
}

fn gen_validator_key(rng: &mut Rng) -> Value {
    json!({
        "bandersnatch": gen_bandersnatch_key(rng),
        "ed25519": Value::String(rng.gen_hex(32)),
        "bls": gen_bls_key(rng),
        "metadata": gen_metadata(rng),
    })
}

fn gen_validator_keys(rng: &mut Rng, n: usize) -> Value {
    Value::Array((0..n).map(|_| gen_validator_key(rng)).collect())
}

fn gen_ticket(rng: &mut Rng) -> Value {
    json!({
        "id": gen_hash(rng),
        "attempt": rng.gen_range(0, N_TICKETS as u64),
    })
}

// ============================================================================
// Safrole
// ============================================================================

fn gen_safrole_input(rng: &mut Rng) -> Value {
    let tau = rng.gen_range(0, 100) as u32;
    let num_eta = 4;

    // gamma_s: tickets or fallback
    let gamma_s = if rng.gen_bool() {
        json!({
            "tickets": Value::Array(
                (0..E_TINY).map(|_| gen_ticket(rng)).collect()
            )
        })
    } else {
        json!({
            "keys": Value::Array(
                (0..E_TINY).map(|_| gen_bandersnatch_key(rng)).collect()
            )
        })
    };

    // Ticket proofs for extrinsic (0-3 tickets)
    let n_tickets = rng.gen_range(0, 4) as usize;
    let extrinsic: Vec<Value> = (0..n_tickets)
        .map(|_| {
            json!({
                "attempt": rng.gen_range(0, N_TICKETS as u64),
                "signature": Value::String(rng.gen_hex(784)),
            })
        })
        .collect();

    json!({
        "pre_state": {
            "tau": tau,
            "eta": Value::Array((0..num_eta).map(|_| gen_hash(rng)).collect()),
            "lambda": gen_validator_keys(rng, V_TINY),
            "kappa": gen_validator_keys(rng, V_TINY),
            "gamma_k": gen_validator_keys(rng, V_TINY),
            "iota": gen_validator_keys(rng, V_TINY),
            "gamma_a": Value::Array((0..rng.gen_range(0, 6)).map(|_| gen_ticket(rng)).collect()),
            "gamma_s": gamma_s,
            "gamma_z": Value::String(rng.gen_hex(144)),
            "post_offenders": Value::Array(vec![]),
        },
        "input": {
            "slot": tau + rng.gen_range(1, 10) as u32,
            "entropy": gen_hash(rng),
            "extrinsic": Value::Array(extrinsic),
        }
    })
}

// ============================================================================
// Statistics
// ============================================================================

fn gen_validator_record(rng: &mut Rng) -> Value {
    json!({
        "blocks": rng.gen_range(0, 100),
        "tickets": rng.gen_range(0, 100),
        "pre_images": rng.gen_range(0, 50),
        "pre_images_size": rng.gen_range(0, 10000),
        "guarantees": rng.gen_range(0, 50),
        "assurances": rng.gen_range(0, 50),
    })
}

fn gen_statistics_input(rng: &mut Rng) -> Value {
    let slot = rng.gen_range(0, 200) as u32;
    let n_preimages = rng.gen_range(0, 3) as usize;
    let n_guarantees = rng.gen_range(0, 3) as usize;
    let n_assurances = rng.gen_range(0, 3) as usize;

    json!({
        "pre_state": {
            "vals_curr_stats": Value::Array((0..V_TINY).map(|_| gen_validator_record(rng)).collect()),
            "vals_last_stats": Value::Array((0..V_TINY).map(|_| gen_validator_record(rng)).collect()),
            "slot": slot,
        },
        "input": {
            "slot": slot + rng.gen_range(1, 20) as u32,
            "author_index": rng.gen_range(0, V_TINY as u64),
            "extrinsic": {
                "tickets": Value::Array((0..rng.gen_range(0, 4)).map(|_| json!({
                    "attempt": rng.gen_range(0, N_TICKETS as u64),
                    "signature": Value::String(rng.gen_hex(784)),
                })).collect()),
                "preimages": Value::Array((0..n_preimages).map(|_| json!({
                    "requester": rng.gen_range(0, 10),
                    "blob": Value::String({ let n = rng.gen_range(1, 100) as usize; rng.gen_hex(n) }),
                })).collect()),
                "guarantees": Value::Array((0..n_guarantees).map(|_| json!({
                    "report": {},
                    "slot": rng.gen_range(0, 100),
                    "signatures": Value::Array((0..rng.gen_range(1, 4)).map(|_| json!({
                        "validator_index": rng.gen_range(0, V_TINY as u64),
                        "signature": gen_signature_ed25519(rng),
                    })).collect()),
                })).collect()),
                "assurances": Value::Array((0..n_assurances).map(|_| json!({
                    "anchor": gen_hash(rng),
                    "bitfield": Value::String(rng.gen_hex(1)),
                    "validator_index": rng.gen_range(0, V_TINY as u64),
                    "signature": gen_signature_ed25519(rng),
                })).collect()),
            },
        }
    })
}

// ============================================================================
// Authorizations
// ============================================================================

fn gen_authorizations_input(rng: &mut Rng) -> Value {
    let n_auths = rng.gen_range(0, 3) as usize;
    json!({
        "pre_state": {
            "auth_pools": Value::Array((0..C_TINY).map(|_|
                Value::Array((0..rng.gen_range(0, 4)).map(|_| gen_hash(rng)).collect())
            ).collect()),
            "auth_queues": Value::Array((0..C_TINY).map(|_|
                Value::Array((0..rng.gen_range(0, 8)).map(|_| gen_hash(rng)).collect())
            ).collect()),
        },
        "input": {
            "slot": rng.gen_range(0, 200),
            "auths": Value::Array((0..n_auths).map(|_| json!({
                "core": rng.gen_range(0, C_TINY as u64),
                "auth_hash": gen_hash(rng),
            })).collect()),
        }
    })
}

// ============================================================================
// History
// ============================================================================

fn gen_reported_package(rng: &mut Rng) -> Value {
    json!({
        "hash": gen_hash(rng),
        "exports_root": gen_hash(rng),
    })
}

fn gen_history_entry(rng: &mut Rng) -> Value {
    json!({
        "header_hash": gen_hash(rng),
        "beefy_root": gen_hash(rng),
        "state_root": gen_hash(rng),
        "reported": Value::Array((0..rng.gen_range(0, 3)).map(|_| gen_reported_package(rng)).collect()),
    })
}

fn gen_history_input(rng: &mut Rng) -> Value {
    let n_history = rng.gen_range(0, 8) as usize;
    let n_peaks = rng.gen_range(0, 10) as usize;
    json!({
        "pre_state": {
            "beta": {
                "history": Value::Array((0..n_history).map(|_| gen_history_entry(rng)).collect()),
                "mmr": {
                    "peaks": Value::Array((0..n_peaks).map(|_|
                        if rng.gen_bool() { Value::Null } else { gen_hash(rng) }
                    ).collect()),
                },
            }
        },
        "input": {
            "header_hash": gen_hash(rng),
            "parent_state_root": gen_hash(rng),
            "accumulate_root": gen_hash(rng),
            "work_packages": Value::Array((0..rng.gen_range(0, 3)).map(|_| gen_reported_package(rng)).collect()),
        }
    })
}

// ============================================================================
// Disputes
// ============================================================================

fn gen_disputes_input(rng: &mut Rng) -> Value {
    let n_verdicts = rng.gen_range(0, 3) as usize;
    let n_culprits = rng.gen_range(0, 2) as usize;
    let n_faults = rng.gen_range(0, 2) as usize;

    let rho: Vec<Value> = (0..C_TINY)
        .map(|_| {
            if rng.gen_bool() {
                Value::Null
            } else {
                json!({"report": {}, "timeout": rng.gen_range(0, 20)})
            }
        })
        .collect();

    json!({
        "pre_state": {
            "psi": {
                "good": Value::Array(vec![]),
                "bad": Value::Array(vec![]),
                "wonky": Value::Array(vec![]),
                "offenders": Value::Array(vec![]),
            },
            "rho": Value::Array(rho),
            "tau": rng.gen_range(0, 200),
            "kappa": gen_validator_keys(rng, V_TINY),
            "lambda": gen_validator_keys(rng, V_TINY),
        },
        "input": {
            "disputes": {
                "verdicts": Value::Array((0..n_verdicts).map(|_| json!({
                    "target": gen_hash(rng),
                    "age": rng.gen_range(0, 10),
                    "votes": Value::Array((0..rng.gen_range(1, 5)).map(|_| json!({
                        "vote": rng.gen_bool(),
                        "index": rng.gen_range(0, V_TINY as u64),
                        "signature": gen_signature_ed25519(rng),
                    })).collect()),
                })).collect()),
                "culprits": Value::Array((0..n_culprits).map(|_| json!({
                    "target": gen_hash(rng),
                    "key": Value::String(rng.gen_hex(32)),
                    "signature": gen_signature_ed25519(rng),
                })).collect()),
                "faults": Value::Array((0..n_faults).map(|_| json!({
                    "target": gen_hash(rng),
                    "vote": rng.gen_bool(),
                    "key": Value::String(rng.gen_hex(32)),
                    "signature": gen_signature_ed25519(rng),
                })).collect()),
            }
        }
    })
}

// ============================================================================
// Dispatcher
// ============================================================================

pub fn generate_input(rng: &mut Rng, sub_transition: &str) -> Value {
    match sub_transition {
        "safrole" => gen_safrole_input(rng),
        "statistics" => gen_statistics_input(rng),
        "authorizations" => gen_authorizations_input(rng),
        "history" => gen_history_input(rng),
        "disputes" => gen_disputes_input(rng),
        other => {
            eprintln!(
                "warning: no random generator for '{other}', generating minimal placeholder"
            );
            json!({"pre_state": {}, "input": {}})
        }
    }
}
