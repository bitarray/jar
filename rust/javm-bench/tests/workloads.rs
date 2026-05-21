//! CI conformance for the bench workloads.
//!
//! Mirrors the per-workload sanity check in `benches/pvm_bench.rs` and
//! `benches/stark_bench.rs` (which only run under `cargo bench`,
//! invisible to CI) as plain `#[test]`s, so any regression in the
//! interpreter, recompiler, or transpiler that changes a workload's
//! return value or gas cost trips a test failure.
//!
//! For each workload we:
//!   1. Drive the byte-PVM interpreter through `Nub::new_local()`.
//!   2. Drive the JIT recompiler through `Nub::new_hyperlight()`.
//!   3. Assert both backends agree on `(return_value, gas_used)`.
//!   4. Pin both against a hardcoded `(value, gas)` from the
//!      reference run on this branch — a deliberate floor that
//!      catches "silently changed gas accounting" or "silently
//!      changed transpiler output" regressions the round-trip
//!      check would miss.
//!
//! Linux x86_64 only: the recompiler path needs Hyperlight + KVM.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use javm_cap::image::Image;
use ssz::Decode;

/// Drive both backends on a workload's Image and check they agree
/// with each other and with the pinned reference.
fn check_workload(name: &str, blob: &[u8], expected_value: u64, expected_gas: u64) {
    let image =
        Image::from_ssz_bytes(blob).unwrap_or_else(|e| panic!("[{name}] decode Image: {e:?}"));
    let built = javm_bench::BuiltCaps::for_image(&image, 0);

    let (interp_val, interp_gas) = javm_bench::run_interpreter(&built);
    assert_eq!(
        interp_val, expected_value,
        "[{name}] interpreter return value drifted: got {interp_val:#x}, expected {expected_value:#x}",
    );
    assert_eq!(
        interp_gas, expected_gas,
        "[{name}] interpreter gas drifted: got {interp_gas}, expected {expected_gas}",
    );

    let (recomp_val, recomp_gas) = javm_bench::run_recompiler(&built);
    assert_eq!(
        recomp_val, interp_val,
        "[{name}] recompiler vs interpreter return value mismatch: recomp={recomp_val:#x} interp={interp_val:#x}",
    );
    assert_eq!(
        recomp_gas, interp_gas,
        "[{name}] recompiler vs interpreter gas mismatch: recomp={recomp_gas} interp={interp_gas}",
    );
}

// PVM-shaped workloads (matches `benches/pvm_bench.rs`).

#[test]
fn prime_sieve() {
    check_workload(
        "prime_sieve",
        include_bytes!(env!("PRIME_SIEVE_BLOB")),
        0x2578,
        8_773_823,
    );
}

#[test]
fn ed25519() {
    check_workload(
        "ed25519",
        include_bytes!(env!("ED25519_BLOB")),
        0x1,
        826_824,
    );
}

#[test]
fn keccak() {
    check_workload(
        "keccak",
        include_bytes!(env!("KECCAK_BLOB")),
        0x39e5_0259,
        102_409,
    );
}

#[test]
fn blake2b() {
    check_workload(
        "blake2b",
        include_bytes!(env!("BLAKE2B_BLOB")),
        0xee1f_55f1,
        62_999,
    );
}

#[test]
fn ecrecover() {
    check_workload(
        "ecrecover",
        include_bytes!(env!("ECRECOVER_BLOB")),
        0x1,
        6_790_808,
    );
}

// STARK-shaped workloads (matches `benches/stark_bench.rs`).

#[test]
fn goldilocks_mul() {
    check_workload(
        "goldilocks_mul",
        include_bytes!(env!("GOLDILOCKS_MUL_BLOB")),
        0x2cf7_3e57,
        2_600_154,
    );
}

#[test]
fn poseidon2_perm() {
    check_workload(
        "poseidon2_perm",
        include_bytes!(env!("POSEIDON2_PERM_BLOB")),
        0x3ce3_3156,
        9_669_150,
    );
}

#[test]
fn mini_verifier() {
    check_workload(
        "mini_verifier",
        include_bytes!(env!("MINI_VERIFIER_BLOB")),
        0xf98f_c4ab,
        4_580_325,
    );
}

#[test]
fn poly_eval() {
    check_workload(
        "poly_eval",
        include_bytes!(env!("POLY_EVAL_BLOB")),
        0x01da_34e2,
        7_129_783,
    );
}

#[test]
fn fri_fold_tree() {
    check_workload(
        "fri_fold_tree",
        include_bytes!(env!("FRI_FOLD_TREE_BLOB")),
        0x37e6_76f4,
        4_950_708,
    );
}
