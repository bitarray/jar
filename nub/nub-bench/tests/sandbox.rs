//! nub's first end-to-end sandbox coverage: the x86-64 JIT actually
//! executing PVM2 programs.
//!
//! Everything before this measured or tested the interpreter, or the
//! JIT's *emission*. Running recompiled code needs the ring-0 substrate
//! in `nub-arch-x86`, which needs a `GuestPersonality` — so until the
//! flat personality existed, nub could not run its own JIT at all
//! without borrowing JAVM's.
//!
//! The assertion that matters is agreement: the JIT and the interpreter
//! must produce the same value *and the same gas* for every program.
//! Gas equality is the strong one — it says the two engines charge
//! identically instruction for instruction, which is what makes a
//! metered VM's two backends interchangeable.
//!
//! Linux x86-64 only, and needs `/dev/kvm`.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use nub_bench::{BENCH_GAS, EXIT_HOST_CALL, PROGRAMS, flat_sandbox};

/// Publish `blob` and invoke `endpoint` through the sandbox, returning
/// `(return_value, gas_used)`.
fn run_jit(name: &str, blob_bytes: &[u8], endpoint: u8) -> (u64, u64) {
    let nub = flat_sandbox();
    let hash = nub
        .put_object(blob_bytes)
        .unwrap_or_else(|e| panic!("[{name}] publish: {e}"));
    let result = nub
        .invoke_cached(hash, endpoint, [0; 4], BENCH_GAS)
        .unwrap_or_else(|e| panic!("[{name}] invoke: {e}"));
    assert_eq!(
        result.exit_reason, EXIT_HOST_CALL,
        "[{name}] did not halt cleanly: exit_reason={} exit_arg={}",
        result.exit_reason, result.exit_arg,
    );
    (result.return_value, BENCH_GAS - result.gas_remaining)
}

/// The whole point: recompiled code and interpreted code agree, and both
/// agree with the pinned vector.
#[test]
fn jit_agrees_with_the_interpreter_on_value_and_gas() {
    for p in PROGRAMS {
        let blob = p.decode();
        let (interp_value, interp_gas) = nub_bench::run_interpreter(p.name, &blob);
        let (jit_value, jit_gas) = run_jit(p.name, p.blob, 0);

        assert_eq!(
            jit_value, interp_value,
            "[{}] JIT and interpreter disagree on the result: \
             jit={jit_value:#x} interp={interp_value:#x}",
            p.name,
        );
        assert_eq!(
            jit_gas, interp_gas,
            "[{}] JIT and interpreter disagree on gas: jit={jit_gas} interp={interp_gas}",
            p.name,
        );
        assert_eq!(
            (jit_value, jit_gas),
            (p.expected_value, p.expected_gas),
            "[{}] JIT drifted from the pinned vector",
            p.name,
        );
    }
}

/// The two-entry ABI works through the sandbox too, and endpoint 2 is
/// re-invocable there — the JIT keeps its compiled image across calls,
/// so this also exercises the warm path.
#[test]
fn endpoint_two_is_re_invocable_through_the_sandbox() {
    const EP_RUN: u8 = 2;
    for p in PROGRAMS {
        let first = run_jit(p.name, p.blob, EP_RUN);
        let second = run_jit(p.name, p.blob, EP_RUN);
        assert_eq!(
            first.0, p.expected_value,
            "[{}] endpoint {EP_RUN} returned the wrong value",
            p.name,
        );
        assert_eq!(
            first, second,
            "[{}] endpoint {EP_RUN} is not stable across sandbox invocations",
            p.name,
        );
    }
}

/// A program is addressed by the content hash of its bytes, and
/// republishing the same bytes must name the same program. This is what
/// lets the host's idempotency cache short-circuit re-puts.
#[test]
fn publishing_is_content_addressed_and_idempotent() {
    let nub = flat_sandbox();
    let p = &PROGRAMS[0];
    let a = nub.put_object(p.blob).expect("publish");
    let b = nub.put_object(p.blob).expect("republish");
    assert_eq!(a, b, "the same bytes hashed to two different names");

    // And the guest agrees with the host's own hash function.
    assert_eq!(
        a,
        nub_flat::hash::content_hash(p.blob),
        "guest-computed hash disagrees with the host's",
    );
}
