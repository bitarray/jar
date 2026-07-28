//! Endpoint 2 must be re-invocable on one instance.
//!
//! This is the regression the shared bump arena's `reset` exists for.
//! Before it, three programs carried a private never-freeing arena and
//! the second call in an instance walked off the end — surfacing as a
//! guest panic, which reads like a miscompile rather than an exhausted
//! allocator.
//!
//! It matters beyond tidiness: measuring steady-state execution means
//! invoking one instance repeatedly, so a single-shot program either
//! cannot be measured that way or, worse, is measured wrongly.

use nub_arch_local::{PreparedProgram, ProgramInstance};
use nub_bench::{BENCH_GAS, EXIT_HOST_CALL, PROGRAMS};

/// Endpoint indices of the two-entry ABI every program exposes.
const EP_INITIALIZE: u8 = 1;
const EP_RUN: u8 = 2;

/// Enough invocations to exhaust every arena in the suite several times
/// over if `reset` were not happening: `fri-fold-tree` allocates 64 KiB
/// of its 256 KiB per call, so it would die on the fifth.
const INVOCATIONS: usize = 20;

#[test]
fn endpoint_two_is_re_invocable_with_stable_value_and_gas() {
    for p in PROGRAMS {
        let blob = p.decode();
        let prepared = PreparedProgram::new(&blob, EP_RUN, [0; 4])
            .unwrap_or_else(|e| panic!("[{}] prepare endpoint {EP_RUN}: {e}", p.name));
        let mut instance = ProgramInstance::new(&prepared.spec());

        let mut observed = Vec::with_capacity(INVOCATIONS);
        for i in 0..INVOCATIONS {
            let mut handler = nub_arch_local::ExitingEcallHandler;
            let r = instance.invoke(&mut handler, BENCH_GAS);
            assert_eq!(
                r.exit_reason, EXIT_HOST_CALL,
                "[{}] invocation {i} did not halt cleanly: exit_reason={} \
                 (1 = guest panic, which is what arena exhaustion looks like)",
                p.name, r.exit_reason,
            );
            observed.push((r.return_value, BENCH_GAS - r.gas_remaining));
        }

        // Every invocation computes the same thing, and agrees with
        // endpoint 0 — endpoint 2 differs only by the `reset_heap` call.
        for (i, (value, _)) in observed.iter().enumerate() {
            assert_eq!(
                *value, p.expected_value,
                "[{}] invocation {i} returned the wrong value",
                p.name,
            );
        }

        // Gas is *not* stable from the first invocation: nub charges
        // first-touch materialization once (lazy code page-in, CoW), so
        // a cold run legitimately costs more than a warm one. What must
        // hold is that it settles — every invocation after the first
        // charges exactly the same, meaning nothing is accumulating.
        let cold = observed[0].1;
        let warm = observed[1].1;
        assert!(
            cold >= warm,
            "[{}] the cold invocation charged less than the warm one \
             ({cold} < {warm}), which inverts the page-in cost",
            p.name,
        );
        for (i, (_, gas)) in observed.iter().enumerate().skip(1) {
            assert_eq!(
                *gas, warm,
                "[{}] invocation {i} charged {gas}, but invocation 1 charged {warm}: \
                 gas is still drifting, so some per-invocation state is accumulating",
                p.name,
            );
        }
    }
}

/// `initialize` is a no-op that must still halt cleanly, so a caller can
/// always run it before the first `run` without special-casing.
#[test]
fn endpoint_one_initializes_cleanly() {
    for p in PROGRAMS {
        let blob = p.decode();
        let result = nub_arch_local::run_blob(&blob, EP_INITIALIZE, [0; 4], BENCH_GAS)
            .unwrap_or_else(|e| panic!("[{}] prepare endpoint {EP_INITIALIZE}: {e}", p.name));
        assert_eq!(
            result.exit_reason, EXIT_HOST_CALL,
            "[{}] initialize did not halt cleanly",
            p.name
        );
        assert_eq!(
            result.return_value, 0,
            "[{}] initialize returned non-zero",
            p.name
        );
    }
}

/// Endpoint 0 stays single-shot by design — it is what the pinned gas
/// vectors address, so it must not gain a `reset_heap` call. This test
/// pins that split: it asserts endpoint 0 still reproduces its vector,
/// which would change the moment someone "helpfully" made it reset too.
#[test]
fn endpoint_zero_still_matches_its_pinned_vector() {
    for p in PROGRAMS {
        let blob = p.decode();
        let (value, gas) = nub_bench::run_interpreter(p.name, &blob);
        assert_eq!(
            (value, gas),
            (p.expected_value, p.expected_gas),
            "[{}]",
            p.name
        );
    }
}
