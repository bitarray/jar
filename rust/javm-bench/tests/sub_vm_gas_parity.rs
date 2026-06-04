//! Consensus gas parity for the **sub-VM recursion** path across runtime
//! eviction — i.e. that runtime eviction is **gas-transparent**.
//!
//! `workloads.rs` pins interp == recomp gas for single-frame programs. The
//! multi-frame sub-VM recursion (`derive_spawn` → `host_call` → … → REPLY →
//! HALT) has no interpreter counterpart to diff against here: the `Nub` local
//! backend's ecall handler *exits* on the first `host_derive_spawn` (it does not
//! recurse), so the in-kernel `nub-arch-x86::call_loop` is the sole driver of a
//! self-recursing guest. We instead pin the property the eviction-recharge bug
//! violated: **the gas a run charges must not depend on whether its frames were
//! evicted.**
//!
//! Eviction (`call_loop::RUNTIME_CACHE_CAP`, currently **512**) drops a paused
//! deep frame's `FrameRuntime` and rebuilds it on resume; it exists only to
//! bound memory and must be invisible to gas. The guest here
//! (`components/tests/sub-vm-reread-recurse`) **re-reads its RO + RW memory
//! after `host_call` returns** — unlike the bench guests, which return a
//! register value and touch no memory on the way up. That post-resume re-read
//! is what an evicted+rebuilt frame must not re-charge category-#3 for (the
//! pages were materialized + charged on the way down). Every level does
//! identical work, so the recompiler's gas is exactly **affine** in depth: any
//! window of N spawning levels charges the same total, whether or not those
//! levels were evicted. We measure two equal 200-level windows that bracket the
//! cap —
//!
//!   * `200 → 400` — entirely below the cap: no frame is ever evicted.
//!   * `600 → 800` — entirely above the cap: every level evicts + rebuilds on
//!     resume.
//!
//! — and assert the two increments are equal. (The windows must sit on opposite
//! sides of `RUNTIME_CACHE_CAP`; if that constant is raised past ~600 or dropped
//! below ~400, move these depths.) The interpreter never evicts, so a
//! gas-transparent recompiler is exactly the one that agrees with it. Before the
//! fix the recompiler reset its `mat_state` / `ro_units` on eviction and
//! re-charged page-in / CoW for the resumed frame's re-read pages, so the
//! all-evicting window cost ~one RO-unit page-in + one RW page-in per level more
//! — a hard fork at depth > cap, invisible to the value-only gates. This test
//! pins the fix (verified to fail without it).
//!
//! Linux x86_64 only: the recompiler path needs Hyperlight + KVM.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

const BLOB: &[u8] = include_bytes!(env!("SUB_VM_REREAD_RECURSE_BLOB"));

/// Per-level RO-unit sum (= `256 × (0+64+128+192)`), matching the guest's
/// `ro_sum()`.
const RO_SUM: u64 = 98_304;

/// The guest's deterministic return: depth 0 → `RO_SUM + (depth & 0xFF)`;
/// depth > 0 also folds the post-resume re-reads → `2*RO_SUM + 2*(depth & 0xFF)`.
fn expected_return(depth: u64) -> u64 {
    if depth == 0 {
        RO_SUM + (depth & 0xFF)
    } else {
        2 * RO_SUM + 2 * (depth & 0xFF)
    }
}

/// `(return_value, gas_used)` for the re-read recurse guest at `depth` on the
/// long-lived Hyperlight recompiler sandbox.
fn recomp_run(depth: u64) -> (u64, u64) {
    let mut nub = javm_bench::nub_hyperlight_lock();
    let top = javm_bench::build_sub_vm_top(&mut nub, BLOB);
    javm_bench::invoke_sub_vm_gas(&mut nub, &top, depth)
}

#[test]
fn eviction_is_gas_transparent() {
    // Two equal 200-level windows bracketing RUNTIME_CACHE_CAP (512): the lower
    // entirely below it (no eviction), the upper entirely above it (every level
    // evicts + rebuilds on resume).
    let runs: Vec<(u64, (u64, u64))> = [200u64, 400, 600, 800]
        .iter()
        .map(|&d| (d, recomp_run(d)))
        .collect();
    // Guard against a silently broken run masquerading as gas agreement.
    for &(d, (v, _)) in &runs {
        assert_eq!(v, expected_return(d), "depth {d} return value");
    }
    let gas = |d: u64| runs.iter().find(|(rd, _)| *rd == d).unwrap().1.1;

    let step_below = gas(400) - gas(200); // 200 levels, none evicted
    let step_across = gas(800) - gas(600); // 200 levels, all evicted + rebuilt

    eprintln!(
        "[sub_vm_gas_parity] gas: d200={} d400={} d600={} d800={}; \
         step_below(200→400)={step_below} step_across(600→800)={step_across}",
        gas(200),
        gas(400),
        gas(600),
        gas(800),
    );

    assert_eq!(
        step_across,
        step_below,
        "runtime eviction leaked into gas: an evicted+resumed frame re-charged \
         category-#3 (page-in/CoW) for its post-resume re-reads. all-evicting \
         200-level window cost {step_across}, no-eviction {step_below} (delta {})",
        step_across as i64 - step_below as i64,
    );
}
