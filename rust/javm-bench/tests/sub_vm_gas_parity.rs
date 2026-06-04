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
//! Eviction (`call_loop::RUNTIME_CACHE_CAP`, 256) drops a paused deep frame's
//! `FrameRuntime` and rebuilds it on resume; it exists only to bound memory and
//! must be invisible to gas. The guest here
//! (`components/tests/sub-vm-reread-recurse`) **re-reads its RO + RW memory
//! after `host_call` returns** — unlike the bench guests, which return a
//! register value and touch no memory on the way up. That post-resume re-read
//! is what an evicted+rebuilt frame must not re-charge category-#3 for (the
//! pages were materialized + charged on the way down). Every level does
//! identical work, so the recompiler's gas is exactly **affine** in depth: any
//! window of N spawning levels charges the same total, whether or not those
//! levels straddle the cap. We measure two equal 100-level windows —
//!
//!   * `100 → 200` — entirely below the cap: no eviction.
//!   * `200 → 300` — crosses the cap: the deepest ~44 frames are evicted while
//!     paused and rebuilt on resume.
//!
//! — and assert the two increments are equal. The interpreter never evicts, so
//! a gas-transparent recompiler is exactly the one that agrees with it. Before
//! the fix the recompiler reset its `mat_state` / `ro_units` on eviction and
//! re-charged page-in / CoW for the resumed frame's re-read pages, so the
//! across-cap window cost strictly more — a hard fork at depth > 256, invisible
//! to the value-only gates. This test pins the fix (verified to fail without
//! it: the across-cap window is ~one RO-unit page-in + one CoW page-in per
//! evicted frame heavier).
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
    let (v100, g100) = recomp_run(100);
    let (v200, g200) = recomp_run(200);
    let (v300, g300) = recomp_run(300);

    // Guard against a silently broken run masquerading as gas agreement.
    assert_eq!(v100, expected_return(100), "depth 100 return value");
    assert_eq!(v200, expected_return(200), "depth 200 return value");
    assert_eq!(v300, expected_return(300), "depth 300 return value");

    let step_below = g200 - g100; // 100 spawning levels, no eviction
    let step_across = g300 - g200; // 100 spawning levels, crosses the cap (256)

    eprintln!(
        "[sub_vm_gas_parity] gas: d100={g100} d200={g200} d300={g300}; \
         step_below(100→200)={step_below} step_across(200→300)={step_across}",
    );

    assert_eq!(
        step_across,
        step_below,
        "runtime eviction leaked into gas: an evicted+resumed frame re-charged \
         category-#3 (page-in/CoW) for its post-resume re-reads. across-cap \
         100-level window cost {step_across}, below-cap {step_below} (delta {})",
        step_across as i64 - step_below as i64,
    );
}
