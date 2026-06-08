//! Gas determinism for the **sub-VM recursion** path: the recompiler must
//! charge identical gas per recursion level, so total gas is exactly **affine**
//! in depth.
//!
//! `workloads.rs` pins interp == recomp gas for single-frame programs. The
//! multi-frame sub-VM recursion (`derive_spawn` → `host_call` → … → REPLY →
//! HALT) has no interpreter counterpart to diff against here: the `Nub` local
//! backend's ecall handler *exits* on the first `host_derive_spawn` (it does not
//! recurse), so the in-kernel `nub-arch-x86::call_loop` is the sole driver of a
//! self-recursing guest. So instead we pin a self-consistency property: every
//! recursion level does identical work, so any window of N levels must charge
//! the same total — gas is affine in depth.
//!
//! The guest (`components/tests/sub-vm-reread-recurse`) **re-reads its RO + RW
//! memory after `host_call` returns** — unlike the bench guests, which return a
//! register value and touch no memory on the way up — so each level exercises
//! the full category-#3 path (RO-unit page-in + CoW) both down and up. We sample
//! two equal 200-level windows (`200→400` and `600→800`) and assert equal gas
//! increments.
//!
//! This was originally the eviction-gas-transparency regression test (a frame
//! whose `FrameRuntime` was evicted + rebuilt must not re-charge category-#3 for
//! pages it already paid for). Runtime eviction has since been removed (the
//! synchronous call stack is bounded structurally — see
//! `docs/spec-staging/implementation/call-depth-and-cap-nesting.md`), so there is
//! no longer an eviction boundary to straddle; the affine-gas check remains as a
//! multi-frame determinism guard (and the gas state still lives on the
//! `KernelFrame` so it survives any future runtime reclamation).
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
    javm_bench::invoke_sub_vm_gas(&nub, &top, depth)
}

#[test]
fn recursion_gas_is_affine_in_depth() {
    // Two equal 200-level windows at different absolute depths. Each level does
    // identical work, so both windows must charge the same total gas.
    let runs: Vec<(u64, (u64, u64))> = [200u64, 400, 600, 800]
        .iter()
        .map(|&d| (d, recomp_run(d)))
        .collect();
    // Guard against a silently broken run masquerading as gas agreement.
    for &(d, (v, _)) in &runs {
        assert_eq!(v, expected_return(d), "depth {d} return value");
    }
    let gas = |d: u64| runs.iter().find(|(rd, _)| *rd == d).unwrap().1.1;

    let lower_window = gas(400) - gas(200); // 200 levels
    let upper_window = gas(800) - gas(600); // 200 levels, deeper

    eprintln!(
        "[sub_vm_gas_parity] gas: d200={} d400={} d600={} d800={}; \
         lower(200→400)={lower_window} upper(600→800)={upper_window}",
        gas(200),
        gas(400),
        gas(600),
        gas(800),
    );

    assert_eq!(
        upper_window,
        lower_window,
        "sub-VM recursion gas is not affine in depth: two equal 200-level windows \
         charged differently (lower {lower_window}, upper {upper_window}, delta {}) \
         — a per-depth-varying category-#3 charge would fork the interpreter",
        upper_window as i64 - lower_window as i64,
    );
}
