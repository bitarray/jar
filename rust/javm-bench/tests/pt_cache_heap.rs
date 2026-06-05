//! Regression test: a steady-state CALL into an already-resident
//! `Cap::Instance` must allocate nothing beyond a small `KernelFrame`
//! — no per-CALL page-table rebuild.
//!
//! The caller `A` (endpoint 0 of `components/benches/pt-cache`)
//! `host_call`s the resident echo `B` (endpoint 1 of the same image)
//! `n` times. We measure the guest
//! heap's **cumulative** allocation counter
//! (`total_allocation_count`) — not the live count — because the page
//! table a CALL builds is freed again at HALT, so it never shows up in
//! the live counter (that's what `heap_drift.rs` guards). The churn of
//! one `A`-invoke is `fixed + n · per_call`; taking the two-point
//! difference `(churn(2n) − churn(n)) / n` cancels `A`'s fixed
//! per-invoke overhead and yields the per-CALL allocation count.
//!
//! Before the page-table cache each CALL rebuilt `B`'s ring-3 page
//! table (PML4 → PDPT → PD → PT intermediates + the CoW'd page),
//! measuring **7** allocations per CALL. Caching the resident
//! instance's page table across CALLs collapses that to **4** — the
//! `KernelFrame` floor (its `mat_state` / cnode / pinned-slot vectors).
//! `CEILING` locks the win: a regression that rebuilds the page table
//! per CALL jumps back to ≥7 and trips it. The test also asserts the
//! churn is **bit-stable** across repeats (determinism).
//!
//! Requires the `heap-diag` feature. Run with:
//!
//! ```bash
//! cargo test -p javm-bench --test pt_cache_heap --features heap-diag \
//!     --release -- --ignored --nocapture
//! ```

#![cfg(all(target_os = "linux", target_arch = "x86_64", feature = "heap-diag"))]

use javm_bench::{PtCacheTop, build_pt_cache_top};
use nub::Nub;

const BLOB: &[u8] = include_bytes!(env!("PT_CACHE_BLOB"));

/// Inner CALL count for the low point of the two-point measurement.
const N: u64 = 50;
/// How many times to re-measure `churn(N)` to assert determinism.
const ROUNDS: usize = 5;
/// Upper bound for the per-CALL allocation churn. The page-table cache
/// brings this to the `KernelFrame` floor (4); the pre-cache behaviour
/// (rebuild the page table every CALL) measured 7, so this ceiling trips
/// on a reintroduced rebuild while leaving headroom for an extra small
/// `KernelFrame` vector.
const CEILING: u64 = 5;

/// Cumulative guest allocations performed during a single invoke of
/// `A` with `n` inner CALLs (the `total_allocation_count` delta across
/// the invoke).
fn invoke_churn(nub: &mut Nub, top: &PtCacheTop, n: u64) -> u64 {
    let before = nub.heap_stats().expect("heap_stats before");
    javm_bench::invoke_pt_cache(nub, top, n);
    let after = nub.heap_stats().expect("heap_stats after");
    after
        .total_allocation_count
        .checked_sub(before.total_allocation_count)
        .expect("total_allocation_count is monotonic")
}

#[test]
#[ignore]
fn pt_cache_heap_per_call_churn() {
    let mut nub = Nub::new_hyperlight().expect("sandbox");
    let top = build_pt_cache_top(&mut nub, BLOB);

    // Warm up (A's + B's JIT compile, the per-image mem backing, any
    // one-shot static init) so the measured churn is steady-state.
    javm_bench::invoke_pt_cache(&mut nub, &top, N);
    javm_bench::invoke_pt_cache(&mut nub, &top, 2 * N);

    // Determinism: the churn of invoking with the same `n` must be
    // bit-identical across repeats.
    let base = invoke_churn(&mut nub, &top, N);
    for r in 0..ROUNDS {
        let again = invoke_churn(&mut nub, &top, N);
        assert_eq!(
            again, base,
            "pt-cache churn not deterministic at round {r}: {again} vs {base}",
        );
    }

    // Per-CALL churn via the two-point difference (cancels A's fixed
    // per-invoke overhead). `churn` is linear in `n`, so churn(2N) ≥
    // churn(N).
    let d_n = invoke_churn(&mut nub, &top, N);
    let d_2n = invoke_churn(&mut nub, &top, 2 * N);
    assert!(
        d_2n >= d_n,
        "churn not monotone in n: churn(N)={d_n} churn(2N)={d_2n}",
    );
    let per_call = (d_2n - d_n) / N;

    eprintln!(
        "pt_cache per-CALL allocation churn = {per_call}  \
         (churn(N={N})={d_n}, churn(2N={})={d_2n})",
        2 * N,
    );
    assert!(
        per_call <= CEILING,
        "per-CALL allocation churn {per_call} exceeds ceiling {CEILING}",
    );
}
