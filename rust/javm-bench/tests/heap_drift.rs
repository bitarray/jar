//! Regression test: the guest heap must not grow across repeated
//! `Nub::invoke_cached` calls. Runs `prime_sieve` 2000 times against
//! a single Hyperlight sandbox, sampling `talc`'s counters every 100
//! iters; asserts that allocated bytes and allocation count are
//! exactly bit-stable from iter 1 onward (iter 0 → 1 is allowed to
//! grow once for one-shot static init).
//!
//! Catches re-introduction of the kind of leak we fixed in commit
//! ad8b227d — there `install_ring3_exit_gate` was `Box::leak`ing 4106
//! B per invocation, exhausting the heap during long bench runs.
//!
//! Requires the `heap-diag` feature. Run with:
//!
//! ```bash
//! cargo test -p javm-bench --test heap_drift --features heap-diag \
//!     --release -- --ignored --nocapture
//! ```

#![cfg(all(target_os = "linux", target_arch = "x86_64", feature = "heap-diag"))]

use javm_cap::image::Image;
use nub::Nub;
use ssz::Decode;

const PRIME_SIEVE_BLOB: &[u8] = include_bytes!(env!("PRIME_SIEVE_BLOB"));
const N: usize = 2000;
const STEP: usize = 100;
const GAS: u64 = 100_000_000_000;

#[test]
#[ignore]
fn heap_drift_prime_sieve() {
    let image = Image::from_ssz_bytes(PRIME_SIEVE_BLOB)
        .expect("decode prime_sieve Image");
    let mut nub = Nub::new_hyperlight().expect("sandbox");
    let published = javm_bench::publish(&mut nub, &image, 0);
    let instance_hash = published.instance_hash;

    // Iter 0: baseline.
    let _ = nub.heap_stats().expect("baseline heap_stats");

    // Iter 1: lets any first-call static init (e.g. one-shot IDT
    // install in `install_ring3_exit_gate`) settle.
    nub.invoke_cached(instance_hash, 0, [0; 4], GAS)
        .expect("invoke_cached");
    let warm = nub.heap_stats().expect("post-warmup heap_stats");
    eprintln!("iter         alloc_B    n_alloc   n_frag   avail_B   Δalloc");
    eprintln!(
        "{:>5}  {:>12}  {:>8}  {:>7}  {:>9}  {:>9}",
        1,
        warm.allocated_bytes,
        warm.allocation_count,
        warm.fragment_count,
        warm.available_bytes,
        0i64,
    );

    // Iters 2..=N: should be exactly bit-stable.
    for i in 2..=N {
        nub.invoke_cached(instance_hash, 0, [0; 4], GAS)
            .expect("invoke_cached");
        if i % STEP == 0 {
            let s = nub.heap_stats().expect("heap_stats");
            let delta = s.allocated_bytes as i64 - warm.allocated_bytes as i64;
            eprintln!(
                "{:>5}  {:>12}  {:>8}  {:>7}  {:>9}  {:>+9}",
                i,
                s.allocated_bytes,
                s.allocation_count,
                s.fragment_count,
                s.available_bytes,
                delta,
            );
            assert_eq!(
                s.allocated_bytes, warm.allocated_bytes,
                "heap drifted at iter {i}: {} bytes vs warm {} bytes",
                s.allocated_bytes, warm.allocated_bytes,
            );
            assert_eq!(
                s.allocation_count, warm.allocation_count,
                "allocation count drifted at iter {i}: {} vs warm {}",
                s.allocation_count, warm.allocation_count,
            );
        }
    }
}
