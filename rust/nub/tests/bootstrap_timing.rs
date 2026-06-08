//! Standalone timing for the `Nub::hyperlight()` singleton. Run with:
//!
//! ```bash
//! cargo test -p nub --release --test bootstrap_timing -- --ignored --nocapture
//! ```
//!
//! `#[ignore]` because it's a manual measurement, not a CI gate. The
//! Hyperlight backend is a process singleton, so this measures the first
//! singleton access separately from repeated cached borrows.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use nub::Nub;
use std::time::Instant;

const N: usize = 10;

#[test]
#[ignore]
fn nub_hyperlight_boot() {
    let t = Instant::now();
    drop(Nub::hyperlight().expect("sandbox"));
    let first = t.elapsed();
    eprintln!(
        "Nub::hyperlight() first singleton access: {:.3} ms",
        first.as_secs_f64() * 1e3,
    );

    let mut samples = Vec::with_capacity(N);
    for i in 0..N {
        let t = Instant::now();
        let nub = Nub::hyperlight().expect("sandbox");
        let elapsed = t.elapsed();
        drop(nub);
        samples.push(elapsed);
        eprintln!(
            "cached borrow {:2}: {:.3} us",
            i,
            elapsed.as_secs_f64() * 1e6
        );
    }

    samples.sort();
    let min = samples[0];
    let p50 = samples[N / 2];
    let p90 = samples[N * 9 / 10];
    let max = samples[N - 1];
    let mean_us = samples.iter().map(|d| d.as_secs_f64()).sum::<f64>() / (N as f64) * 1e6;

    eprintln!();
    eprintln!("Nub::hyperlight() cached singleton borrow across {N} samples:");
    eprintln!("  min: {:.3} us", min.as_secs_f64() * 1e6);
    eprintln!("  p50: {:.3} us", p50.as_secs_f64() * 1e6);
    eprintln!("  p90: {:.3} us", p90.as_secs_f64() * 1e6);
    eprintln!("  max: {:.3} us", max.as_secs_f64() * 1e6);
    eprintln!("  avg: {mean_us:.3} us");
}

#[test]
#[ignore]
fn nub_new_local_boot() {
    // Local is in-process — should be sub-microsecond, but worth
    // confirming.
    let mut samples = Vec::with_capacity(N * 100);
    for _ in 0..N * 100 {
        let t = Instant::now();
        let nub = Nub::new_local();
        let elapsed = t.elapsed();
        drop(nub);
        samples.push(elapsed);
    }

    samples.sort();
    let min = samples[0];
    let p50 = samples[samples.len() / 2];
    let p90 = samples[samples.len() * 9 / 10];
    let max = samples[samples.len() - 1];

    eprintln!();
    eprintln!(
        "Nub::new_local() construction across {} samples:",
        samples.len()
    );
    eprintln!("  min: {:?}", min);
    eprintln!("  p50: {:?}", p50);
    eprintln!("  p90: {:?}", p90);
    eprintln!("  max: {:?}", max);
}
