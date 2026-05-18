//! Standalone timing for `Nub::new_hyperlight()` boot. Run with:
//!
//! ```bash
//! cargo test -p nub --release --test bootstrap_timing -- --ignored --nocapture
//! ```
//!
//! `#[ignore]` because it's a manual measurement, not a CI gate: each
//! sandbox allocates ~768 MiB of mmap'd address space (the
//! `Nub::new_hyperlight()` config = 512 MiB scratch + 256 MiB heap) and
//! runs the guest's init function, so 10 iterations cost ~7.5 GiB of
//! VA + several seconds of wall time. Plenty to be visible in `top`
//! but well within a 32 GiB-RAM dev box.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use nub::Nub;
use std::time::Instant;

const N: usize = 10;

#[test]
#[ignore]
fn nub_new_hyperlight_boot() {
    // One warm-up so any first-time JIT / linker init lands outside
    // the measurement window.
    drop(Nub::new_hyperlight().expect("warm-up sandbox"));

    let mut samples = Vec::with_capacity(N);
    for i in 0..N {
        let t = Instant::now();
        let nub = Nub::new_hyperlight().expect("sandbox");
        let elapsed = t.elapsed();
        // Drop the sandbox AFTER capturing the boot time, so dealloc
        // doesn't pollute the measurement.
        drop(nub);
        samples.push(elapsed);
        eprintln!("iter {:2}: {:.3} ms", i, elapsed.as_secs_f64() * 1e3);
    }

    samples.sort();
    let min = samples[0];
    let p50 = samples[N / 2];
    let p90 = samples[N * 9 / 10];
    let max = samples[N - 1];
    let mean_ms = samples.iter().map(|d| d.as_secs_f64()).sum::<f64>() / (N as f64) * 1e3;

    eprintln!();
    eprintln!("Nub::new_hyperlight() boot across {N} samples (post-warm-up):");
    eprintln!("  min: {:.3} ms", min.as_secs_f64() * 1e3);
    eprintln!("  p50: {:.3} ms", p50.as_secs_f64() * 1e3);
    eprintln!("  p90: {:.3} ms", p90.as_secs_f64() * 1e3);
    eprintln!("  max: {:.3} ms", max.as_secs_f64() * 1e3);
    eprintln!("  avg: {mean_ms:.3} ms");
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
