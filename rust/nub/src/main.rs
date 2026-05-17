//! `nub` host driver: load the `nub-arch-hyperlight` ELF into a Hyperlight
//! sandbox, run the ring-0 spike tests, print the results.
//!
//! Tests:
//!
//! * **A1 smoke**: trivial round-trip. Host calls; guest returns 42.
//!   Validates the build-nub + hyperlight-host plumbing.
//! * **B1 read_cregs**: guest reads CR0, CR4, EFER and reports.
//!   Confirms ring 0, long mode, paging are all active.
//! * **B2 read_cs_cpl**: guest reads CS, reports CPL. Confirms CPL=0.
//! * **C1 pf_roundtrip**: guest installs a #PF handler, touches an
//!   unmapped page. If the handler runs in-guest, the access
//!   succeeds and we measure the round-trip cycle cost. If
//!   Hyperlight forces a VM-exit on #PF instead, the call returns
//!   an error.

use anyhow::Result;
use hyperlight_host::sandbox::{GuestBinary, UninitializedSandbox};

const NUB_ARCH_HYPERLIGHT_BLOB_PATH: &str = env!("NUB_ARCH_HYPERLIGHT_BLOB");

fn main() -> Result<()> {
    println!("nub-prototype: Hyperlight + ring-0 spike");
    println!("guest blob: {NUB_ARCH_HYPERLIGHT_BLOB_PATH}");
    println!();

    let uninit =
        UninitializedSandbox::new(GuestBinary::FilePath(NUB_ARCH_HYPERLIGHT_BLOB_PATH.to_string()), None)?;
    let mut sandbox = uninit.evolve()?;

    // -- A1 smoke --
    let r: u64 = sandbox.call("smoke", ())?;
    println!(
        "A1 smoke           result={:5}     (expected 42)              {}",
        r,
        check(r == 42),
    );

    // -- B1 read_cregs --
    let packed: u64 = sandbox.call("read_cregs", ())?;
    let cr0_bits = packed & 0xFF_FFFF;
    let cr4_bits = (packed >> 24) & 0xFFFF;
    let efer_bits = (packed >> 40) & 0xFFFF;
    let cr0_pe = cr0_bits & (1 << 0) != 0;
    let cr0_pg = cr0_bits & (1 << 16) != 0;
    let cr4_pae = cr4_bits & (1 << 5) != 0;
    let efer_lme = efer_bits & (1 << 8) != 0;
    let efer_lma = efer_bits & (1 << 10) != 0;
    let efer_sce = efer_bits & (1 << 0) != 0;
    let efer_nx = efer_bits & (1 << 11) != 0;
    let ring0_ok = cr0_pe && cr0_pg && cr4_pae && efer_lme && efer_lma;
    println!(
        "B1 read_cregs      CR0:PE={} PG={}  CR4:PAE={}  EFER:LME={} LMA={} SCE={} NX={}  {}",
        bit(cr0_pe),
        bit(cr0_pg),
        bit(cr4_pae),
        bit(efer_lme),
        bit(efer_lma),
        bit(efer_sce),
        bit(efer_nx),
        check(ring0_ok),
    );

    // -- B2 read_cs_cpl --
    let cpl: u64 = sandbox.call("read_cs_cpl", ())?;
    println!(
        "B2 read_cs_cpl     CPL={}                                       {}",
        cpl,
        check(cpl == 0),
    );

    // -- C1 pf_roundtrip --
    match sandbox.call::<u64>("pf_roundtrip", ()) {
        Ok(packed) => {
            let pf_count = packed >> 48;
            let cycles = packed & 0x0000_FFFF_FFFF_FFFF;
            let readback: u64 = sandbox.call("pf_readback", ())?;
            let count_ok = pf_count == 1;
            let value_ok = readback == 0xCAFE_BABE;
            let ns = cycles_to_ns(cycles);
            println!(
                "C1 pf_roundtrip    fires={} readback={:#010x}  cycles={}  (~{} ns)  {}",
                pf_count,
                readback,
                cycles,
                ns,
                check(count_ok && value_ok),
            );
        }
        Err(e) => {
            println!("C1 pf_roundtrip    error: {e}  (likely Hyperlight forces VM-exit on #PF)  ✗");
        }
    }

    // -- C2 cr3_self_swap --
    let cr3: u64 = sandbox.call("cr3_self_swap", ())?;
    println!(
        "C2 cr3_self_swap   CR3={:#x}                              {}",
        cr3,
        check(cr3 != 0),
    );

    // -- D2 cow_roundtrip --
    match sandbox.call::<u64>("cow_roundtrip", ()) {
        Ok(packed) => {
            let pf_count = packed >> 48;
            let cycles = packed & 0x0000_FFFF_FFFF_FFFF;
            let ns = cycles_to_ns(cycles);
            println!(
                "D2 cow_roundtrip   fires={}  cycles={}  (~{} ns)  {}",
                pf_count,
                cycles,
                ns,
                check(pf_count == 1),
            );
        }
        Err(e) => {
            println!("D2 cow_roundtrip   error: {e}  ✗");
        }
    }

    // -- D1 per-call latency --
    const N_CALLS: u64 = 10_000;
    let t1 = std::time::Instant::now();
    for _ in 0..N_CALLS {
        let _: u64 = sandbox.call("noop", ())?;
    }
    let elapsed = t1.elapsed();
    let per_call_ns = elapsed.as_nanos() as u64 / N_CALLS;
    println!(
        "D1 per_call_avg    {} ns/call over {} calls",
        per_call_ns, N_CALLS,
    );

    Ok(())
}

fn check(b: bool) -> &'static str {
    if b { "✓" } else { "✗" }
}
fn bit(b: bool) -> u8 {
    if b { 1 } else { 0 }
}
/// Approximate cycle → ns at i9-13900K's nominal 3.0 GHz (turbo runs
/// to 5.8 but rdtsc tracks the invariant TSC, which is the
/// non-turbo base frequency).
fn cycles_to_ns(cycles: u64) -> u64 {
    cycles / 3
}
