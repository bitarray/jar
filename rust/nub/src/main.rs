//! `nub` host driver: load the `nub-guest` ELF into a Hyperlight
//! sandbox, run the ring-0 spike tests, print the results.
//!
//! Tests:
//!
//! * **A1 smoke**: trivial round-trip. Host calls; guest returns 42.
//!   Validates the build-nub + hyperlight-host plumbing.
//! * **B1 read_cregs**: guest reads CR0, CR4, EFER and reports.
//!   Confirms ring 0, long mode, paging are all active.
//! * **B2 read_cs_cpl**: guest reads CS, reports CPL. Confirms CPL=0.

use anyhow::Result;
use hyperlight_host::sandbox::{GuestBinary, UninitializedSandbox};

const NUB_GUEST_BLOB_PATH: &str = env!("NUB_GUEST_BLOB");

fn main() -> Result<()> {
    println!("nub-prototype: Hyperlight + ring-0 spike");
    println!("guest blob: {NUB_GUEST_BLOB_PATH}");
    println!();

    let uninit =
        UninitializedSandbox::new(GuestBinary::FilePath(NUB_GUEST_BLOB_PATH.to_string()), None)?;
    let mut sandbox = uninit.evolve()?;

    // -- A1 smoke --
    let r: u64 = sandbox.call("smoke", ())?;
    let ok = r == 42;
    println!(
        "A1 smoke           result={:5}     (expected 42)              {}",
        r,
        check(ok),
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

    Ok(())
}

fn check(b: bool) -> &'static str {
    if b { "✓" } else { "✗" }
}
fn bit(b: bool) -> u8 {
    if b { 1 } else { 0 }
}
