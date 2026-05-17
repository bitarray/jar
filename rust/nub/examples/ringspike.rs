//! Ring-0 spike: load the `nub-arch-hyperlight` ELF into a Hyperlight
//! sandbox and run the ring-0 conformance tests that validated the
//! Hyperlight substrate. Run with:
//!
//! ```ignore
//! cargo run -p nub --example ringspike --release
//! ```
//!
//! This is a *regression check* on the Arch substrate, not the kernel
//! interface — it predates `nub-kernel` and bypasses it entirely by
//! calling the guest's bare ring-0 test functions directly through
//! the Hyperlight sandbox. See `tests/smoke.rs` for the Nub-handle
//! smoke tests.
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
use hyperlight_host::sandbox::{GuestBinary, SandboxConfiguration, UninitializedSandbox};

const NUB_ARCH_HYPERLIGHT_BLOB_PATH: &str = env!("NUB_ARCH_HYPERLIGHT_BLOB");

fn main() -> Result<()> {
    println!("nub-prototype: Hyperlight + ring-0 spike");
    println!("guest blob: {NUB_ARCH_HYPERLIGHT_BLOB_PATH}");
    println!();

    // Bump scratch to 8 MiB so all the per-smoke phys-page allocations
    // (per-call BumpArenas + per-test JIT/ctx/stack pages) fit without
    // exhausting Hyperlight's bump-pointer phys allocator. Default is
    // 0x48000 (= 72 pages) which is enough for the original ring-0
    // smokes but not the in-kernel JIT path that lands in Stage C.
    let mut cfg = SandboxConfiguration::default();
    cfg.set_scratch_size(8 * 1024 * 1024);
    let uninit = UninitializedSandbox::new(
        GuestBinary::FilePath(NUB_ARCH_HYPERLIGHT_BLOB_PATH.to_string()),
        Some(cfg),
    )?;
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

    // -- A3 page table smoke (Stage 2.2 prep) --
    let pt: u64 = sandbox.call("page_table_smoke", ())?;
    println!(
        "A3  page_table     readback={:#018x}                {}",
        pt,
        check(pt == 0xCAFE_BABE_DEAD_BEEF),
    );

    // -- A2 int 0x80 IDT handler (Stage 2.2 prep) --
    let int80: u64 = sandbox.call("int80_smoke", ())?;
    println!(
        "A2  int80_smoke    delta={}                                       {}",
        int80,
        check(int80 == 1),
    );

    // -- A4 ring-3 entry (Stage 2.2 prep) --
    let r3: u64 = sandbox.call("ring3_smoke", ())?;
    println!(
        "A4  ring3_smoke    user_rax={:#x}                                {}",
        r3,
        check(r3 == 0x1337),
    );

    // -- B2 javm-recompiler-x86 link smoke (Stage 2.2 prep) --
    let rl: u64 = sandbox.call("recomp_link_smoke", ())?;
    println!(
        "B2  recomp_link    native_bytes={:<3}                              {}",
        rl,
        check(rl > 0),
    );

    // -- C1 in-kernel JIT compile + map (Stage 2.2 prep) --
    let c1: u64 = sandbox.call("c1_jit_compile_smoke", ())?;
    let c1_bytes = c1 >> 16;
    let c1_pages = c1 & 0xFFFF;
    println!(
        "C1  jit_compile    bytes={:<3} pages={}                            {}",
        c1_bytes,
        c1_pages,
        check(c1_bytes > 0 && c1_pages > 0),
    );

    // -- C2 program memory mapping (Stage 2.2 prep) --
    let c2: u64 = sandbox.call("c2_program_mem_smoke", ())?;
    let expected = 0xAA ^ 0xBB ^ 0xCC;
    println!(
        "C2  program_mem    xor={:#04x} (expected {:#04x})                  {}",
        c2,
        expected,
        check(c2 == expected),
    );

    // -- C3 in-kernel JIT at ring 3 (Stage 2.2 prep) --
    let c3: u64 = sandbox.call("c3_jit_run_smoke", ())?;
    let c3_reason = c3 >> 32;
    let c3_arg = c3 & 0xFFFF_FFFF;
    println!(
        "C3  jit_run        exit_reason={} exit_arg={}                       {}",
        c3_reason,
        c3_arg,
        check(c3_reason == 4 && c3_arg == 42),
    );

    // -- A1 bump arena smoke (Stage 2.2 prep) --
    let bump: u64 = sandbox.call("bump_smoke", ())?;
    let aligned = (bump >> 1) & 1 != 0;
    let reuses = bump & 1 != 0;
    println!(
        "A1b bump_smoke     aligned={} reuses_after_reset={}                {}",
        bit(aligned),
        bit(reuses),
        check(aligned && reuses),
    );

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
