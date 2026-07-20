//! Live interpreter ↔ recompiler differential — the edge-case-finding engine.
//!
//! Generates RV64E-subset programs and asserts the two engines agree
//! bit-for-bit on `{exit, x10, gas}`. This needs no oracle: the interpreter is
//! the trusted reference, and a recompiler disagreement is a consensus bug.
//! (Committed golden vectors — the *external*-oracle regression gate — live in
//! `vectors.rs`.)
//!
//! ## Test layout
//! - [`acceptance_div_intmin_neg1`] — the headline case; **green** (the
//!   INT_MIN/-1 recompiler bug this fuzzer surfaced is now fixed).
//! - The `*_sweep` tests are `#[ignore]`-d **hunting tools**: run them with
//!   `--ignored` to search for divergences. They currently surface *open*
//!   recompiler bugs (see `~/docs/pvm-isa/discussions/implementation-bugs.md`),
//!   so they are not part of the default green run.
//!
//! One long-lived Hyperlight sandbox handles every program — no per-program
//! rebuilds (rebuilding was the host-heap-corruption bug; a single sandbox runs
//! thousands of distinct invocations cleanly).
//!
//! Gated to linux/x86_64: the recompiler runs in the Hyperlight/KVM sandbox, so
//! `javm-bench` (and `javm_fuzz::replay`) only exist there. The generator and
//! encoders are covered cross-platform by the `javm-fuzz` lib unit tests.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use javm_fuzz::generate::{Gen, enumerate_boundary};
use javm_fuzz::replay::{Diff, diff, diff_batch};
use javm_fuzz::{MemWindow, Program, encode};
use std::collections::BTreeMap;

fn report(diverged: &[(usize, Diff)], total: usize) -> String {
    let mut lines: Vec<String> = diverged
        .iter()
        .map(|(i, d)| format!("#{i}: {}", d.describe()))
        .collect();
    lines.sort();
    format!(
        "{} / {total} diverged:\n  {}",
        diverged.len(),
        lines.join("\n  ")
    )
}

/// The acceptance case: `div x10, INT_MIN, -1`, with the signature epilogue. An
/// ordinary boundary program the enumerator also produces — nothing here knows
/// the recompiler lacked an INT_MIN/-1 guard; the differential *discovered* it
/// (the recompiler `#DE`-aborted where the interpreter returns INT_MIN). With
/// the guard in place, the two now agree. **This is the green, committed proof.**
#[test]
fn acceptance_div_intmin_neg1() {
    let mut init = BTreeMap::new();
    init.insert(nub_exec::regs::reg_slot_or_ff(8), 0x8000_0000_0000_0000); // x8 = i64::MIN
    init.insert(nub_exec::regs::reg_slot_or_ff(9), 0xFFFF_FFFF_FFFF_FFFF); // x9 = -1
    let mut code = vec![encode::div(10, 8, 9)];
    code.extend(encode::signature_epilogue(javm_fuzz::SIG_BASE));
    let prog = Program {
        code,
        init_regs: init,
        init_mem: None,
    };

    let d = diff(&prog);
    assert!(
        !d.diverges(),
        "interp/recomp diverge on `div INT_MIN, -1`: {}",
        d.describe(),
    );
}

/// Full boundary enumeration through both engines — the biggest edge-case
/// sweep. `#[ignore]`-d: it publishes ~thousands of distinct images into a
/// single long-lived sandbox, and the guest cap directory never evicts blobs,
/// so the guest talc heap eventually OOMs (B13 in implementation-bugs.md — a
/// directory-lifecycle gap, *not* a consensus divergence). Run with `--ignored`
/// to hunt for ISA divergences up to the OOM point.
#[test]
#[ignore = "hunting tool: exhausts the guest heap (B13: directory never evicts blobs)"]
fn boundary_sweep() {
    let progs = enumerate_boundary();
    let diverged = diff_batch(&progs);
    assert!(diverged.is_empty(), "{}", report(&diverged, progs.len()));
}

/// Random-sequence sweep — 256 distinct multi-op programs through both engines.
/// **Green** and part of the default `--ignored`-free run: this is the
/// regression for two bugs this fuzzer surfaced and we fixed:
/// - **B11**: the host read the guest's cap-directory hashbrown table directly,
///   but the host (SSE2, 16-byte `Group`) and guest (`x86_64-unknown-none`, no
///   SSE2, generic 8-byte `Group`) disagree on the control-array layout; once
///   the directory grew past one group the host walked off the end. Publishing
///   256 distinct images forces that growth — pre-fix this panicked at the 6th.
/// - **B12**: the 32-bit `divw`/`remw` zero-divisor guard tested the full
///   64-bit register, so a divisor with a zero low half (e.g. i64::MIN)
///   #DE-faulted the recompiler.
#[test]
fn random_sweep() {
    let progs = Gen::new(0xC0FFEE).random_batch(256, 6);
    let diverged = diff_batch(&progs);
    assert!(diverged.is_empty(), "{}", report(&diverged, progs.len()));
}

// ---- Category-#3 memory materialization acceptance (D-1..D-3) -------------
//
// Each program runs through BOTH engines; the assertion is they agree on
// {exit, x10, gas}. The **gas** equality is the #3 consensus check: the
// interpreter's software first-touch accounting and the recompiler's
// hardware-fault materialization must charge bit-identically. Each program
// declares a zero-filled RW window at DATA_BASE (see `replay::image_for`),
// which both engines lazily materialize.

/// Protocol data base ([`javm_cap::layout::DATA_BASE`]).
const DATA_BASE: u32 = 0x1000_0000;

/// A no-fold memory program: `body` leaves its result in x10, backed by a
/// zero-filled RW window of `window_bytes` at DATA_BASE.
fn mem_prog(body: Vec<u32>, window_bytes: usize) -> Program {
    Program {
        code: body,
        init_regs: BTreeMap::new(),
        init_mem: Some(MemWindow {
            start: DATA_BASE,
            bytes: vec![0u8; window_bytes],
        }),
    }
}

fn assert_agree(prog: &Program, what: &str) {
    let d = diff(prog);
    assert!(
        !d.diverges(),
        "interp/recomp diverge on {what}: {}",
        d.describe(),
    );
}

#[test]
fn mem_page_in_on_read() {
    // First read of a fresh page → page-in charge on both engines; reads 0.
    let mut body = encode::li64(8, DATA_BASE as u64);
    body.push(encode::ld(10, 8, 0)); // x10 = mem[DATA_BASE]
    assert_agree(&mem_prog(body, 8192), "page-in on read");
}

#[test]
fn mem_cow_on_write() {
    // First write → page-in + CoW; the readback is free (page present).
    let mut body = encode::li64(8, DATA_BASE as u64);
    body.extend(encode::li64(9, 0xCAFE));
    body.push(encode::sd(8, 9, 0)); // mem[DATA_BASE] = 0xCAFE
    body.push(encode::ld(10, 8, 0)); // x10 = 0xCAFE
    assert_agree(&mem_prog(body, 8192), "CoW on write");
}

#[test]
fn mem_read_then_write_single_cow() {
    // D-2: a read pages-in (RO); a later write to the *same* page CoWs ONCE —
    // no second page-in. Both engines must charge identically.
    let mut body = encode::li64(8, DATA_BASE as u64);
    body.push(encode::ld(10, 8, 0)); // page-in (read)
    body.extend(encode::li64(9, 0x1234));
    body.push(encode::sd(8, 9, 8)); // same page → CoW only
    body.push(encode::ld(10, 8, 8)); // x10 = 0x1234
    assert_agree(&mem_prog(body, 8192), "read-then-write single CoW (D-2)");
}

#[test]
fn mem_straddle_two_pages() {
    // D-1: an 8-byte store straddling the page boundary materializes BOTH
    // pages; the page set + total must match across engines.
    let straddle = DATA_BASE + 4096 - 4;
    let mut body = encode::li64(8, straddle as u64);
    body.extend(encode::li64(9, 0xA1B2_C3D4_E5F6_0718));
    body.push(encode::sd(8, 9, 0)); // 8-byte store across the boundary
    body.push(encode::ld(10, 8, 0)); // read it back
    assert_agree(&mem_prog(body, 8192), "straddle two pages (D-1)");
}

#[test]
fn mem_straddle_out_of_region_faults() {
    // D-3: an 8-byte load straddling out of a 1-page window faults wholesale
    // on both engines — same PageFault, gas unchanged (nothing #3-charged).
    let straddle = DATA_BASE + 4096 - 4;
    let mut body = encode::li64(8, straddle as u64);
    body.push(encode::ld(10, 8, 0)); // straddles into the unmapped page
    assert_agree(&mem_prog(body, 4096), "straddle out of region (D-3)");
}

// ---- Category-#3 CODE region (PinnedCapRo, lazily materialized) -----------
//
// The guest can read (but not write) its own bytecode via PIC (`auipc`+load).
// Under zero-setup demand paging the code region is materialized read-only on
// first touch and charges #3 page-in identically on both engines.

/// `auipc x8, 0` → x8 = code_base + pc (here pc 0, so x8 = CODE_BASE).
const AUIPC_X8_0: u32 = (8 << 7) | 0x17;

#[test]
fn mem_code_pic_load() {
    // PIC self-read: x8 = code_base; ld x10, 0(x8) reads the program's own
    // first code bytes → charges code-region #3 page-in on BOTH engines,
    // which must agree on {exit, x10, gas}.
    let prog = Program {
        code: vec![AUIPC_X8_0, encode::ld(10, 8, 0)],
        init_regs: BTreeMap::new(),
        init_mem: None,
    };
    assert_agree(&prog, "PIC code load (code #3)");
}

#[test]
fn mem_code_pic_tail_zeros() {
    // A PIC load past the exact code length but within the last (rounded)
    // code page reads the zero-padded tail — both engines serve zeros and
    // charge one page-in (the code page is already in the set). Guards the
    // page-rounded code-region consistency between the engines.
    let prog = Program {
        code: vec![AUIPC_X8_0, encode::ld(10, 8, 256)], // CODE_BASE+256: tail zeros
        init_regs: BTreeMap::new(),
        init_mem: None,
    };
    assert_agree(&prog, "PIC code tail (zero-padded)");
}

#[test]
fn mem_code_store_faults() {
    // A store to the read-only code region faults on both engines (PinnedCapRo
    // write), charging nothing.
    let prog = Program {
        code: vec![AUIPC_X8_0, encode::sd(8, 8, 0)], // sd x8, 0(x8) → write code
        init_regs: BTreeMap::new(),
        init_mem: None,
    };
    assert_agree(&prog, "store to code faults");
}

#[test]
fn mem_code_second_page() {
    // A PIC load landing on the SECOND code page (code > 4 KiB), still within the
    // first 2 MiB RO cluster: both engines charge it under the same cluster as the
    // first page (cluster-granular RO materialization, page_in charged once).
    let mut body = vec![
        AUIPC_X8_0,           // x8 = code_base
        encode::lui(9, 1),    // x9 = 0x1000 (4096)
        encode::add(8, 8, 9), // x8 = code_base + 4096 (second code page)
        encode::ld(10, 8, 0), // read the second code page
    ];
    while body.len() * 4 < 4100 {
        body.push(encode::addi(8, 0, 0)); // pad so a second code page exists
    }
    let prog = Program {
        code: body,
        init_regs: BTreeMap::new(),
        init_mem: None,
    };
    assert_agree(&prog, "PIC load of second code page");
}

#[test]
fn mem_ro_cluster_multipage() {
    // A pinned read-only 8 KiB cap (2 pages) at DATA_BASE, both pages in one
    // 2 MiB cluster. Reading BOTH pages charges a single page_in (cluster
    // materialization) on both engines: the recompiler fault-arounds the
    // cluster on the first fault, then page 1 hits no fault; the interpreter
    // accounts the cluster once. Locks recomp==interp on RO clustering.
    let ro = vec![0xABu8; 8192]; // 2 pages, one cluster
    let mut body = encode::li64(8, DATA_BASE as u64);
    body.push(encode::ld(9, 8, 0)); // RO page 0
    body.extend(encode::li64(10, (DATA_BASE + 4096) as u64));
    body.push(encode::ld(11, 10, 0)); // RO page 1 (same cluster → free)
    let img = javm_fuzz::replay::image_with_ro(&body, DATA_BASE, &ro);
    let d = javm_fuzz::replay::diff_image(&img);
    assert!(
        !d.diverges(),
        "interp/recomp diverge on RO cluster (multi-page): {}",
        d.describe(),
    );
}

#[test]
fn mem_ro_two_caps_one_cluster() {
    // TWO distinct pinned RO caps mapped into the SAME 2 MiB cluster (cap A at
    // DATA_BASE, cap B 1 MiB higher). Per-cap materialization keys on the UNIT
    // (cap ∩ cluster) = unit_base, not the bare cluster, so each cap is its own
    // unit and pays its own page_in — a page-in event touches one DataCap. The
    // recompiler takes a second fault for cap B (A's fault-around mapped only
    // A's range); that fault now CHARGES (different unit), and the interpreter
    // charges the same. The engines must agree.
    const B_OFF: u32 = 0x10_0000; // 1 MiB → same 2 MiB cluster as DATA_BASE
    assert_eq!(
        nub_exec::mat::cluster_of(DATA_BASE),
        nub_exec::mat::cluster_of(DATA_BASE + B_OFF),
        "test setup: both caps must share one cluster",
    );
    let a = vec![0xA1u8; 4096];
    let b = vec![0xB2u8; 4096];
    let mut body = encode::li64(8, DATA_BASE as u64);
    body.push(encode::ld(9, 8, 0)); // read cap A → unit A page_in
    body.extend(encode::li64(10, (DATA_BASE + B_OFF) as u64));
    body.push(encode::ld(11, 10, 0)); // read cap B → unit B page_in (distinct cap)
    let img =
        javm_fuzz::replay::image_with_ro_caps(&body, &[(DATA_BASE, &a), (DATA_BASE + B_OFF, &b)]);
    let d = javm_fuzz::replay::diff_image(&img);
    assert!(
        !d.diverges(),
        "two RO caps in one cluster diverge: {}",
        d.describe(),
    );
}

#[test]
fn mem_ro_per_cap_independent_of_cluster() {
    // Per-cap materialization isolates caps: reading two RO caps costs the same
    // whether or not they share a 2 MiB cluster — each cap is its own unit and
    // pays one page_in regardless of placement (no cross-cap dedup, no cross-cap
    // penalty). Both engines agree in both layouts.
    let a = vec![0xA1u8; 4096];
    let b = vec![0xB2u8; 4096];
    let read_two = |b_addr: u32| {
        let mut body = encode::li64(8, DATA_BASE as u64);
        body.push(encode::ld(9, 8, 0)); // cap A (DATA_BASE)
        body.extend(encode::li64(10, b_addr as u64));
        body.push(encode::ld(11, 10, 0)); // cap B (b_addr)
        javm_fuzz::replay::image_with_ro_caps(&body, &[(DATA_BASE, &a), (b_addr, &b)])
    };
    // B at +1 MiB → same cluster as A; B at +2 MiB → the next cluster.
    let same = javm_fuzz::replay::diff_image(&read_two(DATA_BASE + 0x10_0000));
    let diff = javm_fuzz::replay::diff_image(&read_two(DATA_BASE + 0x20_0000));
    assert!(
        !same.diverges() && !diff.diverges(),
        "divergence: same_cluster={} diff_cluster={}",
        same.describe(),
        diff.describe(),
    );
    // Cluster placement is irrelevant: two caps = two page_ins either way.
    assert_eq!(
        same.interp.gas_used, diff.interp.gas_used,
        "per-cap: sharing a cluster must not change cost (each cap its own unit)",
    );
}

#[test]
fn mem_code_and_data_in_one_block() {
    // A single basic block doing BOTH a code load and a data load — proves
    // the per-region state arrays (code vs data) don't cross-contaminate and
    // the block reserve covers both page-ins. Both engines must agree on gas.
    let body = vec![
        AUIPC_X8_0,                // x8 = code_base
        encode::ld(9, 8, 0),       // code load → page-in code page
        encode::lui(10, 0x1_0000), // x10 = 0x1000_0000 = DATA_BASE
        encode::ld(10, 10, 0),     // data load → page-in data page
    ];
    assert_agree(&mem_prog(body, 4096), "code+data load in one block");
}
