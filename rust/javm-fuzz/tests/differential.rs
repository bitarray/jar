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
use javm_fuzz::{Program, encode};
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

/// The acceptance case: `div x10, INT_MIN, -1`, folded. An ordinary boundary
/// program the enumerator also produces — nothing here knows the recompiler
/// lacked an INT_MIN/-1 guard; the differential *discovered* it (the recompiler
/// `#DE`-aborted where the interpreter returns INT_MIN). With the guard in
/// place, the two now agree. **This is the green, committed proof.**
#[test]
fn acceptance_div_intmin_neg1() {
    let mut init = BTreeMap::new();
    init.insert(javm_exec::regs::reg_slot_or_ff(8), 0x8000_0000_0000_0000); // x8 = i64::MIN
    init.insert(javm_exec::regs::reg_slot_or_ff(9), 0xFFFF_FFFF_FFFF_FFFF); // x9 = -1
    let mut code = vec![encode::div(10, 8, 9)];
    code.extend(encode::fold_epilogue(None));
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
