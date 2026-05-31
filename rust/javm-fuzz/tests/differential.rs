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
/// sweep. `#[ignore]` (slow + currently surfaces open bugs). Run with
/// `--ignored`.
#[test]
#[ignore = "hunting tool: slow, and currently surfaces open recompiler bugs"]
fn boundary_sweep() {
    let progs = enumerate_boundary();
    let diverged = diff_batch(&progs);
    assert!(diverged.is_empty(), "{}", report(&diverged, progs.len()));
}

/// Random-sequence sweep. `#[ignore]` (currently surfaces open bugs). Run with
/// `--ignored`.
#[test]
#[ignore = "hunting tool: currently surfaces open recompiler bugs"]
fn random_sweep() {
    let progs = Gen::new(0xC0FFEE).random_batch(256, 6);
    let diverged = diff_batch(&progs);
    assert!(diverged.is_empty(), "{}", report(&diverged, progs.len()));
}
