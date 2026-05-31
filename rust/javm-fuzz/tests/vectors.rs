//! Committed golden-vector replay — the **external-oracle** regression gate.
//!
//! Loads vectors minted offline by `src/bin/mint.rs` (the `spike` oracle) and
//! replays each through both engines, asserting the interpreter and recompiler
//! agree with each other (incl. gas) AND with the oracle's golden `x10` + exit.
//! Unlike `differential.rs` (which only proves the two engines agree with each
//! other), this proves both match the **formal RISC-V model** — so it would
//! catch a bug the two engines share.
//!
//! The committed corpus is the curated division family (INT_MIN/-1, divide-by-
//! zero, signs) — small enough to stay under the recompiler's sandbox-
//! accumulation threshold and run in CI. Regenerate with
//! `cargo run -p javm-fuzz --bin mint -- tests/vectors/division.json`.
//!
//! Gated to linux/x86_64 (the recompiler half needs the Hyperlight sandbox).
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use javm_fuzz::replay::{diff, reset_sandbox};
use javm_fuzz::{FOLD_VERSION, VectorFile};

const DIVISION: &str = include_str!("vectors/division.json");

#[test]
fn committed_division_vectors_match_gold() {
    let file = VectorFile::from_json(DIVISION).expect("parse division.json");
    assert_eq!(
        file.meta.fold_version, FOLD_VERSION,
        "committed vectors were minted against fold_version {} but the code is at {} — re-mint",
        file.meta.fold_version, FOLD_VERSION,
    );

    let mut failures = Vec::new();
    for (i, v) in file.vectors.iter().enumerate() {
        // Rebuild the sandbox periodically (accumulation); all recompiler calls
        // stay in this one test fn (the sandbox is a process singleton).
        if i % 8 == 0 {
            reset_sandbox();
        }
        let d = diff(&v.to_program());
        // interp ↔ recomp agree (incl. gas), AND both match the oracle gold.
        let matches_gold =
            d.interp.return_value == v.gold.x10 && d.interp.exit_reason == v.gold.exit;
        if d.diverges() || !matches_gold {
            failures.push(format!(
                "{}: gold{{x10={:#018x} exit={}}} | {}",
                v.id,
                v.gold.x10,
                v.gold.exit,
                d.describe(),
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} / {} division vectors failed:\n  {}",
        failures.len(),
        file.vectors.len(),
        failures.join("\n  "),
    );
}
