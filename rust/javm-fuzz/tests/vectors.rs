//! Committed regression-vector replay — the **external-oracle** regression net.
//!
//! Replays every committed vector in `res/vectors/` (real divergences `live.rs`
//! surfaced and minted with the Spike oracle) through both engines, asserting
//! the interpreter and recompiler agree with each other (incl. gas) AND with the
//! oracle's golden `x10` + exit. Unlike `differential.rs` (which only proves the
//! two engines agree), this proves both match the **formal RISC-V model** — so a
//! fixed bug can never silently regress. An empty `res/vectors/` passes
//! trivially (vectors are added as bugs are found + fixed).
//!
//! Gated to linux/x86_64 (the recompiler half needs the Hyperlight sandbox).
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use javm_fuzz::replay::diff;
use javm_fuzz::{FOLD_VERSION, VectorFile};
use std::path::Path;

#[test]
fn committed_regression_vectors_pass() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("res/vectors");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();

    // Flatten all vectors across files (each file = one bug's minimal repro).
    let mut all = Vec::new();
    for f in &files {
        let txt = std::fs::read_to_string(f).expect("read vector file");
        let vf =
            VectorFile::from_json(&txt).unwrap_or_else(|e| panic!("parse {}: {e}", f.display()));
        assert_eq!(
            vf.meta.fold_version,
            FOLD_VERSION,
            "{} was minted against fold_version {} but code is at {} — re-mint",
            f.display(),
            vf.meta.fold_version,
            FOLD_VERSION,
        );
        all.extend(vf.vectors);
    }

    let mut failures = Vec::new();
    for v in &all {
        let d = diff(&v.to_program());
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
        "{} / {} regression vectors failed:\n  {}",
        failures.len(),
        all.len(),
        failures.join("\n  "),
    );
}
