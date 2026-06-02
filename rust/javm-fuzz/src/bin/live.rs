//! Live differential fuzz: continuously generate RV64E-subset programs and
//! compare the **Spike oracle** vs the **interpreter** vs the **recompiler**.
//! Stops at the FIRST program where they disagree, shrinks it to a minimal
//! reproducer, mints its oracle gold, and writes it as a regression vector for
//! `res/vectors/`.
//!
//! Boundary enumeration runs first (deterministic corners — e.g. `div
//! INT_MIN, -1`), then random sequences (state-dependent bugs). Needs `spike`
//! on PATH (the gold) and the Hyperlight recompiler (linux/x86_64).
//!
//! This does NOT rebuild the sandbox between programs — it relies on the
//! Hyperlight accumulation bug being fixed (the whole point of deleting
//! `reset_nub_hyperlight`). A continuous run over thousands of distinct images
//! is the regression test for that fix.
//!
//! Usage: `cargo run -p javm-fuzz --bin live -- [out.json] [--seed N] [--max N]`

// The recompiler differential needs the Hyperlight host stack (`javm-bench`),
// which only builds on linux/x86_64. On other targets this bin is a stub so
// the workspace still compiles (e.g. the macOS interpreter-only CI job).
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {
    eprintln!("live differential fuzz requires linux/x86_64 (Hyperlight recompiler)");
    std::process::exit(1);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use javm_exec::instruction::decode;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use javm_fuzz::generate::{Gen, enumerate_boundary};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use javm_fuzz::oracle::spike_x10;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use javm_fuzz::replay::{replay_interp, replay_recomp};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use javm_fuzz::shrink::shrink;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use javm_fuzz::{FOLD_VERSION, Gold, ISA, Program, Vector, VectorFile, VectorMeta, encode};

/// Do Spike, the interpreter, and the recompiler disagree on `prog`? `None` if
/// Spike couldn't run it (skip). A divergence is any of: either engine's `x10`
/// ≠ the oracle gold, either engine not halting cleanly (`exit` ≠ 4), or the
/// two engines disagreeing on gas (the oracle has no gas).
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn diverges(prog: &Program) -> Option<bool> {
    let gold = spike_x10(prog).ok()?;
    let i = replay_interp(prog);
    let r = replay_recomp(prog);
    Some(
        i.return_value != gold
            || r.return_value != gold
            || i.exit_reason != 4
            || r.exit_reason != 4
            || i.gas_used != r.gas_used,
    )
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn disasm(prog: &Program, fold_len: usize) -> String {
    let body_end = prog.code.len().saturating_sub(fold_len);
    let ops: Vec<String> = prog.code[..body_end]
        .iter()
        .map(|&w| format!("{:?}", decode(&w.to_le_bytes()).unwrap().0))
        .collect();
    format!("[{}] seeds={:?}", ops.join("; "), prog.init_regs)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn vector_id(prog: &Program, fold_len: usize) -> String {
    let body_end = prog.code.len().saturating_sub(fold_len);
    let op = prog
        .code
        .first()
        .map(|&w| format!("{:?}", decode(&w.to_le_bytes()).unwrap().0))
        .unwrap_or_default();
    let op = op.split_whitespace().next().unwrap_or("op").to_lowercase();
    format!("live/{op}_{body_end}op")
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn main() {
    let mut out: Option<String> = None;
    let mut seed = 0xC0FFEEu64; // default: the seed that surfaced the sllw/orc.b bugs
    let mut max = 20_000usize;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--seed" => seed = args.next().and_then(|s| s.parse().ok()).unwrap_or(seed),
            "--max" => max = args.next().and_then(|s| s.parse().ok()).unwrap_or(max),
            p => out = Some(p.to_string()),
        }
    }

    let fold_len = encode::fold_epilogue(None).len();
    let mut rng = Gen::new(seed);
    let mut count = 0usize;

    // Boundary enumeration first (deterministic corners), then random forever.
    let stream = enumerate_boundary()
        .into_iter()
        .chain(std::iter::from_fn(|| Some(rng.random_program(6))));

    for prog in stream {
        count += 1;
        if count > max {
            eprintln!("no divergence in {} programs (seed {seed:#x})", count - 1);
            return;
        }
        if count.is_multiple_of(500) {
            eprintln!("  .. {count} programs checked");
        }
        if diverges(&prog) != Some(true) {
            continue;
        }

        eprintln!("[{count}] DIVERGENCE: {}", disasm(&prog, fold_len));
        // A recompiler abort (e.g. a `#DE` from a div-overflow bug) poisons the
        // sandbox, so every later recomp call returns the abort sentinel —
        // which makes shrinking unreliable (it would "minimize" anything).
        // Generated programs are already small, so report the aborting one
        // as-is; shrink only the clean (value/panic) divergences.
        let aborted = replay_recomp(&prog).exit_reason == javm_bench::ABORT_SENTINEL;
        let minimal = if aborted {
            eprintln!("    (recompiler aborted — poisoned sandbox; skipping shrink)");
            prog.clone()
        } else {
            shrink(&prog, fold_len, |p| diverges(p).unwrap_or(false))
        };
        eprintln!("    minimal: {}", disasm(&minimal, fold_len));

        let gold = spike_x10(&minimal).expect("spike on minimal");
        let i = replay_interp(&minimal);
        let r = replay_recomp(&minimal);
        eprintln!(
            "    gold x10={gold:#018x} | interp{{x10={:#018x} exit={}}} | recomp{{x10={:#018x} exit={}}} | gas i={} r={}",
            i.return_value, i.exit_reason, r.return_value, r.exit_reason, i.gas_used, r.gas_used,
        );

        let id = vector_id(&minimal, fold_len);
        let vector = Vector::from_program(
            id,
            &minimal,
            Gold {
                x10: gold,
                exit: 4,
                exit_arg: 0,
            },
        );
        let file = VectorFile {
            meta: VectorMeta {
                gen_sha: "live".into(),
                seed,
                oracle: "spike-1.1.1-dev".into(),
                isa: ISA.into(),
                fold_version: FOLD_VERSION,
            },
            vectors: vec![vector],
        };
        let json = serde_json::to_string_pretty(&file).expect("serialize vector");
        match &out {
            Some(path) => {
                std::fs::write(path, &json).expect("write vector");
                eprintln!("    wrote regression vector to {path}");
            }
            None => println!("{json}"),
        }
        return;
    }
}
