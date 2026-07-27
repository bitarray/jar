//! Cross-engine benchmark comparison for nub.
//!
//! See `README.md` for the fairness rules this tool enforces. The short
//! version: one compute kernel per program, compiled to every engine's
//! artifact family; only `run()` is timed; gas is reported as a column,
//! never normalized away.

mod backend;
mod report;
mod utils;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use backend::{Engine, Family};
use clap::{Parser, Subcommand};

/// Programs, in report order. Must match `bench-build`.
const PROGRAMS: &[&str] = &[
    "prime-sieve",
    "ed25519",
    "keccak",
    "blake2b",
    "ecrecover",
    "goldilocks-mul",
    "poseidon2-perm",
    "mini-verifier",
    "poly-eval",
    "fri-fold-tree",
];

/// Samples for a compiled engine, and for an interpreter. Interpreters
/// are 10-100x slower; taking the same sample count would triple the
/// suite's wall-clock for no extra statistical power.
const SAMPLES_FAST: usize = 50;
const SAMPLES_SLOW: usize = 10;

#[derive(Parser)]
#[command(
    name = "bench-compare",
    about = "Cross-engine benchmark comparison for nub"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List every available (program, engine) row.
    List,
    /// Run each row once and check every engine agrees on the result.
    Validate {
        /// Write the observed values to `expected.toml` instead of
        /// checking against it. Review the diff before committing.
        #[arg(long)]
        write: bool,
    },
    /// Measure. Optionally filter by a `kind/program/engine` substring.
    Run {
        filter: Option<String>,
        /// Measurement kinds to run.
        #[arg(
            long,
            value_delimiter = ',',
            default_value = "runtime,invoke,oneshot,compilation"
        )]
        kinds: Vec<String>,
    },
    /// Render the measurements as markdown.
    Report {
        /// Overwrite `BENCHMARKS.md`.
        #[arg(long)]
        write: bool,
    },
}

fn main() -> Result<()> {
    // Must happen before anything allocates a mapping we care about.
    utils::disable_aslr_and_restart();
    refuse_debug_build()?;

    let cli = Cli::parse();
    let root = workspace_root()?;

    match cli.command {
        Command::List => list(&root),
        Command::Validate { write } => validate(&root, write),
        Command::Run { filter, kinds } => run(&root, filter.as_deref(), &kinds),
        Command::Report { write } => report::render(&root, write),
    }
}

/// An unoptimized build would make the interpreter rows meaningless and
/// the comparison a lie. benchtool has the same guard, and the same
/// escape hatch.
fn refuse_debug_build() -> Result<()> {
    if cfg!(debug_assertions) && std::env::var("TRUST_ME_BRO_I_KNOW_WHAT_I_AM_DOING").is_err() {
        bail!(
            "refusing to run a debug build: this suite contains interpreters, and unoptimized \
             numbers are not comparable to anything.\n\
             Use `cargo run --release`, or set \
             TRUST_ME_BRO_I_KNOW_WHAT_I_AM_DOING=1 if you really mean it."
        );
    }
    Ok(())
}

fn workspace_root() -> Result<PathBuf> {
    Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR")))
}

fn artifact_path(root: &Path, program: &str, family: Family) -> PathBuf {
    root.join("artifacts")
        .join(family.dir())
        .join(format!("{program}.{}", family.ext()))
}

fn list(root: &Path) -> Result<()> {
    let engines = backend::registry();
    println!("{} engines:", engines.len());
    for e in &engines {
        let c = e.caps();
        println!(
            "  {:32} family={:10} metered={:5} slow={:5} compiles={}",
            e.name(),
            e.family().dir(),
            c.metered,
            c.slow,
            c.compiles
        );
    }
    println!("\n{} programs:", PROGRAMS.len());
    let mut missing = 0;
    for p in PROGRAMS {
        let have: Vec<_> = [
            Family::Pvm2,
            Family::Native,
            Family::Wasm32,
            Family::Polkavm64,
        ]
        .into_iter()
        .filter(|f| artifact_path(root, p, *f).exists())
        .map(|f| f.dir())
        .collect();
        if have.len() < 4 {
            missing += 1;
        }
        println!("  {p:20} artifacts: {}", have.join(" "));
    }
    if missing > 0 {
        println!(
            "\n{missing} program(s) missing artifacts — run `cargo run -p bench-build --release`"
        );
    }
    Ok(())
}

/// One `(engine, program)` execution, run once.
fn probe(engine: &dyn Engine, path: &Path) -> Result<(u32, Option<u64>)> {
    let compiled = engine.create()?.compile(path)?;
    let mut instance = compiled.spawn()?;
    let value = instance.run()?;
    Ok((value, instance.gas_used()))
}

fn validate(root: &Path, write: bool) -> Result<()> {
    let engines = backend::registry();
    let mut observed: BTreeMap<String, u32> = BTreeMap::new();
    let mut failures = Vec::new();

    for program in PROGRAMS {
        let mut values: BTreeMap<u32, Vec<&str>> = BTreeMap::new();
        for engine in &engines {
            let path = artifact_path(root, program, engine.family());
            if !path.exists() {
                continue;
            }
            match probe(engine.as_ref(), &path) {
                Ok((value, gas)) => {
                    values.entry(value).or_default().push(engine.name());
                    let gas = gas.map(|g| format!("{g}")).unwrap_or_else(|| "-".into());
                    println!(
                        "  {program:20} {:32} = {value:#010x}  gas={gas}",
                        engine.name()
                    );
                }
                Err(e) => {
                    // `nub_jit_compile` has no runtime; that is expected,
                    // not a failure.
                    if engine.name() == "nub_jit_compile" {
                        continue;
                    }
                    failures.push(format!("{program} / {}: {e:#}", engine.name()));
                }
            }
        }

        match values.len() {
            0 => {}
            1 => {
                let value = *values.keys().next().unwrap();
                observed.insert((*program).to_string(), value);
            }
            _ => {
                // The check that catches a silently miscompiled guest.
                let detail: Vec<String> = values
                    .iter()
                    .map(|(v, who)| format!("{v:#010x} <- {}", who.join(", ")))
                    .collect();
                failures.push(format!(
                    "{program}: engines disagree: {}",
                    detail.join(" | ")
                ));
            }
        }
        println!();
    }

    let expected_path = root.join("expected.toml");
    if write {
        let mut out = String::from(
            "# Golden return values, one per program.\n\
             #\n\
             # Cross-engine agreement (checked separately) catches a silently\n\
             # miscompiled guest. This file catches the other direction: someone\n\
             # changing a kernel constant, where every engine would agree on the\n\
             # new wrong answer. Regenerate with `validate --write` and review.\n\n",
        );
        for (k, v) in &observed {
            out.push_str(&format!("\"{k}\" = {v}\n"));
        }
        std::fs::write(&expected_path, out)?;
        println!("wrote {}", expected_path.display());
    } else if expected_path.exists() {
        let text = std::fs::read_to_string(&expected_path)?;
        let expected: BTreeMap<String, u32> =
            toml::from_str(&text).context("parse expected.toml")?;
        for (program, value) in &observed {
            match expected.get(program) {
                Some(e) if e == value => {}
                Some(e) => failures.push(format!(
                    "{program}: got {value:#010x}, expected.toml says {e:#010x}"
                )),
                None => failures.push(format!("{program}: absent from expected.toml")),
            }
        }
    } else {
        println!("no expected.toml — run `validate --write` to create one");
    }

    if failures.is_empty() {
        println!("validate: OK ({} programs)", observed.len());
        Ok(())
    } else {
        for f in &failures {
            eprintln!("FAIL {f}");
        }
        bail!("{} validation failure(s)", failures.len())
    }
}

/// Steady-state execution: one instance, invoked repeatedly.
///
/// This is throughput once everything is warm — the number that says how
/// fast an engine *executes*. It deliberately excludes instantiation,
/// because the cold cost differs enormously by engine implementation
/// (nub allocates and copies a flat address space; Wasmtime maps a
/// copy-on-write image) and folding the two together would report a
/// difference in memory strategy as a difference in execution speed.
/// [`measure_oneshot`] reports that other half.
///
/// Requires the program to be re-runnable in one instance. The three
/// guests with a never-freeing bump arena are not, and surface as a
/// skip rather than a wrong number.
fn measure_runtime(engine: &dyn Engine, path: &Path, samples: usize) -> Result<Vec<Duration>> {
    let compiled = engine.create()?.compile(path)?;
    let mut instance = compiled.spawn()?;
    // One untimed warm-up so the first sample is not the odd one out.
    instance.run()?;
    let mut out = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = Instant::now();
        let value = instance.run()?;
        out.push(start.elapsed());
        std::hint::black_box(value);
    }
    Ok(out)
}

/// Cold invocation: a fresh instance every sample, timed through `run`.
///
/// Named `invoke` rather than `oneshot` because it excludes compilation;
/// [`measure_oneshot`] is the one that includes it.
///
/// This is nub's real production model — every invocation builds a new
/// address space — and it is where an engine's instantiation strategy
/// shows up. Measured for all engines identically, so the comparison
/// is like-for-like even though the absolute penalty is very different
/// per engine (for nub's interpreter it is roughly 2x its warm cost).
fn measure_invoke(engine: &dyn Engine, path: &Path, samples: usize) -> Result<Vec<Duration>> {
    let compiled = engine.create()?.compile(path)?;
    let mut out = Vec::with_capacity(samples);
    for _ in 0..samples {
        let mut instance = compiled.spawn()?;
        let start = Instant::now();
        let value = instance.run()?;
        out.push(start.elapsed());
        std::hint::black_box(value);
    }
    Ok(out)
}

/// Time `compile()` only.
fn measure_compilation(engine: &dyn Engine, path: &Path, samples: usize) -> Result<Vec<Duration>> {
    // Engine creation is outside the loop: it is a once-per-process cost
    // in real use, and nub has no engine object to pay it at all.
    let compiler = engine.create()?;
    let mut out = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = Instant::now();
        let compiled = compiler.compile(path)?;
        out.push(start.elapsed());
        std::hint::black_box(&compiled);
    }
    Ok(out)
}

/// Compile **and** execute, from cold, every sample.
///
/// This is the metric that matches how a metered VM is actually used
/// when work arrives as a blob that must be compiled and then run —
/// each iteration pays both. Engines that cache their compilation
/// internally are reset first (see [`Compiled::reset_compilation`]), so
/// no row gets to skip the compile half.
fn measure_oneshot(engine: &dyn Engine, path: &Path, samples: usize) -> Result<Vec<Duration>> {
    let compiler = engine.create()?;
    let mut out = Vec::with_capacity(samples);
    for _ in 0..samples {
        // Untimed: put the engine back in its cold state.
        engine.create()?.compile(path)?.reset_compilation()?;

        let start = Instant::now();
        let compiled = compiler.compile(path)?;
        let mut instance = compiled.spawn()?;
        let value = instance.run()?;
        out.push(start.elapsed());
        std::hint::black_box(value);
    }
    Ok(out)
}

fn run(root: &Path, filter: Option<&str>, kinds: &[String]) -> Result<()> {
    let engines = backend::registry();
    let out_dir = root.join("target/results");
    std::fs::create_dir_all(&out_dir)?;

    for kind in kinds {
        for program in PROGRAMS {
            for engine in &engines {
                let id = format!("{kind}/{program}/{}", engine.name());
                if let Some(f) = filter {
                    if !id.contains(f) {
                        continue;
                    }
                }
                let path = artifact_path(root, program, engine.family());
                if !path.exists() {
                    continue;
                }
                if kind == "compilation" && !engine.caps().compiles {
                    continue;
                }

                let samples = if engine.caps().slow {
                    SAMPLES_SLOW
                } else {
                    SAMPLES_FAST
                };
                let result = match kind.as_str() {
                    "runtime" => measure_runtime(engine.as_ref(), &path, samples),
                    "invoke" => measure_invoke(engine.as_ref(), &path, samples),
                    "oneshot" => measure_oneshot(engine.as_ref(), &path, samples),
                    "compilation" => measure_compilation(engine.as_ref(), &path, samples),
                    other => bail!("unknown kind `{other}` (want runtime, oneshot or compilation)"),
                };

                match result {
                    Ok(samples) => {
                        let record = report::Record::from_samples(
                            kind,
                            program,
                            engine.name(),
                            engine.caps().metered,
                            &samples,
                        );
                        println!("{id:60} {:>12}", report::format_duration(record.median_ns));
                        let file = out_dir.join(format!("{}.json", id.replace('/', "__")));
                        std::fs::write(&file, serde_json::to_string_pretty(&record)?)?;
                    }
                    Err(e) => {
                        if engine.name() == "nub_jit_compile" && kind == "runtime" {
                            continue;
                        }
                        eprintln!("{id:60} SKIP: {e:#}");
                    }
                }
            }
        }
    }
    Ok(())
}
