//! Cross-engine benchmark comparison for nub.
//!
//! See `README.md` for the fairness rules this tool enforces. The short
//! version: one compute kernel per program, compiled to every engine's
//! artifact family; only `run()` is timed; gas is reported as a column,
//! never normalized away.

mod backend;
mod report;
mod size;
mod utils;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use backend::{Artifact, Engine, Family};
use clap::{Parser, Subcommand};
use criterion::{BatchSize, BenchmarkId, Criterion};

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
///
/// These are criterion *sample* counts, not iteration counts: criterion
/// picks the iterations per sample itself from the measurement budget,
/// so a 7 µs row and a 45 ms row both get statistically adequate
/// treatment without either being hand-tuned.
const SAMPLES_FAST: usize = 50;
const SAMPLES_SLOW: usize = 10;

/// How long criterion runs a row before it starts believing the clock,
/// and how long it then measures for. Both are deliberately shorter
/// than criterion's 3 s / 5 s defaults: this suite has ~500 rows and
/// runs one process per row, so the defaults would put a full sweep
/// well past an hour.
const WARM_UP: Duration = Duration::from_millis(1000);
const MEASUREMENT: Duration = Duration::from_millis(3000);

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
            default_value = "cold,invoke,runtime,compilation"
        )]
        kinds: Vec<String>,
        /// Treat `filter` as a complete `kind/program/engine` id rather
        /// than a substring.
        ///
        /// Engine names nest — `polkavm64_recompiler_sync_gas` is a
        /// prefix of `polkavm64_recompiler_sync_gas_full` — so a
        /// substring filter naming the shorter one silently runs both.
        /// `scripts/run.sh` relies on exactly one row per process
        /// (nub's sandbox is a process-wide singleton), so it passes
        /// this.
        #[arg(long)]
        exact: bool,
    },
    /// Artifact size across engines. Reads `artifacts/`; needs no
    /// measurements and writes nothing.
    Size,
    /// Render the measurements as markdown.
    Report {
        /// Overwrite `BENCHMARKS.md`.
        #[arg(long)]
        write: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Timing hygiene, and only the measuring commands need it.
    // Re-exec'ing the process and refusing a debug build to print a
    // table of byte counts would be wrong — and `refuse_debug_build`
    // would block `cargo run -- size` during development. Parsing args
    // first is safe: `exec` replaces the whole image, and no engine has
    // been constructed yet.
    if matches!(cli.command, Command::Run { .. } | Command::Validate { .. }) {
        // Must happen before anything allocates a mapping we care about.
        utils::disable_aslr_and_restart();
        refuse_debug_build()?;
    }

    let root = workspace_root()?;

    match cli.command {
        Command::List => list(&root),
        Command::Validate { write } => validate(&root, write),
        Command::Run {
            filter,
            kinds,
            exact,
        } => run(&root, filter.as_deref(), &kinds, exact),
        Command::Size => {
            print!("{}", size::render(&root, PROGRAMS));
            Ok(())
        }
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
        .filter(|f| f.artifact_path(root, p).exists())
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
    let artifact = Artifact::load(path)?;
    let compiled = engine.create()?.compile(&artifact)?;
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
            let path = engine.family().artifact_path(root, program);
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

/// A criterion benchmark group, measured against the wall clock.
type Group<'a> = criterion::BenchmarkGroup<'a, criterion::measurement::WallTime>;

/// Steady-state execution: one instance, invoked repeatedly.
///
/// This is throughput once everything is warm — the number that says how
/// fast an engine *executes*. It deliberately excludes instantiation,
/// because the cold cost differs enormously by engine implementation
/// (nub allocates and copies a flat address space; Wasmtime maps a
/// copy-on-write image) and folding the two together would report a
/// difference in memory strategy as a difference in execution speed.
/// [`bench_invoke`] reports that other half.
///
/// Requires the program to be re-runnable in one instance. The three
/// guests with a never-freeing bump arena are not — the second probe run
/// below is what catches them, so they surface as a skip rather than a
/// wrong number.
fn bench_runtime(
    g: &mut Group<'_>,
    id: BenchmarkId,
    engine: &dyn Engine,
    artifact: &Artifact,
) -> Result<()> {
    let compiled = engine.create()?.compile(artifact)?;
    let mut instance = compiled.spawn()?;
    // Two probe runs, both untimed: the first warms, the second proves
    // the program survives re-entry. Criterion does its own warm-up on
    // top of this.
    instance.run()?;
    instance.run()?;
    g.bench_function(id, |b| {
        b.iter(|| std::hint::black_box(instance.run().expect("run")))
    });
    Ok(())
}

/// Fresh instance every sample, timed through `run`.
///
/// Instantiation stays in the untimed `setup` half of `iter_batched`, so
/// this measures execution against a cold address space without charging
/// for building it. It is nub's real production model — every invocation
/// builds a new address space — and it is where an engine's
/// instantiation strategy shows up.
fn bench_invoke(
    g: &mut Group<'_>,
    id: BenchmarkId,
    engine: &dyn Engine,
    artifact: &Artifact,
) -> Result<()> {
    let compiled = engine.create()?.compile(artifact)?;
    // Probe outside the clock, so a failure is a skip rather than a
    // panic from inside criterion's measurement loop.
    compiled.spawn()?.run()?;
    g.bench_function(id, |b| {
        b.iter_batched(
            || compiled.spawn().expect("spawn"),
            |mut instance| std::hint::black_box(instance.run().expect("run")),
            BatchSize::PerIteration,
        )
    });
    Ok(())
}

/// Time `compile()` only.
fn bench_compilation(
    g: &mut Group<'_>,
    id: BenchmarkId,
    engine: &dyn Engine,
    artifact: &Artifact,
) -> Result<()> {
    // Engine creation and artifact loading are outside the loop: the
    // first is a once-per-process cost in real use (and nub has no
    // engine object to pay it at all), the second is the harness's own
    // file I/O.
    let compiler = engine.create()?;
    compiler.compile(artifact)?;
    g.bench_function(id, |b| {
        b.iter(|| std::hint::black_box(compiler.compile(artifact).expect("compile")))
    });
    Ok(())
}

/// **Cold recompile + execute** — the bench target.
///
/// Each sample starts with no compiled code and ends with the program
/// having run: exactly the cost a VM pays when a work-package arrives
/// and must be turned into native code and executed once.
///
/// What is deliberately *excluded* is storage. Getting a blob into an
/// engine's object store — for nub, shipping it into the sandbox,
/// decoding and content-hashing it — is dominated by hashing and is a
/// different subsystem from the recompiler. It is measured separately
/// as `compilation` for the engines that have such a step.
///
/// The two shapes below are the same measurement expressed against two
/// designs. An eager engine compiles in `compile`, so that call is
/// inside the clock. nub compiles lazily on first entry, so its
/// equivalent is: publish once up front (untimed), then evict the JIT
/// cache before each sample (untimed) and let `run` recompile.
///
/// `BatchSize::PerIteration` is load-bearing on the lazy path: one
/// eviction serves exactly one sample, and batching would leave every
/// sample after the first measuring an already-warm run.
fn bench_cold(
    g: &mut Group<'_>,
    id: BenchmarkId,
    engine: &dyn Engine,
    artifact: &Artifact,
) -> Result<()> {
    let compiler = engine.create()?;
    if engine.caps().compiles_lazily {
        // Publish once, outside every timed region.
        let compiled = compiler.compile(artifact)?;
        compiled.reset_compilation()?;
        compiled.spawn()?.run()?;
        g.bench_function(id, |b| {
            b.iter_batched(
                || compiled.reset_compilation().expect("reset compilation"),
                |()| {
                    let mut instance = compiled.spawn().expect("spawn");
                    std::hint::black_box(instance.run().expect("run"))
                },
                BatchSize::PerIteration,
            )
        });
    } else {
        compiler.compile(artifact)?.spawn()?.run()?;
        g.bench_function(id, |b| {
            b.iter(|| {
                let compiled = compiler.compile(artifact).expect("compile");
                let mut instance = compiled.spawn().expect("spawn");
                std::hint::black_box(instance.run().expect("run"))
            })
        });
    }
    Ok(())
}

fn run(root: &Path, filter: Option<&str>, kinds: &[String], exact: bool) -> Result<()> {
    let engines = backend::registry();
    let out_dir = root.join("target/results");
    std::fs::create_dir_all(&out_dir)?;
    let criterion_dir = root.join("target/criterion");

    // Plots are per-row SVG rendering we never look at, and this suite
    // has ~500 rows.
    let mut c = Criterion::default()
        .output_directory(&criterion_dir)
        .without_plots();

    for kind in kinds {
        for program in PROGRAMS {
            for engine in &engines {
                let id = format!("{kind}/{program}/{}", engine.name());
                if let Some(f) = filter {
                    let hit = if exact { id == f } else { id.contains(f) };
                    if !hit {
                        continue;
                    }
                }
                let path = engine.family().artifact_path(root, program);
                if !path.exists() {
                    continue;
                }
                if kind == "compilation" && !engine.caps().compiles {
                    continue;
                }
                let artifact = match Artifact::load(&path) {
                    Ok(a) => a,
                    Err(e) => {
                        eprintln!("{id:60} SKIP: {e:#}");
                        continue;
                    }
                };

                let samples = if engine.caps().slow {
                    SAMPLES_SLOW
                } else {
                    SAMPLES_FAST
                };
                let mut group = c.benchmark_group(kind.as_str());
                group.sample_size(samples);
                group.warm_up_time(WARM_UP);
                group.measurement_time(MEASUREMENT);
                let bid = BenchmarkId::new(*program, engine.name());

                let result = match kind.as_str() {
                    "runtime" => bench_runtime(&mut group, bid, engine.as_ref(), &artifact),
                    "invoke" => bench_invoke(&mut group, bid, engine.as_ref(), &artifact),
                    "cold" => bench_cold(&mut group, bid, engine.as_ref(), &artifact),
                    "compilation" => bench_compilation(&mut group, bid, engine.as_ref(), &artifact),
                    other => {
                        bail!("unknown kind `{other}` (want runtime, invoke, cold or compilation)")
                    }
                };
                group.finish();

                match result {
                    Ok(()) => {
                        let record = report::Record::from_criterion(
                            &criterion_dir,
                            kind,
                            program,
                            engine.name(),
                            engine.caps().metered,
                            engine.caps().rebuilds_per_run,
                            samples,
                        )?;
                        println!("{id:60} {}", record.summary());
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
    c.final_summary();
    Ok(())
}
