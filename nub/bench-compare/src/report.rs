//! Turn recorded samples into a markdown table.
//!
//! Two relative columns, not one. `vs fastest` is the usual
//! presentation, but on its own it hides the story: it tells you which
//! engine won without telling you what any of them cost. `vs native` is
//! the absolute anchor — the multiple of bare-metal each engine charges
//! — and it is the column that makes an execution engine's numbers mean
//! something.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// One measured `(kind, program, engine)` cell.
#[derive(Serialize, Deserialize, Clone)]
pub struct Record {
    pub kind: String,
    pub program: String,
    pub engine: String,
    pub metered: bool,
    /// See `Caps::rebuilds_per_run`. Marks a row whose `runtime` figure
    /// still contains per-invocation setup.
    #[serde(default)]
    pub rebuilds_per_run: bool,
    pub samples: usize,
    /// Median, in nanoseconds. The median rather than the mean: a
    /// stray scheduler preemption adds a long tail but never a short
    /// one, so the mean is biased upward by exactly the noise we are
    /// trying to exclude.
    pub median_ns: f64,
    /// Fastest observed sample — the closest thing to an
    /// interference-free measurement.
    pub min_ns: f64,
    pub max_ns: f64,
}

impl Record {
    pub fn from_samples(
        kind: &str,
        program: &str,
        engine: &str,
        metered: bool,
        rebuilds_per_run: bool,
        samples: &[Duration],
    ) -> Self {
        let mut ns: Vec<f64> = samples.iter().map(|d| d.as_secs_f64() * 1e9).collect();
        ns.sort_by(|a, b| a.partial_cmp(b).unwrap());
        Record {
            kind: kind.into(),
            program: program.into(),
            engine: engine.into(),
            metered,
            rebuilds_per_run,
            samples: ns.len(),
            median_ns: ns[ns.len() / 2],
            min_ns: *ns.first().unwrap_or(&0.0),
            max_ns: *ns.last().unwrap_or(&0.0),
        }
    }
}

pub fn format_duration(ns: f64) -> String {
    if ns < 1_000.0 {
        format!("{ns:.1} ns")
    } else if ns < 1_000_000.0 {
        format!("{:.2} µs", ns / 1_000.0)
    } else if ns < 1_000_000_000.0 {
        format!("{:.2} ms", ns / 1_000_000.0)
    } else {
        format!("{:.2} s", ns / 1_000_000_000.0)
    }
}

pub fn render(root: &Path, write: bool) -> Result<()> {
    let dir = root.join("target/results");
    let mut records: Vec<Record> = Vec::new();
    if dir.exists() {
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let text = std::fs::read_to_string(&path)?;
            records.push(serde_json::from_str(&text).with_context(|| path.display().to_string())?);
        }
    }
    if records.is_empty() {
        anyhow::bail!(
            "no results in {} — run `bench-compare run` first",
            dir.display()
        );
    }

    let mut out = String::new();
    out.push_str("# nub benchmark comparison\n\n");
    out.push_str(&headline(&records));
    out.push_str(&provenance(root)?);
    out.push_str(
        "\n## How to read this\n\n\
         Every row runs the *same Rust compute kernel*, compiled to that engine's \
         target. Only the measured call is timed: compilation and instantiation \
         happen before the clock starts, for every engine alike.\n\n\
         `metered` marks engines charging gas/fuel while running, with the counter \
         set to maximum so the instrumentation runs but never fires. **Metered and \
         unmetered rows are not corrected against each other.** Gas is an axis of \
         this comparison, not a confounder to normalize away — read the cost of \
         metering off the `polkavm64_recompiler_no_gas` / `_sync_gas` pair and the \
         `wasmtime_cranelift` / `_fuel` pair, which bracket it.\n\n\
         `vs native` is the multiple of bare-metal cost. It is the number that says \
         what an engine charges you.\n\n",
    );

    // kind -> program -> rows
    let mut by_kind: BTreeMap<String, BTreeMap<String, Vec<Record>>> = BTreeMap::new();
    for r in records {
        by_kind
            .entry(r.kind.clone())
            .or_default()
            .entry(r.program.clone())
            .or_default()
            .push(r);
    }

    for (kind, programs) in &by_kind {
        out.push_str(&format!("\n## {kind}\n"));
        out.push_str(match kind.as_str() {
            "oneshot" => {
                "\nCompile **and** execute, from cold, every sample. The metric that \
                 matches how a metered VM is actually used: work arrives as a blob \
                 that must be compiled and then run, and each iteration pays both. \
                 Engines that cache compilation internally are evicted first, so no \
                 row skips the compile half.\n"
            }
            "invoke" => {
                "\nCold invocation with compilation excluded: a fresh instance every \
                 sample. Where an engine's *instantiation* strategy shows up. \
                 Compare against `runtime` for the same row to see what a cold start \
                 costs it.\n"
            }
            "runtime" => {
                "\nSteady-state execution: one instance, invoked repeatedly. How fast \
                 the engine *executes*, with instantiation excluded.\n\n\
                 Rows are absent where a program cannot be re-run in one instance \
                 (the three guests with a never-freeing bump arena).\n\n\
                 **\u{2020} — this row still contains per-invocation setup.** nub's \
                 invocation model builds a fresh frame and address space on every \
                 call by design, so there is no warm state to hoist out. Its figure \
                 is therefore *not* comparable to a row that reuses one warm \
                 instance; compare it against those rows' `invoke` figures instead, \
                 which also pay instantiation.\n"
            }
            "compilation" => {
                "\nTurning the program into executable form. Engine construction and \
                 file loading are excluded (a once-per-process cost, and the \
                 harness's own I/O). `native` is absent: the OS loader already did \
                 it.\n\n\
                 **`nub_jit` measures publishing here, not codegen.** nub keeps its \
                 object store *inside* the sandbox, so the equivalent up-front work \
                 is shipping the blob across the VM boundary, decoding it, \
                 content-hashing it and materializing its data image — the JIT \
                 itself runs lazily on first entry. `nub_jit_compile` is the \
                 codegen-only figure.\n"
            }
            _ => "\n",
        });

        for (program, rows) in programs {
            let mut rows = rows.clone();
            rows.sort_by(|a, b| a.median_ns.partial_cmp(&b.median_ns).unwrap());
            let fastest = rows.first().map(|r| r.median_ns).unwrap_or(1.0);
            let native = rows
                .iter()
                .find(|r| r.engine == "native")
                .map(|r| r.median_ns);

            out.push_str(&format!("\n### {program}\n\n"));
            out.push_str("| Engine | Metered | Time | vs fastest | vs native |\n");
            out.push_str("|---|---|--:|--:|--:|\n");
            for r in &rows {
                let vs_fastest = r.median_ns / fastest;
                let vs_native = match native {
                    Some(n) if n > 0.0 => format!("{:.1}x", r.median_ns / n),
                    _ => "-".into(),
                };
                let caveat = if r.rebuilds_per_run && kind == "runtime" {
                    " \u{2020}"
                } else {
                    ""
                };
                out.push_str(&format!(
                    "| `{}`{caveat} | {} | {} | {:.2}x | {} |\n",
                    r.engine,
                    if r.metered { "yes" } else { "no" },
                    format_duration(r.median_ns),
                    vs_fastest,
                    vs_native,
                ));
            }
        }
    }

    if write {
        let path = root.join("BENCHMARKS.md");
        std::fs::write(&path, &out)?;
        eprintln!("wrote {}", path.display());
    } else {
        print!("{out}");
    }
    Ok(())
}

/// The rows the headline table covers: metered JIT/recompiler engines.
///
/// Metered because that is the configuration a blockchain VM actually
/// ships; JIT because that is nub's bench target. `polkavm`'s Simple
/// cost model is excluded here on purpose — only the `*_full` rows use a
/// pipeline+cache model comparable to nub's, so those are the ones it is
/// fair to line up against `nub_jit`.
const HEADLINE_ROWS: &[&str] = &[
    "nub_jit",
    "polkavm64_recompiler_sync_gas_full",
    "polkavm64_recompiler_async_gas_full",
    "wasmtime_cranelift_fuel",
];

/// A program-by-engine matrix of compile+execute time, at the top of the
/// report, because it is the number the engine is being built to win.
fn headline(records: &[Record]) -> String {
    let mut cell: BTreeMap<(&str, &str), f64> = BTreeMap::new();
    let mut programs: Vec<&str> = Vec::new();
    for r in records.iter().filter(|r| r.kind == "oneshot") {
        if !HEADLINE_ROWS.contains(&r.engine.as_str()) {
            continue;
        }
        if !programs.contains(&r.program.as_str()) {
            programs.push(&r.program);
        }
        cell.insert((&r.program, &r.engine), r.median_ns);
    }
    if cell.is_empty() {
        return String::new();
    }

    let mut out = String::from(
        "## Compile + execute, metered JIT engines\n\n\
         The bench target: each sample compiles the program and runs it, \
         from cold, with metering on. That is how a metered VM is used when \
         work arrives as a blob — the compile is not amortized away.\n\n\
         Only cost models comparable to nub's appear here. PolkaVM's default \
         `Simple` model is a flat per-instruction cost and is much cheaper to \
         evaluate than nub's pipeline simulation, so the `*_full` rows \
         (`CacheModel::L2Hit`, whose `memory_access_cost: 25` is exactly nub's \
         `MEM_CYCLES_BASE`) are the like-for-like comparison. Full tables for \
         every engine and every measurement kind follow below.\n\n",
    );

    out.push_str("| Program |");
    for e in HEADLINE_ROWS {
        out.push_str(&format!(" `{e}` |"));
    }
    out.push_str("\n|---|");
    for _ in HEADLINE_ROWS {
        out.push_str("--:|");
    }
    out.push('\n');

    for p in &programs {
        out.push_str(&format!("| {p} |"));
        let best = HEADLINE_ROWS
            .iter()
            .filter_map(|e| cell.get(&(p, *e)))
            .cloned()
            .fold(f64::INFINITY, f64::min);
        for e in HEADLINE_ROWS {
            match cell.get(&(p, *e)) {
                Some(v) => {
                    let mark = if (*v - best).abs() < f64::EPSILON {
                        "**"
                    } else {
                        ""
                    };
                    out.push_str(&format!(
                        " {mark}{}{mark} ({:.2}x) |",
                        format_duration(*v),
                        v / best
                    ));
                }
                None => out.push_str(" - |"),
            }
        }
        out.push('\n');
    }
    out.push_str("\nBold = fastest for that program; the multiple is versus it.\n\n");

    // The same rows minus compilation. `invoke`, not `runtime`: every
    // engine pays instantiation in `invoke`, whereas `runtime` hoists it
    // out for engines that can — and nub cannot, since it builds a fresh
    // frame per call. Using `runtime` here would compare nub's
    // setup-inclusive figure against everyone else's warm one.
    //
    // Splitting this out is what separates "our generated code is
    // slower" from "our compile is more expensive" — different problems
    // with different fixes, which one combined number would blur.
    let mut warm: BTreeMap<(&str, &str), f64> = BTreeMap::new();
    for r in records.iter().filter(|r| r.kind == "invoke") {
        if HEADLINE_ROWS.contains(&r.engine.as_str()) {
            warm.insert((&r.program, &r.engine), r.median_ns);
        }
    }
    if !warm.is_empty() {
        out.push_str(
            "### Where that time goes\n\n\
             The same rows with **compilation excluded** — a fresh instance per \
             sample, then execute. Every engine pays instantiation here, so this \
             is like-for-like even for nub, which rebuilds its frame on every \
             call and therefore has no warm state to hoist out.\n\n\
             The bracketed figure is the difference against the table above: what \
             compilation costs that engine.\n\n",
        );
        out.push_str("| Program |");
        for e in HEADLINE_ROWS {
            out.push_str(&format!(" `{e}` |"));
        }
        out.push_str("\n|---|");
        for _ in HEADLINE_ROWS {
            out.push_str("--:|");
        }
        out.push('\n');
        for p in &programs {
            out.push_str(&format!("| {p} |"));
            for e in HEADLINE_ROWS {
                match (warm.get(&(p, *e)), cell.get(&(p, *e))) {
                    (Some(w), Some(total)) => out.push_str(&format!(
                        " {} (+{} compile) |",
                        format_duration(*w),
                        format_duration((total - w).max(0.0))
                    )),
                    (Some(w), None) => out.push_str(&format!(" {} |", format_duration(*w))),
                    _ => out.push_str(" - |"),
                }
            }
            out.push('\n');
        }
        out.push('\n');
    }
    out
}

fn provenance(root: &Path) -> Result<String> {
    let mut s = String::from("## Provenance\n\n");
    let manifest = root.join("artifacts/manifest.json");
    if let Ok(text) = std::fs::read_to_string(&manifest) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            if let Some(rustc) = v.get("rustc").and_then(|r| r.as_str()) {
                s.push_str(&format!("- Guest toolchain: `{rustc}`\n"));
            }
        }
    }
    if let Ok(cpu) = std::fs::read_to_string("/proc/cpuinfo") {
        if let Some(model) = cpu
            .lines()
            .find(|l| l.starts_with("model name"))
            .and_then(|l| l.split(':').nth(1))
        {
            s.push_str(&format!("- CPU: {}\n", model.trim()));
        }
    }
    s.push_str(
        "- ASLR: disabled for the measuring process\n\
         - Harness profile: `lto = true`, `codegen-units = 1`\n",
    );
    Ok(s)
}
