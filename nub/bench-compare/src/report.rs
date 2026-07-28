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
    /// Bounds of criterion's bootstrap confidence interval on the
    /// median. Reporting these is not decoration: a row whose interval
    /// is 30% wide is not a measurement, and without them it looks
    /// exactly as authoritative as one that is 1% wide.
    pub median_lo_ns: f64,
    pub median_hi_ns: f64,
    /// Mean and standard deviation, for the rows where the gap between
    /// mean and median is itself the interesting signal.
    pub mean_ns: f64,
    pub std_dev_ns: f64,
}

/// The shape of criterion's `new/estimates.json`.
#[derive(Deserialize)]
struct CriterionEstimates {
    mean: CriterionStat,
    median: CriterionStat,
    std_dev: CriterionStat,
}

#[derive(Deserialize)]
struct CriterionStat {
    confidence_interval: CriterionCi,
    point_estimate: f64,
}

#[derive(Deserialize)]
struct CriterionCi {
    lower_bound: f64,
    upper_bound: f64,
}

impl Record {
    /// Read back the estimates criterion just wrote for one row.
    ///
    /// criterion owns the statistics — warm-up, adaptive iteration
    /// counts, bootstrap intervals, outlier classification — and this
    /// only reshapes its output into the record the report renders
    /// from, adding the two facts criterion has no way to know: whether
    /// the engine is metered, and whether it rebuilds per run.
    pub fn from_criterion(
        criterion_dir: &Path,
        kind: &str,
        program: &str,
        engine: &str,
        metered: bool,
        rebuilds_per_run: bool,
        samples: usize,
    ) -> Result<Self> {
        let path = criterion_dir
            .join(kind)
            .join(program)
            .join(engine)
            .join("new/estimates.json");
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("read criterion estimates at {}", path.display()))?;
        let est: CriterionEstimates =
            serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
        Ok(Record {
            kind: kind.into(),
            program: program.into(),
            engine: engine.into(),
            metered,
            rebuilds_per_run,
            samples,
            median_ns: est.median.point_estimate,
            median_lo_ns: est.median.confidence_interval.lower_bound,
            median_hi_ns: est.median.confidence_interval.upper_bound,
            mean_ns: est.mean.point_estimate,
            std_dev_ns: est.std_dev.point_estimate,
        })
    }

    /// Half-width of the confidence interval on the median, as a
    /// percentage of it — the one number that says whether this row
    /// should be believed.
    pub fn spread_pct(&self) -> f64 {
        if self.median_ns <= 0.0 {
            return 0.0;
        }
        (self.median_hi_ns - self.median_lo_ns) / 2.0 / self.median_ns * 100.0
    }

    /// One-line console summary.
    pub fn summary(&self) -> String {
        format!(
            "{:>12}  ±{:.1}%",
            format_duration(self.median_ns),
            self.spread_pct()
        )
    }
}

/// Render a confidence-interval half-width, flagging the ones that mean
/// the row should not be read as a measurement.
///
/// The threshold is a judgement, not a statistic: below ~2% a row is
/// solid, and past ~10% the difference between two engines is smaller
/// than the difference between two runs of the same engine.
pub fn format_spread(pct: f64) -> String {
    if pct >= 10.0 {
        format!("**±{pct:.0}%**")
    } else {
        format!("±{pct:.1}%")
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
            "cold" => {
                "\n**The bench target.** Cold recompile + execute: each sample begins \
                 with no compiled code and ends with the program having run.\n\n\
                 Storage is excluded. An eager engine compiles inside the clock; nub \
                 compiles lazily on first entry, so it publishes once up front \
                 (untimed) and its JIT cache is evicted before each sample (also \
                 untimed), leaving `run` to recompile. Both shapes measure the same \
                 thing against different designs.\n"
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
                 **`nub_jit` measures publishing here, not codegen** — and publishing \
                 is *not* part of the bench target above. nub keeps its object store \
                 *inside* the sandbox, so this is the cost of shipping a blob across \
                 the VM boundary, decoding it, content-hashing it and materializing \
                 its data image. It is dominated by hashing and scales with blob \
                 size, not code size. `nub_jit_compile` is the codegen-only figure.\n"
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
            out.push_str("| Engine | Metered | Time | ± | vs fastest | vs native |\n");
            out.push_str("|---|---|--:|--:|--:|--:|\n");
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
                    "| `{}`{caveat} | {} | {} | {} | {:.2}x | {} |\n",
                    r.engine,
                    if r.metered { "yes" } else { "no" },
                    format_duration(r.median_ns),
                    format_spread(r.spread_pct()),
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
    // (median, confidence-interval half-width %) — the second is what
    // says whether the first should be believed.
    let mut cell: BTreeMap<(&str, &str), (f64, f64)> = BTreeMap::new();
    let mut programs: Vec<&str> = Vec::new();
    for r in records.iter().filter(|r| r.kind == "cold") {
        if !HEADLINE_ROWS.contains(&r.engine.as_str()) {
            continue;
        }
        if !programs.contains(&r.program.as_str()) {
            programs.push(&r.program);
        }
        cell.insert((&r.program, &r.engine), (r.median_ns, r.spread_pct()));
    }
    if cell.is_empty() {
        return String::new();
    }

    let mut out = String::from(
        "## Cold recompile + execute, metered JIT engines\n\n\
         The bench target. Each sample starts with no compiled code and ends \
         with the program having run — the cost a VM pays when a work-package \
         arrives, is turned into native code, and executed once. Metering on.\n\n\
         Storage is deliberately excluded. Getting a blob *into* an engine's \
         object store is dominated by hashing and belongs to a different \
         subsystem than the recompiler; for nub that step is measured \
         separately under `compilation`.\n\n\
         Only cost models comparable to nub's appear here. PolkaVM's default \
         `Simple` model is a flat per-instruction cost and is much cheaper to \
         evaluate than nub's pipeline simulation, so the `*_full` rows \
         (`CacheModel::L2Hit`, whose `memory_access_cost: 25` is exactly nub's \
         `MEM_CYCLES_BASE`) are the like-for-like comparison. Full tables for \
         every engine and every measurement kind follow below.\n\n\
         A cell carries a `±` only when its confidence interval is wider \
         than 2% of the median. Where that happens the cell is a range, not \
         a number, and two engines inside each other's interval are not \
         separable by this measurement.\n\n",
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
            .map(|(v, _)| *v)
            .fold(f64::INFINITY, f64::min);
        for e in HEADLINE_ROWS {
            match cell.get(&(p, *e)) {
                Some((v, spread)) => {
                    let mark = if (*v - best).abs() < f64::EPSILON {
                        "**"
                    } else {
                        ""
                    };
                    // Only surfaced when it matters — a ± on every cell
                    // is noise, and a missing one on the cell that needs
                    // it is a lie.
                    let ci = if *spread >= 2.0 {
                        format!(" ±{spread:.0}%")
                    } else {
                        String::new()
                    };
                    out.push_str(&format!(
                        " {mark}{}{mark}{ci} ({:.2}x) |",
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
             the recompile costs that engine.\n\n",
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
                    (Some(w), Some((total, _))) => {
                        let delta = total - w;
                        // A negative recompile cost is physically
                        // impossible: `cold` does strictly more work
                        // than `invoke`. Clamping it to zero would hide
                        // exactly the instability that makes the pair
                        // meaningless, so say so instead.
                        let note = if delta < 0.0 {
                            "(cold < invoke — unstable)".to_string()
                        } else {
                            format!("(+{} recompile)", format_duration(delta))
                        };
                        out.push_str(&format!(" {} {note} |", format_duration(*w)));
                    }
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
