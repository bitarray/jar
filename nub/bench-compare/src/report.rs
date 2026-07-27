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
        samples: &[Duration],
    ) -> Self {
        let mut ns: Vec<f64> = samples.iter().map(|d| d.as_secs_f64() * 1e9).collect();
        ns.sort_by(|a, b| a.partial_cmp(b).unwrap());
        Record {
            kind: kind.into(),
            program: program.into(),
            engine: engine.into(),
            metered,
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
            "runtime" => {
                "\nSteady-state execution: one instance, invoked repeatedly. How fast \
                 the engine *executes*, with instantiation excluded.\n\n\
                 Rows are absent where a program cannot be re-run in one instance \
                 (the three guests with a never-freeing bump arena).\n"
            }
            "oneshot" => {
                "\nCold invocation: a fresh instance every sample. This is nub's real \
                 production model — every invocation builds a new address space — and \
                 it is where an engine's instantiation strategy shows up. Compare \
                 against `runtime` for the same row to see what a cold start costs \
                 that engine.\n"
            }
            "compilation" => {
                "\nTurning the program into executable form. Engine construction is \
                 excluded (a once-per-process cost). `native` is absent: the OS \
                 loader already did it.\n"
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
                out.push_str(&format!(
                    "| `{}` | {} | {} | {:.2}x | {} |\n",
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
