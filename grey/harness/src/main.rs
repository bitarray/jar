//! Integration test harness for the Grey JAM node.
//!
//! Spawns a local testnet, runs end-to-end scenarios (pixel submission,
//! pipeline continuity, chain liveness), and reports results.

mod pixel;
mod poll;
mod rpc;
mod scenarios;
mod testnet;

use std::time::Duration;

use clap::Parser;
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "harness", about = "Grey integration test harness")]
struct Cli {
    /// Skip building grey before running.
    #[arg(long)]
    skip_build: bool,

    /// Don't spawn a testnet; connect to an already-running node.
    #[arg(long)]
    no_testnet: bool,

    /// Use deterministic sequential testnet (fast, single-threaded).
    #[arg(long)]
    seq_testnet: bool,

    /// RPC endpoint URL.
    #[arg(long, default_value = "http://localhost:9933")]
    rpc: String,

    /// Run only the named scenario (e.g. "serial", "repeat", "throughput").
    /// If not specified, all scenarios run in order.
    #[arg(long, value_name = "NAME")]
    scenario: Option<String>,

    /// Output results as JSON (for CI consumption).
    #[arg(long)]
    json: bool,

    /// Enable detailed per-operation timing output.
    #[arg(long)]
    perf: bool,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    // Build grey if needed.
    if !cli.skip_build && !cli.no_testnet {
        info!("building grey...");
        let status = std::process::Command::new("cargo")
            .args(["build", "-p", "grey"])
            .current_dir(env!("CARGO_MANIFEST_DIR").to_string() + "/../..")
            .status()
            .expect("failed to run cargo build");
        if !status.success() {
            error!("cargo build failed");
            std::process::exit(1);
        }
    }

    // Spawn testnet if needed.
    let mut _testnet = None;
    if !cli.no_testnet {
        match testnet::TestnetProcess::spawn(cli.seq_testnet).await {
            Ok(proc) => {
                info!("testnet log: {}", proc.log_path().display());
                _testnet = Some(proc);
            }
            Err(e) => {
                error!("failed to spawn testnet: {e}");
                std::process::exit(1);
            }
        }
    }

    let client = rpc::RpcClient::new(&cli.rpc);

    println!("\n=== HARNESS ===");
    println!("RPC: {}\n", cli.rpc);

    // Wait for RPC.
    println!("Waiting for RPC...");
    if let Err(e) = poll::wait_for_rpc(&client, Duration::from_secs(60)).await {
        error!("RPC not ready: {e}");
        std::process::exit(1);
    }
    let status = client
        .get_status()
        .await
        .expect("RPC ready but get_status failed");
    println!("RPC ready (slot {})", status.head_slot);

    // Wait for pixels service.
    println!("Waiting for pixels service...");
    if let Err(e) = poll::wait_for_service(&client, 2000, Duration::from_secs(60)).await {
        error!("pixels service not ready: {e}");
        std::process::exit(1);
    }
    println!("Pixels service ready\n");

    // Run scenarios sequentially.
    let mut results = Vec::new();
    let consistency_supported = !cli.no_testnet && !cli.seq_testnet;
    let default_scenarios = [
        "serial",
        "repeat",
        "liveness",
        "invalid_wp",
        "recovery",
        "rpc_errors",
        "metrics",
    ];
    let mut all_scenarios = vec![
        "serial",
        "repeat",
        "liveness",
        "invalid_wp",
        "recovery",
        "rpc_errors",
        "metrics",
        "throughput",
    ];
    if consistency_supported {
        all_scenarios.push("consistency");
    }

    // Filter to a single scenario if --scenario is specified.
    let scenario_list: Vec<&str> = if let Some(ref name) = cli.scenario {
        if name == "consistency" && !consistency_supported {
            error!("scenario \"consistency\" requires the networked local testnet");
            std::process::exit(1);
        }
        if !all_scenarios.contains(&name.as_str()) {
            error!(
                "unknown scenario: {:?} (available: {})",
                name,
                all_scenarios.join(", ")
            );
            std::process::exit(1);
        }
        vec![name.as_str()]
    } else {
        // Keep throughput opt-in for now; it is benchmark-style and substantially
        // slower than the default correctness scenarios used in CI.
        default_scenarios.to_vec()
    };

    for (i, name) in scenario_list.iter().enumerate() {
        println!("[{}/{}] {name}", i + 1, scenario_list.len());
        let result = match *name {
            "serial" => scenarios::serial::run(&client).await,
            "repeat" => scenarios::repeat::run(&client).await,
            "liveness" => scenarios::liveness::run(&client).await,
            "invalid_wp" => scenarios::invalid_wp::run(&client).await,
            "recovery" => scenarios::recovery::run(&client).await,
            "rpc_errors" => scenarios::rpc_errors::run(&client).await,
            "metrics" => scenarios::metrics::run(&client).await,
            "consistency" => scenarios::consistency::run(&client).await,
            "throughput" => scenarios::throughput::run(&client).await,
            _ => unreachable!(),
        };
        let dur = result.duration.as_secs();
        if result.pass {
            println!("  PASS ({dur}s)");
            result.print_latency_summary();
            result.print_metric_summary();
            if cli.perf && !result.latencies.is_empty() {
                println!("  Per-operation timing:");
                for sample in &result.latencies {
                    println!(
                        "    {:30} {:>8.1}ms",
                        sample.label,
                        sample.duration.as_secs_f64() * 1000.0,
                    );
                }
            }
            println!();
        } else {
            println!(
                "  FAIL: {} ({dur}s)\n",
                result.error.as_deref().unwrap_or("unknown")
            );
            // Include node log tail on failure for debugging
            if let Some(ref proc) = _testnet {
                print_log_tail(proc.log_path(), 20);
            }
        }
        results.push(result);
    }

    // Summary.
    let passed = results.iter().filter(|r| r.pass).count();
    let total_dur: u64 = results.iter().map(|r| r.duration.as_secs()).sum();

    if cli.json {
        let json_results: Vec<serde_json::Value> = results
            .iter()
            .map(|r| {
                let mut obj = serde_json::json!({
                    "name": r.name,
                    "pass": r.pass,
                    "duration_ms": r.duration.as_millis() as u64,
                });
                if let Some(ref err) = r.error {
                    obj["error"] = serde_json::Value::String(err.clone());
                }
                if !r.latencies.is_empty() {
                    let latencies: Vec<serde_json::Value> = r
                        .latencies
                        .iter()
                        .map(|l| {
                            serde_json::json!({
                                "label": l.label,
                                "duration_ms": l.duration.as_millis() as u64,
                            })
                        })
                        .collect();
                    obj["latencies"] = serde_json::Value::Array(latencies);
                }
                if !r.metrics.is_empty() {
                    let metrics: Vec<serde_json::Value> = r
                        .metrics
                        .iter()
                        .map(|m| {
                            serde_json::json!({
                                "label": m.label,
                                "value": m.value,
                                "unit": m.unit,
                            })
                        })
                        .collect();
                    obj["metrics"] = serde_json::Value::Array(metrics);
                }
                obj
            })
            .collect();
        let output = serde_json::json!({
            "passed": passed,
            "total": results.len(),
            "duration_ms": results.iter().map(|r| r.duration.as_millis() as u64).sum::<u64>(),
            "scenarios": json_results,
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        println!("=== {passed}/{} passed ({total_dur}s) ===", results.len());
        if cli.perf {
            // Aggregate all latency samples across scenarios
            let mut all_latencies: Vec<f64> = results
                .iter()
                .flat_map(|r| {
                    r.latencies
                        .iter()
                        .map(|l| l.duration.as_secs_f64() * 1000.0)
                })
                .collect();
            if !all_latencies.is_empty() {
                all_latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
                let count = all_latencies.len();
                let p50 = all_latencies[count / 2];
                let p90 = all_latencies[count * 9 / 10];
                let p99 = all_latencies[count * 99 / 100];
                println!();
                println!("Aggregate latency ({count} operations):");
                println!("  p50={p50:.1}ms  p90={p90:.1}ms  p99={p99:.1}ms");
            }
        }
    }

    // Kill testnet.
    if let Some(mut t) = _testnet {
        t.kill().await;
    }

    std::process::exit(if passed == results.len() { 0 } else { 1 });
}

/// Print the last N lines of a log file for debugging failed scenarios.
fn print_log_tail(path: &std::path::Path, max_lines: usize) {
    match std::fs::read_to_string(path) {
        Ok(content) => {
            let lines: Vec<&str> = content.lines().collect();
            let start = lines.len().saturating_sub(max_lines);
            println!(
                "  --- Node log (last {} lines from {}) ---",
                max_lines,
                path.display()
            );
            for line in &lines[start..] {
                println!("  | {}", line);
            }
            println!("  --- End of log ---\n");
        }
        Err(e) => {
            println!("  (could not read node log at {}: {})\n", path.display(), e);
        }
    }
}
