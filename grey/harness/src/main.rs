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

    /// RPC endpoint URL.
    #[arg(long, default_value = "http://localhost:9933")]
    rpc: String,
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
        match testnet::TestnetProcess::spawn().await {
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
    let status = client.get_status().await.expect("RPC ready but get_status failed");
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
    let scenario_list = ["serial", "repeat", "liveness"];
    for (i, name) in scenario_list.iter().enumerate() {
        println!("[{}/{}] {name}", i + 1, scenario_list.len());
        let result = match *name {
            "serial" => scenarios::serial::run(&client).await,
            "repeat" => scenarios::repeat::run(&client).await,
            "liveness" => scenarios::liveness::run(&client).await,
            _ => unreachable!(),
        };
        let dur = result.duration.as_secs();
        if result.pass {
            println!("  PASS ({dur}s)\n");
        } else {
            println!("  FAIL: {} ({dur}s)\n", result.error.as_deref().unwrap_or("unknown"));
        }
        results.push(result);
    }

    // Summary.
    let passed = results.iter().filter(|r| r.pass).count();
    let total_dur: u64 = results.iter().map(|r| r.duration.as_secs()).sum();
    println!("=== {passed}/{} passed ({total_dur}s) ===", results.len());

    // Kill testnet.
    if let Some(mut t) = _testnet {
        t.kill().await;
    }

    std::process::exit(if passed == results.len() { 0 } else { 1 });
}
