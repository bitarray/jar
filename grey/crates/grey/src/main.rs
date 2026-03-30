//! Grey — JAM (Join-Accumulate Machine) blockchain node.
//!
//! This is the main entry point for the Grey node implementation.
//! See the Gray Paper v0.7.2 for the full specification.

#[allow(dead_code)]
mod audit;
mod chainspec;
mod config;
#[allow(dead_code)]
mod finality;
mod guarantor;
#[allow(dead_code)]
mod keystore;
mod node;
mod seq_testnet;
#[allow(dead_code)]
mod testnet;
mod tickets;

use clap::Parser;
use grey_types::config::Config;

/// Log output format.
#[derive(clap::ValueEnum, Clone, Debug, Default)]
enum LogFormat {
    /// Human-readable single-line output (default).
    #[default]
    Plain,
    /// Coloured multi-line output for local development.
    Pretty,
    /// JSON Lines — one JSON object per log line. Ideal for log aggregators.
    Json,
}

/// Grey — JAM blockchain node
#[derive(Parser, Debug)]
#[command(name = "grey", about = "JAM blockchain node implementation")]
struct Cli {
    /// Path to a TOML configuration file. CLI flags override config file values.
    #[arg(long, value_name = "PATH")]
    config: Option<String>,

    /// Validator index (0 to V-1)
    #[arg(short = 'i', long, default_value_t = 0)]
    validator_index: u16,

    /// Network listen address
    #[arg(long, default_value = "127.0.0.1")]
    listen_addr: String,

    /// Network listen port
    #[arg(short, long, default_value_t = 9000)]
    port: u16,

    /// Boot peer multiaddresses (comma-separated)
    #[arg(short = 'b', long, value_delimiter = ',')]
    peers: Vec<String>,

    /// Use tiny test config (V=6, C=2, E=12)
    #[arg(long, default_value_t = true)]
    tiny: bool,

    /// Built-in chain preset: "tiny" (V=6, C=2) or "full" (V=1023, C=341)
    #[arg(long, value_name = "PRESET")]
    chain: Option<String>,

    /// Path to a JSON chain spec file (overrides --tiny and --chain)
    #[arg(long, value_name = "PATH")]
    chain_spec: Option<String>,

    /// Genesis time override (Unix timestamp, 0 = use current time)
    #[arg(long, default_value_t = 0)]
    genesis_time: u64,

    /// Just show info and exit (don't run the node)
    #[arg(long)]
    info: bool,

    /// Verify integrity of all stored state data and exit.
    /// Checks blake2b checksums for every stored state entry.
    #[arg(long)]
    verify_state: bool,

    /// Run a sequential block production test (no networking)
    #[arg(long)]
    test: bool,

    /// Number of blocks to produce in test mode
    #[arg(long, default_value_t = 20)]
    test_blocks: u32,

    /// Run a networked testnet for this many seconds (0 = run until Ctrl+C)
    #[arg(long)]
    testnet: Option<u64>,

    /// Run a deterministic sequential testnet (single-threaded, no wall-clock delays)
    #[arg(long)]
    seq_testnet: bool,

    /// Database path for persistent storage
    #[arg(long, default_value = "./grey-db")]
    db_path: String,

    /// Number of blocks to retain after finalization (0 = archive mode, no pruning).
    /// After each finalization, blocks older than finalized_slot - pruning_depth are removed.
    #[arg(long, default_value_t = 0)]
    pruning_depth: u32,

    /// JSON-RPC server port (0 to disable)
    #[arg(long, default_value_t = 9933)]
    rpc_port: u16,

    /// Enable permissive CORS on the RPC server
    #[arg(long)]
    rpc_cors: bool,

    /// RPC listen address (use 0.0.0.0 to bind all interfaces)
    #[arg(long, default_value = "127.0.0.1")]
    rpc_host: String,

    /// Log output format.
    #[arg(long, value_enum, default_value_t = LogFormat::Plain)]
    log_format: LogFormat,

    /// Minimum log level. Supports per-module filtering using the EnvFilter syntax
    /// (e.g. `grey_network=debug,grey_rpc=info`). Falls back to RUST_LOG env var, then
    /// `info`.
    #[arg(long)]
    log_level: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut cli = Cli::parse();

    // Load config file if specified, apply as defaults for unset fields
    if let Some(ref config_path) = cli.config {
        let cfg = config::ConfigFile::load(std::path::Path::new(config_path))
            .map_err(|e| format!("config file error: {e}"))?;

        // Apply config file values as fallbacks. CLI flags take precedence:
        // for fields with defaults, config file applies only when the CLI
        // value matches its default.
        if let Some(v) = cfg.node.validator_index
            && cli.validator_index == 0
        {
            cli.validator_index = v;
        }
        if let Some(ref v) = cfg.node.listen_addr
            && cli.listen_addr == "127.0.0.1"
        {
            cli.listen_addr = v.clone();
        }
        if let Some(v) = cfg.node.port
            && cli.port == 9000
        {
            cli.port = v;
        }
        if let Some(ref v) = cfg.node.db_path
            && cli.db_path == "./grey-db"
        {
            cli.db_path = v.clone();
        }
        if let Some(v) = cfg.rpc.port
            && cli.rpc_port == 9933
        {
            cli.rpc_port = v;
        }
        if let Some(v) = cfg.rpc.cors
            && !cli.rpc_cors
        {
            cli.rpc_cors = v;
        }
        if let Some(ref peers) = cfg.network.boot_peers
            && cli.peers.is_empty()
        {
            cli.peers = peers.clone();
        }
        // Apply log level from config file if CLI flag not set
        if cli.log_level.is_none() {
            cli.log_level = cfg.logging.level;
        }
    }

    // Build EnvFilter: CLI arg > config file > RUST_LOG env var > "info"
    let env_filter = cli
        .log_level
        .clone()
        .or_else(|| std::env::var("RUST_LOG").ok())
        .unwrap_or_else(|| "info".to_string());

    // Select format layer and initialise tracing
    match cli.log_format {
        LogFormat::Json => {
            tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::from(&env_filter))
                .json()
                .flatten_event(true)
                .init();
        }
        LogFormat::Pretty => {
            tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::from(&env_filter))
                .pretty()
                .init();
        }
        LogFormat::Plain => {
            tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::from(&env_filter))
                .init();
        }
    };

    // Resolve protocol config: --chain-spec > --chain > --tiny
    let config = if let Some(ref path) = cli.chain_spec {
        let spec = chainspec::ChainSpec::load(std::path::Path::new(path))
            .map_err(|e| format!("failed to load chain spec from {}: {}", path, e))?;
        tracing::info!(
            "Loaded chain spec '{}' from {} (V={}, C={}, E={})",
            spec.name,
            path,
            spec.config.validators_count,
            spec.config.core_count,
            spec.config.epoch_length,
        );
        spec.to_config()
    } else if let Some(ref preset) = cli.chain {
        match preset.as_str() {
            "tiny" => Config::tiny(),
            "full" => Config::full(),
            other => {
                return Err(format!(
                    "unknown chain preset: {:?} (expected \"tiny\" or \"full\")",
                    other
                )
                .into());
            }
        }
    } else if cli.tiny {
        Config::tiny()
    } else {
        Config::full()
    };

    // Sequential test mode (no networking)
    if cli.test {
        tracing::info!(
            "Running sequential block production test with {} blocks",
            cli.test_blocks
        );
        match testnet::run_sequential_test(cli.test_blocks) {
            Ok(result) => {
                println!();
                println!("=== SEQUENTIAL TEST PASSED ===");
                println!("  Blocks produced: {}", result.blocks_produced);
                println!("  Finalized up to slot: {}", result.finalized_slot);
                println!("  Final state timeslot: {}", result.final_timeslot);
                println!(
                    "  Work packages submitted: {}",
                    result.work_packages_submitted
                );
                println!(
                    "  Work packages accumulated: {}",
                    result.work_packages_accumulated
                );
                println!(
                    "  Authors: {:?}",
                    result
                        .slot_authors
                        .iter()
                        .map(|(s, a)| format!("slot{}->v{}", s, a))
                        .collect::<Vec<_>>()
                );
                return Ok(());
            }
            Err(e) => {
                tracing::error!("SEQUENTIAL TEST FAILED: {}", e);
                std::process::exit(1);
            }
        }
    }

    // Deterministic sequential testnet
    if cli.seq_testnet {
        tracing::info!("Running deterministic sequential testnet");
        return seq_testnet::run_seq_testnet(cli.rpc_port, cli.rpc_cors).await;
    }

    // Networked testnet mode
    if let Some(duration) = cli.testnet {
        tracing::info!("Running networked testnet for {}s", duration);
        match testnet::run_testnet(duration, cli.rpc_cors).await {
            Ok(result) => {
                println!();
                println!("=== TESTNET COMPLETED ===");
                println!("  Validators: {}", result.validators);
                println!("  Duration: {}s", result.duration_secs);
                return Ok(());
            }
            Err(e) => {
                tracing::error!("TESTNET FAILED: {}", e);
                std::process::exit(1);
            }
        }
    }

    if cli.info {
        chainspec::print_genesis_info(&config);
        return Ok(());
    }

    if cli.verify_state {
        let db_path = format!("{}/node-{}.redb", cli.db_path, cli.validator_index);
        println!("Verifying state integrity in {}...", db_path);
        let store = grey_store::Store::open(&db_path)?;
        let (verified, skipped, failed) = store.verify_all_states()?;
        println!(
            "State integrity check complete: {} verified, {} skipped (no checksum), {} FAILED",
            verified, skipped, failed
        );
        if failed > 0 {
            std::process::exit(1);
        }
        return Ok(());
    }

    if cli.validator_index >= config.validators_count {
        tracing::error!(
            "Validator index {} >= V={}",
            cli.validator_index,
            config.validators_count
        );
        std::process::exit(1);
    }

    // Genesis time: use current time if not specified
    let genesis_time = if cli.genesis_time == 0 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    } else {
        cli.genesis_time
    };

    tracing::info!(
        "Starting Grey node: validator={}, port={}, genesis_time={}",
        cli.validator_index,
        cli.port,
        genesis_time
    );

    node::run_node(node::NodeConfig {
        validator_index: cli.validator_index,
        listen_addr: cli.listen_addr,
        listen_port: cli.port,
        boot_peers: cli.peers,
        protocol_config: config,
        genesis_time,
        db_path: cli.db_path,
        rpc_port: cli.rpc_port,
        rpc_cors: cli.rpc_cors,
        genesis_state: None,
        pruning_depth: cli.pruning_depth,
    })
    .await
}
