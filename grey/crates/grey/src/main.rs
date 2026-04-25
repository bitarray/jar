//! Grey — JAM (Join-Accumulate Machine) blockchain node.
//!
//! This is the main entry point for the Grey node implementation.
//! See the Gray Paper v0.7.2 for the full specification.

#[allow(dead_code)]
mod audit;
mod chainspec;
mod config;
#[allow(dead_code)]
mod disputes;
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
mod tracing;

use clap::Parser;
use grey_types::config::Config;

/// Build a detailed version string for --version output.
fn long_version() -> &'static str {
    concat!(
        env!("CARGO_PKG_VERSION"),
        "\nProtocol: JAM (Gray Paper v0.7.2)",
    )
}

/// Log output format.
#[derive(clap::ValueEnum, Clone, Debug, Default, PartialEq, Eq)]
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
#[command(
    name = "grey",
    about = "JAM blockchain node implementation",
    version = env!("CARGO_PKG_VERSION"),
    long_version = long_version(),
)]
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

    /// Export the chain spec to a JSON file and exit.
    #[arg(long, value_name = "PATH")]
    export_chain_spec: Option<String>,

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

    /// Number of blocks to produce in sequential testnet mode (default: from config).
    /// Use with --seq-testnet for extended stability testing.
    #[arg(long)]
    seq_testnet_blocks: Option<u32>,

    /// Database path for persistent storage
    #[arg(long, default_value = "./grey-db")]
    db_path: String,

    /// Path to the keystore directory for validator keys.
    /// If specified and keys exist for the validator index, they are loaded from disk.
    /// If not specified, keys are derived deterministically (test mode only).
    #[arg(long, value_name = "PATH")]
    keystore_path: Option<String>,

    /// Number of blocks to retain after finalization (0 = archive mode, no pruning).
    /// After each finalization, blocks older than finalized_slot - pruning_depth are removed.
    #[arg(long, default_value_t = 0)]
    pruning_depth: u32,

    /// JSON-RPC server port (0 to disable)
    #[arg(long, default_value_t = 9933)]
    rpc_port: u16,

    /// Maximum RPC requests per IP per minute (0 to disable rate limiting).
    #[arg(long, default_value_t = 1000)]
    rpc_rate_limit: u64,

    /// Enable permissive CORS on the RPC server
    #[arg(long)]
    rpc_cors: bool,

    /// RPC listen address (use 0.0.0.0 to bind all interfaces)
    #[arg(long, default_value = "127.0.0.1")]
    rpc_host: String,

    /// Expose Prometheus metrics on a separate port (0 to disable).
    #[arg(long, default_value_t = 0)]
    metrics_port: u16,

    /// Log output format.
    #[arg(long, value_enum, default_value_t = LogFormat::Plain)]
    log_format: LogFormat,

    /// Minimum log level. Supports per-module filtering using the EnvFilter syntax
    /// (e.g. `grey_network=debug,grey_rpc=info`). Falls back to RUST_LOG env var, then
    /// `info`.
    #[arg(long)]
    log_level: Option<String>,
}

impl Cli {
    /// Apply config file values as fallbacks for CLI fields that are still at
    /// their default values.
    fn apply_config_defaults(&mut self, cfg: &config::ConfigFile) {
        let db_path_from_cli = self.db_path != "./grey-db";

        if let Some(v) = cfg.node.validator_index
            && self.validator_index == 0
        {
            self.validator_index = v;
        }
        if let Some(ref v) = cfg.node.listen_addr
            && self.listen_addr == "127.0.0.1"
        {
            self.listen_addr = v.clone();
        }
        if let Some(v) = cfg.node.port
            && self.port == 9000
        {
            self.port = v;
        }
        if let Some(ref v) = cfg.node.chain_spec
            && self.chain_spec.is_none()
        {
            self.chain_spec = Some(v.clone());
        }
        if let Some(ref v) = cfg.node.chain
            && self.chain.is_none()
            && self.chain_spec.is_none()
        {
            self.chain = Some(v.clone());
        }
        if let Some(v) = cfg.node.tiny
            && self.tiny
            && self.chain.is_none()
            && self.chain_spec.is_none()
        {
            self.tiny = v;
        }
        if let Some(v) = cfg.node.genesis_time
            && self.genesis_time == 0
        {
            self.genesis_time = v;
        }
        if let Some(ref v) = cfg.node.db_path
            && !db_path_from_cli
        {
            self.db_path = v.clone();
        }
        if let Some(ref v) = cfg.storage.db_path
            && !db_path_from_cli
        {
            self.db_path = v.clone();
        }
        if let Some(v) = cfg.storage.pruning_depth
            && self.pruning_depth == 0
        {
            self.pruning_depth = v;
        }
        if let Some(v) = cfg.rpc.port
            && self.rpc_port == 9933
        {
            self.rpc_port = v;
        }
        if let Some(v) = cfg.rpc.cors
            && !self.rpc_cors
        {
            self.rpc_cors = v;
        }
        if let Some(ref v) = cfg.rpc.host
            && self.rpc_host == "127.0.0.1"
        {
            self.rpc_host = v.clone();
        }
        if let Some(v) = cfg.rpc.rate_limit
            && self.rpc_rate_limit == 1000
        {
            self.rpc_rate_limit = v;
        }
        if let Some(v) = cfg.rpc.metrics_port
            && self.metrics_port == 0
        {
            self.metrics_port = v;
        }
        if let Some(ref peers) = cfg.network.boot_peers
            && self.peers.is_empty()
        {
            self.peers = peers.clone();
        }
        if self.log_level.is_none() {
            self.log_level = cfg.logging.level.clone();
        }
        if matches!(self.log_format, LogFormat::Plain)
            && let Some(ref fmt) = cfg.logging.format
        {
            match fmt.as_str() {
                "json" => self.log_format = LogFormat::Json,
                "pretty" => self.log_format = LogFormat::Pretty,
                "plain" => {}
                other => eprintln!("warning: unknown log format in config: {:?}", other),
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut cli = Cli::parse();

    // Load config file if specified, apply as defaults for unset fields
    if let Some(ref config_path) = cli.config {
        let cfg = config::ConfigFile::load(std::path::Path::new(config_path))
            .map_err(|e| format!("config file error: {e}"))?;
        cli.apply_config_defaults(&cfg);
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
            "Loaded chain spec '{}' from {} (V={}, C={}, E={}, boot_peers={})",
            spec.name,
            path,
            spec.config.validators_count,
            spec.config.core_count,
            spec.config.epoch_length,
            spec.boot_peers.len(),
        );
        // Use boot peers from chain spec if no CLI peers were provided
        if cli.peers.is_empty() && !spec.boot_peers.is_empty() {
            cli.peers = spec.boot_peers.clone();
            tracing::info!("Loaded {} boot peers from chain spec", cli.peers.len());
        }
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
        return seq_testnet::run_seq_testnet(cli.rpc_port, cli.rpc_cors, cli.seq_testnet_blocks)
            .await;
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

    if let Some(ref path) = cli.export_chain_spec {
        let (genesis_state, _) = grey_consensus::genesis::create_genesis(&config);
        let peer_strings: Vec<String> = cli.peers.clone();
        let spec = if peer_strings.is_empty() {
            chainspec::ChainSpec::from_genesis(&config, &genesis_state)
        } else {
            chainspec::ChainSpec::from_genesis_with_peers(&config, &genesis_state, peer_strings)
        };
        spec.save(std::path::Path::new(path))
            .map_err(|e| format!("failed to export chain spec: {e}"))?;
        println!("Chain spec exported to {}", path);
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
        rpc_host: cli.rpc_host,
        rpc_rate_limit: cli.rpc_rate_limit,
        genesis_state: None,
        pruning_depth: cli.pruning_depth,
        keystore_path: cli.keystore_path,
        metrics_port: cli.metrics_port,
        config_path: cli.config.clone(),
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_cli() -> Cli {
        Cli {
            config: Some("/tmp/grey.toml".to_string()),
            validator_index: 0,
            listen_addr: "127.0.0.1".to_string(),
            port: 9000,
            peers: vec![],
            tiny: true,
            chain: None,
            chain_spec: None,
            genesis_time: 0,
            info: false,
            export_chain_spec: None,
            verify_state: false,
            test: false,
            test_blocks: 20,
            testnet: None,
            seq_testnet: false,
            seq_testnet_blocks: None,
            db_path: "./grey-db".to_string(),
            keystore_path: None,
            pruning_depth: 0,
            rpc_port: 9933,
            rpc_rate_limit: 1000,
            rpc_cors: false,
            rpc_host: "127.0.0.1".to_string(),
            metrics_port: 0,
            log_format: LogFormat::Plain,
            log_level: None,
        }
    }

    fn config_with_all_fields() -> config::ConfigFile {
        config::ConfigFile {
            node: config::NodeConfig {
                validator_index: Some(5),
                listen_addr: Some("0.0.0.0".to_string()),
                port: Some(9001),
                tiny: Some(false),
                chain: Some("full".to_string()),
                chain_spec: Some("/tmp/custom-spec.json".to_string()),
                genesis_time: Some(1_700_000_000),
                db_path: Some("/data/node-db".to_string()),
            },
            rpc: config::RpcConfig {
                port: Some(9944),
                host: Some("0.0.0.0".to_string()),
                cors: Some(true),
                rate_limit: Some(500),
                metrics_port: Some(9100),
            },
            storage: config::StorageConfig {
                db_path: Some("/data/storage-db".to_string()),
                pruning_depth: Some(256),
            },
            network: config::NetworkConfig {
                boot_peers: Some(vec!["/ip4/10.0.0.1/tcp/9000".to_string()]),
            },
            logging: config::LoggingConfig {
                format: Some("json".to_string()),
                level: Some("grey_network=debug,info".to_string()),
            },
        }
    }

    #[test]
    fn test_apply_config_defaults_honors_declared_fields() {
        let mut cli = default_cli();

        cli.apply_config_defaults(&config_with_all_fields());

        assert_eq!(cli.validator_index, 5);
        assert_eq!(cli.listen_addr, "0.0.0.0");
        assert_eq!(cli.port, 9001);
        assert_eq!(cli.chain_spec.as_deref(), Some("/tmp/custom-spec.json"));
        assert_eq!(
            cli.chain, None,
            "chain spec should take precedence over chain"
        );
        assert_eq!(cli.genesis_time, 1_700_000_000);
        assert_eq!(cli.db_path, "/data/storage-db");
        assert_eq!(cli.pruning_depth, 256);
        assert_eq!(cli.rpc_port, 9944);
        assert!(cli.rpc_cors);
        assert_eq!(cli.rpc_host, "0.0.0.0");
        assert_eq!(cli.rpc_rate_limit, 500);
        assert_eq!(cli.metrics_port, 9100);
        assert_eq!(cli.peers, vec!["/ip4/10.0.0.1/tcp/9000".to_string()]);
        assert_eq!(cli.log_format, LogFormat::Json);
        assert_eq!(cli.log_level.as_deref(), Some("grey_network=debug,info"));
    }

    #[test]
    fn test_apply_config_defaults_uses_tiny_when_no_chain_is_set() {
        let mut cli = default_cli();
        let cfg = config::ConfigFile {
            node: config::NodeConfig {
                tiny: Some(false),
                ..Default::default()
            },
            ..Default::default()
        };

        cli.apply_config_defaults(&cfg);

        assert!(!cli.tiny);
    }

    #[test]
    fn test_apply_config_defaults_preserves_cli_overrides() {
        let mut cli = default_cli();
        cli.validator_index = 2;
        cli.listen_addr = "192.0.2.1".to_string();
        cli.port = 9101;
        cli.peers = vec!["/ip4/192.0.2.10/tcp/9000".to_string()];
        cli.tiny = false;
        cli.chain = Some("tiny".to_string());
        cli.chain_spec = Some("/tmp/cli-spec.json".to_string());
        cli.genesis_time = 42;
        cli.db_path = "/cli/db".to_string();
        cli.pruning_depth = 64;
        cli.rpc_port = 19444;
        cli.rpc_rate_limit = 25;
        cli.rpc_cors = true;
        cli.rpc_host = "0.0.0.0".to_string();
        cli.metrics_port = 9200;
        cli.log_format = LogFormat::Pretty;
        cli.log_level = Some("debug".to_string());

        cli.apply_config_defaults(&config_with_all_fields());

        assert_eq!(cli.validator_index, 2);
        assert_eq!(cli.listen_addr, "192.0.2.1");
        assert_eq!(cli.port, 9101);
        assert_eq!(cli.peers, vec!["/ip4/192.0.2.10/tcp/9000".to_string()]);
        assert!(!cli.tiny);
        assert_eq!(cli.chain.as_deref(), Some("tiny"));
        assert_eq!(cli.chain_spec.as_deref(), Some("/tmp/cli-spec.json"));
        assert_eq!(cli.genesis_time, 42);
        assert_eq!(cli.db_path, "/cli/db");
        assert_eq!(cli.pruning_depth, 64);
        assert_eq!(cli.rpc_port, 19444);
        assert_eq!(cli.rpc_rate_limit, 25);
        assert!(cli.rpc_cors);
        assert_eq!(cli.rpc_host, "0.0.0.0");
        assert_eq!(cli.metrics_port, 9200);
        assert_eq!(cli.log_format, LogFormat::Pretty);
        assert_eq!(cli.log_level.as_deref(), Some("debug"));
    }
}
