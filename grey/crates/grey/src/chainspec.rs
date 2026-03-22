//! Chain specification: genesis state serialization and loading.
//!
//! Provides functions to serialize genesis state to a file and load it
//! on first boot, enabling custom validator sets and configuration.

use grey_types::config::Config;
use grey_types::state::State;
use std::path::Path;

/// A chain specification containing genesis configuration.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ChainSpec {
    /// Protocol name.
    pub name: String,
    /// Protocol version.
    pub protocol_version: String,
    /// Genesis state hash (Blake2b-256 of serialized genesis state).
    pub genesis_hash: String,
    /// Protocol configuration parameters.
    pub config: ChainSpecConfig,
}

/// Configuration parameters in the chain spec.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ChainSpecConfig {
    pub validators_count: u16,
    pub core_count: u16,
    pub epoch_length: u32,
    pub max_tickets_per_block: u16,
    pub tickets_per_validator: u16,
    pub recent_history_size: usize,
    pub auth_pool_size: usize,
    pub auth_queue_size: usize,
}

impl ChainSpec {
    /// Create a chain spec from a Config and genesis state.
    pub fn from_genesis(config: &Config, _genesis_state: &State) -> Self {
        // Compute genesis hash from the config blob
        let config_blob = config.encode_config_blob();
        let genesis_hash = grey_crypto::blake2b_256(&config_blob);

        Self {
            name: "Grey JAM".to_string(),
            protocol_version: "0.7.2".to_string(),
            genesis_hash: hex::encode(genesis_hash.0),
            config: ChainSpecConfig {
                validators_count: config.validators_count,
                core_count: config.core_count,
                epoch_length: config.epoch_length,
                max_tickets_per_block: config.max_tickets_per_block,
                tickets_per_validator: config.tickets_per_validator,
                recent_history_size: config.recent_history_size,
                auth_pool_size: config.auth_pool_size,
                auth_queue_size: config.auth_queue_size,
            },
        }
    }

    /// Save chain spec to a JSON file.
    pub fn save(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Load chain spec from a JSON file.
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let json = std::fs::read_to_string(path)?;
        let spec: Self = serde_json::from_str(&json)?;
        Ok(spec)
    }

    /// Convert chain spec config back to a Config.
    /// Uses tiny defaults for fields not in the chain spec.
    pub fn to_config(&self) -> Config {
        let base = if self.config.validators_count <= 6 {
            Config::tiny()
        } else {
            Config::full()
        };
        Config {
            validators_count: self.config.validators_count,
            core_count: self.config.core_count,
            epoch_length: self.config.epoch_length,
            max_tickets_per_block: self.config.max_tickets_per_block,
            tickets_per_validator: self.config.tickets_per_validator,
            recent_history_size: self.config.recent_history_size,
            auth_pool_size: self.config.auth_pool_size,
            auth_queue_size: self.config.auth_queue_size,
            ..base
        }
    }
}

/// Print genesis info for the given configuration.
pub fn print_genesis_info(config: &Config) {
    let config_blob = config.encode_config_blob();
    let genesis_hash = grey_crypto::blake2b_256(&config_blob);
    let seed_hash = grey_crypto::blake2b_256(b"jam");

    println!("Grey — JAM Blockchain Node");
    println!("Protocol: JAM (Join-Accumulate Machine)");
    println!("Specification: Gray Paper v0.7.2");
    println!();
    println!("Configuration:");
    println!("  Validators: {}", config.validators_count);
    println!("  Cores: {}", config.core_count);
    println!("  Epoch length: {} slots", config.epoch_length);
    println!("  Slot period: 6s");
    println!("  Tickets per block: {}", config.max_tickets_per_block);
    println!("  Ticket submission end: slot {}", config.ticket_submission_end());
    println!();
    println!("Genesis config hash: 0x{}", hex::encode(genesis_hash.0));
    println!("Genesis seed hash: {seed_hash}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_spec_roundtrip() {
        let config = Config::tiny();
        let (state, _) = grey_consensus::genesis::create_genesis(&config);

        let spec = ChainSpec::from_genesis(&config, &state);
        assert_eq!(spec.name, "Grey JAM");
        assert_eq!(spec.config.validators_count, 6);
        assert_eq!(spec.config.core_count, 2);
        assert_eq!(spec.config.epoch_length, 12);

        // Roundtrip through JSON
        let json = serde_json::to_string(&spec).unwrap();
        let spec2: ChainSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec2.genesis_hash, spec.genesis_hash);
        assert_eq!(spec2.config.validators_count, spec.config.validators_count);
    }

    #[test]
    fn test_chain_spec_to_config() {
        let config = Config::tiny();
        let (state, _) = grey_consensus::genesis::create_genesis(&config);

        let spec = ChainSpec::from_genesis(&config, &state);
        let config2 = spec.to_config();

        assert_eq!(config2.validators_count, config.validators_count);
        assert_eq!(config2.core_count, config.core_count);
        assert_eq!(config2.epoch_length, config.epoch_length);
    }

    #[test]
    fn test_chain_spec_save_load() {
        let config = Config::tiny();
        let (state, _) = grey_consensus::genesis::create_genesis(&config);
        let spec = ChainSpec::from_genesis(&config, &state);

        let tmp = std::env::temp_dir().join("grey-test-chainspec.json");
        spec.save(&tmp).expect("save should succeed");

        let loaded = ChainSpec::load(&tmp).expect("load should succeed");
        assert_eq!(loaded.genesis_hash, spec.genesis_hash);

        std::fs::remove_file(&tmp).ok();
    }
}
