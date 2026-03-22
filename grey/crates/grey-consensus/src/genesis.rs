//! Genesis state creation for test networks.
//!
//! Creates a valid initial state with known validator keys for a tiny
//! test configuration (V=6, C=2, E=12).

use grey_types::config::Config;
use grey_types::state::*;
use grey_types::validator::ValidatorKey;
use grey_types::{BandersnatchPublicKey, BlsPublicKey, Hash};
use std::collections::BTreeMap;

/// Validator secrets for the test network.
pub struct ValidatorSecrets {
    pub ed25519: grey_crypto::Ed25519Keypair,
    pub bandersnatch: grey_crypto::BandersnatchKeypair,
    pub bls: grey_crypto::BlsKeypair,
    pub index: u16,
}

/// Generate deterministic validator secrets for index `i`.
pub fn make_validator_secrets(index: u16) -> ValidatorSecrets {
    let mut ed_seed = [0u8; 32];
    ed_seed[0] = index as u8;
    ed_seed[1] = (index >> 8) as u8;
    ed_seed[31] = 0xED; // marker for ed25519

    let mut band_seed = [0u8; 32];
    band_seed[0] = index as u8;
    band_seed[1] = (index >> 8) as u8;
    band_seed[31] = 0xBA; // marker for bandersnatch

    let mut bls_seed = [0u8; 32];
    bls_seed[0] = index as u8;
    bls_seed[1] = (index >> 8) as u8;
    bls_seed[31] = 0xBB; // marker for BLS

    ValidatorSecrets {
        ed25519: grey_crypto::Ed25519Keypair::from_seed(&ed_seed),
        bandersnatch: grey_crypto::BandersnatchKeypair::from_seed(&band_seed),
        bls: grey_crypto::BlsKeypair::from_seed(&bls_seed),
        index,
    }
}

/// Create the validator key set from secrets.
pub fn make_validator_key(secrets: &ValidatorSecrets) -> ValidatorKey {
    let bandersnatch = BandersnatchPublicKey(secrets.bandersnatch.public_key_bytes());
    let ed25519 = secrets.ed25519.public_key();

    let bls_bytes = secrets.bls.public_key_bytes();

    // Metadata: encode the validator index and network address.
    // Uses loopback (127.0.0.1) for local testnets; production genesis
    // would use actual public addresses.
    let mut metadata = [0u8; 128];
    metadata[0] = secrets.index as u8;
    metadata[1] = (secrets.index >> 8) as u8;
    // Bytes 2..6: IP address (loopback for testnet)
    metadata[2] = 127;
    metadata[3] = 0;
    metadata[4] = 0;
    metadata[5] = 1;
    let port = 9000u16 + secrets.index;
    metadata[6] = port as u8;
    metadata[7] = (port >> 8) as u8;

    ValidatorKey {
        bandersnatch,
        ed25519,
        bls: BlsPublicKey(bls_bytes),
        metadata,
    }
}

/// Create all validator secrets for a given config.
pub fn make_all_validator_secrets(config: &Config) -> Vec<ValidatorSecrets> {
    (0..config.validators_count)
        .map(make_validator_secrets)
        .collect()
}

/// Create the genesis state for the tiny test network.
///
/// Returns (state, validator_secrets).
pub fn create_genesis(config: &Config) -> (State, Vec<ValidatorSecrets>) {
    let secrets = make_all_validator_secrets(config);
    let validators: Vec<ValidatorKey> = secrets.iter().map(make_validator_key).collect();

    // Compute initial fallback key sequence for epoch 0
    // η₂ is Hash::ZERO at genesis
    let fallback_keys = grey_state::safrole::fallback_key_sequence(
        config,
        &Hash::ZERO,
        &validators,
    );

    let state = State {
        auth_pool: vec![vec![]; config.core_count as usize],
        recent_blocks: RecentBlocks {
            headers: vec![],
            accumulation_log: vec![],
        },
        accumulation_outputs: vec![],
        safrole: SafroleState {
            pending_keys: validators.clone(),
            ring_root: grey_types::BandersnatchRingRoot::default(),
            seal_key_series: SealKeySeries::Fallback(fallback_keys),
            ticket_accumulator: vec![],
        },
        services: BTreeMap::new(),
        entropy: [Hash::ZERO; 4],
        pending_validators: validators.clone(),
        current_validators: validators.clone(),
        previous_validators: validators,
        pending_reports: vec![None; config.core_count as usize],
        timeslot: 0,
        auth_queue: vec![vec![Hash::ZERO; config.core_count as usize]; config.auth_queue_size],
        privileged_services: PrivilegedServices::default(),
        judgments: Judgments::default(),
        statistics: ValidatorStatistics {
            current: vec![ValidatorRecord::default(); config.validators_count as usize],
            last: vec![],
            core_stats: vec![],
            service_stats: BTreeMap::new(),
        },
        accumulation_queue: vec![],
        accumulation_history: vec![],
    };

    (state, secrets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_creation_tiny() {
        let config = Config::tiny();
        let (state, secrets) = create_genesis(&config);

        assert_eq!(state.current_validators.len(), 6);
        assert_eq!(secrets.len(), 6);
        assert_eq!(state.timeslot, 0);
        assert_eq!(state.pending_reports.len(), 2); // C=2

        // All validators should have unique keys
        let mut seen_ed = std::collections::HashSet::new();
        let mut seen_band = std::collections::HashSet::new();
        for v in &state.current_validators {
            assert!(seen_ed.insert(v.ed25519.0));
            assert!(seen_band.insert(v.bandersnatch.0));
        }

        // Seal key series should be fallback mode
        assert!(matches!(
            state.safrole.seal_key_series,
            SealKeySeries::Fallback(_)
        ));
    }

    #[test]
    fn test_deterministic_secrets() {
        let s1 = make_validator_secrets(0);
        let s2 = make_validator_secrets(0);
        assert_eq!(s1.ed25519.public_key().0, s2.ed25519.public_key().0);
        assert_eq!(s1.bandersnatch.public_key_bytes(), s2.bandersnatch.public_key_bytes());
    }
}
