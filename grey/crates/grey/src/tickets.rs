//! Ticket generation and collection for Safrole seal-key contest.
//!
//! Implements ticket submission per Gray Paper Section 6:
//! 1. Each validator generates N=2 ticket attempts per epoch
//! 2. Ring VRF proof over (entropy, attempt_index) proves ticket validity
//! 3. Tickets are broadcast via gossipsub and collected by block authors
//! 4. Top E tickets become the seal-key sequence for the next epoch
//! 5. Outside-in ordering Z (eq 6.25) assigns tickets to timeslots

use grey_consensus::genesis::ValidatorSecrets;
use grey_types::config::Config;
use grey_types::header::TicketProof;
use grey_types::state::State;
use grey_types::{Hash, Timeslot};
use std::collections::BTreeSet;

/// Maximum ticket attempts per validator per epoch (N=2 in tiny, N=2 in full).
const TICKET_ATTEMPTS: u8 = 2;

/// State for ticket collection and submission.
pub struct TicketState {
    /// Tickets we've collected from gossip, pending inclusion in a block.
    /// Stored sorted by ticket ID for efficient merging.
    pub pending_tickets: Vec<TicketProof>,
    /// Ticket IDs already seen (deduplication).
    pub seen_ticket_ids: BTreeSet<Hash>,
    /// Whether we've generated our own tickets for the current epoch.
    pub generated_this_epoch: bool,
    /// Current epoch (to detect epoch transitions).
    pub current_epoch: u32,
}

impl TicketState {
    pub fn new() -> Self {
        Self {
            pending_tickets: Vec::new(),
            seen_ticket_ids: BTreeSet::new(),
            generated_this_epoch: false,
            current_epoch: 0,
        }
    }

    /// Check for epoch change and reset if needed.
    pub fn check_epoch(&mut self, timeslot: Timeslot, config: &Config) {
        let epoch = timeslot / config.epoch_length;
        if epoch != self.current_epoch {
            self.current_epoch = epoch;
            self.generated_this_epoch = false;
            self.pending_tickets.clear();
            self.seen_ticket_ids.clear();
        }
    }

    /// Generate ticket proofs for this validator.
    /// Returns Ring VRF proofs to be broadcast and included in blocks.
    pub fn generate_tickets(
        &mut self,
        config: &Config,
        state: &State,
        secrets: &ValidatorSecrets,
        validator_index: u16,
    ) -> Vec<TicketProof> {
        if self.generated_this_epoch {
            return Vec::new();
        }

        let timeslot = state.timeslot;
        let slot_in_epoch = timeslot % config.epoch_length;

        // Only generate tickets in the submission window (first Y slots of epoch)
        let y = config.ticket_submission_end();
        if slot_in_epoch >= y {
            return Vec::new();
        }

        self.generated_this_epoch = true;

        // Extract Bandersnatch public keys from current validator set for the ring
        let ring_keys: Vec<[u8; 32]> = state
            .current_validators
            .iter()
            .map(|v| v.bandersnatch.0)
            .collect();

        // Generate N ticket attempts using Ring VRF
        let eta2 = &state.entropy[2]; // η₂
        let mut tickets = Vec::new();

        for attempt in 0..TICKET_ATTEMPTS {
            if let Some(proof) =
                generate_ticket_proof(secrets, eta2, attempt, &ring_keys, validator_index as usize)
            {
                tickets.push(proof);
            }
        }

        tickets
    }

    /// Add a ticket proof received from gossip.
    /// Returns true if the ticket was new (not a duplicate).
    pub fn add_ticket(&mut self, proof: TicketProof, config: &Config, state: &State) -> bool {
        // Derive ticket ID from proof to check for duplicates
        let ticket_id = derive_ticket_id(&proof, state);
        if self.seen_ticket_ids.contains(&ticket_id) {
            return false;
        }
        self.seen_ticket_ids.insert(ticket_id);
        self.pending_tickets.push(proof);

        // Sort by ticket ID (required for block inclusion per eq 6.29)
        self.pending_tickets.sort_by(|a, b| {
            let id_a = derive_ticket_id(a, state);
            let id_b = derive_ticket_id(b, state);
            id_a.0.cmp(&id_b.0)
        });

        // Keep at most K tickets per extrinsic
        let max_tickets = config.max_tickets_per_block as usize;
        if self.pending_tickets.len() > max_tickets {
            self.pending_tickets.truncate(max_tickets);
        }

        true
    }

    /// Take tickets for block inclusion (up to K per extrinsic).
    pub fn take_tickets_for_block(&mut self, config: &Config) -> Vec<TicketProof> {
        let max = config.max_tickets_per_block as usize;
        let count = self.pending_tickets.len().min(max);
        self.pending_tickets.drain(..count).collect()
    }
}

/// Generate a ticket Ring VRF proof for a given attempt.
///
/// VRF input: X_T ⌢ η₂ ⌢ E₁(attempt) (eq 6.29).
/// Uses Ring VRF to anonymize the submitter (784-byte proof).
fn generate_ticket_proof(
    secrets: &ValidatorSecrets,
    eta2: &Hash,
    attempt: u8,
    ring_keys: &[[u8; 32]],
    key_index: usize,
) -> Option<TicketProof> {
    let vrf_input = grey_crypto::bandersnatch::build_ticket_vrf_input(&eta2.0, attempt);

    // Generate Ring VRF proof (784 bytes: 32-byte output + 752-byte ring proof)
    let proof = secrets
        .bandersnatch
        .ring_vrf_sign(ring_keys, key_index, &vrf_input, &[])?;

    Some(TicketProof { attempt, proof })
}

/// Derive a ticket ID from a ticket proof by hashing the proof data.
///
/// In the full protocol, the ticket ID is the VRF output hash.
/// For our simplified version, we hash the proof to get a deterministic ID.
fn derive_ticket_id(proof: &TicketProof, _state: &State) -> Hash {
    grey_crypto::blake2b_256(&proof.proof)
}

/// Encode a ticket proof for gossipsub transmission.
/// Format: `[attempt(1)][proof_len(2)][proof(N)]`
pub fn encode_ticket_proof(proof: &TicketProof) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 2 + proof.proof.len());
    buf.push(proof.attempt);
    let len = proof.proof.len() as u16;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&proof.proof);
    buf
}

/// Decode a ticket proof from gossipsub bytes.
pub fn decode_ticket_proof(data: &[u8]) -> Option<TicketProof> {
    if data.len() < 3 {
        return None;
    }
    let attempt = data[0];
    let len = u16::from_le_bytes([data[1], data[2]]) as usize;
    if data.len() < 3 + len {
        return None;
    }
    Some(TicketProof {
        attempt,
        proof: data[3..3 + len].to_vec(),
    })
}

/// Check if the current slot is within the ticket submission window.
pub fn is_ticket_submission_window(timeslot: Timeslot, config: &Config) -> bool {
    let slot_in_epoch = timeslot % config.epoch_length;
    slot_in_epoch < config.ticket_submission_end()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ticket_state_lifecycle() {
        let mut state = TicketState::new();
        let config = Config::tiny();

        // Initially no tickets generated
        assert!(!state.generated_this_epoch);
        assert!(state.pending_tickets.is_empty());

        // Epoch change resets state
        state.generated_this_epoch = true;
        state.current_epoch = 0;
        state.check_epoch(config.epoch_length, &config); // epoch 1
        assert!(!state.generated_this_epoch);
        assert_eq!(state.current_epoch, 1);
    }

    #[test]
    fn test_ticket_generation() {
        let config = Config::tiny();
        let (chain_state, secrets) = grey_consensus::genesis::create_genesis(&config);

        let mut ticket_state = TicketState::new();
        let tickets = ticket_state.generate_tickets(&config, &chain_state, &secrets[0], 0);

        // Should generate TICKET_ATTEMPTS tickets
        assert_eq!(tickets.len(), TICKET_ATTEMPTS as usize);
        assert!(ticket_state.generated_this_epoch);

        // Verify proof is 784 bytes (Ring VRF)
        for t in &tickets {
            assert_eq!(t.proof.len(), 784, "Ring VRF proof must be 784 bytes");
        }

        // Second call should return empty (already generated)
        let tickets2 = ticket_state.generate_tickets(&config, &chain_state, &secrets[0], 0);
        assert!(tickets2.is_empty());
    }

    #[test]
    fn test_ticket_encode_decode() {
        let proof = TicketProof {
            attempt: 1,
            proof: vec![42u8; 96],
        };

        let encoded = encode_ticket_proof(&proof);
        let decoded = decode_ticket_proof(&encoded).expect("decode should succeed");

        assert_eq!(decoded.attempt, proof.attempt);
        assert_eq!(decoded.proof, proof.proof);
    }

    #[test]
    fn test_ticket_deduplication() {
        let config = Config::tiny();
        let (chain_state, _secrets) = grey_consensus::genesis::create_genesis(&config);

        let mut ticket_state = TicketState::new();
        let proof = TicketProof {
            attempt: 0,
            proof: vec![1u8; 96],
        };

        // First add should succeed
        assert!(ticket_state.add_ticket(proof.clone(), &config, &chain_state));
        // Duplicate should be rejected
        assert!(!ticket_state.add_ticket(proof, &config, &chain_state));
        assert_eq!(ticket_state.pending_tickets.len(), 1);
    }

    #[test]
    fn test_submission_window() {
        let config = Config::tiny();
        let y = config.ticket_submission_end();

        // Slot 0 is within window
        assert!(is_ticket_submission_window(0, &config));
        // Slot y-1 is within window
        assert!(is_ticket_submission_window(y - 1, &config));
        // Slot y is outside window
        assert!(!is_ticket_submission_window(y, &config));
        // Slot E-1 is outside window
        assert!(!is_ticket_submission_window(
            config.epoch_length - 1,
            &config
        ));
    }

    #[test]
    fn test_take_tickets_for_block() {
        let config = Config::tiny();
        let (chain_state, _) = grey_consensus::genesis::create_genesis(&config);

        let mut ticket_state = TicketState::new();

        // Add several tickets
        for i in 0..5u8 {
            let proof = TicketProof {
                attempt: i % 2,
                proof: vec![i; 96],
            };
            ticket_state.add_ticket(proof, &config, &chain_state);
        }

        let taken = ticket_state.take_tickets_for_block(&config);
        // Should take up to K tickets
        assert!(!taken.is_empty());
        assert!(taken.len() <= config.max_tickets_per_block as usize);
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn decode_ticket_proof_never_panics(data in prop::collection::vec(any::<u8>(), 0..1024)) {
                let _ = decode_ticket_proof(&data);
            }
        }
    }
}
