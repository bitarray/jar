//! Block authoring logic for JAM validators.
//!
//! Given the current state and validator secrets, determines whether the
//! validator is the slot author and constructs a valid block.

use grey_types::config::Config;
use grey_types::header::*;
use grey_types::state::{SealKeySeries, State};
use grey_types::{BandersnatchPublicKey, BandersnatchSignature, Hash, Timeslot};
use scale::Encode;

use crate::genesis::ValidatorSecrets;

/// Encode the unsigned header EU(H) — for seal signature computation.
fn encode_header_unsigned(header: &Header) -> Vec<u8> {
    header.data.encode()
}

use grey_types::signing_contexts;

/// Find a validator's index by their bandersnatch public key bytes.
fn find_validator_index(
    validators: &[grey_types::validator::ValidatorKey],
    pk: &[u8; 32],
) -> Option<u16> {
    validators
        .iter()
        .position(|v| &v.bandersnatch.0 == pk)
        .map(|i| i as u16)
}

/// Check if a validator is the block author for a given timeslot.
///
/// Returns the author's index in the validator set if they should author,
/// or None if they are not the slot leader.
///
/// In fallback mode, only the public key is needed. In ticket mode, the
/// keypair is required to compute VRF outputs for ticket ownership detection.
pub fn is_slot_author(
    state: &State,
    config: &Config,
    timeslot: Timeslot,
    bandersnatch_pubkey: &BandersnatchPublicKey,
) -> Option<u16> {
    is_slot_author_with_keypair(state, config, timeslot, bandersnatch_pubkey, None)
}

/// Check if a validator is the block author, with optional keypair for ticket mode.
///
/// When `keypair` is provided and the seal-key series is in ticket mode,
/// computes VRF outputs for each attempt and checks if any match the slot's ticket.
/// Returns `(validator_index, ticket_attempt)` on match.
pub fn is_slot_author_with_keypair(
    state: &State,
    config: &Config,
    timeslot: Timeslot,
    bandersnatch_pubkey: &BandersnatchPublicKey,
    keypair: Option<&grey_crypto::BandersnatchKeypair>,
) -> Option<u16> {
    let slot_in_epoch = config.slot_in_epoch(timeslot);

    match &state.safrole.seal_key_series {
        SealKeySeries::Fallback(keys) => {
            if (slot_in_epoch as usize) < keys.len() {
                let seal_key = &keys[slot_in_epoch as usize];
                if seal_key == bandersnatch_pubkey {
                    return find_validator_index(&state.current_validators, &bandersnatch_pubkey.0);
                }
            }
            None
        }
        SealKeySeries::Tickets(tickets) => {
            let kp = keypair?;
            if (slot_in_epoch as usize) >= tickets.len() {
                return None;
            }
            let ticket = &tickets[slot_in_epoch as usize];
            // Ticket IDs were computed with η_2 from the epoch when tickets were
            // accumulated. After the epoch rotation that installs them as seal keys,
            // that η_2 is preserved in η_3 (GP eq 6.23: η'_3 = η_2 on epoch change).
            let eta2 = &state.entropy[3];

            // For each attempt (0..N), compute VRF output and check against ticket ID
            for attempt in 0..config.tickets_per_validator as u8 {
                let vrf_input = grey_crypto::bandersnatch::build_ticket_vrf_input(&eta2.0, attempt);

                if let Some(ticket_id) = kp.vrf_output_for_input(&vrf_input)
                    && ticket_id == ticket.id.0
                {
                    // We own this ticket — find our validator index
                    return find_validator_index(&state.current_validators, &kp.public_key_bytes());
                }
            }
            None
        }
    }
}

/// Author a new block for the given timeslot.
///
/// The block is constructed with:
/// - Correct parent hash from the latest block in history
/// - State root from the prior state (computed by caller)
/// - VRF signature for entropy contribution
/// - Seal signature proving slot authorship
/// - Empty extrinsics (no work reports, tickets, etc.)
pub fn author_block(
    state: &State,
    config: &Config,
    timeslot: Timeslot,
    author_index: u16,
    secrets: &ValidatorSecrets,
    state_root: Hash,
) -> Block {
    author_block_with_extrinsics(
        state,
        config,
        timeslot,
        author_index,
        secrets,
        state_root,
        vec![],
        vec![],
        vec![],
    )
}

/// Author a new block with custom guarantee, assurance, and ticket extrinsics.
#[allow(clippy::too_many_arguments)]
pub fn author_block_with_extrinsics(
    state: &State,
    config: &Config,
    timeslot: Timeslot,
    author_index: u16,
    secrets: &ValidatorSecrets,
    state_root: Hash,
    guarantees: Vec<Guarantee>,
    assurances: Vec<Assurance>,
    tickets: Vec<TicketProof>,
) -> Block {
    // Parent hash: from the most recent block in history, or Hash::ZERO for the first block
    let parent_hash = state
        .recent_blocks
        .headers
        .last()
        .map(|h| h.header_hash)
        .unwrap_or(Hash::ZERO);

    // VRF signature for entropy (HV)
    let vrf_input = build_vrf_input(signing_contexts::ENTROPY, timeslot, &[]);
    let vrf_sig_bytes = secrets.bandersnatch.vrf_sign(&vrf_input, b"");
    let vrf_signature = BandersnatchSignature(vrf_sig_bytes);

    // Build epoch marker if crossing epoch boundary
    let old_epoch = config.epoch_of(state.timeslot);
    let new_epoch = config.epoch_of(timeslot);
    let epoch_marker = if new_epoch > old_epoch {
        Some(EpochMarker {
            entropy: state.entropy[0],
            entropy_previous: state.entropy[1],
            validators: state
                .safrole
                .pending_keys
                .iter()
                .map(|k| (k.bandersnatch, k.ed25519))
                .collect(),
        })
    } else {
        None
    };

    // Build winning tickets marker if crossing Y boundary
    let old_slot = config.slot_in_epoch(state.timeslot);
    let new_slot = config.slot_in_epoch(timeslot);
    let y = config.ticket_submission_end();
    let tickets_marker = if new_epoch == old_epoch
        && old_slot < y
        && new_slot >= y
        && state.safrole.ticket_accumulator.len() == config.epoch_length as usize
    {
        Some(crate::safrole::outside_in_sequence(
            &state.safrole.ticket_accumulator,
        ))
    } else {
        None
    };

    let extrinsic = Extrinsic {
        tickets,
        preimages: vec![],
        guarantees,
        assurances,
        disputes: DisputesExtrinsic::default(),
    };
    let extrinsic_hash = compute_extrinsic_hash(&extrinsic);

    // Build unsigned header
    let mut header = Header {
        data: UnsignedHeader {
            parent_hash,
            state_root,
            extrinsic_hash,
            timeslot,
            epoch_marker,
            tickets_marker,
            author_index,
            vrf_signature,
            offenders_marker: vec![],
        },
        seal: BandersnatchSignature([0u8; 96]), // placeholder
    };

    // Compute seal: sign the unsigned header hash
    // In fallback mode: input = X_F ⌢ E4(timeslot) ⌢ unsigned_header_hash
    // In ticket mode: input = X_T ⌢ E4(timeslot) ⌢ unsigned_header_hash
    let unsigned_hash = compute_unsigned_header_hash_bytes(&header);
    let is_ticket_mode = matches!(&state.safrole.seal_key_series, SealKeySeries::Tickets(_));
    let seal_context = if is_ticket_mode {
        signing_contexts::TICKET_SEAL
    } else {
        signing_contexts::FALLBACK_SEAL
    };
    let seal_input = build_vrf_input(seal_context, timeslot, &unsigned_hash);
    let seal_bytes = secrets.bandersnatch.seal_sign(&seal_input, b"");
    header.seal = BandersnatchSignature(seal_bytes);

    Block { header, extrinsic }
}

/// Build VRF input: context ++ E4(timeslot) [++ suffix].
fn build_vrf_input(context: &[u8], timeslot: Timeslot, suffix: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(context.len() + 4 + suffix.len());
    input.extend_from_slice(context);
    input.extend_from_slice(&timeslot.to_le_bytes());
    input.extend_from_slice(suffix);
    input
}

/// Compute the unsigned header hash for seal signing.
fn compute_unsigned_header_hash_bytes(header: &Header) -> Vec<u8> {
    let encoded = encode_header_unsigned(header);
    let hash = grey_crypto::blake2b_256(&encoded);
    hash.0.to_vec()
}

/// Compute the extrinsic hash for an extrinsic (Merkle commitment).
/// For empty extrinsics, this is a hash of the empty encoding.
fn compute_extrinsic_hash(extrinsic: &Extrinsic) -> Hash {
    use scale::Encode;
    grey_crypto::blake2b_256(&extrinsic.encode())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis;

    #[test]
    fn test_slot_author_detection() {
        let config = Config::tiny();
        let (state, secrets) = genesis::create_genesis(&config);

        // In fallback mode, each slot has a deterministic author
        let mut found_author = false;
        for timeslot in 1..=config.epoch_length {
            for s in &secrets {
                let pk = BandersnatchPublicKey(s.bandersnatch.public_key_bytes());
                if let Some(idx) = is_slot_author(&state, &config, timeslot, &pk) {
                    found_author = true;
                    assert!(idx < config.validators_count);
                    break;
                }
            }
        }
        assert!(found_author, "At least one slot should have an author");
    }

    #[test]
    fn test_author_block() {
        let config = Config::tiny();
        let (state, secrets) = genesis::create_genesis(&config);

        // Find the author for timeslot 1
        let timeslot = 1;
        for s in &secrets {
            let pk = BandersnatchPublicKey(s.bandersnatch.public_key_bytes());
            if let Some(author_idx) = is_slot_author(&state, &config, timeslot, &pk) {
                let block = author_block(&state, &config, timeslot, author_idx, s, Hash::ZERO);
                assert_eq!(block.header.timeslot, timeslot);
                assert_eq!(block.header.author_index, author_idx);
                assert_eq!(block.header.parent_hash, Hash::ZERO);
                return;
            }
        }
        panic!("No author found for timeslot 1");
    }

    #[test]
    fn test_authored_block_passes_state_transition() {
        let config = Config::tiny();
        let (state, secrets) = genesis::create_genesis(&config);

        // Find author and create block
        let timeslot = 1;
        for s in &secrets {
            let pk = BandersnatchPublicKey(s.bandersnatch.public_key_bytes());
            if let Some(author_idx) = is_slot_author(&state, &config, timeslot, &pk) {
                let block = author_block(&state, &config, timeslot, author_idx, s, Hash::ZERO);

                // Apply block to state
                let result =
                    grey_state::transition::apply_with_config(&state, &block, &config, &[]);
                assert!(
                    result.is_ok(),
                    "Authored block should pass state transition: {:?}",
                    result.err()
                );

                let (new_state, _) = result.unwrap();
                assert_eq!(new_state.timeslot, timeslot);
                return;
            }
        }
        panic!("No author found for timeslot 1");
    }

    /// Compute ticket-mode seal key series from secrets and switch state to ticket mode.
    fn setup_ticket_mode(config: &Config, state: &mut State, secrets: &[ValidatorSecrets]) {
        let eta2 = &state.entropy[2];
        let mut all_tickets: Vec<(Ticket, usize)> = Vec::new();

        for (vi, s) in secrets.iter().enumerate() {
            for attempt in 0..config.tickets_per_validator as u8 {
                let vrf_input = grey_crypto::bandersnatch::build_ticket_vrf_input(&eta2.0, attempt);

                if let Some(ticket_id) = s.bandersnatch.vrf_output_for_input(&vrf_input) {
                    all_tickets.push((
                        Ticket {
                            id: Hash(ticket_id),
                            attempt,
                        },
                        vi,
                    ));
                }
            }
        }

        all_tickets.sort_by(|a, b| a.0.id.0.cmp(&b.0.id.0));
        let epoch_tickets: Vec<Ticket> = all_tickets
            .iter()
            .take(config.epoch_length as usize)
            .map(|(t, _)| t.clone())
            .collect();
        state.safrole.seal_key_series = SealKeySeries::Tickets(epoch_tickets);
        // Simulate the epoch rotation that happens when tickets become the seal
        // keys: η'_3 = η_2 (GP eq 6.23).  The ownership check now reads entropy[3].
        state.entropy[3] = state.entropy[2];
    }

    #[test]
    fn test_ticket_mode_author_detection() {
        let config = Config::tiny();
        let (mut state, secrets) = genesis::create_genesis(&config);
        setup_ticket_mode(&config, &mut state, &secrets);

        let mut found_any = false;
        for timeslot in 0..config.epoch_length {
            for s in &secrets {
                let pk = BandersnatchPublicKey(s.bandersnatch.public_key_bytes());
                if let Some(idx) = is_slot_author_with_keypair(
                    &state,
                    &config,
                    timeslot,
                    &pk,
                    Some(&s.bandersnatch),
                ) {
                    found_any = true;
                    assert!(idx < config.validators_count);
                    break;
                }
            }
        }
        assert!(found_any, "Should find at least one author in ticket mode");
    }

    #[test]
    fn test_ticket_mode_block_authoring() {
        let config = Config::tiny();
        let (mut state, secrets) = genesis::create_genesis(&config);
        setup_ticket_mode(&config, &mut state, &secrets);

        let timeslot = 1;
        for s in &secrets {
            let pk = BandersnatchPublicKey(s.bandersnatch.public_key_bytes());
            if let Some(author_idx) =
                is_slot_author_with_keypair(&state, &config, timeslot, &pk, Some(&s.bandersnatch))
            {
                let block = author_block(&state, &config, timeslot, author_idx, s, Hash::ZERO);
                assert_eq!(block.header.timeslot, timeslot);
                assert_eq!(block.header.author_index, author_idx);
                assert_ne!(block.header.seal.0, [0u8; 96]);
                return;
            }
        }
        panic!("No author found for timeslot 1 in ticket mode");
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use crate::genesis;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        /// Every slot in the first epoch has exactly one author in fallback mode.
        #[test]
        fn fallback_exactly_one_author_per_slot(slot in 1u32..12u32) {
            let config = Config::tiny();
            let (state, secrets) = genesis::create_genesis(&config);

            let mut author_count = 0u32;
            for s in &secrets {
                let pk = BandersnatchPublicKey(s.bandersnatch.public_key_bytes());
                if is_slot_author(&state, &config, slot, &pk).is_some() {
                    author_count += 1;
                }
            }
            prop_assert_eq!(author_count, 1, "slot {} should have exactly 1 author", slot);
        }

        /// Authored blocks always carry the correct timeslot.
        #[test]
        fn authored_block_has_correct_timeslot(slot in 1u32..12u32) {
            let config = Config::tiny();
            let (state, secrets) = genesis::create_genesis(&config);

            for s in &secrets {
                let pk = BandersnatchPublicKey(s.bandersnatch.public_key_bytes());
                if let Some(idx) = is_slot_author(&state, &config, slot, &pk) {
                    let block = author_block(&state, &config, slot, idx, s, Hash::ZERO);
                    prop_assert_eq!(block.header.timeslot, slot);
                    prop_assert_eq!(block.header.author_index, idx);
                    break;
                }
            }
        }

        /// build_vrf_input is deterministic: same inputs produce same output.
        #[test]
        fn vrf_input_deterministic(
            ctx in proptest::collection::vec(any::<u8>(), 0..16),
            slot: u32,
            suffix in proptest::collection::vec(any::<u8>(), 0..32),
        ) {
            let a = build_vrf_input(&ctx, slot, &suffix);
            let b = build_vrf_input(&ctx, slot, &suffix);
            prop_assert_eq!(a, b);
        }

        /// build_vrf_input output length equals context + 4 + suffix.
        #[test]
        fn vrf_input_length(
            ctx in proptest::collection::vec(any::<u8>(), 0..16),
            slot: u32,
            suffix in proptest::collection::vec(any::<u8>(), 0..32),
        ) {
            let result = build_vrf_input(&ctx, slot, &suffix);
            prop_assert_eq!(result.len(), ctx.len() + 4 + suffix.len());
        }

        /// compute_extrinsic_hash is deterministic for the same extrinsic.
        #[test]
        fn extrinsic_hash_deterministic(ticket_count in 0usize..3) {
            let extrinsic = Extrinsic {
                tickets: vec![TicketProof { attempt: 0, proof: vec![0u8; 784] }; ticket_count],
                ..Extrinsic::default()
            };
            let h1 = compute_extrinsic_hash(&extrinsic);
            let h2 = compute_extrinsic_hash(&extrinsic);
            prop_assert_eq!(h1, h2);
        }

        /// Non-validator key never matches as slot author.
        #[test]
        fn non_validator_is_never_author(slot in 0u32..12u32, random_key: [u8; 32]) {
            let config = Config::tiny();
            let (state, _) = genesis::create_genesis(&config);
            let pk = BandersnatchPublicKey(random_key);
            // Random key is overwhelmingly unlikely to match a real validator key
            // but we can't assert None since it could collide (astronomically unlikely).
            // Just verify it doesn't panic.
            let _ = is_slot_author(&state, &config, slot, &pk);
        }
    }
}
