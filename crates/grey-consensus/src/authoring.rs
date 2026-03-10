//! Block authoring logic for JAM validators.
//!
//! Given the current state and validator secrets, determines whether the
//! validator is the slot author and constructs a valid block.

use grey_codec::header_codec::{compute_header_hash, encode_header_unsigned};
use grey_types::config::Config;
use grey_types::header::*;
use grey_types::state::{SealKeySeries, State};
use grey_types::{BandersnatchPublicKey, BandersnatchSignature, Hash, Timeslot};

use crate::genesis::ValidatorSecrets;

/// Entropy VRF context string (Appendix I.4.5: X_E = $jam_entropy).
const ENTROPY_CONTEXT: &[u8] = b"jam_entropy";

/// Fallback seal context string (Appendix I.4.5: X_F = $jam_fallback_seal).
const FALLBACK_SEAL_CONTEXT: &[u8] = b"jam_fallback_seal";

/// Check if a validator is the block author for a given timeslot.
///
/// Returns the author's index in the validator set if they should author,
/// or None if they are not the slot leader.
pub fn is_slot_author(
    state: &State,
    config: &Config,
    timeslot: Timeslot,
    bandersnatch_pubkey: &BandersnatchPublicKey,
) -> Option<u16> {
    let slot_in_epoch = timeslot % config.epoch_length;

    match &state.safrole.seal_key_series {
        SealKeySeries::Fallback(keys) => {
            if (slot_in_epoch as usize) < keys.len() {
                let seal_key = &keys[slot_in_epoch as usize];
                if seal_key == bandersnatch_pubkey {
                    // Find the validator index
                    for (i, v) in state.current_validators.iter().enumerate() {
                        if &v.bandersnatch == bandersnatch_pubkey {
                            return Some(i as u16);
                        }
                    }
                }
            }
            None
        }
        SealKeySeries::Tickets(tickets) => {
            if (slot_in_epoch as usize) < tickets.len() {
                let _ticket = &tickets[slot_in_epoch as usize];
                // In ticket mode, the ticket holder is the author.
                // For now, fallback to checking validator index from ticket.
                // Ticket-based authoring requires Ring VRF proof of ownership.
                // For the test network, this is not implemented.
                None
            } else {
                None
            }
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
    // Parent hash: from the most recent block in history, or Hash::ZERO for the first block
    let parent_hash = state
        .recent_blocks
        .headers
        .last()
        .map(|h| h.header_hash)
        .unwrap_or(Hash::ZERO);

    // VRF signature for entropy (HV)
    let vrf_input = build_entropy_vrf_input(timeslot);
    let vrf_sig_bytes = secrets.bandersnatch.vrf_sign(&vrf_input, b"");
    let vrf_signature = BandersnatchSignature(vrf_sig_bytes);

    // Build epoch marker if crossing epoch boundary
    let old_epoch = state.timeslot / config.epoch_length;
    let new_epoch = timeslot / config.epoch_length;
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
    let old_slot = state.timeslot % config.epoch_length;
    let new_slot = timeslot % config.epoch_length;
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

    // Compute extrinsic hash (empty extrinsics = hash of empty encoding)
    let extrinsic = Extrinsic {
        tickets: vec![],
        preimages: vec![],
        guarantees: vec![],
        assurances: vec![],
        disputes: DisputesExtrinsic::default(),
    };
    let extrinsic_hash = compute_extrinsic_hash(&extrinsic);

    // Build unsigned header
    let mut header = Header {
        parent_hash,
        state_root,
        extrinsic_hash,
        timeslot,
        epoch_marker,
        tickets_marker,
        author_index,
        vrf_signature,
        offenders_marker: vec![],
        seal: BandersnatchSignature([0u8; 96]), // placeholder
    };

    // Compute seal: sign the unsigned header hash
    let unsigned_hash = compute_unsigned_header_hash_bytes(&header);
    let seal_input = build_seal_vrf_input(timeslot, &unsigned_hash);
    let seal_bytes = secrets.bandersnatch.seal_sign(&seal_input, b"");
    header.seal = BandersnatchSignature(seal_bytes);

    Block { header, extrinsic }
}

/// Build VRF input for entropy contribution: X_E ++ E4(timeslot).
fn build_entropy_vrf_input(timeslot: Timeslot) -> Vec<u8> {
    let mut input = Vec::with_capacity(ENTROPY_CONTEXT.len() + 4);
    input.extend_from_slice(ENTROPY_CONTEXT);
    input.extend_from_slice(&timeslot.to_le_bytes());
    input
}

/// Build VRF input for fallback seal: X_F ++ unsigned_header_hash.
fn build_seal_vrf_input(timeslot: Timeslot, unsigned_header_hash: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(FALLBACK_SEAL_CONTEXT.len() + 4 + unsigned_header_hash.len());
    input.extend_from_slice(FALLBACK_SEAL_CONTEXT);
    input.extend_from_slice(&timeslot.to_le_bytes());
    input.extend_from_slice(unsigned_header_hash);
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
    // Encode the extrinsic components and hash
    let mut data = Vec::new();

    // Tickets: compact length + items
    grey_codec::encode::encode_compact(extrinsic.tickets.len() as u64, &mut data);
    // Preimages
    grey_codec::encode::encode_compact(extrinsic.preimages.len() as u64, &mut data);
    // Guarantees
    grey_codec::encode::encode_compact(extrinsic.guarantees.len() as u64, &mut data);
    // Assurances
    grey_codec::encode::encode_compact(extrinsic.assurances.len() as u64, &mut data);
    // Disputes: verdicts, culprits, faults all empty
    grey_codec::encode::encode_compact(extrinsic.disputes.verdicts.len() as u64, &mut data);
    grey_codec::encode::encode_compact(extrinsic.disputes.culprits.len() as u64, &mut data);
    grey_codec::encode::encode_compact(extrinsic.disputes.faults.len() as u64, &mut data);

    grey_crypto::blake2b_256(&data)
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
                let block = author_block(
                    &state,
                    &config,
                    timeslot,
                    author_idx,
                    s,
                    Hash::ZERO,
                );
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
                let block = author_block(
                    &state,
                    &config,
                    timeslot,
                    author_idx,
                    s,
                    Hash::ZERO,
                );

                // Apply block to state
                let result = grey_state::transition::apply_with_config(
                    &state,
                    &block,
                    &config,
                    &[],
                );
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
}
