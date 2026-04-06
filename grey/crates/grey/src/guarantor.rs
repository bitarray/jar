//! Guarantor service: process work packages into work reports and guarantees.
//!
//! Responsible for:
//! 1. Receiving work packages from the RPC layer
//! 2. Running the refine pipeline (Ψ_I + Ψ_R)
//! 3. Erasure-coding the work package bundle
//! 4. Storing chunks locally and distributing to peers
//! 5. Signing and broadcasting guarantees
//! 6. Generating availability assurances for chunks we hold

use grey_consensus::genesis::ValidatorSecrets;
use grey_erasure::ErasureParams;
use grey_state::refine::{self, RefineContext};
use grey_store::Store;
use grey_types::config::Config;
use grey_types::header::{Assurance, Guarantee};
use grey_types::state::State;
use grey_types::work::{WorkPackage, WorkReport};
use grey_types::{Ed25519Signature, Hash, signing_contexts};
use scale::Encode;
use std::collections::{BTreeMap, HashSet};

/// Sign a guarantee message: X_G ⌢ report_hash.
///
/// Constructs the signing payload per GP Section 11 and signs with Ed25519.
pub fn sign_guarantee(report_hash: &Hash, secrets: &ValidatorSecrets) -> Ed25519Signature {
    let message = signing_contexts::build_guarantee_message(&report_hash.0);
    secrets.ed25519.sign(&message)
}

/// Tracks pending guarantees and chunks for availability.
#[derive(Default)]
pub struct GuarantorState {
    /// Guarantees we've produced, pending inclusion in a block.
    pub pending_guarantees: Vec<Guarantee>,
    /// Cores for which we hold all chunks (for assurance generation).
    /// Maps core_index → report_hash.
    pub available_cores: BTreeMap<u16, Hash>,
    /// Chunks we've received from peers. Maps report_hash → set of chunk indices.
    pub received_chunks: BTreeMap<Hash, HashSet<u16>>,
}

impl GuarantorState {
    /// Creates a new, empty `GuarantorState`.
    pub fn new() -> Self {
        Self {
            pending_guarantees: Vec::new(),
            available_cores: BTreeMap::new(),
            received_chunks: BTreeMap::new(),
        }
    }

    /// Take all pending guarantees for block inclusion, clearing the buffer.
    pub fn take_guarantees(&mut self) -> Vec<Guarantee> {
        std::mem::take(&mut self.pending_guarantees)
    }

    /// Return a guarantee that couldn't be included (e.g., core occupied).
    pub fn return_guarantee(&mut self, guarantee: Guarantee) {
        self.pending_guarantees.push(guarantee);
    }

    /// Generate an assurance bitfield for cores where we hold chunks.
    pub fn generate_assurance(
        &self,
        config: &Config,
        parent_hash: &Hash,
        validator_index: u16,
        secrets: &ValidatorSecrets,
        state: &State,
    ) -> Option<Assurance> {
        if self.available_cores.is_empty() {
            return None;
        }

        let core_count = config.core_count as usize;
        let bitfield_bytes = core_count.div_ceil(8);
        let mut bitfield = vec![0u8; bitfield_bytes];

        // Set bits for cores with pending reports that we hold chunks for
        let mut any_set = false;
        for &core_idx in self.available_cores.keys() {
            let idx = core_idx as usize;
            if idx < core_count {
                // Only set bit if there's actually a pending report on this core
                if let Some(Some(_)) = state.pending_reports.get(idx) {
                    bitfield[idx / 8] |= 1 << (idx % 8);
                    any_set = true;
                }
            }
        }

        if !any_set {
            return None;
        }

        // Sign: X_A ⌢ H(E(parent_hash, bitfield))
        let mut payload = Vec::new();
        payload.extend_from_slice(&parent_hash.0);
        payload.extend_from_slice(&bitfield);
        let payload_hash = grey_crypto::blake2b_256(&payload);

        let mut message = Vec::with_capacity(13 + 32);
        message.extend_from_slice(signing_contexts::AVAILABLE);
        message.extend_from_slice(&payload_hash.0);

        let signature = secrets.ed25519.sign(&message);

        Some(Assurance {
            anchor: *parent_hash,
            bitfield,
            validator_index,
            signature,
        })
    }
}

/// Process a work package: refine, erasure-code, store chunks, create guarantee.
#[allow(clippy::too_many_arguments)]
pub fn process_work_package(
    config: &Config,
    package: &WorkPackage,
    state: &State,
    store: &Store,
    validator_index: u16,
    secrets: &ValidatorSecrets,
    timeslot: u32,
    guarantor_state: &mut GuarantorState,
) -> Result<Hash, String> {
    // Build a refine context from the current state
    let ctx = StateRefineContext { state };

    // Determine core index for this work package
    // For now, use core 0 (proper core assignment needs guarantor rotation logic)
    let core_index = determine_core(config, state, package);

    // 1. Run the refine pipeline
    let mut report = refine::process_work_package(config, package, &ctx, core_index)
        .map_err(|e| format!("refine failed: {}", e))?;

    // 2. Erasure-code the work package bundle
    let erasure_params = erasure_params_for_config(config);
    let bundle = encode_work_package_bundle(package);
    let bundle_len = bundle.len();

    let chunks = grey_erasure::encode(&erasure_params, &bundle)
        .map_err(|e| format!("erasure encoding failed: {}", e))?;

    // 3. Compute erasure root from chunks and update the report
    let erasure_root = compute_erasure_root(&chunks);
    report.package_spec.erasure_root = erasure_root;

    // 4. Store all chunks locally
    let encoded_report = report.encode();
    let report_hash = grey_crypto::blake2b_256(&encoded_report);

    for (i, chunk) in chunks.iter().enumerate() {
        if let Err(e) = store.put_chunk(&report_hash, i as u16, chunk) {
            tracing::warn!("Failed to store chunk {}: {}", i, e);
        }
    }

    // Track that we have all chunks for this core
    let mut chunk_indices = HashSet::new();
    for i in 0..chunks.len() {
        chunk_indices.insert(i as u16);
    }
    guarantor_state
        .received_chunks
        .insert(report_hash, chunk_indices);
    guarantor_state
        .available_cores
        .insert(core_index, report_hash);

    tracing::info!(
        "Erasure-coded work package: {} chunks of {} bytes each, bundle_len={}, report_hash=0x{}",
        chunks.len(),
        chunks.first().map(|c| c.len()).unwrap_or(0),
        bundle_len,
        hex::encode(&report_hash.0[..8])
    );

    // 5. Sign the guarantee
    let signature = sign_guarantee(&report_hash, secrets);

    let guarantee = Guarantee {
        report,
        timeslot,
        credentials: vec![(validator_index, signature)],
    };

    guarantor_state.pending_guarantees.push(guarantee);

    tracing::info!(
        "Validator {} created guarantee for core {}, report_hash=0x{}",
        validator_index,
        core_index,
        hex::encode(&report_hash.0[..8])
    );

    Ok(report_hash)
}

/// Encode a guarantee for network transmission.
/// Format: `[report_hash (32)][timeslot (4)][credential_count (2)][credentials...]`
pub fn encode_guarantee(guarantee: &Guarantee) -> Vec<u8> {
    let encoded_report = guarantee.report.encode();
    let report_hash = grey_crypto::blake2b_256(&encoded_report);

    let mut buf = Vec::new();
    buf.extend_from_slice(&report_hash.0);
    buf.extend_from_slice(&guarantee.timeslot.to_le_bytes());
    buf.extend_from_slice(&(guarantee.credentials.len() as u16).to_le_bytes());
    for (idx, sig) in &guarantee.credentials {
        buf.extend_from_slice(&idx.to_le_bytes());
        buf.extend_from_slice(&sig.0);
    }
    // Append the full encoded report
    buf.extend_from_slice(&(encoded_report.len() as u32).to_le_bytes());
    buf.extend_from_slice(&encoded_report);
    buf
}

/// Encode an assurance for network transmission.
/// Format: [anchor (32)][bitfield_len (2)][bitfield][validator_index (2)][signature (64)]
pub fn encode_assurance(assurance: &Assurance) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&assurance.anchor.0);
    buf.extend_from_slice(&(assurance.bitfield.len() as u16).to_le_bytes());
    buf.extend_from_slice(&assurance.bitfield);
    buf.extend_from_slice(&assurance.validator_index.to_le_bytes());
    buf.extend_from_slice(&assurance.signature.0);
    buf
}

/// Decode an assurance from network bytes.
pub fn decode_assurance(data: &[u8]) -> Option<Assurance> {
    if data.len() < 32 + 2 {
        return None;
    }
    let mut anchor = [0u8; 32];
    anchor.copy_from_slice(&data[..32]);
    let bf_len = u16::from_le_bytes([data[32], data[33]]) as usize;
    if data.len() < 34 + bf_len + 2 + 64 {
        return None;
    }
    let bitfield = data[34..34 + bf_len].to_vec();
    let pos = 34 + bf_len;
    let validator_index = u16::from_le_bytes([data[pos], data[pos + 1]]);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&data[pos + 2..pos + 66]);

    Some(Assurance {
        anchor: Hash(anchor),
        bitfield,
        validator_index,
        signature: Ed25519Signature(sig),
    })
}

/// Handle a received guarantee from the network.
/// Decode and store the guarantee for block inclusion.
pub fn handle_received_guarantee(
    data: &[u8],
    guarantor_state: &mut GuarantorState,
    _store: &Store,
) {
    // Decode: [report_hash(32)][timeslot(4)][cred_count(2)][creds...][report_len(4)][report...]
    if data.len() < 32 + 4 + 2 {
        tracing::warn!("Received guarantee too short");
        return;
    }

    let mut pos = 0;
    let mut report_hash = [0u8; 32];
    report_hash.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;
    let timeslot = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    pos += 4;
    let cred_count = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    let mut credentials = Vec::with_capacity(cred_count);
    for _ in 0..cred_count {
        if pos + 2 + 64 > data.len() {
            tracing::warn!("Received guarantee: truncated credentials");
            return;
        }
        let idx = u16::from_le_bytes([data[pos], data[pos + 1]]);
        pos += 2;
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&data[pos..pos + 64]);
        pos += 64;
        credentials.push((idx, Ed25519Signature(sig)));
    }

    // Decode the work report
    if pos + 4 > data.len() {
        tracing::warn!("Received guarantee: missing report length");
        return;
    }
    let report_len =
        u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
    pos += 4;
    if pos + report_len > data.len() {
        tracing::warn!("Received guarantee: truncated report data");
        return;
    }
    let report_data = &data[pos..pos + report_len];

    use scale::Decode;
    let report = match WorkReport::decode(report_data) {
        Ok((r, _)) => r,
        Err(e) => {
            tracing::warn!("Received guarantee: failed to decode report: {}", e);
            return;
        }
    };

    // Skip if we already have a pending guarantee for this report
    let encoded = report.encode();
    let computed_hash = grey_crypto::blake2b_256(&encoded);
    if computed_hash.0 != report_hash {
        tracing::warn!(
            "Received guarantee: report hash mismatch (computed=0x{} vs claimed=0x{})",
            hex::encode(&computed_hash.0[..8]),
            hex::encode(&report_hash[..8])
        );
        return;
    }

    // Check for duplicate
    for g in &guarantor_state.pending_guarantees {
        let g_encoded = g.report.encode();
        let g_hash = grey_crypto::blake2b_256(&g_encoded);
        if g_hash == computed_hash {
            return; // Already have this guarantee
        }
    }

    tracing::info!(
        "Received guarantee: report_hash=0x{}, timeslot={}, creds={}, core={}",
        hex::encode(&report_hash[..8]),
        timeslot,
        credentials.len(),
        report.core_index,
    );

    // Store for block inclusion
    guarantor_state.pending_guarantees.push(Guarantee {
        report,
        timeslot,
        credentials,
    });

    // Mark core as available for assurance generation
    guarantor_state.available_cores.insert(
        guarantor_state
            .pending_guarantees
            .last()
            .unwrap()
            .report
            .core_index,
        computed_hash,
    );
}

/// Handle a received assurance from the network.
/// Collect assurances for inclusion in blocks we author.
pub fn handle_received_assurance(data: &[u8], collected_assurances: &mut Vec<Assurance>) {
    if let Some(assurance) = decode_assurance(data) {
        tracing::info!(
            "Received assurance from validator {}, anchor=0x{}",
            assurance.validator_index,
            hex::encode(&assurance.anchor.0[..8])
        );
        collected_assurances.push(assurance);
    } else {
        tracing::warn!("Failed to decode received assurance");
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────

/// Refine context backed by the chain state.
struct StateRefineContext<'a> {
    state: &'a State,
}

impl<'a> RefineContext for StateRefineContext<'a> {
    fn get_code(&self, code_hash: &Hash) -> Option<Vec<u8>> {
        // Code blobs are stored in preimage_lookup keyed by code_hash
        for account in self.state.services.values() {
            if let Some(blob) = account.preimage_lookup.get(code_hash) {
                return Some(blob.clone());
            }
        }
        None
    }

    fn get_storage(&self, service_id: u32, key: &[u8]) -> Option<Vec<u8>> {
        let account = self.state.services.get(&service_id)?;
        account.storage.get(key).cloned()
    }

    fn get_preimage(&self, hash: &Hash) -> Option<Vec<u8>> {
        for account in self.state.services.values() {
            if let Some(data) = account.preimage_lookup.get(hash) {
                return Some(data.clone());
            }
        }
        None
    }
}

/// Determine which core a work package should be assigned to.
fn determine_core(config: &Config, state: &State, package: &WorkPackage) -> u16 {
    // Find a core whose authorization pool contains the package's auth code hash
    for (core_idx, pool) in state.auth_pool.iter().enumerate() {
        for hash in pool {
            if *hash == package.auth_code_hash {
                return core_idx as u16;
            }
        }
    }
    // Fallback: assign to core based on auth code hash modulo core count
    let hash_val = u16::from_le_bytes([package.auth_code_hash.0[0], package.auth_code_hash.0[1]]);
    hash_val % config.core_count
}

/// Get erasure coding parameters for the protocol config.
fn erasure_params_for_config(config: &Config) -> ErasureParams {
    if config.validators_count <= 6 {
        ErasureParams::TINY
    } else {
        ErasureParams::FULL
    }
}

/// Encode a work package for erasure coding.
fn encode_work_package_bundle(package: &WorkPackage) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&package.auth_code_host.to_le_bytes());
    buf.extend_from_slice(&package.auth_code_hash.0);
    buf.extend_from_slice(&(package.authorization.len() as u32).to_le_bytes());
    buf.extend_from_slice(&package.authorization);
    buf.extend_from_slice(&(package.items.len() as u32).to_le_bytes());
    for item in &package.items {
        buf.extend_from_slice(&item.service_id.to_le_bytes());
        buf.extend_from_slice(&item.code_hash.0);
        buf.extend_from_slice(&item.gas_limit.to_le_bytes());
        buf.extend_from_slice(&item.accumulate_gas_limit.to_le_bytes());
        buf.extend_from_slice(&item.exports_count.to_le_bytes());
        buf.extend_from_slice(&(item.payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(&item.payload);
    }
    buf
}

/// Compute a Merkle root of erasure-coded chunks.
fn compute_erasure_root(chunks: &[Vec<u8>]) -> Hash {
    if chunks.is_empty() {
        return Hash::ZERO;
    }
    // Hash each chunk, then build a balanced binary tree
    let leaf_hashes: Vec<Hash> = chunks.iter().map(|c| grey_crypto::blake2b_256(c)).collect();

    balanced_merkle_root(&leaf_hashes)
}

/// Compute a balanced binary Merkle tree root from leaf hashes.
fn balanced_merkle_root(leaves: &[Hash]) -> Hash {
    if leaves.is_empty() {
        return Hash::ZERO;
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            if pair.len() == 2 {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&pair[0].0);
                buf[32..].copy_from_slice(&pair[1].0);
                next.push(grey_crypto::blake2b_256(&buf));
            } else {
                next.push(pair[0]);
            }
        }
        level = next;
    }
    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use grey_types::work::*;

    #[test]
    fn test_encode_work_package_bundle() {
        let pkg = WorkPackage {
            auth_code_host: 1,
            auth_code_hash: Hash([42u8; 32]),
            context: RefinementContext {
                anchor: Hash::ZERO,
                state_root: Hash::ZERO,
                beefy_root: Hash::ZERO,
                lookup_anchor: Hash::ZERO,
                lookup_anchor_timeslot: 0,
                prerequisites: vec![],
            },
            authorization: vec![0xAB, 0xCD],
            authorizer_config: vec![],
            items: vec![WorkItem {
                service_id: 1,
                code_hash: Hash([1u8; 32]),
                gas_limit: 1000,
                accumulate_gas_limit: 500,
                exports_count: 0,
                payload: vec![10, 20, 30],
                imports: vec![],
                extrinsics: vec![],
            }],
        };
        let encoded = encode_work_package_bundle(&pkg);
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_erasure_params() {
        let tiny = Config::tiny();
        let params = erasure_params_for_config(&tiny);
        assert_eq!(params.data_shards, 2);
        assert_eq!(params.total_shards, 6);
    }

    #[test]
    fn test_erasure_root_computation() {
        let chunks = vec![vec![1u8; 4]; 6];
        let root = compute_erasure_root(&chunks);
        assert_ne!(root, Hash::ZERO);

        // Same chunks should produce same root
        let root2 = compute_erasure_root(&chunks);
        assert_eq!(root.0, root2.0);
    }

    #[test]
    fn test_assurance_encode_decode() {
        let assurance = Assurance {
            anchor: Hash([1u8; 32]),
            bitfield: vec![0b00000011], // cores 0 and 1 available
            validator_index: 3,
            signature: Ed25519Signature([42u8; 64]),
        };

        let encoded = encode_assurance(&assurance);
        let decoded = decode_assurance(&encoded).expect("decode should succeed");

        assert_eq!(decoded.anchor.0, assurance.anchor.0);
        assert_eq!(decoded.bitfield, assurance.bitfield);
        assert_eq!(decoded.validator_index, assurance.validator_index);
        assert_eq!(decoded.signature.0, assurance.signature.0);
    }

    #[test]
    fn test_guarantor_state_new() {
        let gs = GuarantorState::new();
        assert!(gs.pending_guarantees.is_empty());
        assert!(gs.available_cores.is_empty());
    }

    #[test]
    fn test_assurance_generation() {
        let config = Config::tiny();
        let (state, secrets) = grey_consensus::genesis::create_genesis(&config);
        let gs = GuarantorState::new();
        let parent_hash = Hash([99u8; 32]);

        // With no available cores, should return None
        let assurance = gs.generate_assurance(&config, &parent_hash, 0, &secrets[0], &state);
        assert!(assurance.is_none());
    }
}
