//! State serialization T(σ) — Gray Paper eq D.2.
//!
//! Converts between the State struct and a flat mapping of 31-byte keys to
//! variable-length byte values, suitable for Merklization via the binary
//! Patricia Merkle trie.

use grey_codec::decode_compact_at;
use grey_codec::encode::encode_compact;
use grey_crypto::blake2b_256;
use grey_types::config::Config;
use grey_types::state::{
    CoreStatistics, Judgments, PendingReport, PrivilegedServices, RecentBlockInfo, RecentBlocks,
    SafroleState, SealKeySeries, ServiceAccount, ServiceStatistics, State, ValidatorRecord,
    ValidatorStatistics,
};
use grey_types::{Hash, ServiceId};
use std::collections::BTreeMap;

/// Construct state key C(i) for a state component index.
fn key_from_index(index: u8) -> [u8; 31] {
    let mut key = [0u8; 31];
    key[0] = index;
    key
}

/// Construct state key C(i) for a state component index (public alias).
pub fn key_for_component(index: u8) -> [u8; 31] {
    key_from_index(index)
}

/// Construct state key C(i, s) for a service-indexed state component (public alias).
pub fn key_for_service_pub(index: u8, service_id: ServiceId) -> [u8; 31] {
    key_for_service(index, service_id)
}

/// Extract the accumulation root (beefy_root) for a given anchor block from the
/// raw C(3) (recent_blocks) state KV blob. Scans the serialized header entries to
/// find the one matching `anchor_hash` and returns its `accumulation_root` field.
pub fn extract_accumulation_root(
    recent_blocks_blob: &[u8],
    anchor_hash: &Hash,
) -> Result<Option<Hash>, String> {
    let mut pos = 0;
    let header_count =
        decode_compact_at(recent_blocks_blob, &mut pos).map_err(|e| e.to_string())? as usize;

    for _ in 0..header_count {
        // Each header: header_hash(32) + accumulation_root(32) + state_root(32) + packages...
        if pos + 96 > recent_blocks_blob.len() {
            return Err("unexpected end in recent_blocks headers".into());
        }
        let mut header_hash = [0u8; 32];
        header_hash.copy_from_slice(&recent_blocks_blob[pos..pos + 32]);
        let mut acc_root = [0u8; 32];
        acc_root.copy_from_slice(&recent_blocks_blob[pos + 32..pos + 64]);
        // Skip state_root
        pos += 96;

        // Skip reported_packages map
        let pkg_count =
            decode_compact_at(recent_blocks_blob, &mut pos).map_err(|e| e.to_string())? as usize;
        // Each package entry is 64 bytes (two hashes)
        let skip = pkg_count * 64;
        if pos + skip > recent_blocks_blob.len() {
            return Err("unexpected end in reported_packages".into());
        }
        pos += skip;

        if header_hash == anchor_hash.0 {
            return Ok(Some(Hash(acc_root)));
        }
    }
    Ok(None)
}

/// Construct state key C(i, s) for a service-indexed state component.
fn key_for_service(index: u8, service_id: ServiceId) -> [u8; 31] {
    let mut key = [0u8; 31];
    let s = service_id.to_le_bytes();
    key[0] = index;
    key[1] = s[0];
    key[2] = 0;
    key[3] = s[1];
    key[4] = 0;
    key[5] = s[2];
    key[6] = 0;
    key[7] = s[3];
    key
}

/// Construct state key C(s, h) where h is an arbitrary byte sequence.
/// The key interleaves E_4(s) and H(h).
fn key_for_service_data(service_id: ServiceId, h: &[u8]) -> [u8; 31] {
    let s = service_id.to_le_bytes();
    let a = blake2b_256(h);
    let mut key = [0u8; 31];
    key[0] = s[0];
    key[1] = a.0[0];
    key[2] = s[1];
    key[3] = a.0[1];
    key[4] = s[2];
    key[5] = a.0[2];
    key[6] = s[3];
    key[7] = a.0[3];
    key[8..31].copy_from_slice(&a.0[4..27]);
    key
}

/// Construct the h argument for storage entries: E_4(2^32-1) ++ k
fn storage_hash_arg(storage_key: &[u8]) -> Vec<u8> {
    let mut h = Vec::with_capacity(4 + storage_key.len());
    h.extend_from_slice(&u32::MAX.to_le_bytes());
    h.extend_from_slice(storage_key);
    h
}

/// Construct the h argument for preimage lookup entries: E_4(2^32-2) ++ hash
fn preimage_hash_arg(hash: &Hash) -> Vec<u8> {
    let mut h = Vec::with_capacity(4 + 32);
    h.extend_from_slice(&(u32::MAX - 1).to_le_bytes());
    h.extend_from_slice(&hash.0);
    h
}

/// Construct the h argument for preimage info entries: E_4(l) ++ hash
fn preimage_info_hash_arg(length: u32, hash: &Hash) -> Vec<u8> {
    let mut h = Vec::with_capacity(4 + 32);
    h.extend_from_slice(&length.to_le_bytes());
    h.extend_from_slice(&hash.0);
    h
}

/// Extract service_id from an opaque service data key C(s, h).
/// The service_id bytes are interleaved at positions 0, 2, 4, 6.
pub fn extract_service_id_from_data_key(key: &[u8; 31]) -> ServiceId {
    u32::from_le_bytes([key[0], key[2], key[4], key[6]])
}

/// Compute the state key for a storage entry: C(s, E_4(2^32-1) ++ k).
pub fn compute_storage_state_key(service_id: ServiceId, storage_key: &[u8]) -> [u8; 31] {
    key_for_service_data(service_id, &storage_hash_arg(storage_key))
}

/// Compute the state key for a preimage lookup entry: C(s, E_4(2^32-2) ++ hash).
pub fn compute_preimage_lookup_state_key(service_id: ServiceId, hash: &Hash) -> [u8; 31] {
    key_for_service_data(service_id, &preimage_hash_arg(hash))
}

/// Compute the state key for a preimage info entry: C(s, E_4(l) ++ hash).
pub fn compute_preimage_info_state_key(
    service_id: ServiceId,
    hash: &Hash,
    length: u32,
) -> [u8; 31] {
    key_for_service_data(service_id, &preimage_info_hash_arg(length, hash))
}

/// Serialize the full state T(σ) into a sorted vector of (key, value) pairs.
pub fn serialize_state(state: &State, config: &Config) -> Vec<([u8; 31], Vec<u8>)> {
    let mut kvs = vec![(
        key_from_index(1),
        serialize_auth_pool(&state.auth_pool, config),
    )];

    // C(2) → ϕ auth_queue
    kvs.push((
        key_from_index(2),
        serialize_auth_queue(&state.auth_queue, config),
    ));

    // C(3) → β recent_blocks
    kvs.push((
        key_from_index(3),
        serialize_recent_blocks(&state.recent_blocks),
    ));

    // C(4) → γ safrole
    kvs.push((key_from_index(4), serialize_safrole(&state.safrole, config)));

    // C(5) → ψ judgments
    kvs.push((key_from_index(5), serialize_judgments(&state.judgments)));

    // C(6) → η entropy
    kvs.push((key_from_index(6), serialize_entropy(&state.entropy)));

    // C(7) → ι pending_validators
    kvs.push((
        key_from_index(7),
        serialize_validators(&state.pending_validators),
    ));

    // C(8) → κ current_validators
    kvs.push((
        key_from_index(8),
        serialize_validators(&state.current_validators),
    ));

    // C(9) → λ previous_validators
    kvs.push((
        key_from_index(9),
        serialize_validators(&state.previous_validators),
    ));

    // C(10) → ρ pending_reports
    kvs.push((
        key_from_index(10),
        serialize_pending_reports(&state.pending_reports),
    ));

    // C(11) → τ timeslot
    kvs.push((key_from_index(11), state.timeslot.to_le_bytes().to_vec()));

    // C(12) → χ privileged_services
    kvs.push((
        key_from_index(12),
        serialize_privileged(&state.privileged_services),
    ));

    // C(13) → π statistics
    kvs.push((
        key_from_index(13),
        serialize_statistics(&state.statistics, config),
    ));

    // C(14) → ω accumulation_queue
    kvs.push((
        key_from_index(14),
        serialize_accumulation_queue(&state.accumulation_queue),
    ));

    // C(15) → ξ accumulation_history
    kvs.push((
        key_from_index(15),
        serialize_accumulation_history(&state.accumulation_history),
    ));

    // C(16) → θ accumulation_outputs
    kvs.push((
        key_from_index(16),
        serialize_accumulation_outputs(&state.accumulation_outputs),
    ));

    // Service accounts and their data
    for (&service_id, account) in &state.services {
        // C(255, s) → service account metadata
        kvs.push((
            key_for_service(255, service_id),
            serialize_service_account_with_id(account, service_id),
        ));

        // C(s, E_4(2^32-1) ++ k) → storage entries
        for (storage_key, value) in &account.storage {
            let h = storage_hash_arg(storage_key);
            kvs.push((key_for_service_data(service_id, &h), value.clone()));
        }

        // C(s, E_4(2^32-2) ++ hash) → preimage lookup
        for (hash, data) in &account.preimage_lookup {
            let h = preimage_hash_arg(hash);
            kvs.push((key_for_service_data(service_id, &h), data.clone()));
        }

        // C(s, E_4(l) ++ hash) → preimage info
        for (&(ref hash, length), timeslots) in &account.preimage_info {
            let h = preimage_info_hash_arg(length, hash);
            let mut val = Vec::new();
            encode_compact(timeslots.len() as u64, &mut val);
            for &t in timeslots {
                val.extend_from_slice(&t.to_le_bytes());
            }
            kvs.push((key_for_service_data(service_id, &h), val));
        }
    }

    // Sort by key
    kvs.sort_by(|a, b| a.0.cmp(&b.0));
    kvs
}

/// Serialize state and include additional opaque KV pairs (from deserialization).
/// The opaque entries are service data keys that were passed through unchanged.
pub fn serialize_state_with_opaque(
    state: &State,
    config: &Config,
    opaque: &[([u8; 31], Vec<u8>)],
) -> Vec<([u8; 31], Vec<u8>)> {
    let mut kvs = serialize_state(state, config);
    // Collect state-generated keys for deduplication
    let state_keys: std::collections::HashSet<[u8; 31]> = kvs.iter().map(|(k, _)| *k).collect();
    // Only add opaque entries whose keys don't collide with state entries
    for (k, v) in opaque {
        if !state_keys.contains(k) {
            kvs.push((*k, v.clone()));
        }
    }
    kvs.sort_by(|a, b| a.0.cmp(&b.0));
    kvs
}

// --- Component serializers ---

/// C(1): α auth_pool — C fixed-size array of compact-length-prefixed hash lists.
fn serialize_auth_pool(auth_pool: &[Vec<Hash>], config: &Config) -> Vec<u8> {
    let mut buf = Vec::new();
    // Fixed-size C array, no outer length prefix
    for core_idx in 0..config.core_count as usize {
        let hashes = auth_pool.get(core_idx).map(|v| v.as_slice()).unwrap_or(&[]);
        encode_compact(hashes.len() as u64, &mut buf);
        for hash in hashes {
            buf.extend_from_slice(&hash.0);
        }
    }
    buf
}

/// C(2): ϕ auth_queue — Q × C × 32 bytes (all fixed-size, no length prefixes).
fn serialize_auth_queue(auth_queue: &[Vec<Hash>], config: &Config) -> Vec<u8> {
    let q = config.auth_queue_size;
    let c = config.core_count as usize;
    let mut buf = Vec::with_capacity(q * c * 32);
    // auth_queue is indexed [queue_slot][core], each entry is a Hash
    for slot_idx in 0..q {
        let slot = auth_queue
            .get(slot_idx)
            .map(|v| v.as_slice())
            .unwrap_or(&[]);
        for core_idx in 0..c {
            let hash = slot.get(core_idx).unwrap_or(&Hash::ZERO);
            buf.extend_from_slice(&hash.0);
        }
    }
    buf
}

/// C(3): β recent_blocks — sorted headers + MMR belt.
fn serialize_recent_blocks(blocks: &RecentBlocks) -> Vec<u8> {
    let mut buf = Vec::new();

    // ↕ sorted headers (compact length prefix)
    encode_compact(blocks.headers.len() as u64, &mut buf);
    for info in &blocks.headers {
        // (h, b, s, ↕p) — header_hash, accumulation_root, state_root, sorted packages
        buf.extend_from_slice(&info.header_hash.0);
        buf.extend_from_slice(&info.accumulation_root.0);
        buf.extend_from_slice(&info.state_root.0);
        // ↕p: sorted map of reported packages
        encode_compact(info.reported_packages.len() as u64, &mut buf);
        for (k, v) in &info.reported_packages {
            buf.extend_from_slice(&k.0);
            buf.extend_from_slice(&v.0);
        }
    }

    // E_M(β_B): accumulation log / MMR belt
    encode_compact(blocks.accumulation_log.len() as u64, &mut buf);
    for entry in &blocks.accumulation_log {
        match entry {
            Some(hash) => {
                buf.push(1);
                buf.extend_from_slice(&hash.0);
            }
            None => {
                buf.push(0);
            }
        }
    }
    buf
}

/// C(4): γ safrole — pending_keys, ring_root, discriminant, seal_keys, ticket_accumulator.
fn serialize_safrole(safrole: &SafroleState, config: &Config) -> Vec<u8> {
    let mut buf = Vec::new();

    // γP: pending_keys — V × 336 bytes (fixed-size, no prefix)
    for key in &safrole.pending_keys {
        buf.extend_from_slice(&key.to_bytes());
    }

    // γZ: ring_root — 144 bytes
    buf.extend_from_slice(&safrole.ring_root.0);

    // γS discriminant + data
    match &safrole.seal_key_series {
        SealKeySeries::Tickets(tickets) => {
            buf.push(0); // discriminant for tickets
            // E tickets, each = Ticket { id: Hash, attempt: u8 }
            // Fixed-size E array, no length prefix
            for ticket in tickets {
                buf.extend_from_slice(&ticket.id.0);
                buf.push(ticket.attempt);
            }
            // Pad if fewer than E tickets
            let e = config.epoch_length as usize;
            for _ in tickets.len()..e {
                buf.extend_from_slice(&Hash::ZERO.0);
                buf.push(0);
            }
        }
        SealKeySeries::Fallback(keys) => {
            buf.push(1); // discriminant for fallback
            // E Bandersnatch keys × 32 bytes (fixed-size array, no prefix)
            for key in keys {
                buf.extend_from_slice(&key.0);
            }
            let e = config.epoch_length as usize;
            for _ in keys.len()..e {
                buf.extend_from_slice(&[0u8; 32]);
            }
        }
    }

    // γA: ticket_accumulator — ↕ sorted sequence
    encode_compact(safrole.ticket_accumulator.len() as u64, &mut buf);
    for ticket in &safrole.ticket_accumulator {
        buf.extend_from_slice(&ticket.id.0);
        buf.push(ticket.attempt);
    }

    buf
}

/// C(5): ψ judgments — 4 sorted sets.
fn serialize_judgments(judgments: &Judgments) -> Vec<u8> {
    let mut buf = Vec::new();

    // ↕ψG
    encode_compact(judgments.good.len() as u64, &mut buf);
    for hash in &judgments.good {
        buf.extend_from_slice(&hash.0);
    }

    // ↕ψB
    encode_compact(judgments.bad.len() as u64, &mut buf);
    for hash in &judgments.bad {
        buf.extend_from_slice(&hash.0);
    }

    // ↕ψW
    encode_compact(judgments.wonky.len() as u64, &mut buf);
    for hash in &judgments.wonky {
        buf.extend_from_slice(&hash.0);
    }

    // ↕ψO
    encode_compact(judgments.offenders.len() as u64, &mut buf);
    for key in &judgments.offenders {
        buf.extend_from_slice(&key.0);
    }

    buf
}

/// C(6): η entropy — 4 × 32 raw bytes.
fn serialize_entropy(entropy: &[Hash; 4]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    for hash in entropy {
        buf.extend_from_slice(&hash.0);
    }
    buf
}

/// C(7,8,9): validator keys — V × 336 raw bytes (fixed-size, no prefix).
fn serialize_validators(validators: &[grey_types::validator::ValidatorKey]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(validators.len() * 336);
    for key in validators {
        buf.extend_from_slice(&key.to_bytes());
    }
    buf
}

/// C(10): ρ pending_reports — C fixed-size array of ¿(report, E_4(timeslot)).
fn serialize_pending_reports(reports: &[Option<PendingReport>]) -> Vec<u8> {
    use grey_codec::Encode;
    let mut buf = Vec::new();
    for report in reports {
        match report {
            None => buf.push(0),
            Some(pr) => {
                buf.push(1);
                // Use standard block encoding E(r ∈ R) for work reports in state
                pr.report.encode_to(&mut buf);
                buf.extend_from_slice(&pr.timeslot.to_le_bytes());
            }
        }
    }
    buf
}

/// C(12): χ privileged — E_4(M, A[0..C], V, R) + ↕Z.
fn serialize_privileged(priv_svc: &PrivilegedServices) -> Vec<u8> {
    let mut buf = Vec::new();

    // E_4(χM)
    buf.extend_from_slice(&priv_svc.manager.to_le_bytes());
    // E_4(χA) — C entries, fixed-size
    for &svc_id in &priv_svc.assigner {
        buf.extend_from_slice(&svc_id.to_le_bytes());
    }
    // E_4(χV)
    buf.extend_from_slice(&priv_svc.designator.to_le_bytes());
    // E_4(χR)
    buf.extend_from_slice(&priv_svc.registrar.to_le_bytes());

    // χZ: sorted map ↕[(E_4(s), E_8(g))]
    encode_compact(priv_svc.always_accumulate.len() as u64, &mut buf);
    for (&service_id, &gas) in &priv_svc.always_accumulate {
        buf.extend_from_slice(&service_id.to_le_bytes());
        buf.extend_from_slice(&gas.to_le_bytes());
    }

    buf
}

/// C(13): π statistics — E_4(π_V, π_L), π_C, π_S.
fn serialize_statistics(stats: &ValidatorStatistics, config: &Config) -> Vec<u8> {
    let mut buf = Vec::new();

    // π_V: V records, each field E_4 (4 bytes LE)
    serialize_validator_records_e4(&stats.current, config.validators_count as usize, &mut buf);

    // π_L: V records, each field E_4 (4 bytes LE)
    serialize_validator_records_e4(&stats.last, config.validators_count as usize, &mut buf);

    // π_C: C core records, compact-encoded fields (GP field order: d, p, i, x, z, e, l, u)
    for core_idx in 0..config.core_count as usize {
        let cs = stats.core_stats.get(core_idx).cloned().unwrap_or_default();
        encode_compact(cs.da_load, &mut buf);
        encode_compact(cs.popularity, &mut buf);
        encode_compact(cs.imports, &mut buf);
        encode_compact(cs.extrinsic_count, &mut buf);
        encode_compact(cs.extrinsic_size, &mut buf);
        encode_compact(cs.exports, &mut buf);
        encode_compact(cs.bundle_size, &mut buf);
        encode_compact(cs.gas_used, &mut buf);
    }

    // π_S: sorted map of service stats (GP field order: p, r, i, x, z, e, a)
    encode_compact(stats.service_stats.len() as u64, &mut buf);
    for (&service_id, ss) in &stats.service_stats {
        buf.extend_from_slice(&service_id.to_le_bytes());
        // p: (provided_count, provided_size)
        encode_compact(ss.provided_count, &mut buf);
        encode_compact(ss.provided_size, &mut buf);
        // r: (refinement_count, refinement_gas_used)
        encode_compact(ss.refinement_count, &mut buf);
        encode_compact(ss.refinement_gas_used, &mut buf);
        // i, x, z, e
        encode_compact(ss.imports, &mut buf);
        encode_compact(ss.extrinsic_count, &mut buf);
        encode_compact(ss.extrinsic_size, &mut buf);
        encode_compact(ss.exports, &mut buf);
        // a: (accumulate_count, accumulate_gas_used)
        encode_compact(ss.accumulate_count, &mut buf);
        encode_compact(ss.accumulate_gas_used, &mut buf);
    }

    buf
}

/// Serialize V validator records with E_4 (all fields as 4-byte LE).
fn serialize_validator_records_e4(records: &[ValidatorRecord], count: usize, buf: &mut Vec<u8>) {
    for i in 0..count {
        let r = records.get(i).cloned().unwrap_or_default();
        buf.extend_from_slice(&r.blocks_produced.to_le_bytes());
        buf.extend_from_slice(&r.tickets_introduced.to_le_bytes());
        buf.extend_from_slice(&r.preimages_introduced.to_le_bytes());
        // d (preimage_bytes) is E_4 — truncated to u32 for state encoding
        buf.extend_from_slice(&(r.preimage_bytes as u32).to_le_bytes());
        buf.extend_from_slice(&r.reports_guaranteed.to_le_bytes());
        buf.extend_from_slice(&r.assurances_made.to_le_bytes());
    }
}

/// C(14): ω accumulation_queue — E fixed-size array of ↕ sorted inner lists.
/// Each entry: E(r ∈ R) followed by ↕ sorted dependency hashes.
fn serialize_accumulation_queue(
    queue: &[Vec<(grey_types::work::WorkReport, Vec<Hash>)>],
) -> Vec<u8> {
    use grey_codec::Encode;
    let mut buf = Vec::new();
    for slot in queue {
        encode_compact(slot.len() as u64, &mut buf);
        for (report, deps) in slot {
            // Use standard block encoding E(r ∈ R) for work reports
            report.encode_to(&mut buf);
            // ↕ sorted dependency hashes
            encode_compact(deps.len() as u64, &mut buf);
            for hash in deps {
                buf.extend_from_slice(&hash.0);
            }
        }
    }
    buf
}

/// C(15): ξ accumulation_history — E fixed-size array of ↕ sorted hash lists.
fn serialize_accumulation_history(history: &[Vec<Hash>]) -> Vec<u8> {
    let mut buf = Vec::new();
    for slot in history {
        encode_compact(slot.len() as u64, &mut buf);
        for hash in slot {
            buf.extend_from_slice(&hash.0);
        }
    }
    buf
}

/// C(16): θ accumulation_outputs — ↕ sorted (E_4(service_id), hash) pairs.
fn serialize_accumulation_outputs(outputs: &[(ServiceId, Hash)]) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_compact(outputs.len() as u64, &mut buf);
    for &(service_id, ref hash) in outputs {
        buf.extend_from_slice(&service_id.to_le_bytes());
        buf.extend_from_slice(&hash.0);
    }
    buf
}

/// E(0, a_c, E_8(a_b, a_g, a_m, a_o, a_f), E_4(a_i, a_r, a_a, a_p))
pub fn serialize_single_service(account: &ServiceAccount) -> Vec<u8> {
    serialize_service_account_with_id(account, 0)
}

fn serialize_service_account_with_id(account: &ServiceAccount, sid: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(89);

    // Compute dependent values i and o from actual storage (GP eq 9.4 / line 1036-1040)
    // a_i = 2·|a_l| + |a_s|
    let computed_i = 2 * account.preimage_info.len() as u32 + account.storage.len() as u32;
    // a_o = Σ_{(h,z) ∈ K(a_l)} (81 + z) + Σ_{(x,y) ∈ a_s} (34 + |y| + |x|)
    let computed_o: u64 = account
        .preimage_info
        .keys()
        .map(|&(_hash, length)| 81u64 + length as u64)
        .sum::<u64>()
        + account
            .storage
            .iter()
            .map(|(k, v)| 34u64 + k.len() as u64 + v.len() as u64)
            .sum::<u64>();

    if computed_i != account.accumulation_counter {
        eprintln!(
            "SERVICE ACCOUNT i mismatch for svc {}: stored={}, computed={} (storage={}, preimage_info={})",
            sid,
            account.accumulation_counter,
            computed_i,
            account.storage.len(),
            account.preimage_info.len()
        );
    }
    if computed_o != account.total_footprint {
        eprintln!(
            "SERVICE ACCOUNT o mismatch for svc {}: stored={}, computed={} (storage entries: {:?})",
            sid,
            account.total_footprint,
            computed_o,
            account
                .storage
                .iter()
                .map(|(k, v)| (k.len(), v.len()))
                .collect::<Vec<_>>()
        );
    }

    // version = 0
    buf.push(0);
    // a_c: code_hash
    buf.extend_from_slice(&account.code_hash.0);
    // E_8 fields: b, g, m, o, f
    buf.extend_from_slice(&account.balance.to_le_bytes());
    buf.extend_from_slice(&account.min_accumulate_gas.to_le_bytes());
    buf.extend_from_slice(&account.min_on_transfer_gas.to_le_bytes());
    buf.extend_from_slice(&account.total_footprint.to_le_bytes());
    buf.extend_from_slice(&account.free_storage_offset.to_le_bytes());
    // E_4 fields: i, r, a, p
    buf.extend_from_slice(&account.accumulation_counter.to_le_bytes());
    buf.extend_from_slice(&account.last_accumulation.to_le_bytes());
    buf.extend_from_slice(&account.last_activity.to_le_bytes());
    buf.extend_from_slice(&account.preimage_count.to_le_bytes());

    buf
}

// --- Deserialization ---

/// Deserialize state from key-value pairs (inverse of serialize_state).
///
/// Returns the State and a list of opaque service data KV pairs that cannot
/// be fully deserialized (because the blake2b hash in the key is irreversible).
/// These opaque entries should be passed to `serialize_state_with_opaque` to
/// include them in re-serialization.
#[allow(clippy::type_complexity)]
pub fn deserialize_state(
    kvs: &[([u8; 31], Vec<u8>)],
    config: &Config,
) -> Result<(State, Vec<([u8; 31], Vec<u8>)>), String> {
    let mut state = State {
        auth_pool: vec![Vec::new(); config.core_count as usize],
        recent_blocks: RecentBlocks {
            headers: Vec::new(),
            accumulation_log: Vec::new(),
        },
        accumulation_outputs: Vec::new(),
        safrole: SafroleState {
            pending_keys: Vec::new(),
            ring_root: grey_types::BandersnatchRingRoot::default(),
            seal_key_series: SealKeySeries::Fallback(Vec::new()),
            ticket_accumulator: Vec::new(),
        },
        services: BTreeMap::new(),
        entropy: [Hash::ZERO; 4],
        pending_validators: Vec::new(),
        current_validators: Vec::new(),
        previous_validators: Vec::new(),
        pending_reports: vec![None; config.core_count as usize],
        timeslot: 0,
        auth_queue: vec![vec![Hash::ZERO; config.core_count as usize]; config.auth_queue_size],
        privileged_services: PrivilegedServices::default(),
        judgments: Judgments::default(),
        statistics: ValidatorStatistics::default(),
        accumulation_queue: vec![Vec::new(); config.epoch_length as usize],
        accumulation_history: vec![Vec::new(); config.epoch_length as usize],
    };

    // Collect opaque service data entries (C(s, h) keys).
    // We can't reverse the blake2b hash to determine the original key/hash,
    // so we store these as raw KV pairs and pass them through unchanged.
    let mut opaque_service_data: Vec<([u8; 31], Vec<u8>)> = Vec::new();

    for (key, value) in kvs {
        match classify_key(key) {
            KeyType::Component(idx) => match idx {
                1 => deserialize_auth_pool(value, config, &mut state.auth_pool)?,
                2 => deserialize_auth_queue(value, config, &mut state.auth_queue)?,
                3 => state.recent_blocks = deserialize_recent_blocks(value)?,
                4 => state.safrole = deserialize_safrole(value, config)?,
                5 => state.judgments = deserialize_judgments(value)?,
                6 => state.entropy = deserialize_entropy(value)?,
                7 => state.pending_validators = deserialize_validators(value)?,
                8 => state.current_validators = deserialize_validators(value)?,
                9 => state.previous_validators = deserialize_validators(value)?,
                10 => state.pending_reports = deserialize_pending_reports(value, config)?,
                11 => {
                    if value.len() < 4 {
                        return Err("timeslot too short".into());
                    }
                    state.timeslot = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
                }
                12 => state.privileged_services = deserialize_privileged(value, config)?,
                13 => state.statistics = deserialize_statistics(value, config)?,
                14 => {
                    state.accumulation_queue = deserialize_accumulation_queue(value, config)?;
                }
                15 => {
                    state.accumulation_history = deserialize_accumulation_history(value, config)?;
                }
                16 => state.accumulation_outputs = deserialize_accumulation_outputs(value)?,
                _ => {} // unknown component index, ignore
            },
            KeyType::ServiceAccount(service_id) => {
                let account = deserialize_service_account(value)?;
                state.services.insert(service_id, account);
            }
            KeyType::ServiceData => {
                opaque_service_data.push((*key, value.clone()));
            }
        }
    }

    Ok((state, opaque_service_data))
}

/// Look up a preimage (e.g., code blob) for a specific service from opaque KV data.
/// This computes the expected key C(service_id, E_4(2^32-2) ++ hash) and searches
/// the opaque data for a matching entry.
pub fn lookup_preimage_in_opaque(
    service_id: ServiceId,
    hash: &Hash,
    opaque_data: &[([u8; 31], Vec<u8>)],
) -> Option<Vec<u8>> {
    let h = preimage_hash_arg(hash);
    let expected_key = key_for_service_data(service_id, &h);
    opaque_data
        .iter()
        .find(|(k, _)| *k == expected_key)
        .map(|(_, v)| v.clone())
}

/// Classify a 31-byte state key.
enum KeyType {
    /// C(i) — state component index.
    Component(u8),
    /// C(255, s) — service account metadata.
    ServiceAccount(ServiceId),
    /// C(s, h) — service data (storage/preimage).
    ServiceData,
}

/// Classify a key based on its structure.
/// C(i): key = [i, 0, 0, ...]
/// C(255, s): key = [255, s0, 0, s1, 0, s2, 0, s3, 0, 0, ...]
/// C(s, h): key = [s0, a0, s1, a1, s2, a2, s3, a3, ...]  (interleaved)
fn classify_key(key: &[u8; 31]) -> KeyType {
    // C(i) keys have index > 0 and index < 255, with remaining bytes = 0
    // C(255, s) keys have key[0] = 255, key[2] = 0, key[4] = 0, key[6] = 0
    // C(s, h) keys have key[0] = s0 which could overlap with C(i)
    //
    // The distinguishing factor: C(i) has key[1..] all zeros.
    // C(255, s) has key[0] = 255 and key[2], key[4], key[6] = 0.
    // C(s, h) has non-zero bytes in odd positions (from hash).

    if key[0] == 255 {
        // Could be C(255, s) — check if positions 2, 4, 6 are zero (C(i,s) format)
        if key[2] == 0 && key[4] == 0 && key[6] == 0 && key[8..].iter().all(|&b| b == 0) {
            let service_id = u32::from_le_bytes([key[1], key[3], key[5], key[7]]);
            return KeyType::ServiceAccount(service_id);
        }
    }

    // Check if this is C(i) — index + all zeros
    if key[1..].iter().all(|&b| b == 0) {
        return KeyType::Component(key[0]);
    }

    // Check for C(i, s) pattern: key[2], key[4], key[6] = 0, rest = 0
    if key[0] >= 1
        && key[0] <= 16
        && key[2] == 0
        && key[4] == 0
        && key[6] == 0
        && key[8..].iter().all(|&b| b == 0)
    {
        return KeyType::Component(key[0]);
    }

    // Otherwise it's a service data key C(s, h)
    KeyType::ServiceData
}

// --- Component deserializers ---

fn decode_compact(data: &[u8], pos: &mut usize) -> Result<u64, String> {
    decode_compact_at(data, pos).map_err(|e| e.to_string())
}

fn read_hash(data: &[u8], pos: &mut usize) -> Result<Hash, String> {
    if *pos + 32 > data.len() {
        return Err("unexpected end reading hash".into());
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(&data[*pos..*pos + 32]);
    *pos += 32;
    Ok(Hash(h))
}

fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32, String> {
    if *pos + 4 > data.len() {
        return Err("unexpected end reading u32".into());
    }
    let v = u32::from_le_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]);
    *pos += 4;
    Ok(v)
}

fn read_u64(data: &[u8], pos: &mut usize) -> Result<u64, String> {
    if *pos + 8 > data.len() {
        return Err("unexpected end reading u64".into());
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&data[*pos..*pos + 8]);
    *pos += 8;
    Ok(u64::from_le_bytes(bytes))
}

fn deserialize_auth_pool(
    data: &[u8],
    config: &Config,
    pool: &mut Vec<Vec<Hash>>,
) -> Result<(), String> {
    let mut pos = 0;
    for core_idx in 0..config.core_count as usize {
        let count = decode_compact(data, &mut pos)? as usize;
        let mut hashes = Vec::with_capacity(count);
        for _ in 0..count {
            hashes.push(read_hash(data, &mut pos)?);
        }
        if core_idx < pool.len() {
            pool[core_idx] = hashes;
        } else {
            pool.push(hashes);
        }
    }
    Ok(())
}

fn deserialize_auth_queue(
    data: &[u8],
    config: &Config,
    queue: &mut Vec<Vec<Hash>>,
) -> Result<(), String> {
    let q = config.auth_queue_size;
    let c = config.core_count as usize;
    let mut pos = 0;
    for slot_idx in 0..q {
        if slot_idx >= queue.len() {
            queue.push(vec![Hash::ZERO; c]);
        }
        for entry in queue[slot_idx].iter_mut().take(c) {
            let hash = read_hash(data, &mut pos)?;
            *entry = hash;
        }
    }
    Ok(())
}

fn deserialize_recent_blocks(data: &[u8]) -> Result<RecentBlocks, String> {
    let mut pos = 0;

    // Headers: ↕ sorted
    let header_count = decode_compact(data, &mut pos)? as usize;
    let mut headers = Vec::with_capacity(header_count);
    for _ in 0..header_count {
        let header_hash = read_hash(data, &mut pos)?;
        let accumulation_root = read_hash(data, &mut pos)?;
        let state_root = read_hash(data, &mut pos)?;

        // ↕ reported_packages map
        let pkg_count = decode_compact(data, &mut pos)? as usize;
        let mut reported_packages = BTreeMap::new();
        for _ in 0..pkg_count {
            let k = read_hash(data, &mut pos)?;
            let v = read_hash(data, &mut pos)?;
            reported_packages.insert(k, v);
        }

        headers.push(RecentBlockInfo {
            header_hash,
            state_root,
            accumulation_root,
            reported_packages,
        });
    }

    // Accumulation log (MMR belt)
    let belt_count = decode_compact(data, &mut pos)? as usize;
    let mut accumulation_log = Vec::with_capacity(belt_count);
    for _ in 0..belt_count {
        if pos >= data.len() {
            return Err("unexpected end in MMR belt".into());
        }
        let disc = data[pos];
        pos += 1;
        match disc {
            0 => accumulation_log.push(None),
            1 => {
                let hash = read_hash(data, &mut pos)?;
                accumulation_log.push(Some(hash));
            }
            _ => return Err(format!("invalid MMR belt discriminant: {disc}")),
        }
    }

    Ok(RecentBlocks {
        headers,
        accumulation_log,
    })
}

fn deserialize_safrole(data: &[u8], config: &Config) -> Result<SafroleState, String> {
    let mut pos = 0;
    let v = config.validators_count as usize;
    let e = config.epoch_length as usize;

    // pending_keys: V × 336 bytes
    let mut pending_keys = Vec::with_capacity(v);
    for _ in 0..v {
        if pos + 336 > data.len() {
            return Err("unexpected end reading pending keys".into());
        }
        let mut bytes = [0u8; 336];
        bytes.copy_from_slice(&data[pos..pos + 336]);
        pending_keys.push(grey_types::validator::ValidatorKey::from_bytes(&bytes));
        pos += 336;
    }

    // ring_root: 144 bytes
    if pos + 144 > data.len() {
        return Err("unexpected end reading ring root".into());
    }
    let mut ring_root = [0u8; 144];
    ring_root.copy_from_slice(&data[pos..pos + 144]);
    pos += 144;

    // discriminant
    if pos >= data.len() {
        return Err("unexpected end reading safrole discriminant".into());
    }
    let disc = data[pos];
    pos += 1;

    let seal_key_series = match disc {
        0 => {
            // Tickets: E entries, each = 32 (id) + 1 (attempt) = 33 bytes
            let mut tickets = Vec::with_capacity(e);
            for _ in 0..e {
                let id = read_hash(data, &mut pos)?;
                if pos >= data.len() {
                    return Err("unexpected end reading ticket attempt".into());
                }
                let attempt = data[pos];
                pos += 1;
                tickets.push(grey_types::header::Ticket { id, attempt });
            }
            SealKeySeries::Tickets(tickets)
        }
        1 => {
            // Fallback: E × 32 bytes
            let mut keys = Vec::with_capacity(e);
            for _ in 0..e {
                if pos + 32 > data.len() {
                    return Err("unexpected end reading fallback key".into());
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&data[pos..pos + 32]);
                keys.push(grey_types::BandersnatchPublicKey(key));
                pos += 32;
            }
            SealKeySeries::Fallback(keys)
        }
        _ => return Err(format!("invalid safrole discriminant: {disc}")),
    };

    // ticket_accumulator: ↕ sorted
    let ta_count = decode_compact(data, &mut pos)? as usize;
    let mut ticket_accumulator = Vec::with_capacity(ta_count);
    for _ in 0..ta_count {
        let id = read_hash(data, &mut pos)?;
        if pos >= data.len() {
            return Err("unexpected end reading ticket acc attempt".into());
        }
        let attempt = data[pos];
        pos += 1;
        ticket_accumulator.push(grey_types::header::Ticket { id, attempt });
    }

    Ok(SafroleState {
        pending_keys,
        ring_root: grey_types::BandersnatchRingRoot(ring_root),
        seal_key_series,
        ticket_accumulator,
    })
}

fn deserialize_judgments(data: &[u8]) -> Result<Judgments, String> {
    let mut pos = 0;
    let mut judgments = Judgments::default();

    let good_count = decode_compact(data, &mut pos)? as usize;
    for _ in 0..good_count {
        judgments.good.insert(read_hash(data, &mut pos)?);
    }

    let bad_count = decode_compact(data, &mut pos)? as usize;
    for _ in 0..bad_count {
        judgments.bad.insert(read_hash(data, &mut pos)?);
    }

    let wonky_count = decode_compact(data, &mut pos)? as usize;
    for _ in 0..wonky_count {
        judgments.wonky.insert(read_hash(data, &mut pos)?);
    }

    let offender_count = decode_compact(data, &mut pos)? as usize;
    for _ in 0..offender_count {
        if pos + 32 > data.len() {
            return Err("unexpected end reading offender key".into());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&data[pos..pos + 32]);
        judgments
            .offenders
            .insert(grey_types::Ed25519PublicKey(key));
        pos += 32;
    }

    Ok(judgments)
}

fn deserialize_entropy(data: &[u8]) -> Result<[Hash; 4], String> {
    if data.len() < 128 {
        return Err("entropy data too short".into());
    }
    let mut entropy = [Hash::ZERO; 4];
    for i in 0..4 {
        entropy[i].0.copy_from_slice(&data[i * 32..(i + 1) * 32]);
    }
    Ok(entropy)
}

fn deserialize_validators(data: &[u8]) -> Result<Vec<grey_types::validator::ValidatorKey>, String> {
    if !data.len().is_multiple_of(336) {
        return Err(format!(
            "validator data length {} not a multiple of 336",
            data.len()
        ));
    }
    let count = data.len() / 336;
    let mut validators = Vec::with_capacity(count);
    for i in 0..count {
        let mut bytes = [0u8; 336];
        bytes.copy_from_slice(&data[i * 336..(i + 1) * 336]);
        validators.push(grey_types::validator::ValidatorKey::from_bytes(&bytes));
    }
    Ok(validators)
}

fn deserialize_pending_reports(
    data: &[u8],
    config: &Config,
) -> Result<Vec<Option<PendingReport>>, String> {
    let mut pos = 0;
    let c = config.core_count as usize;
    let mut reports = Vec::with_capacity(c);

    for _ in 0..c {
        if pos >= data.len() {
            return Err("unexpected end in pending reports".into());
        }
        let disc = data[pos];
        pos += 1;
        match disc {
            0 => reports.push(None),
            1 => {
                // Decode work report + timeslot
                let report = deserialize_work_report(data, &mut pos)?;
                let timeslot = read_u32(data, &mut pos)?;
                reports.push(Some(PendingReport { report, timeslot }));
            }
            _ => return Err(format!("invalid pending report discriminant: {disc}")),
        }
    }

    Ok(reports)
}

/// Deserialize a work report from state context.
///
/// Uses the standard block Decode for WorkReport since serialize_pending_reports
/// uses the standard block Encode (compact for core_index, auth_gas_used, and
/// RefineLoad fields).
fn deserialize_work_report(
    data: &[u8],
    pos: &mut usize,
) -> Result<grey_types::work::WorkReport, String> {
    use grey_codec::Decode;

    let remaining = &data[*pos..];
    let (report, consumed) = grey_types::work::WorkReport::decode(remaining)
        .map_err(|e| format!("work report decode error: {e}"))?;
    *pos += consumed;
    Ok(report)
}

fn deserialize_privileged(data: &[u8], config: &Config) -> Result<PrivilegedServices, String> {
    let mut pos = 0;
    let c = config.core_count as usize;

    let manager = read_u32(data, &mut pos)?;
    let mut assigner = Vec::with_capacity(c);
    for _ in 0..c {
        assigner.push(read_u32(data, &mut pos)?);
    }
    let designator = read_u32(data, &mut pos)?;
    let registrar = read_u32(data, &mut pos)?;

    // χZ: sorted map
    let z_count = decode_compact(data, &mut pos)? as usize;
    let mut always_accumulate = BTreeMap::new();
    for _ in 0..z_count {
        let service_id = read_u32(data, &mut pos)?;
        let gas = read_u64(data, &mut pos)?;
        always_accumulate.insert(service_id, gas);
    }

    Ok(PrivilegedServices {
        manager,
        assigner,
        designator,
        registrar,
        always_accumulate,
    })
}

fn deserialize_statistics(data: &[u8], config: &Config) -> Result<ValidatorStatistics, String> {
    let mut pos = 0;
    let v = config.validators_count as usize;
    let c = config.core_count as usize;

    // π_V: V records, E_4
    let current = deserialize_validator_records_e4(data, &mut pos, v)?;

    // π_L: V records, E_4
    let last = deserialize_validator_records_e4(data, &mut pos, v)?;

    // π_C: C core records, compact-encoded (GP field order: d, p, i, x, z, e, l, u)
    let mut core_stats = Vec::with_capacity(c);
    for _ in 0..c {
        let da_load = decode_compact(data, &mut pos)?;
        let popularity = decode_compact(data, &mut pos)?;
        let imports = decode_compact(data, &mut pos)?;
        let extrinsic_count = decode_compact(data, &mut pos)?;
        let extrinsic_size = decode_compact(data, &mut pos)?;
        let exports = decode_compact(data, &mut pos)?;
        let bundle_size = decode_compact(data, &mut pos)?;
        let gas_used = decode_compact(data, &mut pos)?;
        core_stats.push(CoreStatistics {
            da_load,
            popularity,
            imports,
            extrinsic_count,
            extrinsic_size,
            exports,
            bundle_size,
            gas_used,
        });
    }

    // π_S: sorted map (GP field order: p, r, i, x, z, e, a)
    let s_count = decode_compact(data, &mut pos)? as usize;
    let mut service_stats = BTreeMap::new();
    for _ in 0..s_count {
        let service_id = read_u32(data, &mut pos)?;
        let provided_count = decode_compact(data, &mut pos)?;
        let provided_size = decode_compact(data, &mut pos)?;
        let refinement_count = decode_compact(data, &mut pos)?;
        let refinement_gas_used = decode_compact(data, &mut pos)?;
        let imports = decode_compact(data, &mut pos)?;
        let extrinsic_count = decode_compact(data, &mut pos)?;
        let extrinsic_size = decode_compact(data, &mut pos)?;
        let exports = decode_compact(data, &mut pos)?;
        let accumulate_count = decode_compact(data, &mut pos)?;
        let accumulate_gas_used = decode_compact(data, &mut pos)?;
        service_stats.insert(
            service_id,
            ServiceStatistics {
                provided_count,
                provided_size,
                refinement_count,
                refinement_gas_used,
                imports,
                extrinsic_count,
                extrinsic_size,
                exports,
                accumulate_count,
                accumulate_gas_used,
            },
        );
    }

    Ok(ValidatorStatistics {
        current,
        last,
        core_stats,
        service_stats,
    })
}

fn deserialize_validator_records_e4(
    data: &[u8],
    pos: &mut usize,
    count: usize,
) -> Result<Vec<ValidatorRecord>, String> {
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        let blocks_produced = read_u32(data, pos)?;
        let tickets_introduced = read_u32(data, pos)?;
        let preimages_introduced = read_u32(data, pos)?;
        let preimage_bytes = read_u32(data, pos)? as u64;
        let reports_guaranteed = read_u32(data, pos)?;
        let assurances_made = read_u32(data, pos)?;
        records.push(ValidatorRecord {
            blocks_produced,
            tickets_introduced,
            preimages_introduced,
            preimage_bytes,
            reports_guaranteed,
            assurances_made,
        });
    }
    Ok(records)
}

#[allow(clippy::type_complexity)]
fn deserialize_accumulation_queue(
    data: &[u8],
    config: &Config,
) -> Result<Vec<Vec<(grey_types::work::WorkReport, Vec<Hash>)>>, String> {
    let mut pos = 0;
    let e = config.epoch_length as usize;
    let mut queue = Vec::with_capacity(e);

    for _ in 0..e {
        let inner_count = decode_compact(data, &mut pos)? as usize;
        let mut inner = Vec::with_capacity(inner_count);
        for _ in 0..inner_count {
            let report = deserialize_work_report(data, &mut pos)?;
            let dep_count = decode_compact(data, &mut pos)? as usize;
            let mut deps = Vec::with_capacity(dep_count);
            for _ in 0..dep_count {
                deps.push(read_hash(data, &mut pos)?);
            }
            inner.push((report, deps));
        }
        queue.push(inner);
    }

    Ok(queue)
}

fn deserialize_accumulation_history(
    data: &[u8],
    config: &Config,
) -> Result<Vec<Vec<Hash>>, String> {
    let mut pos = 0;
    let e = config.epoch_length as usize;
    let mut history = Vec::with_capacity(e);

    for _ in 0..e {
        let count = decode_compact(data, &mut pos)? as usize;
        let mut hashes = Vec::with_capacity(count);
        for _ in 0..count {
            hashes.push(read_hash(data, &mut pos)?);
        }
        history.push(hashes);
    }

    Ok(history)
}

fn deserialize_accumulation_outputs(data: &[u8]) -> Result<Vec<(ServiceId, Hash)>, String> {
    let mut pos = 0;
    let count = decode_compact(data, &mut pos)? as usize;
    let mut outputs = Vec::with_capacity(count);
    for _ in 0..count {
        let service_id = read_u32(data, &mut pos)?;
        let hash = read_hash(data, &mut pos)?;
        outputs.push((service_id, hash));
    }
    Ok(outputs)
}

fn deserialize_service_account(data: &[u8]) -> Result<ServiceAccount, String> {
    let mut pos = 0;

    if pos >= data.len() {
        return Err("service account data empty".into());
    }
    let _version = data[pos];
    pos += 1;

    let code_hash = read_hash(data, &mut pos)?;
    let balance = read_u64(data, &mut pos)?;
    let min_accumulate_gas = read_u64(data, &mut pos)?;
    let min_on_transfer_gas = read_u64(data, &mut pos)?;
    let total_footprint = read_u64(data, &mut pos)?;
    let free_storage_offset = read_u64(data, &mut pos)?;
    let accumulation_counter = read_u32(data, &mut pos)?;
    let last_accumulation = read_u32(data, &mut pos)?;
    let last_activity = read_u32(data, &mut pos)?;
    let preimage_count = read_u32(data, &mut pos)?;

    Ok(ServiceAccount {
        code_hash,
        balance,
        min_accumulate_gas,
        min_on_transfer_gas,
        storage: BTreeMap::new(),
        preimage_lookup: BTreeMap::new(),
        preimage_info: BTreeMap::new(),
        total_footprint,
        free_storage_offset,
        accumulation_counter,
        last_accumulation,
        last_activity,
        preimage_count,
    })
}
