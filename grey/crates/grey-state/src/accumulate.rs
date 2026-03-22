//! Accumulate sub-transition (Section 12 of the Gray Paper).
//!
//! Manages the work-report accumulation queue, dependency resolution,
//! and PVM execution of service Accumulate code (ΨA).

use crate::pvm_backend::{ExitReason, PvmInstance};
use grey_types::config::Config;
use grey_types::constants::{
    HOST_CASH, HOST_CORE, HOST_FULL, HOST_HUH, HOST_LOW, HOST_NONE, HOST_OK, HOST_WHAT,
    HOST_WHO,
};
use grey_types::work::{WorkReport, WorkResult};
use grey_types::{Hash, ServiceId, Timeslot};
use javm::Gas;
use std::collections::{BTreeMap, BTreeSet};

/// Decode preimage_info timeslots from compact-encoded raw bytes.
/// Format: compact_len(count) + count × E_4(timeslot).
pub fn decode_preimage_info_timeslots(data: &[u8]) -> Vec<Timeslot> {
    if data.is_empty() {
        return vec![];
    }
    let mut pos = 0;
    let count = match grey_codec::decode_compact_at(data, &mut pos) {
        Ok(n) => n as usize,
        Err(_) => return vec![],
    };
    let mut timeslots = Vec::with_capacity(count);
    for _ in 0..count {
        if pos + 4 > data.len() {
            break;
        }
        let t = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;
        timeslots.push(t);
    }
    timeslots
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A queued work report with unfulfilled dependency hashes (eq 12.3).
#[derive(Clone, Debug)]
pub struct ReadyRecord {
    pub report: WorkReport,
    pub dependencies: Vec<Hash>,
}

/// Service account for the accumulate sub-transition.
/// Matches the test vector schema (distinct from the shared grey_types::state::ServiceAccount).
#[derive(Clone, Debug)]
pub struct AccServiceAccount {
    pub version: u8,
    pub code_hash: Hash,
    pub balance: u64,
    pub min_item_gas: Gas,
    pub min_memo_gas: Gas,
    pub bytes: u64,
    pub deposit_offset: u64,
    pub items: u64,
    pub creation_slot: Timeslot,
    pub last_accumulation_slot: Timeslot,
    pub parent_service: ServiceId,
    /// Storage dictionary (key -> value).
    pub storage: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Preimage lookup dictionary (hash -> data).
    pub preimage_lookup: BTreeMap<Hash, Vec<u8>>,
    /// Preimage info/requests ((hash, length) -> timeslots).
    pub preimage_info: BTreeMap<(Hash, u32), Vec<Timeslot>>,
    /// Opaque service data entries (state key -> value) from initial deserialization.
    /// Used for fallback lookups when storage/preimage maps are incomplete.
    pub opaque_data: BTreeMap<[u8; 31], Vec<u8>>,
}

/// Privileged service indices (eq 9.9), matching test vector format.
#[derive(Clone, Debug, Default)]
pub struct AccPrivileges {
    pub bless: ServiceId,
    pub assign: Vec<ServiceId>,
    pub designate: ServiceId,
    pub register: ServiceId,
    pub always_acc: Vec<(ServiceId, Gas)>,
}

/// Per-service accumulation statistics.
#[derive(Clone, Debug, Default)]
pub struct AccServiceStats {
    pub provided_count: u32,
    pub provided_size: u64,
    pub refinement_count: u32,
    pub refinement_gas_used: Gas,
    pub imports: u32,
    pub extrinsic_count: u32,
    pub extrinsic_size: u64,
    pub exports: u32,
    pub accumulate_count: u32,
    pub accumulate_gas_used: Gas,
}

/// Accumulate sub-transition state (isolated for testability).
#[derive(Clone, Debug)]
pub struct AccumulateState {
    pub slot: Timeslot,
    pub entropy: Hash,
    /// ω: Ready queue — E slots of queued (report, deps) records.
    pub ready_queue: Vec<Vec<ReadyRecord>>,
    /// ξ: Accumulated history — E slots of work-package hashes.
    pub accumulated: Vec<Vec<Hash>>,
    pub privileges: AccPrivileges,
    pub statistics: Vec<(ServiceId, AccServiceStats)>,
    pub accounts: BTreeMap<ServiceId, AccServiceAccount>,
    /// φ: Auth queue changes from assign host call.
    /// Per-core: core_index -> (Q auth hashes, new assigner service ID).
    pub auth_queues: Option<BTreeMap<u16, (Vec<Hash>, ServiceId)>>,
    /// ι: Pending validators from designate host call.
    pub pending_validators: Option<Vec<Vec<u8>>>,
}

/// Input to the accumulate sub-transition.
pub struct AccumulateInput {
    pub slot: Timeslot,
    pub reports: Vec<WorkReport>,
}

/// Output of the accumulate sub-transition.
#[derive(Debug)]
pub struct AccumulateOutput {
    pub hash: Hash,
    /// Per-service yield outputs (service_id, yield_hash) — becomes θ.
    pub outputs: Vec<(ServiceId, Hash)>,
    /// Per-service gas usage from accumulation — needed for π_S statistics.
    pub gas_usage: Vec<(ServiceId, Gas)>,
    /// Accumulation statistics S (GP eq at line 1892):
    /// S[s] = (G(s), N(s)) where G = total gas, N = work item count.
    /// Only includes services where G(s) + N(s) ≠ 0.
    pub accumulation_stats: BTreeMap<ServiceId, (Gas, u32)>,
}

/// Deferred transfer between services (eq 12.16).
#[derive(Clone, Debug)]
pub struct DeferredTransfer {
    pub sender: ServiceId,
    pub destination: ServiceId,
    pub amount: u64,
    pub memo: Vec<u8>,
    pub gas_limit: Gas,
}

/// Output from single-service accumulation (Δ1).
#[derive(Clone, Debug)]
struct ServiceAccResult {
    accounts: BTreeMap<ServiceId, AccServiceAccount>,
    transfers: Vec<DeferredTransfer>,
    output: Option<Hash>,
    gas_used: Gas,
    privileges: AccPrivileges,
    /// Auth queues per core set by assign host call: core -> (Q hashes, new assigner SID).
    /// GP: (x'_e)_q[c] and (x'_e)_a[c] from ΩA (assign).
    auth_queues: Option<BTreeMap<u16, (Vec<Hash>, ServiceId)>>,
    /// Pending validator keys set by designate host call.
    /// GP: (x'_e)_i from ΩD (designate).
    pending_validators: Option<Vec<Vec<u8>>>,
}

// ---------------------------------------------------------------------------
// Queue Management (eq 12.1-12.12)
// ---------------------------------------------------------------------------

/// Compute dependency set for a work report (eq 12.6).
/// D(r) = {prerequisites} ∪ K(segment_root_lookup)
fn compute_dependencies(report: &WorkReport) -> Vec<Hash> {
    let mut deps = BTreeSet::new();
    for prereq in &report.context.prerequisites {
        deps.insert(*prereq);
    }
    for (pkg_hash, _root) in &report.segment_root_lookup {
        deps.insert(*pkg_hash);
    }
    deps.into_iter().collect()
}

/// Partition reports into immediate (R!) and queued (RQ) (eq 12.4-12.5).
/// R! = reports with no prerequisites and no segment imports.
/// RQ = reports with dependencies.
fn partition_reports(reports: &[WorkReport]) -> (Vec<WorkReport>, Vec<ReadyRecord>) {
    let mut immediate = Vec::new();
    let mut queued = Vec::new();
    for r in reports {
        let deps = compute_dependencies(r);
        if deps.is_empty() {
            immediate.push(r.clone());
        } else {
            queued.push(ReadyRecord {
                report: r.clone(),
                dependencies: deps,
            });
        }
    }
    (immediate, queued)
}

/// Extract work-package hashes from reports (eq 12.9).
fn package_hashes(reports: &[WorkReport]) -> BTreeSet<Hash> {
    reports.iter().map(|r| r.package_spec.package_hash).collect()
}

/// Queue editing function E (eq 12.7).
/// Removes entries whose report package hash is in `accumulated_set`,
/// and removes fulfilled dependencies from remaining entries.
fn edit_queue(queue: &[ReadyRecord], accumulated_set: &BTreeSet<Hash>) -> Vec<ReadyRecord> {
    queue
        .iter()
        .filter(|rr| !accumulated_set.contains(&rr.report.package_spec.package_hash))
        .map(|rr| ReadyRecord {
            report: rr.report.clone(),
            dependencies: rr
                .dependencies
                .iter()
                .filter(|d| !accumulated_set.contains(d))
                .cloned()
                .collect(),
        })
        .collect()
}

/// Priority queue resolution Q (eq 12.8).
/// Recursively finds reports with zero remaining dependencies.
fn resolve_queue(queue: &[ReadyRecord]) -> Vec<WorkReport> {
    // Find reports with empty dependency set
    let ready: Vec<WorkReport> = queue
        .iter()
        .filter(|rr| rr.dependencies.is_empty())
        .map(|rr| rr.report.clone())
        .collect();

    if ready.is_empty() {
        return vec![];
    }

    // Remove ready reports and edit remaining
    let ready_hashes = package_hashes(&ready);
    let remaining = edit_queue(queue, &ready_hashes);

    // Recursively resolve
    let mut result = ready;
    result.extend(resolve_queue(&remaining));
    result
}

/// Compute R* with newly queued reports included (eq 12.10-12.12).
fn compute_accumulatable_with_new(
    immediate: &[WorkReport],
    ready_queue: &[Vec<ReadyRecord>],
    new_queued: &[ReadyRecord],
    epoch_length: usize,
    slot_index: usize,
) -> Vec<WorkReport> {
    let mut all_queued: Vec<ReadyRecord> = Vec::new();

    // Rotate: start from slot_index, wrap around
    for i in 0..epoch_length {
        let idx = (slot_index + i) % epoch_length;
        if idx < ready_queue.len() {
            all_queued.extend(ready_queue[idx].iter().cloned());
        }
    }

    // Add new queued reports
    all_queued.extend(new_queued.iter().cloned());

    // Edit queue with immediate report hashes
    let immediate_hashes = package_hashes(immediate);
    let edited = edit_queue(&all_queued, &immediate_hashes);

    let queue_resolved = resolve_queue(&edited);
    eprintln!("accumulatable: immediate={} all_queued={} edited={} resolved={}", immediate.len(), all_queued.len(), edited.len(), queue_resolved.len());
    for (i, rr) in edited.iter().enumerate() {
        if rr.dependencies.len() <= 2 {
            eprintln!("  edited[{}]: deps={}", i, rr.dependencies.len());
        }
    }
    let mut result = immediate.to_vec();
    result.extend(queue_resolved);
    result
}

// ---------------------------------------------------------------------------
// PVM Accumulation (ΨA, Appendix B.4)
// ---------------------------------------------------------------------------

/// Accumulation context L (eq B.7-B.8).
#[derive(Clone, Debug)]
struct AccContext {
    service_id: ServiceId,
    accounts: BTreeMap<ServiceId, AccServiceAccount>,
    /// Initial (pre-accumulation) snapshot for parallel read semantics.
    /// host_read/host_info on OTHER services read from this snapshot.
    init_accounts: BTreeMap<ServiceId, AccServiceAccount>,
    next_service_id: ServiceId,
    transfers: Vec<DeferredTransfer>,
    output: Option<Hash>,
    _preimage_provisions: Vec<(ServiceId, Vec<u8>)>,
    privileges: AccPrivileges,
    /// Pending validator keys set by designate host call (ι).
    pending_validators: Option<Vec<Vec<u8>>>,
    /// Auth queues per core set by assign host call.
    auth_queues: Option<BTreeMap<u16, (Vec<Hash>, ServiceId)>>,
}

/// Run PVM accumulation for a single service (Δ1, eq 12.24).
fn accumulate_single_service(
    config: &Config,
    accounts: &BTreeMap<ServiceId, AccServiceAccount>,
    init_accounts: &BTreeMap<ServiceId, AccServiceAccount>,
    transfers: &[DeferredTransfer],
    reports: &[WorkReport],
    privileges: &AccPrivileges,
    service_id: ServiceId,
    timeslot: Timeslot,
    entropy: &Hash,
    fetch_ctx: &FetchContext,
) -> ServiceAccResult {
    let _account = match accounts.get(&service_id) {
        Some(a) => a,
        None => {
            return ServiceAccResult {
                accounts: accounts.clone(),
                transfers: vec![],
                output: None,
                gas_used: 0,
                privileges: privileges.clone(),
                auth_queues: None,
                pending_validators: None,
            };
        }
    };

    // Compute gas budget: free_gas + transfer_gas + operand_gas
    let free_gas: Gas = privileges
        .always_acc
        .iter()
        .find(|(s, _)| *s == service_id)
        .map(|(_, g)| *g)
        .unwrap_or(0);

    let transfer_gas: Gas = transfers
        .iter()
        .filter(|t| t.destination == service_id)
        .map(|t| t.gas_limit)
        .sum();

    let operand_gas: Gas = reports
        .iter()
        .flat_map(|r| r.results.iter())
        .filter(|d| d.service_id == service_id)
        .map(|d| d.accumulate_gas)
        .sum();

    let total_gas = free_gas
        .saturating_add(transfer_gas)
        .saturating_add(operand_gas);

    if total_gas == 0 && transfers.iter().all(|t| t.destination != service_id) {
        return ServiceAccResult {
            accounts: accounts.clone(),
            transfers: vec![],
            output: None,
            gas_used: 0,
            privileges: privileges.clone(),
            auth_queues: None,
            pending_validators: None,
        };
    }

    // Initialize accumulation context (regular dimension x)
    // Credit incoming transfers to balance first (eq B.9)
    let mut initial_accounts = accounts.clone();
    let transfer_balance: u64 = transfers
        .iter()
        .filter(|t| t.destination == service_id)
        .map(|t| t.amount)
        .sum();
    if let Some(acc) = initial_accounts.get_mut(&service_id) {
        if transfer_balance > 0 {
        }
        acc.balance = acc.balance.saturating_add(transfer_balance);
    }

    // Compute next available service ID (eq B.10)
    // i = S + (H(E_4(s) ++ η'_0 ++ E_4(τ')) mod (2^32 - S - 2^8))
    let s_threshold = grey_types::constants::MIN_PUBLIC_SERVICE_INDEX; // S = 2^16 (GP I.4.4)
    let hash_input = encode_new_service_hash(service_id, entropy, timeslot);
    let hash_bytes = grey_crypto::blake2b_256(&hash_input);
    let range = u32::MAX - s_threshold - 255; // 2^32 - S - 2^8
    // E^{-1}_4(H(...)): first 4 bytes as LE u32
    let hash_val = u32::from_le_bytes([hash_bytes.0[0], hash_bytes.0[1], hash_bytes.0[2], hash_bytes.0[3]]);
    let next_service_id = s_threshold + (hash_val % range);
    // check(): ensure not already in use, advance if needed
    let next_service_id = find_free_service_id(next_service_id, &initial_accounts, s_threshold);

    let regular = AccContext {
        service_id,
        accounts: initial_accounts.clone(),
        init_accounts: init_accounts.clone(),
        next_service_id,
        transfers: vec![],
        output: None,
        _preimage_provisions: vec![],
        privileges: privileges.clone(),
        pending_validators: None,
        auth_queues: None,
    };
    let exceptional = regular.clone();

    // Count items for this service (transfers to + work digests for)
    let transfer_count = transfers.iter().filter(|t| t.destination == service_id).count();
    let work_count: usize = reports.iter().flat_map(|r| &r.results).filter(|d| d.service_id == service_id).count();
    let item_count = (transfer_count + work_count) as u32;

    // Encode minimal argument blob: varint(timeslot, service_id, item_count)
    let args = encode_accumulate_args(timeslot, service_id, item_count);

    // Build per-service fetch context with encoded items
    let items_blob = build_items_blob(transfers, service_id, reports);
    // Build individual items for fetch mode 15
    let mut individual_items: Vec<Vec<u8>> = Vec::new();
    for t in transfers.iter().filter(|t| t.destination == service_id) {
        let mut item = vec![1u8]; // transfer discriminator
        item.extend(encode_transfer(t));
        individual_items.push(item);
    }
    for report in reports {
        for digest in &report.results {
            if digest.service_id == service_id {
                let mut item = vec![0u8]; // operand discriminator
                item.extend(encode_operand(report, digest));
                individual_items.push(item);
            }
        }
    }


    let service_fetch_ctx = FetchContext {
        config_blob: fetch_ctx.config_blob.clone(),
        entropy: fetch_ctx.entropy,
        items_blob,
        items: individual_items,
    };

    // Look up code blob from preimage_lookup using code_hash
    let code_blob = initial_accounts
        .get(&service_id)
        .and_then(|a| a.preimage_lookup.get(&a.code_hash).cloned());

    if code_blob.is_none() {
        // No code available: credit transfers but skip PVM execution.
        tracing::warn!(service_id, "accumulate: no code blob found for service, skipping PVM execution");
        return ServiceAccResult {
            accounts: initial_accounts,
            transfers: vec![],
            output: None,
            gas_used: 0,
            privileges: privileges.clone(),
            auth_queues: None,
            pending_validators: None,
        };
    }
    let code_blob = code_blob.unwrap();


    // Run PVM
    let (final_context, gas_used) =
        run_accumulate_pvm(config, &code_blob, total_gas, &args, regular, exceptional, timeslot, entropy, &service_fetch_ctx);

    tracing::debug!(service_id, gas_used, total_gas, "accumulate PVM execution complete");


    ServiceAccResult {
        accounts: final_context.accounts,
        transfers: final_context.transfers,
        output: final_context.output,
        gas_used,
        privileges: final_context.privileges,
        auth_queues: final_context.auth_queues,
        pending_validators: final_context.pending_validators,
    }
}

/// Encode arguments for ΨA invocation (Gray Paper eq B.9).
/// Format: varint(timeslot) ⌢ varint(service_id) ⌢ varint(item_count)
/// Items are accessed via fetch host call, NOT the argument blob.
fn encode_accumulate_args(
    timeslot: Timeslot,
    service_id: ServiceId,
    item_count: u32,
) -> Vec<u8> {
    let mut args = Vec::new();
    grey_codec::encode::encode_natural(timeslot as usize, &mut args);
    grey_codec::encode::encode_natural(service_id as usize, &mut args);
    grey_codec::encode::encode_natural(item_count as usize, &mut args);
    args
}

/// Encode a single work-item operand (type U, eq:operandtuple).
/// EU(x) ≡ E(xp, xe, xa, xy, xg, O(xl), ↕xt)
fn encode_operand(
    report: &WorkReport,
    digest: &grey_types::work::WorkDigest,
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&report.package_spec.package_hash.0); // p: 32 bytes
    buf.extend_from_slice(&report.package_spec.exports_root.0); // e: 32 bytes
    buf.extend_from_slice(&report.authorizer_hash.0);           // a: 32 bytes
    buf.extend_from_slice(&digest.payload_hash.0);              // y: 32 bytes
    grey_codec::encode::encode_natural(digest.accumulate_gas as usize, &mut buf); // g: varint
    // O(xl) - result encoding (GP C.5: discriminated union)
    match &digest.result {
        WorkResult::Ok(data) => {
            buf.push(0);
            grey_codec::encode::encode_natural(data.len(), &mut buf);
            buf.extend_from_slice(data);
        }
        WorkResult::OutOfGas => buf.push(1),
        WorkResult::Panic => buf.push(2),
        WorkResult::BadExports => buf.push(3),
        WorkResult::BadCode => buf.push(4),
        WorkResult::CodeOversize => buf.push(5),
    }
    // ↕xt - length-prefixed authorizer trace
    grey_codec::encode::encode_natural(report.auth_output.len(), &mut buf);
    buf.extend_from_slice(&report.auth_output);
    buf
}

/// Encode a single deferred transfer (type X, eq C.31).
/// EX(x) ≡ E(E4(xs), E4(xd), E8(xa), xm, E8(xg))
fn encode_transfer(t: &DeferredTransfer) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&t.sender.to_le_bytes());      // E4(sender)
    buf.extend_from_slice(&t.destination.to_le_bytes());  // E4(dest)
    buf.extend_from_slice(&t.amount.to_le_bytes());       // E8(amount)
    // Memo: fixed 128 bytes (padded with zeros)
    let mut memo = [0u8; 128];
    let copy_len = t.memo.len().min(128);
    memo[..copy_len].copy_from_slice(&t.memo[..copy_len]);
    buf.extend_from_slice(&memo);                          // memo: 128 bytes
    buf.extend_from_slice(&t.gas_limit.to_le_bytes());    // E8(gas_limit)
    buf
}

/// Build encoded items list for fetch (eq C.33).
/// Items are discriminated: 0x00 + EU(operand) or 0x01 + EX(transfer).
/// Order: transfers first (iT), then operands (iU).
fn build_items_blob(
    transfers: &[DeferredTransfer],
    service_id: ServiceId,
    reports: &[WorkReport],
) -> Vec<u8> {
    let mut items: Vec<Vec<u8>> = Vec::new();
    // iT: transfers to this service
    for t in transfers.iter().filter(|t| t.destination == service_id) {
        let mut item = vec![1u8]; // transfer discriminator
        item.extend(encode_transfer(t));
        items.push(item);
    }
    // iU: work-item operands for this service
    for report in reports {
        for digest in &report.results {
            if digest.service_id == service_id {
                let mut item = vec![0u8]; // operand discriminator
                item.extend(encode_operand(report, digest));
                items.push(item);
            }
        }
    }
    // Encode as length-prefixed sequence: varint(count) + item_0 + item_1 + ...
    let mut blob = Vec::new();
    grey_codec::encode::encode_natural(items.len(), &mut blob);
    for item in &items {
        blob.extend(item);
    }
    blob
}

/// Encode hash input for new service ID computation.
fn encode_new_service_hash(service_id: ServiceId, entropy: &Hash, timeslot: Timeslot) -> Vec<u8> {
    // GP eq: E(s, η'_0, H_T) — uses JAM general encoding (compact naturals for numbers)
    let mut buf = Vec::new();
    grey_codec::encode::encode_compact(service_id as u64, &mut buf);
    buf.extend_from_slice(&entropy.0);
    grey_codec::encode::encode_compact(timeslot as u64, &mut buf);
    buf
}

/// Data available to the fetch host call during accumulation.
struct FetchContext {
    /// Protocol configuration blob (mode 0).
    config_blob: Vec<u8>,
    /// Entropy hash η'_0 (mode 1).
    entropy: Hash,
    /// Encoded items blob for modes 14/15.
    items_blob: Vec<u8>,
    /// Individual encoded items (discriminated).
    items: Vec<Vec<u8>>,
}

/// Run PVM accumulation with host-call loop.
fn run_accumulate_pvm(
    config: &Config,
    code_blob: &[u8],
    gas: Gas,
    args: &[u8],
    mut regular: AccContext,
    mut exceptional: AccContext,
    timeslot: Timeslot,
    entropy: &Hash,
    fetch_ctx: &FetchContext,
) -> (AccContext, Gas) {
    // Initialize PVM
    let mut pvm = match PvmInstance::initialize(code_blob, args, gas) {
        Some(p) => p,
        None => {
            return (exceptional, 0);
        }
    };

    // Set entry point: ΨM(c, 5, ...) starts at instruction counter 5 for accumulate
    pvm.set_pc(5);
    let initial_gas = pvm.gas();
    let mut _host_call_count = 0u32;

    loop {
        let gas_before = pvm.gas();
        let exit_reason = pvm.run();
        let gas_after = pvm.gas();
        eprintln!("exit={:?} pc={} gas_consumed={} remaining={}", exit_reason, pvm.pc(), gas_before - gas_after, gas_after);

        match exit_reason {
            ExitReason::Halt => {
                let gas_used = initial_gas - pvm.gas();

                // GP Ψ_M (eq A.36): On halt, o = μ'[φ'_7..φ'_7+φ'_8] if
                // N_{φ'_7 ..+ φ'_8} ⊆ V_{μ'}.  Registers are 64-bit, addresses
                // are 32-bit, so the full u64 range must fit in [0, 2^32).
                // GP completion function C: If o ∈ H (|o| = 32), yield = o.
                let out_ptr = pvm.reg(7);
                let out_len = pvm.reg(8);
                if out_len == 32
                    && out_ptr.checked_add(32).map_or(false, |end| end <= (1u64 << 32))
                {
                    let ptr32 = out_ptr as u32;
                    let mut bytes = [0u8; 32];
                    let mut accessible = true;
                    for i in 0..32u32 {
                        match pvm.read_byte(ptr32 + i) {
                            Some(b) => bytes[i as usize] = b,
                            None => { accessible = false; break; }
                        }
                    }
                    if accessible {
                        regular.output = Some(grey_types::Hash(bytes));
                    }
                }

                return (regular, gas_used);
            }
            ExitReason::Panic => {
                let gas_used = initial_gas - pvm.gas();
                return (exceptional, gas_used);
            }
            ExitReason::OutOfGas => {
                let gas_used = initial_gas;
                return (exceptional, gas_used);
            }
            ExitReason::PageFault(_addr) => {
                let gas_used = initial_gas - pvm.gas();
                return (exceptional, gas_used);
            }
            ExitReason::HostCall(id) => {
                _host_call_count += 1;
                let _gas_before_host = pvm.gas();
                let ok = handle_host_call(
                    config,
                    id,
                    &mut pvm,
                    &mut regular,
                    &mut exceptional,
                    timeslot,
                    entropy,
                    fetch_ctx,
                );
                let _gas_after_host = pvm.gas();
                if !ok {
                    let gas_used = initial_gas - pvm.gas();
                    return (exceptional, gas_used);
                }
            }
        }
    }
}

/// Handle a host call from the PVM during accumulation.
/// Returns true to continue, false to abort.
fn handle_host_call(
    config: &Config,
    id: u32,
    pvm: &mut PvmInstance,
    regular: &mut AccContext,
    exceptional: &mut AccContext,
    timeslot: Timeslot,
    _entropy: &Hash,
    fetch_ctx: &FetchContext,
) -> bool {
    // JAR v0.8.0 hostcall numbering: 0=gas, 1=grow_heap(new), 2+=shifted by 1.
    // Host-call gas cost: all host calls cost g=10 (charged upfront).
    let host_gas_cost: u64 = 10;

    if pvm.gas() < host_gas_cost {
        pvm.set_gas(0);
        return false;
    }
    pvm.set_gas(pvm.gas() - host_gas_cost);

    // JAR v0.8.0 ID mapping: 0→gas, 1→grow_heap, 2..=27→old 1..=26, 100→log
    let result = match id {
        0 => host_gas(pvm, regular),
        1 => host_grow_heap(pvm),
        2 => host_fetch(pvm, fetch_ctx),
        3 => host_lookup(pvm, regular),
        4 => host_read(pvm, regular),
        5 => host_write(pvm, regular),
        6 => host_info(pvm, regular),
        15 => host_bless(pvm, regular, exceptional, config),
        16 => host_assign(pvm, regular, exceptional, config),
        17 => host_designate(pvm, regular, exceptional, config),
        18 => host_checkpoint(pvm, regular, exceptional),
        19 => host_new(pvm, regular, timeslot),
        20 => host_upgrade(pvm, regular),
        21 => host_transfer(pvm, regular),
        22 => host_eject(pvm, regular, timeslot, config),
        23 => host_query(pvm, regular),
        24 => host_solicit(pvm, regular, timeslot),
        25 => host_forget(pvm, regular, timeslot, config),
        26 => host_yield(pvm, regular),
        27 => host_provide(pvm, regular),
        100 => {
            pvm.set_reg(7, HOST_WHAT);
            true
        }
        _ => {
            pvm.set_reg(7, HOST_WHAT);
            true
        }
    };

    result
}

/// gas (id=0): Return remaining gas in φ[7].
fn host_gas(pvm: &mut PvmInstance, _ctx: &mut AccContext) -> bool {
    pvm.set_reg(7, pvm.gas());
    true
}

/// grow_heap (JAR v0.8.0, id=1): Grow the heap to a desired page count.
/// φ[7] = desired last writable page index + 1 (i.e. target page count).
/// Returns in φ[7]: current page count (before or after growth).
/// Extra gas cost: (new_pages - current_pages) × 10.
fn host_grow_heap(pvm: &mut PvmInstance) -> bool {
    let desired = pvm.reg(7);
    let ps = javm::PVM_PAGE_SIZE;
    let current_pages = (pvm.heap_top() as u64 + ps as u64 - 1) / ps as u64;
    eprintln!("grow_heap: desired={} current_pages={} heap_top={}", desired, current_pages, pvm.heap_top());

    if desired <= current_pages || desired > (1u64 << 32) / ps as u64 {
        // No-op: already at or beyond desired, or exceeds address space
        pvm.set_reg(7, current_pages);
        return true;
    }

    let new_pages = desired - current_pages;
    let extra_gas = new_pages * 10;
    if pvm.gas() < extra_gas {
        pvm.set_gas(0);
        return false; // OOG
    }
    pvm.set_gas(pvm.gas() - extra_gas);

    // Map new pages as ReadWrite
    let old_top = pvm.heap_top();
    let new_top = (desired as u32) * ps;
    pvm.map_pages_rw(old_top / ps, desired as u32);
    pvm.set_heap_top(new_top);

    pvm.set_reg(7, current_pages);
    true
}

/// fetch (id=2 in v0.8.0): Read protocol/context data (ΩY).
/// φ[7]=buffer_ptr, φ[8]=offset, φ[9]=max_len, φ[10]=mode, φ[11]=sub1, φ[12]=sub2
/// Returns: φ'[7] = |v| (total data length) or NONE (u64::MAX).
fn host_fetch(pvm: &mut PvmInstance, fetch_ctx: &FetchContext) -> bool {
    let buf_ptr = pvm.reg(7) as u32;
    let offset = pvm.reg(8);
    let max_len = pvm.reg(9);
    let mode = pvm.reg(10);
    let sub1 = pvm.reg(11) as usize;
    // Select data based on mode (accumulate context: modes 0, 1, 14, 15)
    // GP line 3943: Ω_Y(ρ, φ, μ, ∅, η_0', ∅, ∅, ∅, ∅, i, (x, y))
    // Position 5 = η_0' maps to mode 1 (n).
    // Modes 2-13 NONE (r, p, x̄, ī all ∅ in accumulate context).
    let owned_data: Option<Vec<u8>>;
    let data: Option<&[u8]> = match mode {
        0 => Some(&fetch_ctx.config_blob),        // Protocol configuration
        1 => Some(&fetch_ctx.entropy.0),           // Entropy η'_0
        14 => Some(&fetch_ctx.items_blob),         // All items encoded
        15 => {                                     // Single item at index φ[11]
            if sub1 < fetch_ctx.items.len() {
                owned_data = Some(fetch_ctx.items[sub1].clone());
                owned_data.as_deref()
            } else {
                None
            }
        }
        _ => None,
    };

    let data = match data {
        Some(d) => d,
        None => {
            pvm.set_reg(7, u64::MAX); // NONE
            return true;
        }
    };

    let data_len = data.len() as u64;
    let f = offset.min(data_len);
    let l = max_len.min(data_len - f);


    // Dump hex for debugging
    if mode == 0 {
    } else if mode == 1 {
    } else if mode == 14 && data.len() <= 512 {
    } else if mode == 15 && data.len() <= 512 {
        if data.len() > 134 {
        }
    }

    // Write data[f..f+l] to memory at buf_ptr
    if l > 0 {
        let src = &data[f as usize..(f + l) as usize];
        if pvm.try_write_bytes(buf_ptr, src).is_none() {
            return false; // page fault → PANIC
        }
    }

    // Return total length of the data
    pvm.set_reg(7, data_len);
    true
}

/// read (id=3): Read from service storage.
/// φ[7] = service_id (or if ≥ 2^32, defaults to current service s),
/// φ[8] = key_ptr, φ[9] = key_len,
/// φ[10] = output_ptr, φ[11] = output_max_len
/// Returns: φ[7] = value_len or NONE
fn host_read(pvm: &mut PvmInstance, ctx: &mut AccContext) -> bool {
    // GP eq B.14: s* = s if φ₇ = NONE, else φ₇
    let service_id = if pvm.reg(7) == u64::MAX {
        ctx.service_id
    } else if pvm.reg(7) <= u32::MAX as u64 {
        pvm.reg(7) as ServiceId
    } else {
        pvm.set_reg(7, u64::MAX); // NONE
        return true;
    };
    let key_ptr = pvm.reg(8) as u32;
    let key_len = pvm.reg(9) as u32;
    let out_ptr = pvm.reg(10) as u32;
    let offset = pvm.reg(11);
    let max_len = pvm.reg(12);

    let key = match pvm.try_read_bytes(key_ptr, key_len) {
        Some(k) => k,
        None => return false, // page fault → PANIC
    };

    // For parallel semantics: read self from mutable accounts, others from init snapshot
    let target_accounts = if service_id == ctx.service_id {
        &mut ctx.accounts
    } else {
        &mut ctx.init_accounts
    };
    if let Some(account) = target_accounts.get_mut(&service_id) {
        // Check structured storage first, then fall back to opaque data
        let value = if let Some(v) = account.storage.get(&key) {
            Some(v.clone())
        } else {
            // Look up in opaque data by computing expected state key
            let state_key =
                grey_merkle::state_serial::compute_storage_state_key(service_id, &key);
            if let Some(v) = account.opaque_data.remove(&state_key) {
                // Promote from opaque to structured storage
                account.storage.insert(key.clone(), v.clone());
                Some(v)
            } else {
                None
            }
        };

        if let Some(value) = value {
            let v_len = value.len() as u64;
            let f = offset.min(v_len) as usize;
            let l = max_len.min(v_len - f as u64) as usize;
            if l > 0 {
                if pvm.try_write_bytes(out_ptr, &value[f..f + l]).is_none() {
                    return false; // page fault → PANIC
                }
            }
            pvm.set_reg(7, v_len);
        } else {
            pvm.set_reg(7, u64::MAX); // NONE
        }
    } else {
        pvm.set_reg(7, u64::MAX); // NONE
    }

    true
}

/// write (id=4): Write to current service's storage.
/// φ[7] = key_ptr, φ[8] = key_len, φ[9] = value_ptr, φ[10] = value_len
/// Returns: φ[7] = OK(0) or error
fn host_write(pvm: &mut PvmInstance, ctx: &mut AccContext) -> bool {

    let key_ptr = pvm.reg(7) as u32;
    let key_len = pvm.reg(8) as u32;
    let value_ptr = pvm.reg(9) as u32;
    let value_len = pvm.reg(10) as u32;

    let key = match pvm.try_read_bytes(key_ptr, key_len) {
        Some(k) => k,
        None => return false, // page fault → PANIC
    };
    let value = match pvm.try_read_bytes(value_ptr, value_len) {
        Some(v) => v,
        None => return false, // page fault → PANIC
    };

    if let Some(account) = ctx.accounts.get_mut(&ctx.service_id) {
        // Promote from opaque data if not in structured storage
        if !account.storage.contains_key(&key) {
            let state_key = grey_merkle::state_serial::compute_storage_state_key(
                ctx.service_id, &key,
            );
            if let Some(v) = account.opaque_data.remove(&state_key) {
                account.storage.insert(key.clone(), v);
            }
        }

        let old_len: u64 = account
            .storage
            .get(&key)
            .map(|v| v.len() as u64)
            .unwrap_or(u64::MAX);

        let old_size: u64 = account
            .storage
            .get(&key)
            .map(|v| (34 + key.len() + v.len()) as u64)
            .unwrap_or(0);

        let new_bytes;
        let new_items;
        if value_len == 0 {
            if account.storage.contains_key(&key) {
                new_bytes = account.bytes.saturating_sub(old_size);
                new_items = account.items.saturating_sub(1);
            } else {
                new_bytes = account.bytes;
                new_items = account.items;
            }
        } else {
            let new_size = (34 + key.len() + value.len()) as u64;
            let was_new = !account.storage.contains_key(&key);
            new_bytes = account.bytes.saturating_sub(old_size).saturating_add(new_size);
            new_items = if was_new { account.items + 1 } else { account.items };
        }

        let threshold = {
            let raw = grey_types::constants::BALANCE_SERVICE_MINIMUM as i64
                + grey_types::constants::BALANCE_PER_ITEM as i64 * new_items as i64
                + grey_types::constants::BALANCE_PER_OCTET as i64 * new_bytes as i64
                - account.deposit_offset as i64;
            std::cmp::max(0, raw) as u64
        };
        if threshold > account.balance {
            pvm.set_reg(7, HOST_FULL);
            return true;
        }

        if value_len == 0 {
            if account.storage.remove(&key).is_some() {
                account.bytes = new_bytes;
                account.items = new_items;
            }
        } else {
            account.storage.insert(key, value);
            account.bytes = new_bytes;
            account.items = new_items;
        }
        pvm.set_reg(7, old_len);
    } else {
        pvm.set_reg(7, u64::MAX);
    }

    true
}

/// info (id=5): Get service account info (GP eq ΩI).
/// φ[7] = service_id (or 2^64-1 for current service s)
/// φ[8] = output_ptr (o), φ[9] = offset (f), φ[10] = max_len (l)
/// Returns φ[7] = |v| (total info length) or NONE
fn host_info(pvm: &mut PvmInstance, ctx: &mut AccContext) -> bool {
    let service_id = if pvm.reg(7) == u64::MAX {
        ctx.service_id
    } else if pvm.reg(7) <= u32::MAX as u64 {
        pvm.reg(7) as ServiceId
    } else {
        pvm.set_reg(7, u64::MAX); // NONE
        return true;
    };
    let out_ptr = pvm.reg(8) as u32;
    let offset = pvm.reg(9);
    let max_len = pvm.reg(10);

    // For parallel semantics: read self from mutable accounts, others from init snapshot
    let target = if service_id == ctx.service_id {
        ctx.accounts.get(&service_id)
    } else {
        ctx.init_accounts.get(&service_id)
    };
    if let Some(account) = target {
        // Build info struct v per GP:
        // E(a_c, E_8(a_b, a_t, a_g, a_m, a_o), E_4(a_i), E_8(a_f), E_4(a_r, a_a, a_p))
        // = 32 + 40 + 4 + 8 + 12 = 96 bytes
        let threshold = {
            let total = grey_types::constants::BALANCE_SERVICE_MINIMUM
                + grey_types::constants::BALANCE_PER_ITEM * account.items
                + grey_types::constants::BALANCE_PER_OCTET * account.bytes;
            total.saturating_sub(account.deposit_offset)
        };

        let mut buf = [0u8; 96];
        buf[0..32].copy_from_slice(&account.code_hash.0);       // a_c
        buf[32..40].copy_from_slice(&account.balance.to_le_bytes()); // a_b
        buf[40..48].copy_from_slice(&threshold.to_le_bytes());   // a_t
        buf[48..56].copy_from_slice(&account.min_item_gas.to_le_bytes()); // a_g
        buf[56..64].copy_from_slice(&account.min_memo_gas.to_le_bytes()); // a_m
        buf[64..72].copy_from_slice(&account.bytes.to_le_bytes()); // a_o
        buf[72..76].copy_from_slice(&(account.items as u32).to_le_bytes()); // a_i
        buf[76..84].copy_from_slice(&account.deposit_offset.to_le_bytes()); // a_f
        buf[84..88].copy_from_slice(&account.creation_slot.to_le_bytes()); // a_r
        buf[88..92].copy_from_slice(&account.last_accumulation_slot.to_le_bytes()); // a_a
        buf[92..96].copy_from_slice(&account.parent_service.to_le_bytes()); // a_p


        let v_len = buf.len() as u64;
        let f = offset.min(v_len);
        let l = max_len.min(v_len - f);

        if l > 0 {
            if pvm.try_write_bytes(out_ptr, &buf[f as usize..(f + l) as usize]).is_none() {
                return false; // page fault → PANIC
            }
        }
        pvm.set_reg(7, v_len); // return |v|
    } else {
        pvm.set_reg(7, u64::MAX); // NONE
    }

    true
}

/// checkpoint (id=17): Save rollback point. y ← x.
fn host_checkpoint(
    pvm: &mut PvmInstance,
    regular: &mut AccContext,
    exceptional: &mut AccContext,
) -> bool {
    *exceptional = regular.clone();
    pvm.set_reg(7, pvm.gas());
    true
}

/// transfer (id=20): Queue a deferred balance transfer (GP eq B.19-B.20).
/// φ[7] = dest, φ[8] = amount, φ[9] = gas_limit, φ[10] = memo_ptr
/// Memo is always exactly W_T (128) bytes read from memory at φ[10].
/// Returns: OK, WHO (dest unknown), LOW (gas < min), CASH (insufficient balance)
fn host_transfer(pvm: &mut PvmInstance, ctx: &mut AccContext) -> bool {
    const MEMO_SIZE: u32 = 128; // W_T

    let dest = pvm.reg(7) as ServiceId;
    let amount = pvm.reg(8);
    let gas_limit = pvm.reg(9);
    let memo_ptr = pvm.reg(10) as u32;

    let memo = match pvm.try_read_bytes(memo_ptr, MEMO_SIZE) {
        Some(m) => m,
        None => return false, // page fault → PANIC
    };

    if !ctx.accounts.contains_key(&dest) {
        pvm.set_reg(7, HOST_WHO);
        return true;
    }

    if let Some(dest_acc) = ctx.accounts.get(&dest) {
        if gas_limit < dest_acc.min_memo_gas {
            pvm.set_reg(7, HOST_LOW);
            return true;
        }
    }

    if let Some(account) = ctx.accounts.get(&ctx.service_id) {
        if account.balance < amount {
            pvm.set_reg(7, HOST_CASH);
            return true;
        }
    }

    if pvm.gas() < gas_limit {
        pvm.set_gas(0);
        return false;
    }
    pvm.set_gas(pvm.gas() - gas_limit);

    if let Some(account) = ctx.accounts.get_mut(&ctx.service_id) {
        account.balance -= amount;
    }

    ctx.transfers.push(DeferredTransfer {
        sender: ctx.service_id,
        destination: dest,
        amount,
        memo,
        gas_limit,
    });

    pvm.set_reg(7, 0); // OK
    true
}

/// eject (id=21): Eject a service (GP eq ΩJ, lines 4601-4621).
/// φ[7] = d (target service to eject), φ[8] = o (hash_ptr, 32 bytes)
/// Checks: code_hash must equal ℰ_{32}(caller), items must be 2,
/// (h,l) must be in preimage_info, and preimage must be old enough (y < t - D).
fn host_eject(pvm: &mut PvmInstance, ctx: &mut AccContext, timeslot: Timeslot, config: &Config) -> bool {
    let d = pvm.reg(7) as ServiceId;
    let o_ptr = pvm.reg(8) as u32;

    // Step 1: Read hash h from memory at o..o+32. PANIC if inaccessible.
    let hash_data = match pvm.try_read_bytes(o_ptr, 32) {
        Some(data) => data,
        None => return false, // page fault → PANIC (⚡)
    };
    let mut h = [0u8; 32];
    h.copy_from_slice(&hash_data);
    let h = Hash(h);

    // Step 2: Resolve target service account.
    // d = (x_e)_d[d] if d ≠ x_s ∧ d ∈ K((x_e)_d); else ∇
    let ejected = if d != ctx.service_id {
        ctx.accounts.get(&d)
    } else {
        None
    };

    // Step 3: WHO if d = ∇ OR d.code_hash ≠ ℰ₃₂(x_s)
    // ℰ₃₂(x_s) = 32-byte little-endian encoding of the caller's service ID
    let caller_id_encoded = {
        let mut buf = [0u8; 32];
        buf[..4].copy_from_slice(&ctx.service_id.to_le_bytes());
        Hash(buf)
    };

    let ejected = match ejected {
        Some(acc) if acc.code_hash == caller_id_encoded => acc,
        _ => {
            pvm.set_reg(7, HOST_WHO);
            return true;
        }
    };

    // Step 4: Compute l = max(81, d_o) - 81 (preimage data length from total footprint)
    let l = ejected.bytes.max(81) - 81;

    // Step 5: HUH if d.items ≠ 2
    if ejected.items != 2 {
        pvm.set_reg(7, HOST_HUH);
        return true;
    }

    let info_key = (h, l as u32);
    // Promote preimage_info from opaque if needed
    if !ejected.preimage_info.contains_key(&info_key) {
        let state_key = grey_merkle::state_serial::compute_preimage_info_state_key(d, &h, l as u32);
        if let Some(account) = ctx.accounts.get_mut(&d) {
            if let Some(v) = account.opaque_data.remove(&state_key) {
                let timeslots = decode_preimage_info_timeslots(&v);
                account.preimage_info.insert(info_key, timeslots);
            }
        }
    }

    // Re-borrow after mutable promotion
    let ejected = ctx.accounts.get(&d).unwrap();
    let timeslots = match ejected.preimage_info.get(&info_key) {
        Some(ts) => ts,
        None => {
            pvm.set_reg(7, HOST_HUH);
            return true;
        }
    };

    // Step 6: OK if d_l[(h,l)] = [x, y] and y < t - D; else HUH
    if timeslots.len() >= 2 {
        let y = timeslots[1];
        if y < timeslot.saturating_sub(config.preimage_expunge_period) {
            // Success: remove target, transfer balance to caller
            let ejected_balance = ctx.accounts.get(&d).unwrap().balance;
            ctx.accounts.remove(&d);
            if let Some(self_acc) = ctx.accounts.get_mut(&ctx.service_id) {
                self_acc.balance = self_acc.balance.saturating_add(ejected_balance);
            }
            pvm.set_reg(7, HOST_OK);
            return true;
        }
    }

    pvm.set_reg(7, HOST_HUH);
    true
}

/// yield (id=25): Set accumulation output hash.
/// φ[7] = hash_ptr (pointer to 32-byte hash in memory)
fn host_yield(pvm: &mut PvmInstance, ctx: &mut AccContext) -> bool {
    let hash_ptr = pvm.reg(7) as u32;

    let data = match pvm.try_read_bytes(hash_ptr, 32) {
        Some(d) => d,
        None => return false, // page fault → PANIC
    };
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&data);

    ctx.output = Some(Hash(hash));
    pvm.set_reg(7, 0); // OK
    true
}

/// lookup (id=2): Preimage lookup (GP ΩL).
/// φ[7] = service_id (or NONE for self), φ[8] = hash_ptr, φ[9] = output_ptr,
/// φ[10] = offset, φ[11] = max_len
fn host_lookup(pvm: &mut PvmInstance, ctx: &mut AccContext) -> bool {
    let service_id = if pvm.reg(7) == HOST_NONE || pvm.reg(7) as u32 as u64 == pvm.reg(7) && pvm.reg(7) as u32 == ctx.service_id {
        ctx.service_id
    } else if pvm.reg(7) <= u32::MAX as u64 {
        pvm.reg(7) as ServiceId
    } else {
        pvm.set_reg(7, HOST_NONE);
        return true;
    };
    let hash_ptr = pvm.reg(8) as u32;
    let out_ptr = pvm.reg(9) as u32;
    let offset = pvm.reg(10);
    let max_len = pvm.reg(11);

    let hash_data = match pvm.try_read_bytes(hash_ptr, 32) {
        Some(d) => d,
        None => return false, // page fault → PANIC
    };
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hash_data);
    let hash = Hash(hash);

    // For parallel semantics: lookup self from mutable accounts, others from init snapshot
    let target = if service_id == ctx.service_id {
        ctx.accounts.get_mut(&service_id)
    } else {
        ctx.init_accounts.get_mut(&service_id)
    };
    if let Some(account) = target {
        // Check structured preimage_lookup first, then fall back to opaque data
        let value = if let Some(v) = account.preimage_lookup.get(&hash) {
            Some(v.clone())
        } else {
            let state_key =
                grey_merkle::state_serial::compute_preimage_lookup_state_key(service_id, &hash);
            if let Some(v) = account.opaque_data.remove(&state_key) {
                // Promote from opaque to structured preimage_lookup
                account.preimage_lookup.insert(hash, v.clone());
                Some(v)
            } else {
                None
            }
        };

        if let Some(value) = value {
            let v_len = value.len() as u64;
            let f = offset.min(v_len) as usize;
            let l = max_len.min(v_len - f as u64) as usize;
            if l > 0 {
                if pvm.try_write_bytes(out_ptr, &value[f..f + l]).is_none() {
                    return false; // page fault → PANIC
                }
            }
            pvm.set_reg(7, v_len);
        } else {
            pvm.set_reg(7, HOST_NONE);
        }
    } else {
        pvm.set_reg(7, HOST_NONE);
    }
    true
}

/// bless (id=14): Update privileged services (GP ΩB).
/// φ[7]=m, φ[8]=a, φ[9]=v, φ[10]=r, φ[11]=o, φ[12]=n
/// Updates the regular context's environment privileges (x'_e)_{(m,a,v,r,z)}.
fn host_bless(
    pvm: &mut PvmInstance,
    regular: &mut AccContext,
    _exceptional: &mut AccContext,
    config: &Config,
) -> bool {
    let m = pvm.reg(7);
    let a_ptr = pvm.reg(8) as u32;
    let v = pvm.reg(9);
    let r = pvm.reg(10);
    let o_ptr = pvm.reg(11) as u32;
    let n = pvm.reg(12) as u32;

    let c = config.core_count as u32;

    // Read auth pool: C u32 values from memory at address a_ptr
    let auth_pool_bytes = match pvm.try_read_bytes(a_ptr, 4 * c) {
        Some(b) => b,
        None => return false, // page fault → PANIC
    };
    let auth_pool: Vec<ServiceId> = (0..c as usize)
        .map(|i| {
            u32::from_le_bytes([
                auth_pool_bytes[i * 4],
                auth_pool_bytes[i * 4 + 1],
                auth_pool_bytes[i * 4 + 2],
                auth_pool_bytes[i * 4 + 3],
            ])
        })
        .collect();

    // Read always-accumulate map: n entries of (u32, u64) = 12 bytes each
    let always_bytes = match pvm.try_read_bytes(o_ptr, 12 * n) {
        Some(b) => b,
        None => return false, // page fault → PANIC
    };
    let always_acc: Vec<(ServiceId, Gas)> = (0..n as usize)
        .map(|i| {
            let sid = u32::from_le_bytes([
                always_bytes[i * 12],
                always_bytes[i * 12 + 1],
                always_bytes[i * 12 + 2],
                always_bytes[i * 12 + 3],
            ]);
            let gas = u64::from_le_bytes([
                always_bytes[i * 12 + 4],
                always_bytes[i * 12 + 5],
                always_bytes[i * 12 + 6],
                always_bytes[i * 12 + 7],
                always_bytes[i * 12 + 8],
                always_bytes[i * 12 + 9],
                always_bytes[i * 12 + 10],
                always_bytes[i * 12 + 11],
            ]);
            (sid, gas)
        })
        .collect();

    // Check (m, v, r) are valid service IDs (fit in u32)
    if m > u32::MAX as u64 || v > u32::MAX as u64 || r > u32::MAX as u64 {
        pvm.set_reg(7, HOST_WHO);
        return true;
    }

    // Update regular context's environment privileges
    regular.privileges = AccPrivileges {
        bless: m as ServiceId,
        assign: auth_pool,
        designate: v as ServiceId,
        register: r as ServiceId,
        always_acc,
    };

    pvm.set_reg(7, HOST_OK);
    true
}

/// assign (id=15): Update authorization queue for a core (GP ΩA).
/// φ[7]=c, φ[8]=o, φ[9]=a
/// Updates the regular context's environment (x'_e)_q[c] and (x'_e)_a[c].
fn host_assign(
    pvm: &mut PvmInstance,
    regular: &mut AccContext,
    _exceptional: &mut AccContext,
    config: &Config,
) -> bool {
    let c = pvm.reg(7);
    let o_ptr = pvm.reg(8) as u32;
    let a = pvm.reg(9);

    // GP order (eq Ω_A): read memory FIRST, then check privileges.
    // If memory inaccessible → PANIC (⚡), takes priority over all other checks.
    let q_count = config.auth_queue_size as u32;
    let queue_bytes = match pvm.try_read_bytes(o_ptr, 32 * q_count) {
        Some(b) => b,
        None => return false, // page fault → PANIC
    };

    if c >= config.core_count as u64 {
        pvm.set_reg(7, HOST_CORE);
        return true;
    }

    let core = c as u16;

    // Check caller is the current assigner for this core
    if core < regular.privileges.assign.len() as u16 {
        if regular.service_id != regular.privileges.assign[core as usize] {
            pvm.set_reg(7, HOST_HUH);
            return true;
        }
    } else {
        pvm.set_reg(7, HOST_HUH);
        return true;
    }

    if a > u32::MAX as u64 {
        pvm.set_reg(7, HOST_WHO);
        return true;
    }

    let queue: Vec<Hash> = (0..q_count as usize)
        .map(|i| {
            let mut h = [0u8; 32];
            h.copy_from_slice(&queue_bytes[i * 32..(i + 1) * 32]);
            Hash(h)
        })
        .collect();

    // Store in regular context
    if regular.auth_queues.is_none() {
        regular.auth_queues = Some(BTreeMap::new());
    }
    regular
        .auth_queues
        .as_mut()
        .unwrap()
        .insert(core, (queue, a as ServiceId));

    pvm.set_reg(7, HOST_OK);
    true
}

/// designate (id=16): Set pending validator keys (GP ΩD).
/// φ[7]=o (memory offset for V validator keys, 336 bytes each)
/// Updates the regular context's environment (x'_e)_i (pending validators).
fn host_designate(
    pvm: &mut PvmInstance,
    regular: &mut AccContext,
    _exceptional: &mut AccContext,
    config: &Config,
) -> bool {
    let o_ptr = pvm.reg(7) as u32;

    let v = config.validators_count as u32;
    let key_size = 336u32; // Each validator key is 336 bytes

    // GP order (eq Ω_D): read memory FIRST, then check privileges.
    // If memory inaccessible → PANIC (⚡), takes priority over all other checks.
    let keys_bytes = match pvm.try_read_bytes(o_ptr, key_size * v) {
        Some(b) => b,
        None => return false, // page fault → PANIC
    };

    // Check caller is the designator
    if regular.service_id != regular.privileges.designate {
        pvm.set_reg(7, HOST_HUH);
        return true;
    }

    let keys: Vec<Vec<u8>> = (0..v as usize)
        .map(|i| keys_bytes[i * key_size as usize..(i + 1) * key_size as usize].to_vec())
        .collect();

    regular.pending_validators = Some(keys);

    pvm.set_reg(7, HOST_OK);
    true
}

/// new (id=18): Create a new service account (GP ΩN).
/// φ[7]=o (code hash ptr), φ[8]=l (preimage length), φ[9]=g, φ[10]=m, φ[11]=f, φ[12]=i
fn host_new(pvm: &mut PvmInstance, ctx: &mut AccContext, timeslot: Timeslot) -> bool {
    let o_ptr = pvm.reg(7) as u32;
    let l = pvm.reg(8);
    let g = pvm.reg(9);
    let m = pvm.reg(10);
    let f = pvm.reg(11); // freeze / free_storage_offset
    let hint_i = pvm.reg(12);

    // Read code hash from memory
    let hash_data = match pvm.try_read_bytes(o_ptr, 32) {
        Some(d) => d,
        None => return false, // page fault → PANIC
    };
    let mut code_hash = [0u8; 32];
    code_hash.copy_from_slice(&hash_data);
    let code_hash = Hash(code_hash);

    // Validate l fits u32
    if l > u32::MAX as u64 {
        return false; // panic
    }

    // Build the new account to compute its threshold balance
    let mut preimage_info = BTreeMap::new();
    preimage_info.insert((code_hash, l as u32), vec![]);

    // Compute derived footprint for new account (GP eq 9.4)
    // a_i = 2·|a_l| + |a_s| = 2·1 + 0 = 2
    let items_count = 2u64 * preimage_info.len() as u64;
    // a_o = Σ(81 + z) for (h,z) ∈ K(a_l)
    let footprint = 81u64 + l;

    // a_t = max(0, B_S + B_I·a_i + B_L·a_o - a_f) (GP eq 9.8)
    let threshold = {
        let raw = grey_types::constants::BALANCE_SERVICE_MINIMUM as i64
            + grey_types::constants::BALANCE_PER_ITEM as i64 * items_count as i64
            + grey_types::constants::BALANCE_PER_OCTET as i64 * footprint as i64
            - f as i64;
        std::cmp::max(0, raw) as u64
    };

    // Check f ≠ 0 requires caller to be manager (GP: if f ≠ 0 ∧ x_s ≠ χ_M → HUH)
    if f != 0 && ctx.service_id != ctx.privileges.bless {
        pvm.set_reg(7, HOST_HUH);
        return true;
    }

    // Check caller has enough balance after deduction
    // GP: let s = x_s except s_b = (x_s)_b - a_t; if s_b < (x_s)_t → CASH
    // i.e. caller's balance after deducting a_t must still be ≥ caller's own threshold
    if let Some(self_acc) = ctx.accounts.get(&ctx.service_id) {
        let caller_threshold = compute_account_threshold(self_acc);
        if self_acc.balance.saturating_sub(threshold) < caller_threshold {
            pvm.set_reg(7, HOST_CASH);
            return true;
        }
    } else {
        pvm.set_reg(7, HOST_CASH);
        return true;
    }

    // Find service ID
    let s_threshold = grey_types::constants::MIN_PUBLIC_SERVICE_INDEX; // S = 2^16 (GP I.4.4)
    let new_id = if ctx.service_id == ctx.privileges.register && (hint_i as u32) < s_threshold && hint_i <= u32::MAX as u64 {
        // Registrar can use IDs below S threshold
        let id = hint_i as u32;
        if ctx.accounts.contains_key(&id) {
            pvm.set_reg(7, HOST_FULL);
            return true;
        }
        id
    } else {
        // Use next_service_id from context
        let id = ctx.next_service_id;
        if ctx.accounts.contains_key(&id) {
            pvm.set_reg(7, HOST_FULL);
            return true;
        }
        id
    };

    // Debit caller by threshold amount (GP: s_b = (x_s)_b - a_t)
    if let Some(self_acc) = ctx.accounts.get_mut(&ctx.service_id) {
        self_acc.balance -= threshold;
    }

    let new_account = AccServiceAccount {
        version: 0,
        code_hash,
        balance: threshold,
        min_item_gas: g,
        min_memo_gas: m,
        bytes: footprint,
        deposit_offset: f,
        items: items_count,
        creation_slot: timeslot,
        last_accumulation_slot: 0,
        parent_service: ctx.service_id,
        storage: BTreeMap::new(),
        preimage_lookup: BTreeMap::new(),
        preimage_info,
        opaque_data: BTreeMap::new(),
    };

    ctx.accounts.insert(new_id, new_account);

    // Advance next_service_id: i* = check(S + (x_i - S + 42) mod (2^32 - S - 2^8)) (GP eq 24.62)
    let range = u32::MAX - s_threshold - 255;
    let candidate = s_threshold + ((new_id - s_threshold + 42) % range);
    ctx.next_service_id = find_free_service_id(candidate, &ctx.accounts, s_threshold);

    pvm.set_reg(7, new_id as u64);
    true
}

/// upgrade (id=19): Update service code hash, gas limits (GP ΩU).
/// φ[7]=o (code hash ptr), φ[8]=g (min_item_gas), φ[9]=m (min_memo_gas)
fn host_upgrade(pvm: &mut PvmInstance, ctx: &mut AccContext) -> bool {
    let o_ptr = pvm.reg(7) as u32;
    let g = pvm.reg(8);
    let m = pvm.reg(9);

    let hash_data = match pvm.try_read_bytes(o_ptr, 32) {
        Some(d) => d,
        None => return false, // page fault → PANIC
    };
    let mut code_hash = [0u8; 32];
    code_hash.copy_from_slice(&hash_data);

    if let Some(account) = ctx.accounts.get_mut(&ctx.service_id) {
        account.code_hash = Hash(code_hash);
        account.min_item_gas = g;
        account.min_memo_gas = m;
        pvm.set_reg(7, HOST_OK);
    } else {
        pvm.set_reg(7, HOST_NONE);
    }
    true
}

/// query (id=22): Query preimage info status (GP ΩQ).
/// φ[7]=o (hash ptr), φ[8]=z (length)
fn host_query(pvm: &mut PvmInstance, ctx: &mut AccContext) -> bool {
    let o_ptr = pvm.reg(7) as u32;
    let z = pvm.reg(8) as u32;

    let hash_data = match pvm.try_read_bytes(o_ptr, 32) {
        Some(d) => d,
        None => return false, // page fault → PANIC
    };
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hash_data);
    let hash = Hash(hash);

    // Promote preimage_info from opaque if needed (query is always on self)
    if let Some(account) = ctx.accounts.get_mut(&ctx.service_id) {
        let key = (hash, z);
        if !account.preimage_info.contains_key(&key) {
            let state_key = grey_merkle::state_serial::compute_preimage_info_state_key(
                ctx.service_id, &hash, z,
            );
            if let Some(v) = account.opaque_data.remove(&state_key) {
                let timeslots = decode_preimage_info_timeslots(&v);
                account.preimage_info.insert(key, timeslots);
            }
        }
    }

    // query always operates on the current service's own account
    let account = ctx.accounts.get(&ctx.service_id);
    if let Some(account) = account {
        if let Some(timeslots) = account.preimage_info.get(&(hash, z)) {
            match timeslots.len() {
                0 => {
                    pvm.set_reg(7, 0);
                    pvm.set_reg(8, 0);
                }
                1 => {
                    pvm.set_reg(7, 1 + ((timeslots[0] as u64) << 32));
                    pvm.set_reg(8, 0);
                }
                2 => {
                    pvm.set_reg(7, 2 + ((timeslots[0] as u64) << 32));
                    pvm.set_reg(8, timeslots[1] as u64);
                }
                _ => {
                    pvm.set_reg(7, 3 + ((timeslots[0] as u64) << 32));
                    pvm.set_reg(8, timeslots[1] as u64 + ((timeslots[2] as u64) << 32));
                }
            }
        } else {
            pvm.set_reg(7, HOST_NONE);
            pvm.set_reg(8, 0);
        }
    } else {
        pvm.set_reg(7, HOST_NONE);
        pvm.set_reg(8, 0);
    }
    true
}

/// solicit (id=23): Request a preimage (GP ΩS).
/// φ[7]=o (hash ptr), φ[8]=z (length)
fn host_solicit(pvm: &mut PvmInstance, ctx: &mut AccContext, timeslot: Timeslot) -> bool {
    let o_ptr = pvm.reg(7) as u32;
    let z = pvm.reg(8) as u32;

    let hash_data = match pvm.try_read_bytes(o_ptr, 32) {
        Some(d) => d,
        None => return false, // page fault → PANIC
    };
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hash_data);
    let hash = Hash(hash);

    if let Some(account) = ctx.accounts.get_mut(&ctx.service_id) {
        let key = (hash, z);
        // Promote from opaque data if not in structured preimage_info
        if !account.preimage_info.contains_key(&key) {
            let state_key = grey_merkle::state_serial::compute_preimage_info_state_key(
                ctx.service_id, &hash, z,
            );
            if let Some(v) = account.opaque_data.remove(&state_key) {
                // Decode timeslots: compact-encoded count + 4-byte LE timeslots
                let timeslots = decode_preimage_info_timeslots(&v);
                account.preimage_info.insert(key, timeslots);
            }
        }

        if let Some(ts) = account.preimage_info.get(&key) {
            let n = ts.len();
            if n == 1 || n == 2 {
                // Has 1 or 2 timeslots — append τ' (GP: |l| ∈ {1,2} → l ++ [τ'])
                let mut new_ts = ts.clone();
                new_ts.push(timeslot);
                account.preimage_info.insert(key, new_ts);
            } else {
                // Empty (already solicited) or 3+ (max reached) → HUH
                pvm.set_reg(7, HOST_HUH);
                return true;
            }
        } else {
            // New solicitation: create entry with empty timeslots
            account.preimage_info.insert(key, vec![]);
            // Update items/bytes for the new preimage_info entry
            // GP eq 9.4: items += 2 (each preimage_info entry counts as 2 items)
            account.items += 2;
            account.bytes += 81 + z as u64;
        }

        // Check minimum balance requirement
        let threshold = compute_account_threshold(account);
        if threshold > account.balance {
            // Undo the insert
            if account.preimage_info.get(&key).map(|v| v.is_empty()).unwrap_or(false) {
                account.preimage_info.remove(&key);
                account.items -= 2;
                account.bytes -= 81 + z as u64;
            }
            pvm.set_reg(7, HOST_FULL);
            return true;
        }

        pvm.set_reg(7, HOST_OK);
    } else {
        pvm.set_reg(7, HOST_HUH);
    }
    true
}

/// forget (id=24): Remove a preimage request (GP ΩF).
/// φ[7]=o (hash ptr), φ[8]=z (length)
fn host_forget(pvm: &mut PvmInstance, ctx: &mut AccContext, timeslot: Timeslot, config: &Config) -> bool {
    let o_ptr = pvm.reg(7) as u32;
    let z = pvm.reg(8) as u32;

    let hash_data = match pvm.try_read_bytes(o_ptr, 32) {
        Some(d) => d,
        None => return false, // page fault → PANIC
    };
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hash_data);
    let hash = Hash(hash);

    let d_const = config.preimage_expunge_period; // D

    if let Some(account) = ctx.accounts.get_mut(&ctx.service_id) {
        let key = (hash, z);
        // Promote from opaque data if not in structured preimage_info
        if !account.preimage_info.contains_key(&key) {
            let state_key = grey_merkle::state_serial::compute_preimage_info_state_key(
                ctx.service_id, &hash, z,
            );
            if let Some(v) = account.opaque_data.remove(&state_key) {
                // Decode timeslots: compact-encoded count + 4-byte LE timeslots
                let timeslots = decode_preimage_info_timeslots(&v);
                account.preimage_info.insert(key, timeslots);
            }
        }
        // Also promote preimage_lookup from opaque if needed for removal
        if !account.preimage_lookup.contains_key(&hash) {
            let lookup_key =
                grey_merkle::state_serial::compute_preimage_lookup_state_key(ctx.service_id, &hash);
            if let Some(v) = account.opaque_data.remove(&lookup_key) {
                account.preimage_lookup.insert(hash, v);
            }
        }

        if let Some(ts) = account.preimage_info.get(&key).cloned() {
            match ts.len() {
                0 | 2 if ts.len() == 0 || (ts.len() == 2 && ts[1] < timeslot.saturating_sub(d_const)) => {
                    // Remove preimage_info entry and preimage_lookup
                    account.preimage_info.remove(&key);
                    account.preimage_lookup.remove(&hash);
                    // Update items/bytes for removed preimage_info entry
                    account.items = account.items.saturating_sub(2);
                    account.bytes = account.bytes.saturating_sub(81 + z as u64);
                }
                1 => {
                    // Set forget time: [x] → [x, t]
                    let mut new_ts = ts;
                    new_ts.push(timeslot);
                    account.preimage_info.insert(key, new_ts);
                }
                3 if ts[1] < timeslot.saturating_sub(d_const) => {
                    // [x, y, w] with y < t - D → [w, t]
                    account.preimage_info.insert(key, vec![ts[2], timeslot]);
                }
                _ => {
                    pvm.set_reg(7, HOST_HUH);
                    return true;
                }
            }
            pvm.set_reg(7, HOST_OK);
        } else {
            pvm.set_reg(7, HOST_HUH);
        }
    } else {
        pvm.set_reg(7, HOST_HUH);
    }
    true
}

/// provide (id=26): Provide a preimage (GP ΩP, lines 4704-4727).
/// φ[7]=s (target service or NONE for self), φ[8]=o (data ptr), φ[9]=z (data len)
/// Adds (service, data) to the preimage provisions set x_p.
fn host_provide(pvm: &mut PvmInstance, ctx: &mut AccContext) -> bool {
    let target = if pvm.reg(7) == HOST_NONE {
        ctx.service_id
    } else if pvm.reg(7) <= u32::MAX as u64 {
        pvm.reg(7) as ServiceId
    } else {
        pvm.set_reg(7, HOST_WHO);
        return true;
    };
    let o_ptr = pvm.reg(8) as u32;
    let z = pvm.reg(9) as u32;

    // Read data from memory. PANIC if inaccessible.
    let data = match pvm.try_read_bytes(o_ptr, z) {
        Some(d) => d,
        None => return false, // page fault → PANIC (⚡)
    };
    let hash = grey_crypto::blake2b_256(&data);

    // WHO if target service doesn't exist
    let account = match ctx.accounts.get_mut(&target) {
        Some(acc) => acc,
        None => {
            pvm.set_reg(7, HOST_WHO);
            return true;
        }
    };

    // Promote preimage_info from opaque data if needed
    let key = (hash, z);
    if !account.preimage_info.contains_key(&key) {
        let state_key = grey_merkle::state_serial::compute_preimage_info_state_key(
            target, &hash, z,
        );
        if let Some(v) = account.opaque_data.remove(&state_key) {
            // Decode timeslots: compact-encoded count + 4-byte LE timeslots
            let timeslots = decode_preimage_info_timeslots(&v);
            account.preimage_info.insert(key, timeslots);
        }
    }

    // HUH if a_l[(H(i), z)] not present or ≠ [] — must be solicited (empty timeslots)
    match account.preimage_info.get(&key) {
        Some(ts) if ts.is_empty() => {} // OK: solicited
        _ => {
            pvm.set_reg(7, HOST_HUH);
            return true;
        }
    }

    // HUH if (s, i) already in preimage provisions set
    if ctx._preimage_provisions.iter().any(|(sid, d)| *sid == target && *d == data) {
        pvm.set_reg(7, HOST_HUH);
        return true;
    }

    // OK: add (s, i) to preimage provisions set
    ctx._preimage_provisions.push((target, data));
    pvm.set_reg(7, HOST_OK);
    true
}

/// Compute the minimum balance threshold for a service account (GP eq 9.4/9.8).
/// a_i = 2·|a_l| + |a_s|
/// a_o = Σ(81+z) for (h,z)∈K(a_l) + Σ(34+|y|+|x|) for (x,y)∈a_s
/// a_t = max(0, B_S + B_I·a_i + B_L·a_o - a_f)
fn compute_account_threshold(account: &AccServiceAccount) -> u64 {
    // Use stored items/bytes which are maintained incrementally by host calls.
    // GP eq 9.8: a_t = max(0, B_S + B_I·a_i + B_L·a_o - a_f)
    let raw = grey_types::constants::BALANCE_SERVICE_MINIMUM as i64
        + grey_types::constants::BALANCE_PER_ITEM as i64 * account.items as i64
        + grey_types::constants::BALANCE_PER_OCTET as i64 * account.bytes as i64
        - account.deposit_offset as i64;
    std::cmp::max(0, raw) as u64
}

/// Find a free service ID starting from the given candidate.
/// GP check(δ, n): find next free service ID starting at candidate.
/// Wraps within [S, 2^32 - 2^8) by incrementing by 1.
fn find_free_service_id(
    candidate: ServiceId,
    accounts: &BTreeMap<ServiceId, AccServiceAccount>,
    s_threshold: u32,
) -> ServiceId {
    let range = u32::MAX - s_threshold - 255; // 2^32 - S - 2^8
    let mut id = s_threshold + (candidate.wrapping_sub(s_threshold) % range);
    let start = id;
    loop {
        if !accounts.contains_key(&id) {
            return id;
        }
        // check() increments by 1 per GP eq (24.51)
        id = s_threshold + ((id - s_threshold + 1) % range);
        if id == start {
            break;
        }
    }
    id
}

// ---------------------------------------------------------------------------
// Accumulation Pipeline (Δ+, Δ*, Δ1)
// ---------------------------------------------------------------------------

/// Batch accumulation Δ* (eq 12.19).
/// All reports in the batch are processed together — each involved service
/// receives ALL items from ALL reports in a single PVM invocation.
fn accumulate_batch(
    config: &Config,
    accounts: &BTreeMap<ServiceId, AccServiceAccount>,
    transfers: &[DeferredTransfer],
    reports: &[WorkReport],
    privileges: &AccPrivileges,
    timeslot: Timeslot,
    entropy: &Hash,
    fetch_ctx: &FetchContext,
) -> (
    BTreeMap<ServiceId, AccServiceAccount>,
    Vec<DeferredTransfer>,
    Vec<(ServiceId, Hash)>,
    Vec<(ServiceId, Gas)>,
    AccPrivileges,
    Option<BTreeMap<u16, (Vec<Hash>, ServiceId)>>,
    Option<Vec<Vec<u8>>>,
) {
    // Collect all involved service IDs across all reports
    let mut involved = BTreeSet::new();
    for report in reports {
        for digest in &report.results {
            involved.insert(digest.service_id);
        }
    }
    for (sid, _) in &privileges.always_acc {
        involved.insert(*sid);
    }
    for t in transfers {
        involved.insert(t.destination);
    }

    let mut current_accounts = accounts.clone();
    // Initial snapshot for parallel read semantics (info/read/lookup on other services)
    let init_accounts = accounts.clone();
    let mut all_transfers = Vec::new();
    let mut outputs = Vec::new();
    let mut gas_usage = Vec::new();
    let mut current_privileges = privileges.clone();
    // Track auth_queues and pending_validators from host calls.
    // GP Δ* merge: q'_c = ((Δ(a_c)_e)_q)_c, i' = (Δ(v)_e)_i
    // In sequential model: last service to call assign/designate wins per-core.
    let mut batch_auth_queues: Option<BTreeMap<u16, (Vec<Hash>, ServiceId)>> = None;
    let mut batch_pending_validators: Option<Vec<Vec<u8>>> = None;

    // Save initial privileges for R-merge
    let initial_privileges = privileges.clone();
    let mut per_service_privs: BTreeMap<ServiceId, AccPrivileges> = BTreeMap::new();

    for &sid in &involved {
        let _prev_designate = current_privileges.designate;
        let _prev_bless = current_privileges.bless;
        let result = accumulate_single_service(
            config,
            &current_accounts,
            &init_accounts,
            transfers,
            reports,
            &current_privileges,
            sid,
            timeslot,
            entropy,
            fetch_ctx,
        );

        current_accounts = result.accounts;
        all_transfers.extend(result.transfers);
        gas_usage.push((sid, result.gas_used));

        // Collect auth_queues from assign host call.
        if let Some(aq) = &result.auth_queues {
            let merged = batch_auth_queues.get_or_insert_with(BTreeMap::new);
            for (core, entry) in aq {
                merged.insert(*core, entry.clone());
            }
        }

        // Collect pending_validators from designate host call.
        if result.pending_validators.is_some() {
            batch_pending_validators = result.pending_validators;
        }

        // Track per-service privilege snapshots for R-merge
        per_service_privs.insert(sid, result.privileges.clone());

        // Sequential privilege propagation (for subsequent services in this batch)
        current_privileges = result.privileges;

        if let Some(output) = result.output {
            outputs.push((sid, output));
        }
    }

    // GP R-merge: R(o, a, b) = b if a == o, else a
    // o = original, a = manager's result, b = designated service's result
    let priv_r = |o: ServiceId, a: ServiceId, b: ServiceId| -> ServiceId {
        if a == o { b } else { a }
    };

    let delta_priv = |s: ServiceId| -> &AccPrivileges {
        per_service_privs.get(&s).unwrap_or(&initial_privileges)
    };

    let m = initial_privileges.bless;  // original manager
    let v = initial_privileges.designate;  // original designator
    let r = initial_privileges.register;  // original registrar

    let e_star = delta_priv(m);  // manager's result

    // m' = e*_m (manager from manager's result)
    let m_prime = e_star.bless;
    // z' = e*_z (always_acc from manager's result)
    let z_prime = e_star.always_acc.clone();

    // a'_c = R(a_c, e*_a_c, Delta(a_c)_a_c)
    let mut a_prime = initial_privileges.assign.clone();
    for (c, a_c) in initial_privileges.assign.iter().enumerate() {
        let e_star_ac = e_star.assign.get(c).copied().unwrap_or(*a_c);
        let delta_ac = delta_priv(*a_c);
        let delta_ac_ac = delta_ac.assign.get(c).copied().unwrap_or(*a_c);
        a_prime[c] = priv_r(*a_c, e_star_ac, delta_ac_ac);
    }

    // v' = R(v, e*_v, Delta(v)_v)
    let delta_v = delta_priv(v);
    let v_prime = priv_r(v, e_star.designate, delta_v.designate);

    // r' = R(r, e*_r, Delta(r)_r)
    let delta_r = delta_priv(r);
    let r_prime = priv_r(r, e_star.register, delta_r.register);

    current_privileges = AccPrivileges {
        bless: m_prime,
        assign: a_prime,
        designate: v_prime,
        register: r_prime,
        always_acc: z_prime,
    };

    (
        current_accounts,
        all_transfers,
        outputs,
        gas_usage,
        current_privileges,
        batch_auth_queues,
        batch_pending_validators,
    )
}

/// Outer accumulation Δ+ (eq 12.18).
///
/// GP: Δ+(g, t, r, e, f) where:
///   g = gas budget, t = deferred transfers, r = work reports,
///   e = state context, f = always-accumulate services (empty in recursive calls)
///
/// n = |t| + i + |f|  — if n = 0, return (base case)
/// g* = g + Σ(t_g for t in t) — gas augmented by transfer gas
/// Recursive call uses f = {} (always_acc only in first batch)
fn accumulate_all(
    config: &Config,
    gas_budget: Gas,
    transfers: Vec<DeferredTransfer>,
    reports: &[WorkReport],
    accounts: &BTreeMap<ServiceId, AccServiceAccount>,
    privileges: &AccPrivileges,
    timeslot: Timeslot,
    entropy: &Hash,
    fetch_ctx: &FetchContext,
) -> (
    usize,
    BTreeMap<ServiceId, AccServiceAccount>,
    Vec<(ServiceId, Hash)>,
    Vec<(ServiceId, Gas)>,
    AccPrivileges,
    Option<BTreeMap<u16, (Vec<Hash>, ServiceId)>>,
    Option<Vec<Vec<u8>>>,
) {
    // Include all reports that fit in gas budget.
    // GP: i is the maximum index such that Σ g_d for reports[..i] ≤ g.
    let mut gas_sum: Gas = 0;
    let mut max_reports = 0;
    for report in reports {
        let report_gas: Gas = report.results.iter().map(|d| d.accumulate_gas).sum();
        if gas_sum.saturating_add(report_gas) > gas_budget {
            break;
        }
        gas_sum = gas_sum.saturating_add(report_gas);
        max_reports += 1;
    }

    // GP: n = |t| + i + |f| — total items to process
    let n = transfers.len() + max_reports + privileges.always_acc.len();
    if timeslot == 24 {
        eprintln!("acc_all t=24: budget={gas_budget} reports={max_reports}/{} xfers={} always={} n={n}",
            reports.len(), transfers.len(), privileges.always_acc.len());
    }
    let _ = &transfers;
    if n == 0 {
        return (0, accounts.clone(), vec![], vec![], privileges.clone(), None, None);
    }

    // Process this batch: Δ*(e, t, r[..i], f)
    let batch_reports = &reports[..max_reports];
    let (new_accounts, new_transfers, outputs, gas_usage, new_privileges, batch_aq, batch_pv) =
        accumulate_batch(config, accounts, &transfers, batch_reports, privileges, timeslot, entropy, fetch_ctx);

    let batch_gas_used: Gas = gas_usage.iter().map(|(_, g)| *g).sum();

    // GP: g* = g + Σ(t_g for t in t) — augment gas with transfer gas
    let transfer_gas: Gas = transfers.iter().map(|t| t.gas_limit).sum();
    let g_star = gas_budget.saturating_add(transfer_gas);
    let remaining_gas = g_star.saturating_sub(batch_gas_used);

    // GP: recursive call uses f = {} (always_acc only in first batch)
    let mut recursive_privileges = new_privileges.clone();
    recursive_privileges.always_acc = vec![];

    // Always recurse — handles remaining reports AND deferred transfers
    let (more_count, final_accounts, more_outputs, more_gas, final_privileges, more_aq, more_pv) =
        accumulate_all(
            config,
            remaining_gas,
            new_transfers,
            &reports[max_reports..],
            &new_accounts,
            &recursive_privileges,
            timeslot,
            entropy,
            fetch_ctx,
        );

    let mut all_outputs = outputs;
    all_outputs.extend(more_outputs);
    let mut all_gas = gas_usage;
    all_gas.extend(more_gas);

    // Merge auth_queues: later batches override earlier per-core
    let final_aq = match (batch_aq, more_aq) {
        (None, None) => None,
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (Some(mut a), Some(b)) => { a.extend(b); Some(a) }
    };
    // Pending validators: later batch wins
    let final_pv = more_pv.or(batch_pv);

    (
        max_reports + more_count,
        final_accounts,
        all_outputs,
        all_gas,
        final_privileges,
        final_aq,
        final_pv,
    )
}

// ---------------------------------------------------------------------------
// Top-Level Processing Function
// ---------------------------------------------------------------------------

/// Process the accumulate sub-transition.
pub fn process_accumulate(
    config: &Config,
    state: &mut AccumulateState,
    input: &AccumulateInput,
) -> AccumulateOutput {
    let epoch_length = config.epoch_length as usize;
    let slot_index = input.slot as usize % epoch_length;

    // Step 1: Partition input reports into immediate and queued
    let (immediate, new_queued) = partition_reports(&input.reports);

    // Step 1b: Compute ⊜(ξ) — union of all accumulated package hashes (eq 12.5).
    // R^Q ≡ E([D(r) | ...], ⊜(ξ)) — new queued reports must have
    // already-accumulated dependencies stripped via the full history.
    let accumulated_union: BTreeSet<Hash> = state
        .accumulated
        .iter()
        .flat_map(|slot_hashes| slot_hashes.iter().cloned())
        .collect();
    eprintln!("accumulated_union: {} hashes", accumulated_union.len());
    for h in accumulated_union.iter().take(5) {
        eprintln!("  {}", hex::encode(&h.0[..8]));
    }
    let edited_new_queued = edit_queue(&new_queued, &accumulated_union);
    eprintln!("new_queued: {} entries, edited: {}", new_queued.len(), edited_new_queued.len());
    for rr in &new_queued {
        eprintln!("  new_queued deps: {}", rr.dependencies.len());
        for d in &rr.dependencies {
            eprintln!("    dep: {}", hex::encode(&d.0[..8]));
        }
    }
    for rr in &edited_new_queued {
        eprintln!("  edited_new deps: {}", rr.dependencies.len());
    }

    // Step 2: Compute R* (all accumulatable reports)
    let accumulatable = compute_accumulatable_with_new(
        &immediate,
        &state.ready_queue,
        &edited_new_queued,
        epoch_length,
        slot_index,
    );

    // Step 3: Compute gas budget (eq 12.25): g = max(G_T, G_A × C + Σχ_Z)
    let always_gas: Gas = state.privileges.always_acc.iter().map(|(_, g)| *g).sum();
    let ga_times_c = grey_types::constants::GAS_ACCUMULATE * config.core_count as u64;
    let gas_budget = config.gas_total_accumulation.max(ga_times_c + always_gas);

    // Build shared fetch context (items are per-service, built in accumulate_single_service)
    let fetch_ctx = FetchContext {
        config_blob: config.encode_config_blob(),
        entropy: state.entropy,
        items_blob: vec![],
        items: vec![],
    };

    // Step 4: Run accumulation pipeline (Δ+)
    let (n, new_accounts, mut outputs, gas_usage, new_privileges, acc_auth_queues, acc_pending_validators) = accumulate_all(
        config,
        gas_budget,
        vec![],
        &accumulatable,
        &state.accounts,
        &state.privileges,
        input.slot,
        &state.entropy,
        &fetch_ctx,
    );

    // Step 5: Update service accounts
    state.accounts = new_accounts;

    // Step 5b: Store auth_queues and pending_validators from host calls
    state.auth_queues = acc_auth_queues;
    state.pending_validators = acc_pending_validators;

    // Step 6: Update last_accumulation_slot for all accumulated services
    // This tracks the accumulation timeslot in the internal AccServiceAccount representation.
    // The mapping to ServiceAccount fields (a_r = creation slot, a_a = most recent accumulation)
    // is handled in acc_to_service.
    for (sid, _) in &gas_usage {
        if let Some(account) = state.accounts.get_mut(sid) {
            account.last_accumulation_slot = input.slot;
        }
    }

    // Step 7: Update statistics
    update_statistics(&mut state.statistics, &gas_usage, &accumulatable, n);

    // Step 8: Update accumulated history (eq 12.32)
    // Shift: drop oldest, add new slot at end
    shift_accumulated(
        &mut state.accumulated,
        &accumulatable,
        n,
        epoch_length,
    );

    // Step 9: Update ready queue (eq 12.34)
    let accumulated_hashes: BTreeSet<Hash> = state
        .accumulated
        .last()
        .map(|v| v.iter().cloned().collect())
        .unwrap_or_default();

    update_ready_queue(
        &mut state.ready_queue,
        &edited_new_queued,
        &accumulated_hashes,
        epoch_length,
        state.slot,
        input.slot,
    );

    // Step 10: Update privileges
    state.privileges = new_privileges;

    // Step 11: Update slot
    state.slot = input.slot;

    // Step 12: Compute accumulation statistics S (GP eq at line 1892)
    // S[s] = (G(s), N(s)) where G = total gas, N = work item count
    let mut accum_stats: BTreeMap<ServiceId, (Gas, u32)> = BTreeMap::new();
    for (sid, gas) in &gas_usage {
        accum_stats.entry(*sid).or_insert((0, 0)).0 += *gas;
    }
    let reports_slice = &accumulatable[..n];
    for report in reports_slice {
        for digest in &report.results {
            accum_stats.entry(digest.service_id).or_insert((0, 0)).1 += 1;
        }
    }
    // Filter: G(s) + N(s) ≠ 0
    accum_stats.retain(|_, (g, n)| *g + *n as u64 != 0);

    // Step 13: Compute output hash (Keccak Merkle root of outputs)
    let _ = &outputs;
    let output_hash = compute_output_hash(&outputs);
    // Sort outputs by service ID (GP eq 12.17: θ is a sorted sequence)
    outputs.sort_by_key(|(sid, _)| *sid);
    AccumulateOutput {
        hash: output_hash,
        outputs,
        gas_usage,
        accumulation_stats: accum_stats,
    }
}

/// Shift accumulated history (eq 12.32).
/// Always shifts left by 1, dropping the oldest entry and recording new hashes at [E-1].
fn shift_accumulated(
    accumulated: &mut Vec<Vec<Hash>>,
    accumulatable: &[WorkReport],
    n: usize,
    epoch_length: usize,
) {
    // Shift left by 1
    if !accumulated.is_empty() {
        accumulated.remove(0);
    }
    accumulated.push(vec![]);

    // Ensure correct length
    while accumulated.len() < epoch_length {
        accumulated.push(vec![]);
    }

    // Record accumulated package hashes in the last slot (sorted)
    let last_idx = epoch_length - 1;
    let mut hashes: Vec<Hash> = accumulatable[..n]
        .iter()
        .map(|r| r.package_spec.package_hash)
        .collect();
    hashes.sort();
    accumulated[last_idx] = hashes;
}

/// Update ready queue after accumulation (eq 12.34).
/// The ready queue is a circular buffer indexed by slot % E.
/// All positions for skipped+current slots are cleared.
/// Position m (current slot) receives new queued entries.
/// Other surviving positions are edited to remove fulfilled dependencies.
fn update_ready_queue(
    ready_queue: &mut Vec<Vec<ReadyRecord>>,
    new_queued: &[ReadyRecord],
    accumulated_hashes: &BTreeSet<Hash>,
    epoch_length: usize,
    prev_slot: Timeslot,
    current_slot: Timeslot,
) {
    // Ensure correct length
    while ready_queue.len() < epoch_length {
        ready_queue.push(vec![]);
    }

    // Clear positions for all slots from prev_slot+1 to current_slot
    let slots_advanced = if current_slot > prev_slot {
        (current_slot - prev_slot) as usize
    } else {
        1
    };

    for offset in 0..slots_advanced.min(epoch_length) {
        let slot = prev_slot as usize + 1 + offset;
        let pos = slot % epoch_length;
        ready_queue[pos] = vec![];
    }

    // Edit surviving slots: remove fulfilled dependencies and accumulated reports
    for slot in ready_queue.iter_mut() {
        *slot = edit_queue(slot, accumulated_hashes);
    }

    // Insert newly queued reports at current position m
    let m = current_slot as usize % epoch_length;
    let edited_new = edit_queue(new_queued, accumulated_hashes);
    ready_queue[m].extend(edited_new);
}

/// Update per-service statistics.
fn update_statistics(
    stats: &mut Vec<(ServiceId, AccServiceStats)>,
    gas_usage: &[(ServiceId, Gas)],
    accumulatable: &[WorkReport],
    n: usize,
) {
    // Statistics are computed fresh per block, not accumulated from pre-state.
    let reports = &accumulatable[..n];
    let mut stat_map: BTreeMap<ServiceId, AccServiceStats> = BTreeMap::new();

    for report in reports {
        for digest in &report.results {
            let entry = stat_map.entry(digest.service_id).or_default();
            entry.refinement_count += 1;
            entry.refinement_gas_used += digest.gas_used;
            entry.imports += digest.imports_count as u32;
            entry.extrinsic_count += digest.extrinsics_count as u32;
            entry.extrinsic_size += digest.extrinsics_size as u64;
            entry.exports += digest.exports_count as u32;
        }
    }

    // N(s) = count of work-item digests for service s in accumulated reports
    for report in reports {
        for digest in &report.results {
            stat_map
                .entry(digest.service_id)
                .or_default()
                .accumulate_count += 1;
        }
    }

    // G(s) = Σ(u for (s,u) in u) — total gas used for service s
    for (sid, gas) in gas_usage {
        stat_map.entry(*sid).or_default().accumulate_gas_used += *gas;
    }

    // GP: S ≡ { (s ↦ (G(s), N(s))) | G(s) + N(s) ≠ 0 }
    // Exclude entries where both gas and item count are zero
    *stats = stat_map
        .into_iter()
        .filter(|(_, s)| s.accumulate_gas_used + s.accumulate_count as u64 != 0)
        .collect();
}

/// Compute the accumulate output hash (M_K over per-service yields, eq 12.17).
///
/// Each service that calls yield produces a (service_id, output_hash) pair.
/// The output commitment is the balanced Keccak-256 Merkle root (M_K) over the
/// list of encoded pairs `E4(service_id) ⌢ output_hash`, sorted by service_id.
fn compute_output_hash(outputs: &[(ServiceId, Hash)]) -> Hash {
    if outputs.is_empty() {
        return Hash([0u8; 32]);
    }
    // Sort by service_id numerically (GP eq 12.17: sorted sequence keyed by service ID)
    let mut sorted: Vec<(ServiceId, Hash)> = outputs.to_vec();
    sorted.sort_by_key(|(sid, _)| *sid);
    // Encode each (service_id, yield_hash) pair as 36 bytes
    let leaves: Vec<Vec<u8>> = sorted
        .iter()
        .map(|(sid, hash)| {
            let mut leaf = Vec::with_capacity(36);
            leaf.extend_from_slice(&sid.to_le_bytes());
            leaf.extend_from_slice(&hash.0);
            leaf
        })
        .collect();
    // Balanced Keccak-256 Merkle tree M_K (eq E.4)
    keccak_merkle_root(leaves)
}

/// GP node function N(v, H) (eq E.1) — returns raw bytes (blob or hash).
///
/// - |v| = 0: H_0 (32 zero bytes)
/// - |v| = 1: v_0 (raw blob, NOT hashed)
/// - |v| > 1: H("node" ⌢ N(left, H) ⌢ N(right, H))
///
/// Note: Reference implementations (Strawberry/Go) use "node" without '$' prefix.
fn keccak_merkle_node(leaves: &[Vec<u8>]) -> Vec<u8> {
    match leaves.len() {
        0 => vec![0u8; 32],
        1 => leaves[0].clone(),
        n => {
            let mid = (n + 1) / 2; // ceil(n/2)
            let left = keccak_merkle_node(&leaves[..mid]);
            let right = keccak_merkle_node(&leaves[mid..]);
            let mut input = Vec::with_capacity(4 + left.len() + right.len());
            input.extend_from_slice(b"node");
            input.extend_from_slice(&left);
            input.extend_from_slice(&right);
            grey_crypto::keccak_256(&input).0.to_vec()
        }
    }
}

/// Well-balanced Keccak-256 Merkle tree M_B(v, H_K) (eq E.1).
///
/// - |v| = 1: H_K(v_0) (hash the single item)
/// - otherwise: N(v, H_K)
fn keccak_merkle_root(leaves: Vec<Vec<u8>>) -> Hash {
    if leaves.len() == 1 {
        return grey_crypto::keccak_256(&leaves[0]);
    }
    let result = keccak_merkle_node(&leaves);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    Hash(hash)
}

// ---------------------------------------------------------------------------
// Bridge: State ↔ AccumulateState conversion
// ---------------------------------------------------------------------------

use grey_types::state::{PrivilegedServices, ServiceAccount, State};

/// Convert a ServiceAccount to AccServiceAccount, optionally looking up
/// the code blob from opaque state data.
fn service_to_acc(
    sid: ServiceId,
    a: &ServiceAccount,
    opaque_data: &[([u8; 31], Vec<u8>)],
) -> AccServiceAccount {
    // Collect per-service opaque data entries
    let mut per_service_opaque: BTreeMap<[u8; 31], Vec<u8>> = BTreeMap::new();
    for (key, value) in opaque_data {
        let entry_sid = grey_merkle::state_serial::extract_service_id_from_data_key(key);
        if entry_sid == sid {
            per_service_opaque.insert(*key, value.clone());
        }
    }

    // Build preimage_lookup from ServiceAccount, plus code blob from opaque data
    let mut preimage_lookup = a.preimage_lookup.clone();
    if a.code_hash != Hash::ZERO && !preimage_lookup.contains_key(&a.code_hash) {
        let code_key =
            grey_merkle::state_serial::compute_preimage_lookup_state_key(sid, &a.code_hash);
        if let Some(code_blob) = per_service_opaque.remove(&code_key) {
            preimage_lookup.insert(a.code_hash, code_blob);
        }
    }

    AccServiceAccount {
        version: 0,
        code_hash: a.code_hash,
        balance: a.balance,
        min_item_gas: a.min_accumulate_gas,
        min_memo_gas: a.min_on_transfer_gas,
        bytes: a.total_footprint,
        deposit_offset: a.free_storage_offset,
        items: a.accumulation_counter as u64,
        creation_slot: a.last_accumulation, // position r = creation timeslot
        last_accumulation_slot: a.last_activity, // position a = last accumulation timeslot
        parent_service: a.preimage_count, // position p = parent service ID
        storage: a.storage.clone(),
        preimage_lookup,
        preimage_info: a.preimage_info.clone(),
        opaque_data: per_service_opaque,
    }
}

/// Convert AccServiceAccount back to ServiceAccount.
///
/// GP field mapping (eq D.2 serialization):
///   position i (accumulation_counter) = a_i = 2·|a_l| + |a_s|  (GP eq 9.4)
///   position o (total_footprint) = a_o = Σ(81+z) + Σ(34+|y|+|x|)  (GP eq 9.4)
///   position r (last_accumulation) = creation slot — preserved from original
///   position a (last_activity) = most recent accumulation slot — set to timeslot if accumulated
///   position p (preimage_count) = parent service ID  (GP eq 9.3)
fn acc_to_service(
    a: &AccServiceAccount,
    original: Option<&ServiceAccount>,
    was_accumulated: bool,
    accumulation_timeslot: Timeslot,
) -> ServiceAccount {
    // a_a: set to current timeslot if this service was accumulated (GP eq 12.25: a'_a = τ')
    let last_activity = if was_accumulated {
        accumulation_timeslot
    } else {
        original.map(|o| o.last_activity).unwrap_or(0)
    };
    // a_r: always preserve creation slot from original
    let last_accumulation = original.map(|o| o.last_accumulation).unwrap_or(a.creation_slot);

    ServiceAccount {
        code_hash: a.code_hash,
        balance: a.balance,
        min_accumulate_gas: a.min_item_gas,
        min_on_transfer_gas: a.min_memo_gas,
        storage: a.storage.clone(),
        preimage_lookup: a.preimage_lookup.clone(),
        preimage_info: a.preimage_info.clone(),
        free_storage_offset: a.deposit_offset,
        total_footprint: a.bytes,
        accumulation_counter: a.items as u32,
        last_accumulation,
        last_activity,
        preimage_count: a.parent_service,
    }
}

/// Convert PrivilegedServices to AccPrivileges.
fn privileges_to_acc(p: &PrivilegedServices) -> AccPrivileges {
    AccPrivileges {
        bless: p.manager,
        assign: p.assigner.clone(),
        designate: p.designator,
        register: p.registrar,
        always_acc: p.always_accumulate.iter().map(|(&s, &g)| (s, g)).collect(),
    }
}

/// Convert AccPrivileges back to PrivilegedServices.
fn acc_to_privileges(p: &AccPrivileges) -> PrivilegedServices {
    PrivilegedServices {
        manager: p.bless,
        assigner: p.assign.clone(),
        designator: p.designate,
        registrar: p.register,
        always_accumulate: p.always_acc.iter().map(|&(s, g)| (s, g)).collect(),
    }
}

/// Convert State's accumulation_queue to AccumulateState's ready_queue format.
fn state_queue_to_ready(queue: &[Vec<(WorkReport, Vec<Hash>)>]) -> Vec<Vec<ReadyRecord>> {
    queue
        .iter()
        .map(|slot| {
            slot.iter()
                .map(|(report, deps)| ReadyRecord {
                    report: report.clone(),
                    dependencies: deps.clone(),
                })
                .collect()
        })
        .collect()
}

/// Convert AccumulateState's ready_queue back to State's accumulation_queue format.
fn ready_to_state_queue(ready: &[Vec<ReadyRecord>]) -> Vec<Vec<(WorkReport, Vec<Hash>)>> {
    ready
        .iter()
        .map(|slot| {
            slot.iter()
                .map(|rr| (rr.report.clone(), rr.dependencies.clone()))
                .collect()
        })
        .collect()
}

/// Run accumulation on available reports, updating the state in-place.
///
/// Returns (accumulate_root_hash, accumulation_stats, remaining_opaque_data) where:
/// - accumulation_stats is the S mapping: service_id → (total_gas, work_item_count) per GP eq 1892
/// - remaining_opaque_data is the opaque service data entries after consuming entries accessed
///   by host calls during accumulation
pub fn run_accumulation(
    config: &Config,
    state: &mut State,
    prev_timeslot: Timeslot,
    available_reports: Vec<WorkReport>,
    opaque_data: &[([u8; 31], Vec<u8>)],
) -> (Hash, BTreeMap<ServiceId, (Gas, u32)>, Vec<([u8; 31], Vec<u8>)>) {
    let _epoch_length = config.epoch_length as usize;


    // GP eq 12.22-12.24: Δ+ is always called, even with no available reports.
    // Always-accumulate services (χ_Z) must run every block.
    // Build AccumulateState from main State
    let mut acc_state = AccumulateState {
        slot: prev_timeslot,
        entropy: state.entropy[0],
        ready_queue: state_queue_to_ready(&state.accumulation_queue),
        accumulated: state.accumulation_history.clone(),
        privileges: privileges_to_acc(&state.privileged_services),
        statistics: vec![],
        accounts: state
            .services
            .iter()
            .map(|(&sid, a)| (sid, service_to_acc(sid, a, opaque_data)))
            .collect(),
        auth_queues: None,
        pending_validators: None,
    };

    let input = AccumulateInput {
        slot: state.timeslot,
        reports: available_reports,
    };

    let acc_output = process_accumulate(config, &mut acc_state, &input);

    // Build set of accumulated service IDs from accumulation_stats
    let accumulated_sids: std::collections::BTreeSet<ServiceId> =
        acc_output.accumulation_stats.keys().copied().collect();

    // Collect remaining opaque data from all service accounts after accumulation.
    // Ejected services are removed from acc_state.accounts, so their opaque data
    // is correctly excluded.
    let mut remaining_opaque: Vec<([u8; 31], Vec<u8>)> = Vec::new();
    for (_, acc) in &acc_state.accounts {
        for (k, v) in &acc.opaque_data {
            remaining_opaque.push((*k, v.clone()));
        }
    }

    // Propagate results back to State
    let new_services: BTreeMap<ServiceId, ServiceAccount> = acc_state
        .accounts
        .iter()
        .map(|(&sid, a)| {
            let was_accumulated = accumulated_sids.contains(&sid);
            (sid, acc_to_service(a, state.services.get(&sid), was_accumulated, state.timeslot))
        })
        .collect();

    // Log new service IDs being written back
    for (&sid, _) in &new_services {
        if !state.services.contains_key(&sid) {
        }
    }
    state.services = new_services;
    state.accumulation_history = acc_state.accumulated;
    state.accumulation_queue = ready_to_state_queue(&acc_state.ready_queue);
    state.privileged_services = acc_to_privileges(&acc_state.privileges);
    state.accumulation_outputs = acc_output.outputs.clone();

    // Apply auth queue changes from assign host call (GP: φ' = q' from Δ*).
    // auth_queue[slot_idx][core_idx] = queue_hashes[slot_idx] for each modified core.
    if let Some(ref aq) = acc_state.auth_queues {
        for (&core, (queue_hashes, _assigner)) in aq {
            let c = core as usize;
            for (slot_idx, hash) in queue_hashes.iter().enumerate() {
                if slot_idx < state.auth_queue.len() {
                    // Ensure the core dimension exists
                    while state.auth_queue[slot_idx].len() <= c {
                        state.auth_queue[slot_idx].push(Hash::ZERO);
                    }
                    state.auth_queue[slot_idx][c] = *hash;
                }
            }
        }
    }

    // Apply pending validator changes from designate host call (GP: ι' from Δ*).
    if let Some(ref pv) = acc_state.pending_validators {
        state.pending_validators = pv
            .iter()
            .map(|bytes| {
                if bytes.len() == 336 {
                    let arr: &[u8; 336] = bytes.as_slice().try_into().unwrap();
                    grey_types::validator::ValidatorKey::from_bytes(arr)
                } else {
                    grey_types::validator::ValidatorKey::null()
                }
            })
            .collect();
    }

    (acc_output.hash, acc_output.accumulation_stats, remaining_opaque)
}
