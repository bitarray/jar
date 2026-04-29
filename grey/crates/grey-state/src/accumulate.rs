//! Accumulate sub-transition (Section 12 of the Gray Paper).
//!
//! Manages the work-report accumulation queue, dependency resolution,
//! and PVM execution of service Accumulate code (ΨA).

use crate::pvm_backend::PvmInstance;
use grey_types::config::Config;
use grey_types::constants::HOST_WHAT;
use grey_types::work::{WorkReport, WorkResult};
use grey_types::{Hash, ServiceId, Timeslot};
use javm::Gas;
use std::collections::{BTreeMap, BTreeSet};

/// Decode preimage_info timeslots from compact-encoded raw bytes.
/// Format: compact_len(count) + count × E_4(timeslot).
pub fn decode_preimage_info_timeslots(data: &[u8]) -> Vec<Timeslot> {
    if data.is_empty() {
        return Vec::new();
    }
    let mut pos = 0;
    if pos + 4 > data.len() {
        return Vec::new();
    }
    let count = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    // Bound count by remaining bytes: each Timeslot is 4 bytes, so count cannot
    // exceed (data.len() - pos) / 4. Without this guard, a crafted count prefix
    // (up to u32::MAX) would trigger a multi-GB Vec::with_capacity allocation.
    let max_count = (data.len() - pos) / 4;
    let count = count.min(max_count);
    let mut timeslots = Vec::with_capacity(count);
    for _ in 0..count {
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
    pub quota_items: u64,
    pub min_item_gas: Gas,
    pub min_memo_gas: Gas,
    pub bytes: u64,
    pub quota_bytes: u64,
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
    pub quota_service: ServiceId,
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
    /// `S[s]` = (G(s), N(s)) where G = total gas, N = work item count.
    /// Only includes services where G(s) + N(s) ≠ 0.
    pub accumulation_stats: BTreeMap<ServiceId, (Gas, u32)>,
}

/// Deferred transfer between services (eq 12.16).
#[derive(Clone, Debug)]
pub struct DeferredTransfer {
    pub sender: ServiceId,
    pub destination: ServiceId,
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

impl ServiceAccResult {
    /// Build a no-op result for early exits (no account, zero gas, no code).
    fn skipped(
        accounts: BTreeMap<ServiceId, AccServiceAccount>,
        privileges: AccPrivileges,
    ) -> Self {
        Self {
            accounts,
            transfers: vec![],
            output: None,
            gas_used: 0,
            privileges,
            auth_queues: None,
            pending_validators: None,
        }
    }
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
    for pkg_hash in report.segment_root_lookup.keys() {
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
    reports
        .iter()
        .map(|r| r.package_spec.package_hash)
        .collect()
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
        return Vec::new();
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
    let mut result = immediate.to_vec();
    result.extend(queue_resolved);
    result
}

// ---------------------------------------------------------------------------
// PVM Accumulation (ΨA, Appendix B.4)
// ---------------------------------------------------------------------------

/// Accumulation context L (eq B.7-B.8).
#[derive(Clone, Debug)]
#[allow(dead_code)] // fields used by future accumulation host-call implementations
struct AccContext {
    service_id: ServiceId,
    accounts: BTreeMap<ServiceId, AccServiceAccount>,
    /// Initial (pre-accumulation) snapshot for parallel read semantics.
    /// host_read/host_info on OTHER services read from this snapshot.
    init_accounts: BTreeMap<ServiceId, AccServiceAccount>,
    next_service_id: ServiceId,
    transfers: Vec<DeferredTransfer>,
    output: Option<Hash>,
    privileges: AccPrivileges,
    /// Pending validator keys set by designate host call (ι).
    pending_validators: Option<Vec<Vec<u8>>>,
    /// Auth queues per core set by assign host call.
    auth_queues: Option<BTreeMap<u16, (Vec<Hash>, ServiceId)>>,
}

/// Run PVM accumulation for a single service (Δ1, eq 12.24).
#[allow(clippy::too_many_arguments)]
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
            return ServiceAccResult::skipped(accounts.clone(), privileges.clone());
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
        return ServiceAccResult::skipped(accounts.clone(), privileges.clone());
    }

    // Initialize accumulation context (regular dimension x)
    let initial_accounts = accounts.clone();

    // Compute next available service ID (eq B.10)
    // i = S + (H(E_4(s) ++ η'_0 ++ E_4(τ')) mod (2^32 - S - 2^8))
    let s_threshold = grey_types::constants::MIN_PUBLIC_SERVICE_INDEX; // S = 2^16 (GP I.4.4)
    let hash_input = encode_new_service_hash(service_id, entropy, timeslot);
    let hash_bytes = grey_crypto::blake2b_256(&hash_input);
    let range = u32::MAX - s_threshold - 255; // 2^32 - S - 2^8
    // E^{-1}_4(H(...)): first 4 bytes as LE u32
    let hash_val = u32::from_le_bytes([
        hash_bytes.0[0],
        hash_bytes.0[1],
        hash_bytes.0[2],
        hash_bytes.0[3],
    ]);
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
        privileges: privileges.clone(),
        pending_validators: None,
        auth_queues: None,
    };
    let exceptional = regular.clone();

    // Count items for this service (transfers to + work digests for)
    let transfer_count = transfers
        .iter()
        .filter(|t| t.destination == service_id)
        .count();
    let work_count: usize = reports
        .iter()
        .flat_map(|r| &r.results)
        .filter(|d| d.service_id == service_id)
        .count();
    let item_count = (transfer_count + work_count) as u32;

    // Encode minimal argument blob: varint(timeslot, service_id, item_count)
    let args = encode_accumulate_args(timeslot, service_id, item_count);

    // Build per-service fetch context with encoded items
    let individual_items = collect_items(transfers, service_id, reports);
    let items_blob = build_items_blob(transfers, service_id, reports);

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
        tracing::warn!(
            service_id,
            "accumulate: no code blob found for service, skipping PVM execution"
        );
        return ServiceAccResult::skipped(initial_accounts, privileges.clone());
    }
    let code_blob = code_blob.unwrap();

    // Run PVM
    let (final_context, gas_used) = run_accumulate_pvm(
        config,
        &code_blob,
        total_gas,
        &args,
        regular,
        exceptional,
        timeslot,
        entropy,
        &service_fetch_ctx,
        service_id,
    );

    tracing::debug!(
        service_id,
        gas_used,
        total_gas,
        "accumulate PVM execution complete"
    );

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
fn encode_accumulate_args(timeslot: Timeslot, service_id: ServiceId, item_count: u32) -> Vec<u8> {
    let mut args = Vec::new();
    args.extend_from_slice(&timeslot.to_le_bytes());
    args.extend_from_slice(&service_id.to_le_bytes());
    args.extend_from_slice(&item_count.to_le_bytes());
    args
}

/// Encode a single work-item operand (type U, eq:operandtuple).
/// EU(x) ≡ E(xp, xe, xa, xy, xg, O(xl), ↕xt)
fn encode_operand(report: &WorkReport, digest: &grey_types::work::WorkDigest) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&report.package_spec.package_hash.0); // p: 32 bytes
    buf.extend_from_slice(&report.package_spec.exports_root.0); // e: 32 bytes
    buf.extend_from_slice(&report.authorizer_hash.0); // a: 32 bytes
    buf.extend_from_slice(&digest.payload_hash.0); // y: 32 bytes
    buf.extend_from_slice(&digest.accumulate_gas.to_le_bytes()); // g: varint
    // O(xl) - result encoding (GP C.5: discriminated union)
    match &digest.result {
        WorkResult::Ok(data) => {
            buf.push(0);
            buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
            buf.extend_from_slice(data);
        }
        WorkResult::OutOfGas => buf.push(1),
        WorkResult::Panic => buf.push(2),
        WorkResult::BadExports => buf.push(3),
        WorkResult::BadCode => buf.push(4),
        WorkResult::CodeOversize => buf.push(5),
    }
    // ↕xt - length-prefixed authorizer trace
    buf.extend_from_slice(&(report.auth_output.len() as u32).to_le_bytes());
    buf.extend_from_slice(&report.auth_output);
    buf
}

/// Encode a single deferred transfer (type X, eq C.31).
/// EX(x) ≡ E(E4(xs), E4(xd), E8(0), xm, E8(xg))
/// Amount field is always 0 in coinless design (preserved for format compatibility).
fn encode_transfer(t: &DeferredTransfer) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&t.sender.to_le_bytes()); // E4(sender)
    buf.extend_from_slice(&t.destination.to_le_bytes()); // E4(dest)
    buf.extend_from_slice(&0u64.to_le_bytes()); // E8(amount=0, coinless)
    // Memo: fixed 128 bytes (padded with zeros)
    let mut memo = [0u8; 128];
    let copy_len = t.memo.len().min(128);
    memo[..copy_len].copy_from_slice(&t.memo[..copy_len]);
    buf.extend_from_slice(&memo); // memo: 128 bytes
    buf.extend_from_slice(&t.gas_limit.to_le_bytes()); // E8(gas_limit)
    buf
}

/// Collect discriminated items for a service: 0x01 + EX(transfer) and 0x00 + EU(operand).
/// Order: transfers first (iT), then operands (iU).
fn collect_items(
    transfers: &[DeferredTransfer],
    service_id: ServiceId,
    reports: &[WorkReport],
) -> Vec<Vec<u8>> {
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
    items
}

/// Build encoded items blob for fetch (eq C.33).
fn build_items_blob(
    transfers: &[DeferredTransfer],
    service_id: ServiceId,
    reports: &[WorkReport],
) -> Vec<u8> {
    let items = collect_items(transfers, service_id, reports);
    let mut blob = Vec::new();
    blob.extend_from_slice(&(items.len() as u32).to_le_bytes());
    for item in &items {
        blob.extend(item);
    }
    blob
}

/// Encode hash input for new service ID computation.
fn encode_new_service_hash(service_id: ServiceId, entropy: &Hash, timeslot: Timeslot) -> Vec<u8> {
    // GP eq: E(s, η'_0, H_T) — uses JAM general encoding (compact naturals for numbers)
    let mut buf = Vec::new();
    buf.extend_from_slice(&service_id.to_le_bytes());
    buf.extend_from_slice(&entropy.0);
    buf.extend_from_slice(&timeslot.to_le_bytes());
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

/// Run accumulation using the capability kernel.
/// Protocol cap CALLs exit the kernel and are dispatched here.
#[allow(clippy::too_many_arguments)]
fn run_accumulate_pvm(
    config: &Config,
    code_blob: &[u8],
    gas: Gas,
    args: &[u8],
    mut regular: AccContext,
    mut exceptional: AccContext,
    timeslot: Timeslot,
    _entropy: &Hash,
    fetch_ctx: &FetchContext,
    service_id: u32,
) -> (AccContext, Gas) {
    use javm::kernel::KernelResult;

    let mut pvm = match PvmInstance::initialize(code_blob, args, gas) {
        Some(p) => p,
        None => {
            return (exceptional, 0);
        }
    };

    // Single entrypoint PC=0. Set φ[7]=1 for accumulate operation.
    // φ[8]=args_base and φ[9]=args_len are set by the kernel init.
    // Set φ[7]=1 for accumulate operation (cold path, before execution)
    pvm.set_reg(7, 1);

    let initial_gas = pvm.gas();
    tracing::info!(
        phi7 = pvm.reg(7),
        phi8 = pvm.reg(8),
        phi9 = pvm.reg(9),
        "accumulate start regs"
    );

    loop {
        let result = pvm.kernel_run();

        match result {
            KernelResult::Halt(exit_value) => {
                let gas_used = initial_gas - pvm.gas();
                tracing::info!(exit_value, gas_used, service_id, "accumulate PVM halted");

                // Output hash is set via the OUTPUT protocol cap during execution
                // (stored in regular.output by the OUTPUT handler).
                // exit_value (φ[7]) is unused for output in the capability model.

                return (regular, gas_used);
            }
            KernelResult::Panic => {
                let gas_used = initial_gas - pvm.gas();
                return (exceptional, gas_used);
            }
            KernelResult::OutOfGas => {
                return (exceptional, initial_gas);
            }
            KernelResult::PageFault(_) => {
                let gas_used = initial_gas - pvm.gas();
                return (exceptional, gas_used);
            }
            KernelResult::ProtocolCall { slot } => {
                // Snapshot argument registers (φ[7]-φ[12]) for the handler.
                // Only these are used by protocol call handlers.
                let mut regs = [0u64; 13];
                regs[7..=12].iter_mut().enumerate().for_each(|(j, r)| {
                    *r = pvm.reg(7 + j);
                });
                let ok = handle_host_call(
                    config,
                    slot,
                    &mut pvm,
                    &regs,
                    &mut regular,
                    &mut exceptional,
                    timeslot,
                    fetch_ctx,
                    service_id,
                );
                if !ok {
                    let gas_used = initial_gas - pvm.gas();
                    return (exceptional, gas_used);
                }
                // Resume kernel execution
            }
        }
    }
}

/// Handle a protocol cap call. Slot numbers 1-28 (IPC=0, protocol caps shifted +1).
/// Returns true to continue, false to abort.
#[allow(clippy::too_many_arguments)]
fn handle_host_call(
    _config: &Config,
    slot: u8,
    pvm: &mut PvmInstance,
    regs: &[u64; 13],
    regular: &mut AccContext,
    exceptional: &mut AccContext,
    _timeslot: Timeslot,
    fetch_ctx: &FetchContext,
    service_id: u32,
) -> bool {
    const RESULT_NONE: u64 = u64::MAX;

    /// Read data from a capability or resume with RESULT_NONE and return early.
    macro_rules! read_data_or_fail {
        ($pvm:expr, $cap:expr, $off:expr, $len:expr) => {
            match $pvm.kernel_read_data($cap, $off, $len) {
                Some(data) => data,
                None => {
                    $pvm.kernel_resume(RESULT_NONE, 0);
                    return true;
                }
            }
        };
    }

    tracing::info!(slot, service_id, "handle_host_call");
    match slot {
        1 => {
            // GAS: return remaining gas
            pvm.kernel_resume(pvm.gas(), 0);
            true
        }
        2 => {
            // FETCH: φ[7]=mode, φ[8]=sub, φ[9]=out_off, φ[10]=max_len, φ[12]=data_cap
            let mode = regs[7] as u32;
            let sub = regs[8] as usize;
            let out_off = regs[9] as u32;
            let max_len = regs[10] as usize;
            let cap_idx = regs[12] as u8;

            let items_count = fetch_ctx.items.len();
            let first_item_len = fetch_ctx.items.first().map(|i| i.len()).unwrap_or(0);
            tracing::info!(
                mode,
                sub,
                out_off,
                max_len,
                cap_idx,
                items_count,
                first_item_len,
                "FETCH"
            );
            let data: Option<&[u8]> = match mode {
                0 => Some(&fetch_ctx.config_blob),
                1 => Some(fetch_ctx.entropy.as_ref()),
                14 => Some(&fetch_ctx.items_blob),
                15 => fetch_ctx.items.get(sub).map(|v| v.as_slice()),
                _ => None,
            };
            match data {
                Some(d) => {
                    let l = max_len.min(d.len());
                    pvm.kernel_write_data(cap_idx, out_off, &d[..l]);
                    pvm.kernel_resume(d.len() as u64, 0);
                }
                None => pvm.kernel_resume(RESULT_NONE, 0),
            }
            true
        }
        4 => {
            // STORAGE_R: φ[7]=key_off, φ[8]=key_len, φ[9]=out_off, φ[10]=max_len, φ[12]=data_cap
            let key_off = regs[7] as u32;
            let key_len = regs[8] as u32;
            let out_off = regs[9] as u32;
            let max_len = regs[10] as usize;
            let cap_idx = regs[12] as u8;

            let key = read_data_or_fail!(pvm, cap_idx, key_off, key_len);
            // Look up in current service's storage
            let value = regular
                .accounts
                .get(&service_id)
                .and_then(|a| a.storage.get(&key));
            match value {
                Some(v) => {
                    let l = max_len.min(v.len());
                    pvm.kernel_write_data(cap_idx, out_off, &v[..l]);
                    pvm.kernel_resume(v.len() as u64, 0);
                }
                None => pvm.kernel_resume(RESULT_NONE, 0),
            }
            true
        }
        5 => {
            // STORAGE_W: φ[7]=key_off, φ[8]=key_len, φ[9]=val_off, φ[10]=val_len, φ[12]=data_cap
            let key_off = regs[7] as u32;
            let key_len = regs[8] as u32;
            let val_off = regs[9] as u32;
            let val_len = regs[10] as u32;
            let cap_idx = regs[12] as u8;

            let key = read_data_or_fail!(pvm, cap_idx, key_off, key_len);
            let value = read_data_or_fail!(pvm, cap_idx, val_off, val_len);
            // Get old value length for return
            let account = match regular.accounts.get_mut(&service_id) {
                Some(a) => a,
                None => {
                    pvm.kernel_resume(RESULT_NONE, 0);
                    return true;
                }
            };
            let old_len = account
                .storage
                .get(&key)
                .map_or(RESULT_NONE, |v| v.len() as u64);
            if val_len == 0 {
                account.storage.remove(&key);
            } else {
                account.storage.insert(key, value);
            }
            pvm.kernel_resume(old_len, 0);
            true
        }
        18 => {
            // CHECKPOINT: y' = x (copy regular context to exceptional)
            *exceptional = regular.clone();
            pvm.kernel_resume(0, 0);
            true
        }
        26 => {
            // OUTPUT (yield in GP): set accumulation output hash
            let hash_off = regs[7] as u32;
            let data_cap = regs[12] as u8;
            if let Some(hash_bytes) = pvm.kernel_read_data(data_cap, hash_off, 32) {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&hash_bytes);
                regular.output = Some(grey_types::Hash(hash));
            }
            pvm.kernel_resume(0, 0);
            true
        }
        _ => {
            pvm.kernel_resume(HOST_WHAT, 0);
            true
        }
    }
}
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
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
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
    let priv_r =
        |o: ServiceId, a: ServiceId, b: ServiceId| -> ServiceId { if a == o { b } else { a } };

    let delta_priv = |s: ServiceId| -> &AccPrivileges {
        per_service_privs.get(&s).unwrap_or(&initial_privileges)
    };

    let m = initial_privileges.bless; // original manager
    let v = initial_privileges.designate; // original designator
    let r = initial_privileges.register; // original registrar

    let e_star = delta_priv(m); // manager's result

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

    // q' = quota_service from manager's result (same pattern as m')
    let q_prime = e_star.quota_service;

    current_privileges = AccPrivileges {
        bless: m_prime,
        assign: a_prime,
        designate: v_prime,
        register: r_prime,
        always_acc: z_prime,
        quota_service: q_prime,
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
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
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
    let _ = &transfers;
    if n == 0 {
        return (
            0,
            accounts.clone(),
            vec![],
            vec![],
            privileges.clone(),
            None,
            None,
        );
    }

    // Process this batch: Δ*(e, t, r[..i], f)
    let batch_reports = &reports[..max_reports];
    let (new_accounts, new_transfers, outputs, gas_usage, new_privileges, batch_aq, batch_pv) =
        accumulate_batch(
            config,
            accounts,
            &transfers,
            batch_reports,
            privileges,
            timeslot,
            entropy,
            fetch_ctx,
        );

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
        (Some(mut a), Some(b)) => {
            a.extend(b);
            Some(a)
        }
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
    let edited_new_queued = edit_queue(&new_queued, &accumulated_union);

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
    let (
        n,
        new_accounts,
        mut outputs,
        gas_usage,
        new_privileges,
        acc_auth_queues,
        acc_pending_validators,
    ) = accumulate_all(
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
    shift_accumulated(&mut state.accumulated, &accumulatable, n, epoch_length);

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
            // N(s) = count of work-item digests for service s
            entry.accumulate_count += 1;
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

/// Well-balanced Keccak-256 Merkle tree M_B(v, H_K) (eq E.1).
///
/// Delegates to `grey_merkle::balanced_merkle_root` with keccak_256 as hash function.
fn keccak_merkle_root(leaves: Vec<Vec<u8>>) -> Hash {
    let refs: Vec<&[u8]> = leaves.iter().map(|v| v.as_slice()).collect();
    grey_merkle::balanced_merkle_root(&refs, grey_crypto::keccak_256)
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
        quota_items: a.quota_items,
        min_item_gas: a.min_accumulate_gas,
        min_memo_gas: a.min_on_transfer_gas,
        bytes: a.total_footprint,
        quota_bytes: a.quota_bytes,
        items: a.accumulation_counter as u64,
        creation_slot: a.last_accumulation, // position r = creation timeslot
        last_accumulation_slot: a.last_activity, // position a = last accumulation timeslot
        parent_service: a.preimage_count,   // position p = parent service ID
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
    let last_accumulation = original
        .map(|o| o.last_accumulation)
        .unwrap_or(a.creation_slot);

    ServiceAccount {
        code_hash: a.code_hash,
        quota_items: a.quota_items,
        min_accumulate_gas: a.min_item_gas,
        min_on_transfer_gas: a.min_memo_gas,
        storage: a.storage.clone(),
        preimage_lookup: a.preimage_lookup.clone(),
        preimage_info: a.preimage_info.clone(),
        quota_bytes: a.quota_bytes,
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
        quota_service: p.quota_service,
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
        quota_service: p.quota_service,
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
#[allow(clippy::type_complexity)]
pub fn run_accumulation(
    config: &Config,
    state: &mut State,
    prev_timeslot: Timeslot,
    available_reports: Vec<WorkReport>,
    opaque_data: &[([u8; 31], Vec<u8>)],
) -> (
    Hash,
    BTreeMap<ServiceId, (Gas, u32)>,
    Vec<([u8; 31], Vec<u8>)>,
) {
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
    for acc in acc_state.accounts.values() {
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
            (
                sid,
                acc_to_service(a, state.services.get(&sid), was_accumulated, state.timeslot),
            )
        })
        .collect();

    // Log new service IDs being written back
    for &sid in new_services.keys() {
        if !state.services.contains_key(&sid) {}
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

    (
        acc_output.hash,
        acc_output.accumulation_stats,
        remaining_opaque,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_hash;
    use grey_types::work::{AvailabilitySpec, WorkReport};

    fn make_report(pkg_hash_byte: u8) -> WorkReport {
        WorkReport {
            package_spec: AvailabilitySpec {
                package_hash: make_hash(pkg_hash_byte),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    // --- decode_preimage_info_timeslots ---

    #[test]
    fn test_decode_preimage_info_timeslots_empty() {
        assert_eq!(decode_preimage_info_timeslots(&[]), vec![]);
    }

    #[test]
    fn test_decode_preimage_info_timeslots_truncated_header() {
        assert_eq!(decode_preimage_info_timeslots(&[1, 2, 3]), vec![]);
    }

    #[test]
    fn test_decode_preimage_info_timeslots_zero_count() {
        let data = 0u32.to_le_bytes();
        assert_eq!(decode_preimage_info_timeslots(&data), vec![]);
    }

    #[test]
    fn test_decode_preimage_info_timeslots_single() {
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes()); // count = 1
        data.extend_from_slice(&42u32.to_le_bytes()); // timeslot = 42
        assert_eq!(decode_preimage_info_timeslots(&data), vec![42]);
    }

    #[test]
    fn test_decode_preimage_info_timeslots_multiple() {
        let mut data = Vec::new();
        data.extend_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(&10u32.to_le_bytes());
        data.extend_from_slice(&20u32.to_le_bytes());
        data.extend_from_slice(&30u32.to_le_bytes());
        assert_eq!(decode_preimage_info_timeslots(&data), vec![10, 20, 30]);
    }

    #[test]
    fn test_decode_preimage_info_timeslots_truncated_elements() {
        // count = 2 but only 1 timeslot present
        let mut data = Vec::new();
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&42u32.to_le_bytes());
        // Gracefully returns what it can parse
        assert_eq!(decode_preimage_info_timeslots(&data), vec![42]);
    }

    #[test]
    fn test_decode_preimage_info_timeslots_huge_count_no_oom() {
        // Adversarial input: count prefix claims u32::MAX items but no payload.
        // Without the bounds check, Vec::with_capacity(u32::MAX) attempts a ~16GB
        // allocation and aborts the process.
        let data = u32::MAX.to_le_bytes();
        assert_eq!(decode_preimage_info_timeslots(&data), vec![]);
    }

    // --- compute_dependencies ---

    #[test]
    fn test_compute_dependencies_empty() {
        let report = make_report(1);
        assert!(compute_dependencies(&report).is_empty());
    }

    #[test]
    fn test_compute_dependencies_with_prerequisites() {
        let mut report = make_report(1);
        report.context.prerequisites = vec![make_hash(10), make_hash(20)];
        let deps = compute_dependencies(&report);
        assert_eq!(deps.len(), 2);
        assert!(deps.contains(&make_hash(10)));
        assert!(deps.contains(&make_hash(20)));
    }

    #[test]
    fn test_compute_dependencies_with_segment_lookup() {
        let mut report = make_report(1);
        report
            .segment_root_lookup
            .insert(make_hash(30), Hash([0; 32]));
        let deps = compute_dependencies(&report);
        assert_eq!(deps.len(), 1);
        assert!(deps.contains(&make_hash(30)));
    }

    #[test]
    fn test_compute_dependencies_deduplicates() {
        let mut report = make_report(1);
        let shared = make_hash(42);
        report.context.prerequisites = vec![shared];
        report.segment_root_lookup.insert(shared, Hash([0; 32]));
        // Same hash in both — should appear once
        let deps = compute_dependencies(&report);
        assert_eq!(deps.len(), 1);
    }

    // --- partition_reports ---

    #[test]
    fn test_partition_reports_all_immediate() {
        let reports = vec![make_report(1), make_report(2)];
        let (immediate, queued) = partition_reports(&reports);
        assert_eq!(immediate.len(), 2);
        assert_eq!(queued.len(), 0);
    }

    #[test]
    fn test_partition_reports_mixed() {
        let r1 = make_report(1); // no deps → immediate
        let mut r2 = make_report(2);
        r2.context.prerequisites = vec![make_hash(99)]; // has dep → queued
        let (immediate, queued) = partition_reports(&[r1, r2]);
        assert_eq!(immediate.len(), 1);
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].dependencies.len(), 1);
    }

    // --- edit_queue ---

    #[test]
    fn test_edit_queue_removes_accumulated() {
        let rr = ReadyRecord {
            report: make_report(1),
            dependencies: vec![make_hash(99)],
        };
        let accumulated: BTreeSet<Hash> = [make_hash(1)].into_iter().collect();
        let result = edit_queue(&[rr], &accumulated);
        // Report's package hash (1) is in accumulated set → removed
        assert!(result.is_empty());
    }

    #[test]
    fn test_edit_queue_removes_fulfilled_deps() {
        let rr = ReadyRecord {
            report: make_report(1),
            dependencies: vec![make_hash(10), make_hash(20)],
        };
        let accumulated: BTreeSet<Hash> = [make_hash(10)].into_iter().collect();
        let result = edit_queue(&[rr], &accumulated);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].dependencies, vec![make_hash(20)]);
    }

    // --- resolve_queue ---

    #[test]
    fn test_resolve_queue_empty() {
        assert!(resolve_queue(&[]).is_empty());
    }

    #[test]
    fn test_resolve_queue_all_ready() {
        let records = vec![
            ReadyRecord {
                report: make_report(1),
                dependencies: vec![],
            },
            ReadyRecord {
                report: make_report(2),
                dependencies: vec![],
            },
        ];
        let resolved = resolve_queue(&records);
        assert_eq!(resolved.len(), 2);
    }

    #[test]
    fn test_resolve_queue_none_ready() {
        let records = vec![ReadyRecord {
            report: make_report(1),
            dependencies: vec![make_hash(99)],
        }];
        assert!(resolve_queue(&records).is_empty());
    }

    // --- encode_accumulate_args ---

    #[test]
    fn test_encode_accumulate_args() {
        let result = encode_accumulate_args(100, 42, 3);
        assert_eq!(result.len(), 12); // 4 + 4 + 4
        assert_eq!(u32::from_le_bytes(result[0..4].try_into().unwrap()), 100);
        assert_eq!(u32::from_le_bytes(result[4..8].try_into().unwrap()), 42);
        assert_eq!(u32::from_le_bytes(result[8..12].try_into().unwrap()), 3);
    }

    // --- keccak_merkle_root ---

    #[test]
    fn test_keccak_merkle_root_empty() {
        let result = keccak_merkle_root(vec![]);
        assert_eq!(result, Hash([0u8; 32]));
    }

    #[test]
    fn test_keccak_merkle_root_single() {
        let leaf = vec![1, 2, 3];
        let result = keccak_merkle_root(vec![leaf.clone()]);
        // Single leaf: H_K(leaf)
        assert_eq!(result, grey_crypto::keccak_256(&leaf));
    }

    #[test]
    fn test_keccak_merkle_root_two_leaves() {
        let leaves = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let result = keccak_merkle_root(leaves);
        // Two leaves: keccak("node" ⌢ leaf0 ⌢ leaf1)
        let mut expected_input = Vec::new();
        expected_input.extend_from_slice(b"node");
        expected_input.extend_from_slice(&[1, 2, 3]);
        expected_input.extend_from_slice(&[4, 5, 6]);
        let expected = grey_crypto::keccak_256(&expected_input);
        assert_eq!(result, expected);
    }

    // --- compute_output_hash ---

    #[test]
    fn test_compute_output_hash_empty() {
        assert_eq!(compute_output_hash(&[]), Hash([0u8; 32]));
    }

    #[test]
    fn test_compute_output_hash_single() {
        let outputs = vec![(42u32, make_hash(1))];
        let result = compute_output_hash(&outputs);
        // Single leaf: keccak(E4(42) ⌢ hash)
        let mut leaf = Vec::with_capacity(36);
        leaf.extend_from_slice(&42u32.to_le_bytes());
        leaf.extend_from_slice(&make_hash(1).0);
        assert_eq!(result, grey_crypto::keccak_256(&leaf));
    }

    #[test]
    fn test_compute_output_hash_sorts_by_service_id() {
        // Provide out-of-order, verify same result as sorted
        let outputs_unordered = vec![(100u32, make_hash(2)), (50u32, make_hash(1))];
        let outputs_ordered = vec![(50u32, make_hash(1)), (100u32, make_hash(2))];
        assert_eq!(
            compute_output_hash(&outputs_unordered),
            compute_output_hash(&outputs_ordered)
        );
    }
}
