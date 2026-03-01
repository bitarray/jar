//! Accumulation pipeline (Section 12 of the Gray Paper).
//!
//! Implements the Δ+, Δ*, and Δ1 functions for processing available work-reports
//! and applying their results to service state.

use grey_types::constants::*;
use grey_types::state::{PrivilegedServices, ServiceAccount, State};
use grey_types::work::WorkReport;
use grey_types::{Balance, Gas, Hash, ServiceId, Timeslot};
use std::collections::{BTreeMap, BTreeSet};

/// Errors during accumulation.
#[derive(Debug, thiserror::Error)]
pub enum AccumulationError {
    #[error("service {0} not found")]
    ServiceNotFound(ServiceId),

    #[error("insufficient gas: need {needed}, have {available}")]
    InsufficientGas { needed: Gas, available: Gas },

    #[error("gas limit exceeded")]
    GasLimitExceeded,
}

/// A deferred transfer between services (eq 12.16: X).
#[derive(Clone, Debug)]
pub struct DeferredTransfer {
    /// Sender service.
    pub sender: ServiceId,
    /// Destination service.
    pub destination: ServiceId,
    /// Amount to transfer.
    pub amount: Balance,
    /// Memo (up to WT=128 bytes).
    pub memo: Vec<u8>,
    /// Gas limit for the transfer's on-transfer handler.
    pub gas_limit: Gas,
}

/// Operand tuple for accumulation of a work-item (eq 12.14: U).
#[derive(Clone, Debug)]
pub struct AccumulationOperand {
    /// Work-package hash.
    pub package_hash: Hash,
    /// Segment-root.
    pub segment_root: Hash,
    /// Authorizer hash.
    pub authorizer_hash: Hash,
    /// Payload hash from work-digest.
    pub payload_hash: Hash,
    /// Gas limit for accumulation.
    pub gas_limit: Gas,
    /// Authorization trace.
    pub auth_trace: Vec<u8>,
    /// Work result (output blob or error indicator).
    pub work_result: AccumulationWorkResult,
}

/// Simplified work result for accumulation operands.
#[derive(Clone, Debug)]
pub enum AccumulationWorkResult {
    /// Successful refinement with output bytes.
    Ok(Vec<u8>),
    /// Refinement error.
    Error,
}

/// Output of the single-service accumulation Δ1 (eq 12.24).
#[derive(Clone, Debug)]
pub struct ServiceAccumulationResult {
    /// Posterior service accounts (after mutations).
    pub services: BTreeMap<ServiceId, ServiceAccount>,
    /// Deferred transfers produced.
    pub transfers: Vec<DeferredTransfer>,
    /// Accumulation output hash (if yielded).
    pub output: Option<Hash>,
    /// Gas actually used.
    pub gas_used: Gas,
}

/// Output of the batch accumulation Δ* (eq 12.19).
#[derive(Clone, Debug)]
pub struct BatchAccumulationResult {
    /// Updated service accounts.
    pub services: BTreeMap<ServiceId, ServiceAccount>,
    /// Deferred transfers produced by all services.
    pub transfers: Vec<DeferredTransfer>,
    /// Accumulation outputs: (service_id, hash).
    pub outputs: Vec<(ServiceId, Hash)>,
    /// Gas usage: (service_id, gas_used).
    pub gas_usage: Vec<(ServiceId, Gas)>,
}

/// Output of the outer accumulation Δ+ (eq 12.18).
#[derive(Clone, Debug)]
pub struct AccumulationOutput {
    /// Number of reports accumulated.
    pub reports_accumulated: usize,
    /// Updated service accounts.
    pub services: BTreeMap<ServiceId, ServiceAccount>,
    /// Updated privileged services.
    pub privileged_services: PrivilegedServices,
    /// Accumulation outputs (θ').
    pub outputs: Vec<(ServiceId, Hash)>,
    /// Gas usage per service.
    pub gas_usage: Vec<(ServiceId, Gas)>,
}

/// Compute the total gas budget for accumulation (eq 12.25).
///
/// g = max(GT, GA * C + Σ(χZ values))
pub fn total_gas_budget(always_accumulate: &BTreeMap<ServiceId, Gas>) -> Gas {
    let always_gas: Gas = always_accumulate.values().sum();
    let base = GAS_ACCUMULATE * TOTAL_CORES as u64 + always_gas;
    GAS_TOTAL_ACCUMULATION.max(base)
}

/// Extract work-digests for a specific service from available reports.
///
/// Returns operands for the service plus the total gas allocated.
pub fn collect_operands_for_service(
    reports: &[WorkReport],
    service_id: ServiceId,
) -> (Vec<AccumulationOperand>, Gas) {
    let mut operands = Vec::new();
    let mut total_gas: Gas = 0;

    for report in reports {
        for digest in &report.digests {
            if digest.service_id == service_id {
                operands.push(AccumulationOperand {
                    package_hash: report.availability.package_hash,
                    segment_root: report.availability.segment_root,
                    authorizer_hash: report.authorizer_hash,
                    payload_hash: digest.payload_hash,
                    gas_limit: digest.gas_limit,
                    auth_trace: report.authorizer_trace.clone(),
                    work_result: match &digest.result {
                        grey_types::work::WorkResult::Ok(data) => AccumulationWorkResult::Ok(data.clone()),
                        _ => AccumulationWorkResult::Error,
                    },
                });
                total_gas = total_gas.saturating_add(digest.gas_limit);
            }
        }
    }

    (operands, total_gas)
}

/// Single-service accumulation Δ1 (eq 12.24).
///
/// Accumulates all work-items and transfers targeting a specific service.
/// NOTE: This is a simplified version — full PVM invocation of ΨA is not yet implemented.
/// Currently applies transfers and tracks gas without running the accumulate code.
pub fn accumulate_service(
    services: &BTreeMap<ServiceId, ServiceAccount>,
    service_id: ServiceId,
    operands: &[AccumulationOperand],
    incoming_transfers: &[DeferredTransfer],
    free_gas: Gas,
    timeslot: Timeslot,
) -> ServiceAccumulationResult {
    let mut services = services.clone();

    // Compute gas budget: free gas + transfer gas + operand gas
    let transfer_gas: Gas = incoming_transfers
        .iter()
        .filter(|t| t.destination == service_id)
        .map(|t| t.gas_limit)
        .sum();
    let operand_gas: Gas = operands.iter().map(|o| o.gas_limit).sum();
    let total_gas = free_gas
        .saturating_add(transfer_gas)
        .saturating_add(operand_gas);

    // Credit incoming transfers to service balance
    if let Some(account) = services.get_mut(&service_id) {
        for transfer in incoming_transfers {
            if transfer.destination == service_id {
                account.balance = account.balance.saturating_add(transfer.amount);
            }
        }
        // Update accumulation metadata
        account.last_accumulation = timeslot;
        account.accumulation_counter = account.accumulation_counter.saturating_add(1);
    }

    // In a full implementation, we would:
    // 1. Look up the service's code via code_hash
    // 2. Invoke ΨA with the PVM (entry point 5 = accumulate)
    // 3. Handle host calls (read, write, transfer, new, etc.)
    // 4. Collapse the result (using checkpoint on panic/OOG)
    //
    // For now, we simulate accumulation:
    // - Gas is consumed proportionally
    // - No state mutations beyond transfer credits
    let gas_used = total_gas.min(GAS_ACCUMULATE);

    ServiceAccumulationResult {
        services,
        transfers: vec![],
        output: None,
        gas_used,
    }
}

/// Batch accumulation Δ* (eq 12.19).
///
/// Processes all services involved in the current batch of reports.
pub fn accumulate_batch(
    services: &BTreeMap<ServiceId, ServiceAccount>,
    transfers: &[DeferredTransfer],
    reports: &[WorkReport],
    always_accumulate: &BTreeMap<ServiceId, Gas>,
    timeslot: Timeslot,
) -> BatchAccumulationResult {
    // Collect all involved services
    let mut involved: BTreeSet<ServiceId> = BTreeSet::new();

    for report in reports {
        for digest in &report.digests {
            involved.insert(digest.service_id);
        }
    }
    for (service_id, _) in always_accumulate {
        involved.insert(*service_id);
    }
    for transfer in transfers {
        involved.insert(transfer.destination);
    }

    let mut result_services = services.clone();
    let mut all_transfers = Vec::new();
    let mut outputs = Vec::new();
    let mut gas_usage = Vec::new();

    // Accumulate each service independently
    for &service_id in &involved {
        let (operands, _operand_gas) = collect_operands_for_service(reports, service_id);
        let free_gas = always_accumulate.get(&service_id).copied().unwrap_or(0);

        let result = accumulate_service(
            &result_services,
            service_id,
            &operands,
            transfers,
            free_gas,
            timeslot,
        );

        // Merge results
        result_services = result.services;
        all_transfers.extend(result.transfers);
        gas_usage.push((service_id, result.gas_used));

        if let Some(output) = result.output {
            outputs.push((service_id, output));
        }
    }

    BatchAccumulationResult {
        services: result_services,
        transfers: all_transfers,
        outputs,
        gas_usage,
    }
}

/// Outer accumulation function Δ+ (eq 12.18).
///
/// Processes reports sequentially within the gas budget, handling deferred transfers
/// from each batch by feeding them into subsequent batches.
pub fn accumulate_all(
    state: &State,
    available_reports: &[WorkReport],
    timeslot: Timeslot,
) -> AccumulationOutput {
    let budget = total_gas_budget(&state.privileged_services.always_accumulate);
    let mut remaining_gas = budget;
    let mut current_services = state.services.clone();
    let mut all_outputs = Vec::new();
    let mut all_gas_usage = Vec::new();
    let mut pending_transfers: Vec<DeferredTransfer> = Vec::new();
    let mut reports_accumulated = 0usize;

    // Split reports into those we can process within budget
    let mut report_idx = 0;
    while report_idx < available_reports.len() {
        // Calculate gas needed for this report
        let report = &available_reports[report_idx];
        let report_gas: Gas = report.digests.iter().map(|d| d.gas_limit).sum();

        if report_gas > remaining_gas {
            break; // No more gas for additional reports
        }

        // Process this report as a batch
        let batch_reports = &available_reports[report_idx..=report_idx];
        let empty_map = BTreeMap::new();
        let always_accum = if report_idx == 0 {
            &state.privileged_services.always_accumulate
        } else {
            &empty_map
        };
        let result = accumulate_batch(
            &current_services,
            &pending_transfers,
            batch_reports,
            always_accum,
            timeslot,
        );

        // Update state
        current_services = result.services;
        pending_transfers = result.transfers;
        all_outputs.extend(result.outputs);

        let batch_gas_used: Gas = result.gas_usage.iter().map(|(_, g)| *g).sum();
        all_gas_usage.extend(result.gas_usage);
        remaining_gas = remaining_gas.saturating_sub(batch_gas_used);
        reports_accumulated += 1;
        report_idx += 1;
    }

    // Update last-accumulation timeslot for all affected services
    let accumulated_services: BTreeSet<ServiceId> = all_gas_usage
        .iter()
        .filter(|(_, g)| *g > 0)
        .map(|(s, _)| *s)
        .collect();

    for service_id in &accumulated_services {
        if let Some(account) = current_services.get_mut(service_id) {
            account.last_activity = timeslot;
        }
    }

    AccumulationOutput {
        reports_accumulated,
        services: current_services,
        privileged_services: state.privileged_services.clone(),
        outputs: all_outputs,
        gas_usage: all_gas_usage,
    }
}

/// Check if a preimage is solicited but not yet provided for a service (eq 12.36: Y).
pub fn is_preimage_solicited(
    account: &ServiceAccount,
    data: &[u8],
) -> bool {
    let hash = grey_crypto::blake2b_256(data);
    let len = data.len() as u32;
    // Solicited means: entry exists in preimage_info but NOT in preimage_lookup
    account.preimage_info.contains_key(&(hash, len)) && !account.preimage_lookup.contains_key(&hash)
}

/// Integrate preimage extrinsics into service state (eq 12.37-12.38).
///
/// For each (service_id, data) pair in the extrinsic:
/// - The preimage must be solicited (is in preimage_info but not preimage_lookup)
/// - Store the data in preimage_lookup
/// - Record the timeslot in preimage_info
pub fn integrate_preimages(
    services: &mut BTreeMap<ServiceId, ServiceAccount>,
    preimages: &[(ServiceId, Vec<u8>)],
    timeslot: Timeslot,
) {
    for (service_id, data) in preimages {
        if let Some(account) = services.get_mut(service_id) {
            if is_preimage_solicited(account, data) {
                let hash = grey_crypto::blake2b_256(data);
                let len = data.len() as u32;

                // Store the actual data
                account.preimage_lookup.insert(hash, data.clone());

                // Update preimage info with provision timeslot
                if let Some(info) = account.preimage_info.get_mut(&(hash, len)) {
                    if info.len() < 3 {
                        info.push(timeslot);
                    }
                }
            }
        }
    }
}

/// Collect the set of work-package hashes from accumulated reports (P function).
pub fn accumulated_package_hashes(reports: &[WorkReport], count: usize) -> BTreeSet<Hash> {
    reports
        .iter()
        .take(count)
        .map(|r| r.availability.package_hash)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use grey_types::work::*;

    fn make_service(balance: Balance) -> ServiceAccount {
        ServiceAccount {
            code_hash: Hash::ZERO,
            balance,
            min_accumulate_gas: 0,
            min_on_transfer_gas: 0,
            storage: BTreeMap::new(),
            preimage_lookup: BTreeMap::new(),
            preimage_info: BTreeMap::new(),
            free_storage_offset: 0,
            total_footprint: 0,
            accumulation_counter: 0,
            last_accumulation: 0,
            last_activity: 0,
            preimage_count: 0,
        }
    }

    fn make_work_report(service_id: ServiceId, gas: Gas) -> WorkReport {
        WorkReport {
            availability: AvailabilitySpec {
                package_hash: Hash([1u8; 32]),
                bundle_length: 0,
                erasure_root: Hash::ZERO,
                segment_root: Hash::ZERO,
                segment_count: 0,
            },
            context: RefinementContext {
                anchor: Hash::ZERO,
                state_root: Hash::ZERO,
                beefy_root: Hash::ZERO,
                lookup_anchor: Hash::ZERO,
                lookup_anchor_timeslot: 0,
                prerequisites: vec![],
            },
            core_index: 0,
            authorizer_hash: Hash::ZERO,
            authorizer_trace: vec![],
            segment_root_lookup: BTreeMap::new(),
            digests: vec![WorkDigest {
                service_id,
                code_hash: Hash::ZERO,
                payload_hash: Hash::ZERO,
                gas_limit: gas,
                result: WorkResult::Ok(vec![]),
                gas_used: gas / 2,
                imports_count: 0,
                extrinsics_count: 0,
                extrinsics_size: 0,
                exports_count: 0,
            }],
            auth_gas_used: 0,
        }
    }

    #[test]
    fn test_total_gas_budget() {
        let empty: BTreeMap<ServiceId, Gas> = BTreeMap::new();
        let budget = total_gas_budget(&empty);
        assert_eq!(budget, GAS_TOTAL_ACCUMULATION);
    }

    #[test]
    fn test_total_gas_budget_with_always_accumulate() {
        let mut always = BTreeMap::new();
        always.insert(1, GAS_TOTAL_ACCUMULATION); // enough to exceed GT
        let budget = total_gas_budget(&always);
        assert!(budget >= GAS_TOTAL_ACCUMULATION);
    }

    #[test]
    fn test_collect_operands() {
        let report = make_work_report(42, 1000);
        let (operands, gas) = collect_operands_for_service(&[report], 42);
        assert_eq!(operands.len(), 1);
        assert_eq!(gas, 1000);
    }

    #[test]
    fn test_collect_operands_different_service() {
        let report = make_work_report(42, 1000);
        let (operands, gas) = collect_operands_for_service(&[report], 99);
        assert_eq!(operands.len(), 0);
        assert_eq!(gas, 0);
    }

    #[test]
    fn test_accumulate_service_credits_transfers() {
        let mut services = BTreeMap::new();
        services.insert(1, make_service(100));

        let transfers = vec![DeferredTransfer {
            sender: 0,
            destination: 1,
            amount: 50,
            memo: vec![],
            gas_limit: 1000,
        }];

        let result = accumulate_service(&services, 1, &[], &transfers, 0, 10);
        assert_eq!(result.services[&1].balance, 150);
    }

    #[test]
    fn test_accumulate_all_basic() {
        let mut services = BTreeMap::new();
        services.insert(42, make_service(1000));

        let state = State {
            services,
            privileged_services: PrivilegedServices::default(),
            auth_pool: vec![],
            recent_blocks: grey_types::state::RecentBlocks {
                headers: vec![],
                accumulation_log: vec![],
            },
            accumulation_outputs: vec![],
            safrole: grey_types::state::SafroleState {
                pending_keys: vec![],
                ring_root: grey_types::BandersnatchRingRoot::default(),
                seal_key_series: grey_types::state::SealKeySeries::Fallback(vec![]),
                ticket_accumulator: vec![],
            },
            entropy: [Hash::ZERO; 4],
            pending_validators: vec![],
            current_validators: vec![],
            previous_validators: vec![],
            pending_reports: vec![],
            timeslot: 0,
            auth_queue: vec![],
            judgments: grey_types::state::Judgments::default(),
            statistics: grey_types::state::ValidatorStatistics::default(),
            accumulation_queue: vec![],
            accumulation_history: vec![],
        };

        let report = make_work_report(42, 1000);
        let output = accumulate_all(&state, &[report], 1);

        assert_eq!(output.reports_accumulated, 1);
        assert!(output.services.contains_key(&42));
    }

    #[test]
    fn test_integrate_preimages() {
        let mut services = BTreeMap::new();
        let mut account = make_service(1000);
        let data = b"hello world";
        let hash = grey_crypto::blake2b_256(data);
        let len = data.len() as u32;

        // Solicit the preimage first
        account.preimage_info.insert((hash, len), vec![0]);

        services.insert(1, account);

        integrate_preimages(&mut services, &[(1, data.to_vec())], 10);

        // Check that the preimage was stored
        assert!(services[&1].preimage_lookup.contains_key(&hash));
        assert_eq!(services[&1].preimage_lookup[&hash], data);
    }

    #[test]
    fn test_is_preimage_solicited() {
        let mut account = make_service(1000);
        let data = b"test";
        let hash = grey_crypto::blake2b_256(data);
        let len = data.len() as u32;

        // Not solicited initially
        assert!(!is_preimage_solicited(&account, data));

        // After soliciting
        account.preimage_info.insert((hash, len), vec![0]);
        assert!(is_preimage_solicited(&account, data));

        // After providing
        account.preimage_lookup.insert(hash, data.to_vec());
        assert!(!is_preimage_solicited(&account, data));
    }

    #[test]
    fn test_accumulated_package_hashes() {
        let r1 = make_work_report(1, 100);
        let mut r2 = make_work_report(2, 200);
        r2.availability.package_hash = Hash([2u8; 32]);

        let hashes = accumulated_package_hashes(&[r1, r2], 2);
        assert_eq!(hashes.len(), 2);
    }
}
