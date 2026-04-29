//! Work report guarantee processing sub-transition (Section 11, eq 11.23-11.42).
//!
//! Validates and processes work report guarantees submitted in the block extrinsic.

use grey_types::config::Config;
use grey_types::validator::ValidatorKey;
use grey_types::work::{WorkDigest, WorkReport, WorkResult};
use grey_types::{Ed25519PublicKey, Ed25519Signature, Hash, ServiceId, Timeslot, signing_contexts};
use javm::Gas;
use std::collections::{BTreeMap, BTreeSet};

/// Maximum accumulate gas per work report (GA).
const MAX_ACCUMULATE_GAS: Gas = 10_000_000;

/// Maximum output size per work result item (bytes).
const MAX_OUTPUT_PER_ITEM: usize = 18_432;

/// Maximum segment root lookup entries per work report.
const MAX_SEGMENT_LOOKUPS: usize = 4;

stf_error! {
    /// Error type for reports validation.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum ReportError {
        OutOfOrderGuarantee => "out_of_order_guarantee",
        BadCoreIndex => "bad_core_index",
        CoreEngaged => "core_engaged",
        DuplicatePackage => "duplicate_package",
        MissingWorkResults => "missing_work_results",
        NotSortedOrUniqueGuarantors => "not_sorted_or_unique_guarantors",
        BadValidatorIndex => "bad_validator_index",
        BannedValidator => "banned_validator",
        InsufficientGuarantees => "insufficient_guarantees",
        WrongAssignment => "wrong_assignment",
        BadSignature => "bad_signature",
        AnchorNotRecent => "anchor_not_recent",
        BadStateRoot => "bad_state_root",
        BadBeefyMmrRoot => "bad_beefy_mmr_root",
        FutureReportSlot => "future_report_slot",
        ReportEpochBeforeLast => "report_epoch_before_last",
        CoreUnauthorized => "core_unauthorized",
        BadServiceId => "bad_service_id",
        BadCodeHash => "bad_code_hash",
        ServiceItemGasTooLow => "service_item_gas_too_low",
        WorkReportGasTooHigh => "work_report_gas_too_high",
        WorkReportTooBig => "work_report_too_big",
        TooManyDependencies => "too_many_dependencies",
        DependencyMissing => "dependency_missing",
        SegmentRootLookupInvalid => "segment_root_lookup_invalid",
    }
}

/// A guarantee input as parsed from the extrinsic.
#[derive(Clone, Debug)]
pub struct GuaranteeInput {
    pub report: WorkReport,
    pub slot: Timeslot,
    pub signatures: Vec<(u16, Ed25519Signature)>,
}

/// Recent block info for validation.
#[derive(Clone, Debug)]
pub struct RecentBlockEntry {
    pub header_hash: Hash,
    pub state_root: Hash,
    pub beefy_root: Hash,
    pub reported: Vec<(Hash, Hash)>,
}

/// Availability assignment slot.
#[derive(Clone, Debug)]
pub struct AvailAssignment {
    pub report: WorkReport,
    pub timeout: Timeslot,
}

/// Service account info needed for validation.
#[derive(Clone, Debug)]
pub struct ServiceInfo {
    pub code_hash: Hash,
    pub min_item_gas: Gas,
}

/// Per-core statistics.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CoreStats {
    pub da_load: u64,
    pub popularity: u64,
    pub imports: u64,
    pub extrinsic_count: u64,
    pub extrinsic_size: u64,
    pub exports: u64,
    pub bundle_size: u64,
    pub gas_used: u64,
}

impl CoreStats {
    /// Accumulate refine-load fields from a work digest.
    fn add_digest(&mut self, digest: &WorkDigest) {
        self.imports += digest.imports_count as u64;
        self.extrinsic_count += digest.extrinsics_count as u64;
        self.extrinsic_size += digest.extrinsics_size as u64;
        self.exports += digest.exports_count as u64;
        self.gas_used += digest.gas_used;
    }
}

/// Per-service statistics output from reports processing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServiceStats {
    pub provided_count: u32,
    pub provided_size: u64,
    pub refinement_count: u32,
    pub refinement_gas_used: u64,
    pub imports: u64,
    pub extrinsic_count: u64,
    pub extrinsic_size: u64,
    pub exports: u64,
    pub accumulate_count: u32,
    pub accumulate_gas_used: u64,
}

impl ServiceStats {
    /// Accumulate refinement fields from a work digest.
    fn add_digest(&mut self, digest: &WorkDigest) {
        self.refinement_count += 1;
        self.refinement_gas_used += digest.gas_used;
        self.imports += digest.imports_count as u64;
        self.extrinsic_count += digest.extrinsics_count as u64;
        self.extrinsic_size += digest.extrinsics_size as u64;
        self.exports += digest.exports_count as u64;
    }
}

/// Reported package output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportedPackage {
    pub work_package_hash: Hash,
    pub segment_tree_root: Hash,
}

/// Output of successful reports processing.
#[derive(Clone, Debug)]
pub struct ReportsOutput {
    pub reported: Vec<ReportedPackage>,
    pub reporters: Vec<Ed25519PublicKey>,
}

/// Complete state needed for reports validation.
pub struct ReportsState {
    pub avail_assignments: Vec<Option<AvailAssignment>>,
    pub curr_validators: Vec<ValidatorKey>,
    pub prev_validators: Vec<ValidatorKey>,
    pub entropy: [Hash; 4],
    pub offenders: BTreeSet<Ed25519PublicKey>,
    pub recent_blocks: Vec<RecentBlockEntry>,
    pub auth_pools: Vec<Vec<Hash>>,
    pub accounts: BTreeMap<ServiceId, ServiceInfo>,
    pub cores_statistics: Vec<CoreStats>,
    pub services_statistics: BTreeMap<ServiceId, ServiceStats>,
}

/// Apply the reports sub-transition.
pub fn process_reports(
    config: &Config,
    state: &mut ReportsState,
    guarantees: &[GuaranteeInput],
    current_slot: Timeslot,
    known_packages: &BTreeSet<Hash>,
) -> Result<ReportsOutput, ReportError> {
    let num_cores = config.core_count as usize;
    let num_validators = state.curr_validators.len();
    let rotation_period = config.rotation_period();

    // eq 11.24: Guarantees must be sorted by core_index
    if !crate::is_strictly_sorted_by_key(guarantees, |g| g.report.core_index) {
        return Err(ReportError::OutOfOrderGuarantee);
    }

    // Collect all package hashes upfront for dependency/duplicate checking
    let all_batch_packages: BTreeSet<Hash> = guarantees
        .iter()
        .map(|g| g.report.package_spec.package_hash)
        .collect();

    // Compute the per-validator core assignment for M and M*
    let assignment_m =
        compute_core_assignments(config, &state.entropy[2], current_slot, num_validators);
    let prev_timeslot = current_slot.saturating_sub(rotation_period);
    let prev_same_epoch = config.epoch_of(prev_timeslot) == config.epoch_of(current_slot);
    let prev_entropy = if prev_same_epoch {
        &state.entropy[2]
    } else {
        &state.entropy[3]
    };
    let assignment_m_star =
        compute_core_assignments(config, prev_entropy, prev_timeslot, num_validators);

    // Track seen packages for duplicate checking
    let mut seen_packages: BTreeSet<Hash> = BTreeSet::new();

    // Collect all reported packages and reporters
    let mut reported = Vec::new();
    let mut reporter_set: BTreeSet<Ed25519PublicKey> = BTreeSet::new();

    for guarantee in guarantees {
        let report = &guarantee.report;
        let core = report.core_index as usize;

        // eq 11.25: Core index must be valid
        if core >= num_cores {
            return Err(ReportError::BadCoreIndex);
        }

        // Core must not already be engaged
        if state.avail_assignments[core].is_some() {
            return Err(ReportError::CoreEngaged);
        }

        // Package must not be duplicated in this batch
        let pkg_hash = report.package_spec.package_hash;
        if !seen_packages.insert(pkg_hash) {
            return Err(ReportError::DuplicatePackage);
        }

        // Package must not be in recent blocks
        for block in &state.recent_blocks {
            for (reported_hash, _) in &block.reported {
                if *reported_hash == pkg_hash {
                    return Err(ReportError::DuplicatePackage);
                }
            }
        }

        // Report must have at least one result
        if report.results.is_empty() {
            return Err(ReportError::MissingWorkResults);
        }

        // Credentials must be sorted by validator_index, unique
        if !crate::is_strictly_sorted_by_key(&guarantee.signatures, |s| s.0) {
            return Err(ReportError::NotSortedOrUniqueGuarantors);
        }

        // All validator indices must be valid
        for (idx, _) in &guarantee.signatures {
            if *idx as usize >= num_validators {
                return Err(ReportError::BadValidatorIndex);
            }
        }

        // Determine which rotation this guarantee belongs to
        let current_rot = config.rotation_of(current_slot);
        let guarantee_rot = config.rotation_of(guarantee.slot);

        // Report slot must not be in the future
        if guarantee.slot > current_slot {
            return Err(ReportError::FutureReportSlot);
        }

        // Report must be from current or previous rotation
        if current_rot > guarantee_rot + 1 {
            return Err(ReportError::ReportEpochBeforeLast);
        }

        // Determine which validator set and assignment to use (eq 11.22, 11.26)
        let is_current_rotation = current_rot == guarantee_rot;
        let (validators, assignment) = if is_current_rotation {
            // Same rotation: use M and current validators
            (&state.curr_validators, &assignment_m)
        } else {
            // Previous rotation: use M* and validator set determined by epoch
            if prev_same_epoch {
                (&state.curr_validators, &assignment_m_star)
            } else {
                (&state.prev_validators, &assignment_m_star)
            }
        };

        // Check no banned validators
        for (idx, _) in &guarantee.signatures {
            let ed25519_key = &validators[*idx as usize].ed25519;
            if state.offenders.contains(ed25519_key) {
                return Err(ReportError::BannedValidator);
            }
        }

        // Must have enough guarantors (credential is 2 to 3 entries per spec eq 11.23)
        if guarantee.signatures.len() < 2 {
            return Err(ReportError::InsufficientGuarantees);
        }

        // Assignment validation: all signing validators must be assigned to this core
        for (idx, _) in &guarantee.signatures {
            if assignment[*idx as usize] != core {
                return Err(ReportError::WrongAssignment);
            }
        }

        // Verify Ed25519 signatures
        let report_hash = grey_crypto::report_hash(report);
        let message = signing_contexts::build_guarantee_message(&report_hash.0);

        for (idx, sig) in &guarantee.signatures {
            let ed25519_key = &validators[*idx as usize].ed25519;
            if !grey_crypto::ed25519_verify(ed25519_key, &message, sig) {
                return Err(ReportError::BadSignature);
            }
        }

        // Anchor must be in recent blocks
        let anchor_block = state
            .recent_blocks
            .iter()
            .find(|b| b.header_hash == report.context.anchor)
            .ok_or(ReportError::AnchorNotRecent)?;

        // State root must match
        if report.context.state_root != anchor_block.state_root {
            return Err(ReportError::BadStateRoot);
        }

        // Beefy root must match
        if report.context.beefy_root != anchor_block.beefy_root {
            return Err(ReportError::BadBeefyMmrRoot);
        }

        // Authorization: authorizer_hash must be in auth_pools[core]
        if core >= state.auth_pools.len()
            || !state.auth_pools[core].contains(&report.authorizer_hash)
        {
            return Err(ReportError::CoreUnauthorized);
        }

        // Validate work results
        let mut total_gas: Gas = 0;
        for digest in &report.results {
            // Service must exist
            let service = state
                .accounts
                .get(&digest.service_id)
                .ok_or(ReportError::BadServiceId)?;

            // Code hash must match
            if digest.code_hash != service.code_hash {
                return Err(ReportError::BadCodeHash);
            }

            // Accumulate gas must meet service minimum
            if digest.accumulate_gas < service.min_item_gas {
                return Err(ReportError::ServiceItemGasTooLow);
            }

            // Check output size
            if let WorkResult::Ok(ref data) = digest.result
                && data.len() > MAX_OUTPUT_PER_ITEM
            {
                return Err(ReportError::WorkReportTooBig);
            }

            total_gas = total_gas.saturating_add(digest.accumulate_gas);
        }

        // Total gas must not exceed GA
        if total_gas > MAX_ACCUMULATE_GAS {
            return Err(ReportError::WorkReportGasTooHigh);
        }

        // Segment root lookup validation
        if report.segment_root_lookup.len() > MAX_SEGMENT_LOOKUPS {
            return Err(ReportError::TooManyDependencies);
        }

        // Segment root lookup entries must reference valid packages with matching roots
        for (lookup_hash, lookup_root) in &report.segment_root_lookup {
            // Check in recent blocks: must match exports_root
            let in_recent = state.recent_blocks.iter().any(|b| {
                b.reported
                    .iter()
                    .any(|(h, exports_root)| h == lookup_hash && exports_root == lookup_root)
            });
            // Check in current batch guarantees
            let in_batch = guarantees.iter().any(|g| {
                g.report.package_spec.package_hash == *lookup_hash
                    && g.report.package_spec.exports_root == *lookup_root
            });
            if !in_recent && !in_batch {
                return Err(ReportError::SegmentRootLookupInvalid);
            }
        }

        // Prerequisite packages must be available
        for prereq in &report.context.prerequisites {
            let in_known = known_packages.contains(prereq);
            let in_batch = all_batch_packages.contains(prereq);

            if !in_known && !in_batch {
                return Err(ReportError::DependencyMissing);
            }
        }

        // Collect reported package
        reported.push(ReportedPackage {
            work_package_hash: pkg_hash,
            segment_tree_root: report.package_spec.exports_root,
        });

        // Collect reporter ed25519 keys
        for (idx, _) in &guarantee.signatures {
            reporter_set.insert(validators[*idx as usize].ed25519);
        }
    }

    // Apply state changes: place reports in availability assignments
    for guarantee in guarantees {
        let core = guarantee.report.core_index as usize;
        state.avail_assignments[core] = Some(AvailAssignment {
            report: guarantee.report.clone(),
            timeout: current_slot,
        });

        // Update core and service statistics in a single pass
        let has_core = core < state.cores_statistics.len();
        if has_core {
            state.cores_statistics[core].bundle_size =
                guarantee.report.package_spec.bundle_length as u64;
        }
        for digest in &guarantee.report.results {
            if has_core {
                state.cores_statistics[core].add_digest(digest);
            }
            state
                .services_statistics
                .entry(digest.service_id)
                .or_default()
                .add_digest(digest);
        }
    }

    let reporters: Vec<Ed25519PublicKey> = reporter_set.into_iter().collect();

    // Sort reported packages by work_package_hash
    reported.sort_by_key(|a| a.work_package_hash.0);

    Ok(ReportsOutput {
        reported,
        reporters,
    })
}

/// Compute per-validator core assignments (eq 11.19-11.20).
///
/// P(e, t): For each validator i, compute assigned core as:
///   1. initial[i] = floor(C * i / V)  (home core)
///   2. Shuffle initial sequence with entropy e
///   3. Apply rotation: (shuffled[i] + floor((t mod E) / R)) mod C
fn compute_core_assignments(
    config: &Config,
    entropy: &Hash,
    timeslot: Timeslot,
    validator_count: usize,
) -> Vec<usize> {
    let v = validator_count;
    let c = config.core_count as usize;

    // Step 1: initial assignment [floor(C*i/V) | i < V]
    let mut cores: Vec<usize> = (0..v).map(|i| c * i / v).collect();

    // Step 2: Shuffle with entropy
    grey_crypto::shuffle::shuffle_with_hash(&mut cores, entropy);

    // Step 3: Apply rotation R(c, n) = [(x + n) mod C | x <- c]
    let rot_offset = config.rotation_in_epoch(timeslot) as usize;
    for core in &mut cores {
        *core = (*core + rot_offset) % c;
    }

    cores
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_error_as_str_exhaustive() {
        // Verify every variant has a non-empty string representation
        let variants: Vec<ReportError> = vec![
            ReportError::OutOfOrderGuarantee,
            ReportError::BadCoreIndex,
            ReportError::CoreEngaged,
            ReportError::DuplicatePackage,
            ReportError::MissingWorkResults,
            ReportError::NotSortedOrUniqueGuarantors,
            ReportError::BadValidatorIndex,
            ReportError::BannedValidator,
            ReportError::InsufficientGuarantees,
            ReportError::WrongAssignment,
            ReportError::BadSignature,
            ReportError::AnchorNotRecent,
            ReportError::BadStateRoot,
            ReportError::BadBeefyMmrRoot,
            ReportError::FutureReportSlot,
            ReportError::ReportEpochBeforeLast,
            ReportError::CoreUnauthorized,
            ReportError::BadServiceId,
            ReportError::BadCodeHash,
            ReportError::ServiceItemGasTooLow,
            ReportError::WorkReportGasTooHigh,
            ReportError::WorkReportTooBig,
            ReportError::TooManyDependencies,
            ReportError::DependencyMissing,
            ReportError::SegmentRootLookupInvalid,
        ];
        for v in &variants {
            let s = v.as_str();
            assert!(!s.is_empty(), "{:?} has empty as_str()", v);
            assert!(
                s.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "{:?} has non-snake_case as_str: {}",
                v,
                s
            );
        }
    }

    #[test]
    fn test_compute_core_assignments_basic() {
        let config = Config::tiny(); // V=6, C=2
        let entropy = Hash([42u8; 32]);
        let v = config.validators_count as usize;
        let assignments = compute_core_assignments(&config, &entropy, 0, v);
        assert_eq!(assignments.len(), v);
        for &core in &assignments {
            assert!(core < config.core_count as usize);
        }
    }

    #[test]
    fn test_compute_core_assignments_deterministic() {
        let config = Config::tiny();
        let v = config.validators_count as usize;
        let entropy = Hash([7u8; 32]);
        let a1 = compute_core_assignments(&config, &entropy, 5, v);
        let a2 = compute_core_assignments(&config, &entropy, 5, v);
        assert_eq!(a1, a2);
    }

    #[test]
    fn test_compute_core_assignments_different_entropy() {
        let config = Config::tiny();
        let v = config.validators_count as usize;
        let a1 = compute_core_assignments(&config, &Hash([1u8; 32]), 0, v);
        let a2 = compute_core_assignments(&config, &Hash([2u8; 32]), 0, v);
        assert_ne!(a1, a2);
    }

    #[test]
    fn test_compute_core_assignments_rotation() {
        let config = Config::tiny(); // R=4
        let v = config.validators_count as usize;
        let entropy = Hash([42u8; 32]);
        let a0 = compute_core_assignments(&config, &entropy, 0, v);
        let a4 = compute_core_assignments(&config, &entropy, 4, v);
        assert_ne!(a0, a4, "different rotation periods should differ");
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use grey_types::Hash;
    use grey_types::config::Config;
    use grey_types::testing::arb_hash;
    use grey_types::work::WorkReport;
    use proptest::prelude::*;

    fn make_reports_state(config: &Config) -> ReportsState {
        let v = config.validators_count as usize;
        let c = config.core_count as usize;
        let validators: Vec<ValidatorKey> = (0..v).map(|_| ValidatorKey::default()).collect();
        ReportsState {
            avail_assignments: vec![None; c],
            curr_validators: validators.clone(),
            prev_validators: validators,
            entropy: [Hash::ZERO; 4],
            offenders: BTreeSet::new(),
            recent_blocks: vec![],
            auth_pools: vec![vec![]; c],
            accounts: BTreeMap::new(),
            cores_statistics: vec![CoreStats::default(); c],
            services_statistics: BTreeMap::new(),
        }
    }

    proptest! {
        /// All core assignments are within [0, core_count).
        #[test]
        fn assignments_in_bounds(
            entropy in arb_hash(),
            timeslot in 0u32..10000,
        ) {
            let config = Config::tiny(); // V=6, C=2
            let v = config.validators_count as usize;
            let c = config.core_count as usize;
            let assignments = compute_core_assignments(&config, &entropy, timeslot, v);
            prop_assert_eq!(assignments.len(), v);
            for (i, &core) in assignments.iter().enumerate() {
                prop_assert!(core < c, "validator {i}: core {core} >= C {c}");
            }
        }

        /// Core assignments are deterministic: same inputs → same outputs.
        #[test]
        fn assignments_deterministic(
            entropy in arb_hash(),
            timeslot in 0u32..10000,
        ) {
            let config = Config::tiny();
            let v = config.validators_count as usize;
            let a1 = compute_core_assignments(&config, &entropy, timeslot, v);
            let a2 = compute_core_assignments(&config, &entropy, timeslot, v);
            prop_assert_eq!(a1, a2);
        }

        /// Empty guarantees always succeed.
        #[test]
        fn empty_guarantees_always_ok(timeslot in 0u32..10000) {
            let config = Config::tiny();
            let mut state = make_reports_state(&config);
            let known = BTreeSet::new();
            let result = process_reports(&config, &mut state, &[], timeslot, &known);
            prop_assert!(result.is_ok());
            let output = result.unwrap();
            prop_assert!(output.reported.is_empty());
            prop_assert!(output.reporters.is_empty());
        }

        /// Guarantees with unsorted core indices are rejected.
        #[test]
        fn unsorted_cores_rejected(
            timeslot in 0u32..10000,
        ) {
            let config = Config::tiny(); // C=2
            let mut state = make_reports_state(&config);
            let known = BTreeSet::new();

            // Two guarantees: core 1 before core 0 → unsorted
            let report0 = WorkReport { core_index: 1, ..WorkReport::default() };
            let report1 = WorkReport { core_index: 0, ..WorkReport::default() };
            let guarantees = vec![
                GuaranteeInput {
                    report: report0,
                    slot: timeslot,
                    signatures: vec![],
                },
                GuaranteeInput {
                    report: report1,
                    slot: timeslot,
                    signatures: vec![],
                },
            ];
            let result = process_reports(&config, &mut state, &guarantees, timeslot, &known);
            prop_assert!(matches!(result, Err(ReportError::OutOfOrderGuarantee)));
        }

        /// Guarantees with core_index >= core_count are rejected.
        #[test]
        fn bad_core_index_rejected(
            bad_core in 2u16..100, // C=2 for tiny
            timeslot in 0u32..10000,
        ) {
            let config = Config::tiny();
            let mut state = make_reports_state(&config);
            let known = BTreeSet::new();

            let report = WorkReport { core_index: bad_core, ..WorkReport::default() };
            let guarantees = vec![GuaranteeInput {
                report,
                slot: timeslot,
                signatures: vec![],
            }];
            let result = process_reports(&config, &mut state, &guarantees, timeslot, &known);
            prop_assert!(matches!(result, Err(ReportError::BadCoreIndex)));
        }
    }
}
