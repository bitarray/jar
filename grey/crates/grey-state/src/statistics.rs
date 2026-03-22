//! Validator activity statistics sub-transition (Section 13, eq 13.3-13.5).
//!
//! Updates per-validator performance records based on block activity,
//! and computes per-core (π_C) and per-service (π_S) statistics.

use grey_types::config::Config;
use grey_types::constants::ERASURE_PIECE_SIZE;
use grey_types::header::Extrinsic;
use grey_types::state::{CoreStatistics, ServiceStatistics, ValidatorRecord, ValidatorStatistics};
use grey_types::work::WorkReport;
use grey_types::Timeslot;
use std::collections::BTreeMap;

/// Apply the statistics sub-transition.
///
/// Updates the validator statistics based on the block's author and extrinsic content.
/// On epoch boundaries, rotates current stats to last and resets current.
/// Computes per-core statistics (π_C) from incoming and available work reports.
/// Computes per-service statistics (π_S) from incoming reports and preimage data.
pub fn update_statistics(
    config: &Config,
    stats: &mut ValidatorStatistics,
    prior_timeslot: Timeslot,
    new_timeslot: Timeslot,
    author_index: u16,
    extrinsic: &Extrinsic,
    incoming_reports: &[&WorkReport],
    available_reports: &[WorkReport],
    accumulation_stats: &std::collections::BTreeMap<grey_types::ServiceId, (javm::Gas, u32)>,
) {
    let old_epoch = prior_timeslot / config.epoch_length;
    let new_epoch = new_timeslot / config.epoch_length;

    let num_validators = stats.current.len();

    // Epoch transition: rotate statistics (eq 13.4)
    if new_epoch > old_epoch {
        stats.last = stats.current.clone();
        stats.current = vec![ValidatorRecord::default(); num_validators];
    }

    let author = author_index as usize;
    if author < stats.current.len() {
        // Block author: increment blocks_produced (eq 13.5)
        stats.current[author].blocks_produced += 1;

        // Tickets introduced
        stats.current[author].tickets_introduced += extrinsic.tickets.len() as u32;

        // Preimages introduced
        stats.current[author].preimages_introduced += extrinsic.preimages.len() as u32;

        // Preimage total bytes
        let preimage_bytes: u64 = extrinsic
            .preimages
            .iter()
            .map(|(_, data)| data.len() as u64)
            .sum();
        stats.current[author].preimage_bytes += preimage_bytes;
    }

    // Assurances: each validator that submitted an assurance
    for assurance in &extrinsic.assurances {
        let idx = assurance.validator_index as usize;
        if idx < stats.current.len() {
            stats.current[idx].assurances_made += 1;
        }
    }

    // Guarantees: G = set of Ed25519 keys from guarantee credentials (eq 13.5)
    // π_V'[v]_g ≡ a[v]_g + (κ'_v ∈ G) — boolean membership, not count
    {
        let mut reporters = std::collections::HashSet::new();
        for guarantee in &extrinsic.guarantees {
            for (validator_idx, _sig) in &guarantee.credentials {
                reporters.insert(*validator_idx as usize);
            }
        }
        for idx in reporters {
            if idx < stats.current.len() {
                stats.current[idx].reports_guaranteed += 1;
            }
        }
    }

    // Compute per-core statistics π_C (eq 13.3)
    compute_core_statistics(config, stats, &extrinsic.assurances, incoming_reports, available_reports);

    // Compute per-service statistics π_S (eq 13.3)
    compute_service_statistics(stats, extrinsic, incoming_reports, accumulation_stats);
}

/// Compute per-core statistics π_C (GP eq 2046-2085).
///
/// For each core c:
///   R(c) = sum over (d in r.results, r in I, r.core_index == c) of refine-load fields
///   L(c) = sum over (r in I, r.core_index == c) of r.package_spec.bundle_length
///   D(c) = sum over (r in R, r.core_index == c) of (bundle_length + W_G * ceil(exports_count * 65/64))
///   p    = count of assurances with bit c set
fn compute_core_statistics(
    config: &Config,
    stats: &mut ValidatorStatistics,
    assurances: &grey_types::header::AssurancesExtrinsic,
    incoming_reports: &[&WorkReport],
    available_reports: &[WorkReport],
) {
    let num_cores = config.core_count as usize;
    let segment_size = config.erasure_pieces_per_segment as u64 * ERASURE_PIECE_SIZE as u64;

    let mut core_stats = vec![CoreStatistics::default(); num_cores];

    // R(c): sum refine-load fields from incoming reports' digests
    for report in incoming_reports {
        let c = report.core_index as usize;
        if c >= num_cores {
            continue;
        }
        for digest in &report.results {
            core_stats[c].imports += digest.imports_count as u64;
            core_stats[c].extrinsic_count += digest.extrinsics_count as u64;
            core_stats[c].extrinsic_size += digest.extrinsics_size as u64;
            core_stats[c].exports += digest.exports_count as u64;
            core_stats[c].gas_used += digest.gas_used;
        }
        // L(c): bundle size from incoming reports
        core_stats[c].bundle_size += report.package_spec.bundle_length as u64;
    }

    // D(c): DA load from available reports (newly available via assurances)
    for report in available_reports {
        let c = report.core_index as usize;
        if c >= num_cores {
            continue;
        }
        let bundle_len = report.package_spec.bundle_length as u64;
        let exports = report.package_spec.exports_count as u64;
        // D(c) = bundle_length + W_G * ceil(exports_count * 65 / 64)
        let segments_bytes = segment_size * ceiling_div(exports * 65, 64);
        core_stats[c].da_load += bundle_len + segments_bytes;
    }

    // p: popularity = count of assurance bitfield bits set per core
    for assurance in assurances {
        for core in 0..num_cores {
            let byte_idx = core / 8;
            let bit_idx = core % 8;
            if byte_idx < assurance.bitfield.len()
                && (assurance.bitfield[byte_idx] & (1 << bit_idx)) != 0
            {
                core_stats[core].popularity += 1;
            }
        }
    }

    stats.core_stats = core_stats;
}

/// Compute per-service statistics π_S (GP eq 2087-2142).
///
/// For each service s in the union of {services from incoming digests} ∪ {services from preimages} ∪ {services from accumulation}:
///   R(s) = (count, gas_used, imports, extrinsic_count, extrinsic_size, exports) summed from incoming digests
///   p = (count, size) from preimage extrinsic entries
///   a = accumulation results: (gas_used, item_count) per service from the accumulation pipeline
fn compute_service_statistics(
    stats: &mut ValidatorStatistics,
    extrinsic: &Extrinsic,
    incoming_reports: &[&WorkReport],
    accumulation_stats: &std::collections::BTreeMap<grey_types::ServiceId, (javm::Gas, u32)>,
) {
    let mut svc_stats: BTreeMap<grey_types::ServiceId, ServiceStatistics> = BTreeMap::new();

    // s^R: services from incoming work digests (GP eq 2121-2142: R(s))
    for report in incoming_reports {
        for digest in &report.results {
            let entry = svc_stats.entry(digest.service_id).or_default();
            entry.refinement_count += 1;
            entry.refinement_gas_used += digest.gas_used;
            entry.imports += digest.imports_count as u64;
            entry.extrinsic_count += digest.extrinsics_count as u64;
            entry.extrinsic_size += digest.extrinsics_size as u64;
            entry.exports += digest.exports_count as u64;
        }
    }

    // s^P: services from preimage extrinsic
    for (service_id, data) in &extrinsic.preimages {
        let entry = svc_stats.entry(*service_id).or_default();
        entry.provided_count += 1;
        entry.provided_size += data.len() as u64;
    }

    // K(S): services from accumulation statistics (GP eq 2113: a ≔ U(S[s], (0,0)))
    // S[s] = (G(s), N(s)) — gas and work item count
    for (service_id, (gas, item_count)) in accumulation_stats {
        let entry = svc_stats.entry(*service_id).or_default();
        entry.accumulate_gas_used += *gas;
        entry.accumulate_count += *item_count as u64;
    }

    stats.service_stats = svc_stats;
}

/// Integer ceiling division.
fn ceiling_div(a: u64, b: u64) -> u64 {
    if b == 0 {
        return 0;
    }
    (a + b - 1) / b
}
