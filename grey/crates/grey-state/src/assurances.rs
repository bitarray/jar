//! Availability assurances sub-transition (Section 11.2, eq 11.10-11.17).
//!
//! Processes availability assurances to determine which pending work reports
//! have become available.

use grey_types::config::Config;
use grey_types::header::Assurance;
use grey_types::state::PendingReport;
use grey_types::validator::ValidatorKey;
use grey_types::work::WorkReport;
use grey_types::Hash;

/// Error type for assurances validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssuranceError {
    NotSortedOrUniqueAssurers,
    BadSignature,
    BadValidatorIndex,
    CoreNotEngaged,
    BadAttestationParent,
}

impl AssuranceError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotSortedOrUniqueAssurers => "not_sorted_or_unique_assurers",
            Self::BadSignature => "bad_signature",
            Self::BadValidatorIndex => "bad_validator_index",
            Self::CoreNotEngaged => "core_not_engaged",
            Self::BadAttestationParent => "bad_attestation_parent",
        }
    }
}

/// Output of successful assurances processing.
#[derive(Debug, Clone)]
pub struct AssuranceOutput {
    /// Work reports that became available.
    pub reported: Vec<WorkReport>,
}

/// Apply the assurances sub-transition.
///
/// Returns the list of newly available work reports, or an error.
pub fn process_assurances(
    config: &Config,
    pending_reports: &mut Vec<Option<PendingReport>>,
    assurances: &[Assurance],
    current_timeslot: u32,
    parent_hash: Hash,
    current_validators: &[ValidatorKey],
) -> Result<AssuranceOutput, AssuranceError> {
    let super_majority = config.super_majority();
    let num_cores = config.core_count as usize;

    // Validate validator indices (must be valid before other checks)
    for a in assurances {
        if a.validator_index as usize >= current_validators.len() {
            return Err(AssuranceError::BadValidatorIndex);
        }
    }

    // eq 11.12: Assurances must be sorted by validator index, no duplicates
    for w in assurances.windows(2) {
        if w[0].validator_index >= w[1].validator_index {
            return Err(AssuranceError::NotSortedOrUniqueAssurers);
        }
    }

    // eq 11.11: All assurance anchors must equal parent hash
    for a in assurances {
        if a.anchor != parent_hash {
            return Err(AssuranceError::BadAttestationParent);
        }
    }

    // eq 11.13: Verify signatures
    // Message: X_A ⌢ H(E(H_P, a_f))  where X_A = "jam_available"
    for a in assurances {
        let idx = a.validator_index as usize;
        let ed25519_key = &current_validators[idx].ed25519;

        // Encode (parent_hash, bitfield) and hash
        let mut payload = Vec::new();
        payload.extend_from_slice(&parent_hash.0);
        payload.extend_from_slice(&a.bitfield);
        let payload_hash = grey_crypto::blake2b_256(&payload);

        let mut message = Vec::with_capacity(13 + 32);
        message.extend_from_slice(b"jam_available");
        message.extend_from_slice(&payload_hash.0);

        if !grey_crypto::ed25519_verify(ed25519_key, &message, &a.signature) {
            return Err(AssuranceError::BadSignature);
        }
    }

    // eq 11.15: Bits may only be set for cores with pending reports
    for a in assurances {
        for core in 0..num_cores {
            let byte_idx = core / 8;
            let bit_idx = core % 8;
            if byte_idx < a.bitfield.len() && (a.bitfield[byte_idx] & (1 << bit_idx)) != 0 {
                if core >= pending_reports.len() || pending_reports[core].is_none() {
                    return Err(AssuranceError::CoreNotEngaged);
                }
            }
        }
    }

    // eq 11.16: Count assurances per core, determine available reports
    let mut assurance_counts = vec![0u32; num_cores];
    for a in assurances {
        for core in 0..num_cores {
            let byte_idx = core / 8;
            let bit_idx = core % 8;
            if byte_idx < a.bitfield.len() && (a.bitfield[byte_idx] & (1 << bit_idx)) != 0 {
                assurance_counts[core] += 1;
            }
        }
    }

    let mut available: Vec<WorkReport> = Vec::new();
    for core in 0..num_cores.min(pending_reports.len()) {
        if assurance_counts[core] >= super_majority as u32 {
            if let Some(pending) = &pending_reports[core] {
                available.push(pending.report.clone());
            }
        }
    }

    // eq 11.17: Clear available and timed-out reports
    let timeout = config.availability_timeout;
    for core in 0..pending_reports.len() {
        if let Some(pending) = &pending_reports[core] {
            let is_available =
                assurance_counts.get(core).copied().unwrap_or(0) >= super_majority as u32;
            let is_timed_out = current_timeslot >= pending.timeslot + timeout;

            if is_available || is_timed_out {
                pending_reports[core] = None;
            }
        }
    }

    Ok(AssuranceOutput {
        reported: available,
    })
}
