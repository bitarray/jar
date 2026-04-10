//! Disputes sub-transition (Section 10, eq 10.1-10.20).
//!
//! Processes verdicts, culprits, and faults to update the judgment state.

use grey_types::config::Config;
use grey_types::header::DisputesExtrinsic;
use grey_types::state::{Judgments, PendingReport};
use grey_types::validator::ValidatorKey;
use grey_types::{Ed25519PublicKey, Hash, signing_contexts};
use std::collections::BTreeSet;

/// Check that a slice is strictly sorted (no duplicates).
fn check_sorted_unique<T: Ord + Clone>(items: &[T], err: DisputeError) -> Result<(), DisputeError> {
    if crate::is_strictly_sorted_by_key(items, |x| x.clone()) {
        Ok(())
    } else {
        Err(err)
    }
}

stf_error! {
    /// Error type for disputes validation.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum DisputeError {
        JudgementsNotSortedUnique => "judgements_not_sorted_unique",
        VerdictsNotSortedUnique => "verdicts_not_sorted_unique",
        CulpritsNotSortedUnique => "culprits_not_sorted_unique",
        FaultsNotSortedUnique => "faults_not_sorted_unique",
        BadSignature => "bad_signature",
        BadVoteSplit => "bad_vote_split",
        NotEnoughCulprits => "not_enough_culprits",
        NotEnoughFaults => "not_enough_faults",
        AlreadyJudged => "already_judged",
        OffenderAlreadyReported => "offender_already_reported",
        CulpritsVerdictNotBad => "culprits_verdict_not_bad",
        FaultVerdictWrong => "fault_verdict_wrong",
        BadGuarantorKey => "bad_guarantor_key",
        BadAuditorKey => "bad_auditor_key",
        BadJudgementAge => "bad_judgement_age",
    }
}

/// Output of a successful disputes transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisputeOutput {
    /// New offender keys to include in the header's offenders marker.
    pub offenders_mark: Vec<Ed25519PublicKey>,
}

/// Apply the disputes sub-transition (Section 10).
///
/// Returns Ok(output) with offender keys, or Err(error) if validation fails.
pub fn process_disputes(
    config: &Config,
    judgments: &mut Judgments,
    pending_reports: &mut [Option<PendingReport>],
    current_timeslot: u32,
    disputes: &DisputesExtrinsic,
    current_validators: &[ValidatorKey],
    previous_validators: &[ValidatorKey],
) -> Result<DisputeOutput, DisputeError> {
    let super_majority = Config::super_majority_of(current_validators.len()) as u16;
    let one_third = Config::one_third_of(current_validators.len()) as u16;
    let current_epoch = current_timeslot / config.epoch_length;

    // eq 10.10: Judgments within each verdict must be sorted by validator index, no duplicates
    for verdict in &disputes.verdicts {
        let indices: Vec<u16> = verdict
            .judgments
            .iter()
            .map(|j| j.validator_index)
            .collect();
        check_sorted_unique(&indices, DisputeError::JudgementsNotSortedUnique)?;
    }

    // eq 10.7: Verdicts must be sorted by report hash, no duplicates
    {
        let hashes: Vec<&Hash> = disputes.verdicts.iter().map(|v| &v.report_hash).collect();
        check_sorted_unique(&hashes, DisputeError::VerdictsNotSortedUnique)?;
    }

    // eq 10.9: No verdict report hash may already be judged
    for verdict in &disputes.verdicts {
        if judgments.good.contains(&verdict.report_hash)
            || judgments.bad.contains(&verdict.report_hash)
            || judgments.wonky.contains(&verdict.report_hash)
        {
            return Err(DisputeError::AlreadyJudged);
        }
    }

    // eq 10.4: Validate judgment age (epoch index)
    for verdict in &disputes.verdicts {
        let age = verdict.age;
        if age != current_epoch && age != current_epoch.wrapping_sub(1) {
            return Err(DisputeError::BadJudgementAge);
        }
    }

    // eq 10.3: Verify judgment signatures
    for verdict in &disputes.verdicts {
        let validators = if verdict.age == current_epoch {
            current_validators
        } else {
            previous_validators
        };

        for judgment in &verdict.judgments {
            let idx = judgment.validator_index as usize;
            if idx >= validators.len() {
                return Err(DisputeError::BadSignature);
            }

            let ed25519_key = &validators[idx].ed25519;
            let message =
                signing_contexts::build_judgment_message(judgment.is_valid, &verdict.report_hash.0);
            if !grey_crypto::ed25519_verify(ed25519_key, &message, &judgment.signature) {
                return Err(DisputeError::BadSignature);
            }
        }
    }

    // eq 10.12: Validate vote split — must be exactly super_majority, 0, or one_third
    // Build verdict summary: (report_hash, positive_count)
    let mut verdict_summary: Vec<(Hash, u16)> = Vec::new();
    for verdict in &disputes.verdicts {
        let positive: u16 = verdict.positive_count() as u16;

        if positive != super_majority && positive != 0 && positive != one_third {
            return Err(DisputeError::BadVoteSplit);
        }
        verdict_summary.push((verdict.report_hash, positive));
    }

    // Update judgment sets based on verdicts (eq 10.16-10.18)
    for &(ref report_hash, positive) in &verdict_summary {
        if positive == super_majority {
            judgments.good.insert(*report_hash);
        } else if positive == 0 {
            judgments.bad.insert(*report_hash);
        } else {
            // one_third → wonky
            judgments.wonky.insert(*report_hash);
        }
    }

    // eq 10.14: Bad verdicts require at least 2 culprit entries
    for &(ref report_hash, positive) in &verdict_summary {
        if positive == 0 {
            let culprit_count = disputes
                .culprits
                .iter()
                .filter(|c| c.report_hash == *report_hash)
                .count();
            if culprit_count < 2 {
                return Err(DisputeError::NotEnoughCulprits);
            }
        }
    }

    // eq 10.13: Good verdicts require at least 1 fault entry
    for &(ref report_hash, positive) in &verdict_summary {
        if positive == super_majority {
            let fault_count = disputes
                .faults
                .iter()
                .filter(|f| f.report_hash == *report_hash)
                .count();
            if fault_count < 1 {
                return Err(DisputeError::NotEnoughFaults);
            }
        }
    }

    // eq 10.8: Culprits sorted by key, no duplicates
    {
        let keys: Vec<&Ed25519PublicKey> =
            disputes.culprits.iter().map(|c| &c.validator_key).collect();
        check_sorted_unique(&keys, DisputeError::CulpritsNotSortedUnique)?;
    }

    // eq 10.8: Faults sorted by key, no duplicates
    {
        let keys: Vec<&Ed25519PublicKey> =
            disputes.faults.iter().map(|f| &f.validator_key).collect();
        check_sorted_unique(&keys, DisputeError::FaultsNotSortedUnique)?;
    }

    // Build the set of allowed keys: union of current and previous ed25519 keys, minus offenders
    let allowed_keys: BTreeSet<Ed25519PublicKey> = current_validators
        .iter()
        .chain(previous_validators.iter())
        .map(|v| v.ed25519)
        .filter(|k| !judgments.offenders.contains(k))
        .collect();

    // eq 10.5: Validate culprits
    for culprit in &disputes.culprits {
        // Report must be in bad set
        if !judgments.bad.contains(&culprit.report_hash) {
            return Err(DisputeError::CulpritsVerdictNotBad);
        }

        // Key must be in allowed set
        if !allowed_keys.contains(&culprit.validator_key) {
            if judgments.offenders.contains(&culprit.validator_key) {
                return Err(DisputeError::OffenderAlreadyReported);
            }
            return Err(DisputeError::BadGuarantorKey);
        }

        // Verify guarantee signature: X_G = "jam_guarantee"
        let message = signing_contexts::build_guarantee_message(&culprit.report_hash.0);
        if !grey_crypto::ed25519_verify(&culprit.validator_key, &message, &culprit.signature) {
            return Err(DisputeError::BadSignature);
        }
    }

    // eq 10.6: Validate faults
    for fault in &disputes.faults {
        // Check report is in good or bad set
        let is_bad = judgments.bad.contains(&fault.report_hash);
        let is_good = judgments.good.contains(&fault.report_hash);

        if !is_bad && !is_good {
            return Err(DisputeError::FaultVerdictWrong);
        }

        // eq 10.6: r ∈ ψ'_B ⇔ ¬(r ∈ ψ'_G) ⇔ v
        // If report is bad, the fault's vote must be true (they voted valid for a bad report)
        // If report is good, the fault's vote must be false (they voted invalid for a good report)
        if is_bad && !fault.is_valid {
            return Err(DisputeError::FaultVerdictWrong);
        }
        if is_good && fault.is_valid {
            return Err(DisputeError::FaultVerdictWrong);
        }

        // Key must be in allowed set
        if !allowed_keys.contains(&fault.validator_key) {
            if judgments.offenders.contains(&fault.validator_key) {
                return Err(DisputeError::OffenderAlreadyReported);
            }
            return Err(DisputeError::BadAuditorKey);
        }

        // Verify judgment signature
        let message =
            signing_contexts::build_judgment_message(fault.is_valid, &fault.report_hash.0);
        if !grey_crypto::ed25519_verify(&fault.validator_key, &message, &fault.signature) {
            return Err(DisputeError::BadSignature);
        }
    }

    // eq removenonpositive: Clear pending reports with non-good verdicts
    // For each core c: if H(E(ρ[c].r)) matches a verdict with t < ⌊2/3 V⌋ + 1, clear it
    {
        let non_good: std::collections::BTreeSet<Hash> = verdict_summary
            .iter()
            .filter(|&&(_, positive)| positive < super_majority)
            .map(|(h, _)| *h)
            .collect();

        if !non_good.is_empty() {
            for slot in pending_reports.iter_mut() {
                if let Some(pending) = slot.as_ref() {
                    let report_hash = grey_crypto::report_hash(&pending.report);
                    if non_good.contains(&report_hash) {
                        *slot = None;
                    }
                }
            }
        }
    }

    // eq 10.19: Add offender keys to punish set
    let mut offenders_mark = Vec::new();
    for culprit in &disputes.culprits {
        judgments.offenders.insert(culprit.validator_key);
        offenders_mark.push(culprit.validator_key);
    }
    for fault in &disputes.faults {
        judgments.offenders.insert(fault.validator_key);
        offenders_mark.push(fault.validator_key);
    }

    Ok(DisputeOutput { offenders_mark })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_hash;
    use grey_types::config::Config;
    use grey_types::header::{DisputesExtrinsic, Judgment, Verdict};
    use grey_types::validator::ValidatorKey;

    fn test_config() -> Config {
        Config::tiny()
    }

    fn make_ed25519_key(byte: u8) -> Ed25519PublicKey {
        Ed25519PublicKey([byte; 32])
    }

    fn make_validators(n: usize) -> Vec<ValidatorKey> {
        (0..n)
            .map(|i| ValidatorKey {
                ed25519: make_ed25519_key(i as u8),
                bandersnatch: grey_types::BandersnatchPublicKey([i as u8; 32]),
                bls: grey_types::BlsPublicKey([i as u8; 144]),
                metadata: [i as u8; 128],
            })
            .collect()
    }

    fn empty_disputes() -> DisputesExtrinsic {
        DisputesExtrinsic {
            verdicts: vec![],
            culprits: vec![],
            faults: vec![],
        }
    }

    #[test]
    fn test_check_sorted_unique_empty() {
        let items: Vec<u32> = vec![];
        assert!(check_sorted_unique(&items, DisputeError::VerdictsNotSortedUnique).is_ok());
    }

    #[test]
    fn test_check_sorted_unique_single() {
        assert!(check_sorted_unique(&[42u32], DisputeError::VerdictsNotSortedUnique).is_ok());
    }

    #[test]
    fn test_check_sorted_unique_sorted() {
        assert!(check_sorted_unique(&[1u32, 2, 3], DisputeError::VerdictsNotSortedUnique).is_ok());
    }

    #[test]
    fn test_check_sorted_unique_duplicate() {
        assert_eq!(
            check_sorted_unique(&[1u32, 2, 2], DisputeError::VerdictsNotSortedUnique),
            Err(DisputeError::VerdictsNotSortedUnique)
        );
    }

    #[test]
    fn test_check_sorted_unique_unsorted() {
        assert_eq!(
            check_sorted_unique(&[3u32, 1, 2], DisputeError::VerdictsNotSortedUnique),
            Err(DisputeError::VerdictsNotSortedUnique)
        );
    }

    #[test]
    fn test_empty_disputes_succeeds() {
        let config = test_config();
        let validators = make_validators(6);
        let mut judgments = Judgments::default();
        let mut pending = vec![None; config.core_count as usize];

        let result = process_disputes(
            &config,
            &mut judgments,
            &mut pending,
            100,
            &empty_disputes(),
            &validators,
            &validators,
        );
        assert!(result.is_ok());
        assert!(result.unwrap().offenders_mark.is_empty());
    }

    #[test]
    fn test_verdicts_not_sorted() {
        let config = test_config();
        let validators = make_validators(6);
        let mut judgments = Judgments::default();
        let mut pending = vec![None; config.core_count as usize];

        // Two verdicts with report_hash[1] > report_hash[0] — wrong order
        let disputes = DisputesExtrinsic {
            verdicts: vec![
                Verdict {
                    report_hash: make_hash(2),
                    age: 100 / config.epoch_length,
                    judgments: vec![],
                },
                Verdict {
                    report_hash: make_hash(1),
                    age: 100 / config.epoch_length,
                    judgments: vec![],
                },
            ],
            culprits: vec![],
            faults: vec![],
        };

        let result = process_disputes(
            &config,
            &mut judgments,
            &mut pending,
            100,
            &disputes,
            &validators,
            &validators,
        );
        assert_eq!(result, Err(DisputeError::VerdictsNotSortedUnique));
    }

    #[test]
    fn test_already_judged_report() {
        let config = test_config();
        let validators = make_validators(6);
        let mut judgments = Judgments::default();
        let mut pending = vec![None; config.core_count as usize];

        let report_hash = make_hash(1);
        judgments.good.insert(report_hash);

        let disputes = DisputesExtrinsic {
            verdicts: vec![Verdict {
                report_hash,
                age: 100 / config.epoch_length,
                judgments: vec![],
            }],
            culprits: vec![],
            faults: vec![],
        };

        let result = process_disputes(
            &config,
            &mut judgments,
            &mut pending,
            100,
            &disputes,
            &validators,
            &validators,
        );
        assert_eq!(result, Err(DisputeError::AlreadyJudged));
    }

    #[test]
    fn test_bad_judgement_age() {
        let config = test_config();
        let validators = make_validators(6);
        let mut judgments = Judgments::default();
        let mut pending = vec![None; config.core_count as usize];
        let timeslot = 100u32;
        let current_epoch = timeslot / config.epoch_length;

        // Age two epochs ago — too old
        let disputes = DisputesExtrinsic {
            verdicts: vec![Verdict {
                report_hash: make_hash(1),
                age: current_epoch.wrapping_sub(2),
                judgments: vec![],
            }],
            culprits: vec![],
            faults: vec![],
        };

        let result = process_disputes(
            &config,
            &mut judgments,
            &mut pending,
            timeslot,
            &disputes,
            &validators,
            &validators,
        );
        assert_eq!(result, Err(DisputeError::BadJudgementAge));
    }

    #[test]
    fn test_judgments_not_sorted_within_verdict() {
        let config = test_config();
        let validators = make_validators(6);
        let mut judgments = Judgments::default();
        let mut pending = vec![None; config.core_count as usize];
        let sig = grey_types::Ed25519Signature([0u8; 64]);

        // Judgments within a verdict must be sorted by validator_index
        let disputes = DisputesExtrinsic {
            verdicts: vec![Verdict {
                report_hash: make_hash(1),
                age: 100 / config.epoch_length,
                judgments: vec![
                    Judgment {
                        is_valid: true,
                        validator_index: 3,
                        signature: sig,
                    },
                    Judgment {
                        is_valid: true,
                        validator_index: 1,
                        signature: sig,
                    },
                ],
            }],
            culprits: vec![],
            faults: vec![],
        };

        let result = process_disputes(
            &config,
            &mut judgments,
            &mut pending,
            100,
            &disputes,
            &validators,
            &validators,
        );
        assert_eq!(result, Err(DisputeError::JudgementsNotSortedUnique));
    }

    #[test]
    fn test_error_as_str() {
        assert_eq!(DisputeError::BadSignature.as_str(), "bad_signature");
        assert_eq!(DisputeError::BadVoteSplit.as_str(), "bad_vote_split");
        assert_eq!(
            DisputeError::JudgementsNotSortedUnique.as_str(),
            "judgements_not_sorted_unique"
        );
        assert_eq!(DisputeError::AlreadyJudged.as_str(), "already_judged");
    }
}
