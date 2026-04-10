//! Block equivocation resolution — node-level stub.
//!
//! # Distinction from `grey-state/src/disputes.rs`
//!
//! `grey-state/src/disputes.rs` handles §10 on-chain work-report verdict
//! processing: verdicts, culprits, faults, offender slashing. It operates on
//! `report_hash` values inside the state transition.
//!
//! This module handles the *finality* side of block-level equivocation: once
//! the network has identified which of two same-slot blocks is the loser,
//! `report_loser` removes it from `GrandpaState` and un-poisons the slot so
//! the surviving fork can become acceptable to GRANDPA again.
//!
//! # §17 block-author slashing
//!
//! When a quorum resolves the equivocation, the author key of the losing block
//! is returned. Actual on-chain slashing of block producers is a §17 concern
//! distinct from §10 (which slashes work-report culprits). The mechanism is
//! not yet specified; `report_loser` logs the offender key until the spec
//! defines the appropriate extrinsic or offence report.

use crate::finality::GrandpaState;
use grey_types::{Ed25519PublicKey, Hash};

/// Notify the finality layer that `loser_hash` has been identified as the
/// losing block in a same-slot equivocation and must be removed.
///
/// Returns the author key of the purged block if known, so the caller can
/// log or report the equivocating validator.
///
/// The caller is responsible for verifying equivocation evidence (quorum of
/// validator countersignatures) before invoking this function.
pub fn report_loser(loser_hash: Hash, grandpa: &mut GrandpaState) -> Option<Ed25519PublicKey> {
    let author = grandpa.purge_block(loser_hash);
    tracing::info!(
        "Block equivocation resolved: purged losing block {:?} from finality state",
        loser_hash
    );
    if let Some(ref key) = author {
        tracing::warn!(
            offender = ?key,
            "Equivocating block author identified — TODO(§17): submit offence report when spec defines block-author slashing"
        );
    }
    author
}
