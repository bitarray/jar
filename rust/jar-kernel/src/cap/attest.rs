//! Attestation routing — stub for the event-redesign migration.
//!
//! In the event-redesign, AttestationCap is the proof itself. The prior
//! exercise model (`attest(cap, blob) -> Bool` deciding verify-vs-sign
//! at exercise time) is replaced by `mint_attest_cap(authority, key,
//! blob, sig?, dest)` callable inside verify only. The kernel decides
//! verify-vs-sign based on whether `sig` is provided + key holdings.
//!
//! The cursor and routing structures defined here will be reworked in
//! Stage C/D when verify_block + dispatch process land.

use crate::types::{AttestationEntry, KeyId};

/// Cursor into a trace slice. Used for both per-event and block-level
/// trace consumption during verify.
#[derive(Clone, Debug, Default)]
pub struct AttestCursor {
    pub attestation_pos: usize,
    pub result_pos: usize,
}

impl AttestCursor {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Verify-mode signature check stub. Concrete implementation lands in
/// Stage C/D when mint_attest_cap is implemented.
pub fn verify_entry(_entry: &AttestationEntry, _expected_key: &KeyId) -> bool {
    true
}
