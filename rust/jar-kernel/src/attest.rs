//! AttestationCap routing. Mode-blind: kernel decides verify-vs-sign per call.
//!
//! For each `attest(cap, blob)`:
//! - If `body.attestation_trace[cursor]` exists and matches `cap.key`: verify
//!   the embedded signature against `(cap.key, blob)`. Advance cursor.
//! - Else if the local node holds `cap.key` (via Hardware): sign blob, append
//!   to attestation_trace. Advance cursor.
//! - Else: return false (userspace decides).
//!
//! Hashing and signature verification are kernel-static (`crypto::hash`,
//! `crypto::verify`); only key-custody operations (`sign`, `holds_key`)
//! route through Hardware.

use jar_types::{AttestationEntry, AttestationScope, Capability, KResult, KernelError, KeyId};

use crate::crypto;
use crate::runtime::Hardware;

/// Per-invocation cursor over body's attestation trace slices.
#[derive(Debug, Default)]
pub struct AttestCursor {
    pub attestation_pos: usize,
    pub result_pos: usize,
}

/// Outcome of one `attest()` call.
#[derive(Debug, Eq, PartialEq)]
pub enum AttestOutcome {
    /// Verifier mode: signature verified.
    Verified,
    /// Verifier mode: trace entry rejected (sig didn't match).
    VerifyFailed,
    /// Producer mode: kernel signed, appended to trace.
    Produced,
    /// Producer mode: position reserved (Sealing); kernel will fill at end.
    Reserved,
    /// Neither verify nor produce path applied (no trace, no held key).
    Absent,
}

impl AttestOutcome {
    pub fn as_bool(&self) -> bool {
        matches!(
            self,
            AttestOutcome::Verified | AttestOutcome::Produced | AttestOutcome::Reserved
        )
    }
}

/// Process one `attest(cap, blob)` call.
///
/// `cap` — the AttestationCap variant. Must be `Capability::AttestationCap`.
/// `blob` — userspace-supplied blob (Direct) or `None` (Sealing).
/// `body_attestation_trace` — the trace; verifier sees populated, producer
/// sees `None` for the slot at the cursor (we'll append).
pub fn attest<H: Hardware>(
    cap: &Capability,
    blob: Option<&[u8]>,
    cursor: &mut AttestCursor,
    body_attestation_trace: &mut Vec<AttestationEntry>,
    hw: &H,
) -> KResult<AttestOutcome> {
    let (key, scope) = match cap {
        Capability::AttestationCap { key, scope } => (key.clone(), *scope),
        _ => {
            return Err(KernelError::Internal(
                "attest() called on non-AttestationCap".into(),
            ));
        }
    };

    // Verifier mode: a trace entry already exists at the cursor.
    if cursor.attestation_pos < body_attestation_trace.len() {
        let entry = &body_attestation_trace[cursor.attestation_pos];
        if entry.key != key {
            return Err(KernelError::TraceDivergence(format!(
                "attestation cursor key mismatch at {}: expected {:?}, found {:?}",
                cursor.attestation_pos, key, entry.key
            )));
        }
        let blob_for_verify: Vec<u8> = match scope {
            AttestationScope::Direct => blob
                .ok_or_else(|| KernelError::Internal("Direct attest needs userspace blob".into()))?
                .to_vec(),
            AttestationScope::Sealing => {
                // Verifier-side: blob_hash is reconstructed from the container.
                // For the kernel-pure layer we trust the proposer's recorded
                // blob_hash and verify the signature against it. (A real impl
                // would re-derive the canonical container hash here.)
                entry.blob_hash.as_ref().to_vec()
            }
        };
        let blob_hash = crypto::hash(&blob_for_verify);
        if blob_hash != entry.blob_hash {
            return Ok(AttestOutcome::VerifyFailed);
        }
        let ok = crypto::verify(&key, &blob_for_verify, &entry.signature);
        cursor.attestation_pos += 1;
        return Ok(if ok {
            AttestOutcome::Verified
        } else {
            AttestOutcome::VerifyFailed
        });
    }

    // Producer mode: append to trace if we hold the key.
    if !hw.holds_key(&key) {
        return Ok(AttestOutcome::Absent);
    }

    match scope {
        AttestationScope::Direct => {
            let b = blob.ok_or_else(|| {
                KernelError::Internal("Direct attest needs userspace blob".into())
            })?;
            let blob_hash = crypto::hash(b);
            let sig = hw
                .sign(&key, b)
                .map_err(|_| KernelError::Internal("Hardware refused to sign".into()))?;
            body_attestation_trace.push(AttestationEntry {
                key,
                blob_hash,
                signature: sig,
            });
            cursor.attestation_pos += 1;
            Ok(AttestOutcome::Produced)
        }
        AttestationScope::Sealing => {
            // Reserve the position with a sentinel; kernel fills it post-execution.
            body_attestation_trace.push(AttestationEntry {
                key,
                blob_hash: jar_types::Hash::ZERO,
                signature: jar_types::Signature::default(),
            });
            cursor.attestation_pos += 1;
            Ok(AttestOutcome::Reserved)
        }
    }
}

/// Inspect the public key of an AttestationCap.
pub fn key_of(cap: &Capability) -> KResult<KeyId> {
    match cap {
        Capability::AttestationCap { key, .. } => Ok(key.clone()),
        Capability::AttestationAggregateCap { key } => Ok(key.clone()),
        _ => Err(KernelError::Internal(
            "attestation_key on non-attestation cap".into(),
        )),
    }
}
