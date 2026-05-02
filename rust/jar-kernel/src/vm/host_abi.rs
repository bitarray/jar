//! Host-call ABI for the event-redesign: protocol slot numbers and
//! register conventions.
//!
//! javm's `KernelResult::ProtocolCall { slot }` carries the protocol
//! slot number (1..=28). The event-redesign collapses the prior host
//! surface into three calls — `emit_event`, `mint_attest_cap`, and
//! `setScore`. Older slots (Attest / SlotClear / SlotRead /
//! AttestationKey / ResultEqual) are retired; their slot numbers
//! deliberately do not get re-used so any guest blob still compiled
//! against the old ABI surfaces cleanly via `from_slot`'s "unknown
//! protocol slot" error.
//!
//! Register conventions:
//! - φ[7]..φ[12] carry up to 6 inputs.
//! - φ[7] carries the primary return value; φ[8] the secondary.
//! - Pointer/length pairs reference the guest's flat memory window.

use crate::types::KernelError;

/// Sentinel returned from host calls signalling success when the call
/// has no natural return value.
pub const RC_OK: u64 = 0;

/// Generic error sentinel.
pub const RC_ERR: u64 = u64::MAX;

/// "None" / "absent" sentinel for read-style host calls.
pub const RC_NONE: u64 = u64::MAX - 1;

/// Read-only context attempted a mutating host call (e.g. process
/// invocation calling `mint_attest_cap` or `setScore`, both of which
/// are verify-only).
pub const RC_READONLY: u64 = u64::MAX - 2;

/// Quota exceeded.
pub const RC_QUOTA: u64 = u64::MAX - 3;

/// Scope violation (mint_attest_cap for a key outside the
/// AttestationScope's restricted seen-set).
pub const RC_AUTHORITY: u64 = u64::MAX - 4;

/// Cap not found / slot empty / malformed input.
pub const RC_BAD_CAP: u64 = u64::MAX - 5;

/// Protocol slots assigned to the event-redesign host calls. Slot
/// numbers are kept stable so guest blobs and on-chain code can pin
/// them explicitly.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[repr(u8)]
pub enum HostCall {
    /// `emit_event(target_path, blob)` — uniform void emit. Available
    /// in both verify and process. Routes through `Command::Emit` (or
    /// the hardware short-circuit hook for self-only-subbed dispatch
    /// endpoints).
    EmitEvent = 4,
    /// `mint_attest_cap(scope, key, blob, sig?)` — verify-only.
    /// Cap's existence is the proof; no separate exercise call. Scope
    /// is enforced by the kernel against the verify-context
    /// `AttestationScopeCap`.
    MintAttestCap = 5,
    /// `setScore(identifier, score)` — verify-only. Buffers the
    /// verifying event into the per-(endpoint, cycle) max-register;
    /// collisions defer to next cycle.
    SetScore = 6,
}

impl HostCall {
    pub fn from_slot(slot: u8) -> Result<HostCall, KernelError> {
        match slot {
            4 => Ok(HostCall::EmitEvent),
            5 => Ok(HostCall::MintAttestCap),
            6 => Ok(HostCall::SetScore),
            _ => Err(KernelError::Internal(format!(
                "unknown protocol slot {slot}"
            ))),
        }
    }
}
