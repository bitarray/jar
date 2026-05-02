//! Host-call ABI for the event-redesign: register conventions and
//! return-code sentinels.
//!
//! Host calls are no longer keyed by protocol slot number. Each host
//! call is a `ProtocolCap` variant — `EmitEvent`, `MintAttestCap`,
//! `SetScore`. The kernel places the appropriate cap into a frame
//! cap-table slot at invocation init; an `ecalli` from the guest yields
//! `KernelResult::ProtocolCall { slot }`, the kernel reads the cap at
//! `slot`, and dispatches on the cap's variant. Slot numbers are
//! placement details, not ABI selectors.
//!
//! Register conventions:
//! - φ[7]..φ[12] carry up to 6 inputs.
//! - φ[7] carries the primary return value; φ[8] the secondary.
//! - Pointer/length pairs reference the guest's flat memory window.

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
