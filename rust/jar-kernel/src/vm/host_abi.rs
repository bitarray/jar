//! Host-call ABI: protocol slot numbers and register conventions.
//!
//! javm's `KernelResult::ProtocolCall { slot }` carries the protocol slot
//! number (1..=28). We assign one slot per kernel host call. Args + return
//! values flow through registers φ[7..12] and through guest memory windows
//! addressed by pointer arguments.
//!
//! Register conventions:
//! - φ[7]..φ[12] carry up to 6 inputs.
//! - φ[7] carries the primary return value; φ[8] the secondary (when used).
//! - Pointer/length pairs reference the guest's flat memory window.

use crate::types::KernelError;

/// Sentinel returned from host calls signalling success when the call has no
/// natural return value.
pub const RC_OK: u64 = 0;

/// Generic error sentinel.
pub const RC_ERR: u64 = u64::MAX;

/// "None" / "absent" sentinel for read-style host calls.
pub const RC_NONE: u64 = u64::MAX - 1;

/// Read-only context attempted a mutating host call.
pub const RC_READONLY: u64 = u64::MAX - 2;

/// Quota exceeded (storage_write).
pub const RC_QUOTA: u64 = u64::MAX - 3;

/// Pinning violation (state-level cnode grant / move, or arg-scan at
/// invocation entry).
pub const RC_PINNING: u64 = u64::MAX - 4;

/// Cap not found / slot empty.
pub const RC_BAD_CAP: u64 = u64::MAX - 5;

/// The protocol slot numbers we assign to each kernel host call. javm reserves
/// slots 1..=28 as ProtocolCaps; we use a subset, with reserved gaps where
/// host calls have retired — see below.
///
/// Reserved gaps:
/// - Slot 1 / 2 / 3 — formerly `Gas` / `SelfId` / `Caller`, retired in
///   favour of `Capability::Gas` / `SelfId` / `CallerVault` / `CallerKernel`
///   placed at ephemeral sub-slots 3 / 2 / 1 by the kernel at invocation
///   entry. Guests read them via cap-ref into the ephemeral table.
/// - Slot 7 / 8 / 9 — formerly `CnodeGrant` / `CnodeRevoke` / `CnodeMove`,
///   retired in favour of javm management ecallis (`MGMT_DROP`, dynamic-ecall
///   `MOVE` / `COPY`) operating through cap-indirection on the unified
///   cap-table.
/// - Slot 10 — formerly `CapDerive`, retired (replacement direction: javm
///   `MGMT_DOWNGRADE`).
/// - Slot 11 — formerly `CapCall`, retired in favour of plain javm CALL on
///   a Handle / Callable cap-table slot.
/// - Slot 12 / 13 / 14 — formerly `VaultInitialize` / `CreateVault` /
///   `QuotaSet`, retired (these are kernel-internal operations triggered by
///   `Command::*` post-execution, not guest-visible host calls).
/// - Slot 17 — formerly `AttestationAggregate`, retired (was a no-op stub
///   returning success; BLS aggregation isn't wired yet).
/// - Slot 20 — formerly `SlotEmit`, retired (step-3 emit is unimplemented).
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[repr(u8)]
pub enum HostCall {
    Attest = 15,
    AttestationKey = 16,
    ResultEqual = 18,
    SlotClear = 19,
    /// Read the prior-slot SCALE bytes into a guest memory window. Only valid
    /// during dispatch step-3 (`AggregateMerge`).
    SlotRead = 21,
}

impl HostCall {
    pub fn from_slot(slot: u8) -> Result<HostCall, KernelError> {
        match slot {
            15 => Ok(HostCall::Attest),
            16 => Ok(HostCall::AttestationKey),
            18 => Ok(HostCall::ResultEqual),
            19 => Ok(HostCall::SlotClear),
            21 => Ok(HostCall::SlotRead),
            _ => Err(KernelError::Internal(format!(
                "unknown protocol slot {}",
                slot
            ))),
        }
    }
}
