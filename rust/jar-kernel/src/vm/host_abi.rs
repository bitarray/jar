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

/// Host call is not yet implemented.
pub const RC_UNIMPLEMENTED: u64 = u64::MAX - 6;

/// The protocol slot numbers we assign to each kernel host call. javm reserves
/// slots 1..=28 as ProtocolCaps; we use a subset, with reserved gaps at
/// slots 7, 8, 9, and 11 — see below.
///
/// Reserved gaps:
/// - Slot 7 / 8 / 9 — formerly `CnodeGrant` / `CnodeRevoke` / `CnodeMove`,
///   retired in favour of javm management ecallis (`MGMT_DROP`, dynamic-ecall
///   `MOVE` / `COPY`) operating through cap-indirection on the unified
///   cap-table.
/// - Slot 11 — formerly `CapCall`, retired in favour of plain javm CALL on
///   a Handle / Callable cap-table slot.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[repr(u8)]
pub enum HostCall {
    Gas = 1,
    SelfId = 2,
    Caller = 3,
    StorageRead = 4,
    StorageWrite = 5,
    StorageDelete = 6,
    // 7 — formerly CnodeGrant, retired (use javm dynamic-ecall COPY).
    // 8 — formerly CnodeRevoke, retired (use javm MGMT_DROP).
    // 9 — formerly CnodeMove, retired (use javm dynamic-ecall MOVE).
    CapDerive = 10,
    // 11 — formerly CapCall, retired (use javm CALL instead).
    VaultInitialize = 12,
    CreateVault = 13,
    QuotaSet = 14,
    Attest = 15,
    AttestationKey = 16,
    AttestationAggregate = 17,
    ResultEqual = 18,
    SlotClear = 19,
    SlotEmit = 20, // synthesized by step-3 dispatch when target is self-DispatchRef
    /// Read the prior-slot SCALE bytes into a guest memory window. Only valid
    /// during dispatch step-3 (`AggregateMerge`).
    SlotRead = 21,
}

impl HostCall {
    pub fn from_slot(slot: u8) -> Result<HostCall, KernelError> {
        match slot {
            1 => Ok(HostCall::Gas),
            2 => Ok(HostCall::SelfId),
            3 => Ok(HostCall::Caller),
            4 => Ok(HostCall::StorageRead),
            5 => Ok(HostCall::StorageWrite),
            6 => Ok(HostCall::StorageDelete),
            10 => Ok(HostCall::CapDerive),
            12 => Ok(HostCall::VaultInitialize),
            13 => Ok(HostCall::CreateVault),
            14 => Ok(HostCall::QuotaSet),
            15 => Ok(HostCall::Attest),
            16 => Ok(HostCall::AttestationKey),
            17 => Ok(HostCall::AttestationAggregate),
            18 => Ok(HostCall::ResultEqual),
            19 => Ok(HostCall::SlotClear),
            20 => Ok(HostCall::SlotEmit),
            21 => Ok(HostCall::SlotRead),
            _ => Err(KernelError::Internal(format!(
                "unknown protocol slot {}",
                slot
            ))),
        }
    }
}
