//! `ProtocolCap` — jar-kernel's impl of `javm::ProtocolCap`. The
//! payload of `javm::Cap::Protocol(_)`. The complete Frame cap type
//! (`javm::Cap<ProtocolCap>`) is exported as `crate::cap::Cap`.
//!
//! Each variant is one concrete JAR-specific payload that can occupy
//! the `Protocol(_)` arm of a Frame cap-table slot.
//!
//! | What                                          | Where                              |
//! |-----------------------------------------------|------------------------------------|
//! | `Cap::Code(_)` / `Cap::Data(_)`               | first-class javm arms              |
//! | `Cap::Protocol(ProtocolCap::Reg(_))`          | persistent cap from `vault.slots`  |
//! | `Cap::Protocol(ProtocolCap::EmitEvent)` etc.  | host-call selector                 |
//! | `Cap::Protocol(ProtocolCap::SelfId(…))` etc.  | Frame-only kernel-injected markers |
//!
//! Persistent `RegCap::Code` and executable `Cap::Code` are deliberately
//! different: a Frame can hold a persistent code reference through
//! `ProtocolCap::Reg(RegCap::Code(_))`, while executable compiled code is
//! the first-class `Cap::Code` arm produced by explicit VM construction
//! or a future code-load management op.

use crate::cap::{
    AttestationAggregateCap, AttestationCap, AttestationScopeCap, CallerKernelCap, CallerVaultCap,
    RegCap, SelfCap, VaultRights,
};
use crate::types::VaultId;
use javm::cap::ProtocolCap as ProtocolCapT;

/// Cursor into a trace slice. Used for both per-event and block-level
/// trace consumption during verify. Stage D wires it; today it is a
/// placeholder field on `InvocationHost`.
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

/// Cap-table slot reserved for the kernel-cap payload at frame init
/// (host-call selector range is 4..=21; slot 32 sits comfortably above
/// it).
pub const KERNEL_CAP_SLOT: u8 = 32;

/// The protocol-cap payload type jar-kernel substitutes into
/// `javm::Cap::Protocol(_)`. See module-level docs.
///
/// Host-call variants (`EmitEvent`, `MintAttestCap`, `SetScore`) are
/// placed in cap-table slots at invocation init. An `ecalli` from the
/// guest yields `KernelResult::ProtocolCall { slot }`; the kernel reads
/// the cap at that slot and dispatches on the variant. Slot numbers are
/// placement convention; the cap value is the selector.
#[derive(Clone, Debug)]
pub enum ProtocolCap {
    // ---- Persistent caps embedded in Frame ----
    //
    // Every `RegCap` is a valid Frame `Cap` through this arm. The reverse
    // direction is fallible and lives in `crate::cap` as `TryFrom<&Cap>
    // for RegCap`.
    Reg(RegCap),

    // ---- Host-call caps. CALL on one of these yields to the host ----
    //
    // Frame-only, kernel-injected at invocation init (no σ presence).
    /// `emit_event(target_path, blob)` — available in verify and process.
    EmitEvent,
    /// `mint_attest_cap(scope, key, blob, sig?)` — verify-only.
    MintAttestCap,
    /// `setScore(identifier, score)` — verify-only.
    SetScore,
    /// `open(file_cap_slot, dst_slot)` — process-only. Reads bytes
    /// from `state.data_blobs[file_id]` and allocates a fresh
    /// ephemeral `Cap::Data` from the active VM's Untyped + backing.
    Open,
    /// `save(data_cap_slot, quota_cap_slot, dst_slot)` — process-only.
    /// Mints a fresh `FileId` in `state.data_blobs` from a Frame
    /// `Cap::Data` source, debiting the named StorageQuota.
    Save,

    // ---- Frame-only kernel-injected context kinds ----
    //
    // No CapId, no σ presence. Placed at invocation init or at
    // CALL/REPLY transitions; reclaimed at frame teardown.
    /// Per-invocation self identity — kernel-injected in the BareFrame
    /// by jar-kernel's host ABI.
    SelfId(SelfCap),
    /// Per-frame caller for vault → vault sub-CALLs.
    CallerVault(CallerVaultCap),
    /// Per-frame caller for kernel-fired top-level invocations.
    CallerKernel(CallerKernelCap),
    /// Kernel-passed scope cap held in a Frame slot during verify;
    /// gates `mint_attest_cap` calls.
    AttestationScope(AttestationScopeCap),
    /// AttestationCap minted via CALL on AttestationScope (verify-only).
    /// Lives only in the verify Frame; its existence is the proof.
    Attestation(AttestationCap),
    /// Aggregate signature handle (BLS / threshold). Stubbed.
    AttestationAggregate(AttestationAggregateCap),
}

impl ProtocolCapT for ProtocolCap {
    type ForeignFrameId = VaultId;
    type FinalStepRights = VaultRights;

    fn is_copyable(&self) -> bool {
        true
    }

    /// A `VaultRef` with `rights.read` is a foreign-frame handle:
    /// javm's resolve walk crosses through it into the named Vault's
    /// CNode. Operation rights (Grant / Revoke / Derive / Initialize)
    /// are recorded at this step and consulted by the host adapter at
    /// the final step of the walk.
    fn as_foreign_frame(&self) -> Option<(VaultId, VaultRights)> {
        match self {
            ProtocolCap::Reg(RegCap::VaultRef(vr)) if vr.rights.read => {
                Some((vr.vault_id, vr.rights))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::{VaultRefCap, VaultRights};

    #[test]
    fn vault_ref_with_read_announces_foreign_frame() {
        let cap = ProtocolCap::Reg(RegCap::VaultRef(VaultRefCap {
            vault_id: VaultId(42),
            rights: VaultRights::ALL,
        }));
        let (id, rights) = cap.as_foreign_frame().expect("VaultRef -> foreign frame");
        assert_eq!(id, VaultId(42));
        assert_eq!(rights, VaultRights::ALL);
    }
}
