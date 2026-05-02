//! `ProtocolCap` — jar-kernel's impl of `javm::ProtocolCap`. The
//! payload of `javm::Cap::Protocol(_)`. The complete Frame cap type
//! (`javm::Cap<ProtocolCap>`) is exported as `crate::cap::Cap`.
//!
//! Each variant is one concrete kind that can occupy a Frame cap-table
//! slot. There is no generic "registered" wrapper: the type system
//! enumerates exactly what is valid as a Frame cap.
//!
//! | What                                          | Where                              |
//! |-----------------------------------------------|------------------------------------|
//! | `Cap::Code(_)` / `Cap::Data(_)`               | first-class javm arms              |
//! | `Cap::Protocol(ProtocolCap::VaultRef(_))`     | value cap from `vault.slots`       |
//! | `Cap::Protocol(ProtocolCap::Resource(_))`     | value cap from `vault.slots`       |
//! | `Cap::Protocol(ProtocolCap::HostCall(_))`     | host-call selector                 |
//! | `Cap::Protocol(ProtocolCap::SelfId(…))` etc.  | Frame-only kernel-injected markers |
//!
//! Code / Data / EventEndpoint deliberately have no `ProtocolCap`
//! variant: Code/Data project to first-class `Cap::Code` / `Cap::Data`
//! during `vault_init` (they're never relocated mid-VM); EventEndpoint
//! lives only in `σ.{transact,dispatch}_endpoints` and never enters a
//! Frame as a guest-visible cap.

use crate::cap::{
    AttestationAggregateCap, AttestationCap, AttestationScopeCap, CallerKernelCap, CallerVaultCap,
    ResourceCap, SelfCap, VaultRefCap, VaultRights,
};
use crate::runtime::Hardware;
use crate::types::{KResult, VaultId};
use javm::cap::ProtocolCap as ProtocolCapT;

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
    // ---- Host-call caps. CALL on one of these yields to the host ----
    //
    // Frame-only, kernel-injected at invocation init (no σ presence).
    /// `emit_event(target_path, blob)` — available in verify and process.
    EmitEvent,
    /// `mint_attest_cap(scope, key, blob, sig?)` — verify-only.
    MintAttestCap,
    /// `setScore(identifier, score)` — verify-only.
    SetScore,

    /// A VaultRef. Inline value (no `CapId`). Same shape whether the
    /// cap originated from a `vault.slots[…]` entry or was kernel-
    /// injected (home VaultRef at MainFrame slot 1, sub-CALL caller
    /// hookup, etc.). Identity is `(vault_id, rights)`.
    VaultRef(VaultRefCap),

    /// A Resource cap projected from `vault.slots`. Pure value — no
    /// CapId since Resource caps no longer go through cap_registry.
    Resource(ResourceCap),

    // ---- Frame-only kernel-injected context kinds ----
    //
    // No CapId, no σ presence. Placed at invocation init or at
    // CALL/REPLY transitions; reclaimed at frame teardown.
    /// Per-VM self-identity — pinned at MainFrame slot 2 (`SELF_SLOT`).
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

impl ProtocolCap {
    /// Dispatch a CALL on this cap. The `drive_invocation` loop reads
    /// the cap at the firing `slot` and invokes this method; each
    /// variant defines what its CALL means. Variants that have no
    /// CALL semantics (Frame-only context kinds: SelfId, Caller*,
    /// Attestation, AttestationAggregate) return `Fault`.
    ///
    /// CALL semantics today:
    ///   - `EmitEvent` / `MintAttestCap` / `SetScore` → host call.
    ///   - everything else → fault. As more variants gain CALL meaning
    ///     (e.g., `AttestationScope` minting an `Attestation`,
    ///     `Resource` invoking a governance op, `VaultRef` initializing
    ///     a sub-frame), they slot in here as additional arms.
    pub fn call<H: Hardware>(
        &self,
        vm: &mut crate::vm::Vm,
        ctx: &mut crate::vm::InvocationCtx<'_, H>,
    ) -> KResult<crate::vm::HostCallOutcome> {
        use crate::vm::HostCallOutcome;
        use crate::vm::host_calls::{attest, emit, score};
        match self {
            ProtocolCap::EmitEvent => emit::host_emit_event(vm, ctx),
            ProtocolCap::MintAttestCap => attest::host_mint_attest_cap(vm, ctx),
            ProtocolCap::SetScore => score::host_set_score(vm, ctx),
            other => Ok(HostCallOutcome::Fault(format!(
                "CALL on cap with no CALL semantics: {other:?}"
            ))),
        }
    }
}

impl ProtocolCapT for ProtocolCap {
    type ForeignFrameId = VaultId;
    type FinalStepRights = VaultRights;

    fn is_copyable(&self) -> bool {
        true
    }

    fn is_movable(&self) -> bool {
        true
    }

    fn is_droppable(&self) -> bool {
        true
    }

    /// A `VaultRef` with `rights.read` is a foreign-frame handle:
    /// javm's resolve walk crosses through it into the named Vault's
    /// CNode. Operation rights (Grant / Revoke / Derive / Initialize)
    /// are recorded at this step and consulted by the host adapter at
    /// the final step of the walk.
    fn as_foreign_frame(&self) -> Option<(VaultId, VaultRights)> {
        match self {
            ProtocolCap::VaultRef(vr) if vr.rights.read => Some((vr.vault_id, vr.rights)),
            _ => None,
        }
    }

    /// Produce a fresh `CallerVault` cap for an internal CALL
    /// transition. Reads the caller VM's home VaultRef at MainFrame
    /// slot 1 and wraps its `vault_id`. Returns `None` if slot 1
    /// doesn't hold a VaultRef — that should only happen on the
    /// bare Frame itself (which never executes guest code).
    fn caller_cap_for(caller_table: &javm::cap::CapTable<Self>) -> Option<javm::cap::Cap<Self>> {
        let home_vault_id = match caller_table.get(1) {
            Some(javm::cap::Cap::Protocol(ProtocolCap::VaultRef(vr))) => vr.vault_id,
            _ => return None,
        };
        Some(javm::cap::Cap::Protocol(ProtocolCap::CallerVault(
            CallerVaultCap {
                vault_id: home_vault_id,
            },
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::{Cap, VaultRefCap, VaultRights};
    use javm::cap::CapTable;

    #[test]
    fn caller_cap_for_reads_home_vault_ref() {
        let mut t: CapTable<ProtocolCap> = CapTable::new();
        let vault_id = VaultId(42);
        t.set(
            1,
            Cap::Protocol(ProtocolCap::VaultRef(VaultRefCap {
                vault_id,
                rights: VaultRights::ALL,
            })),
        );
        match ProtocolCap::caller_cap_for(&t) {
            Some(Cap::Protocol(ProtocolCap::CallerVault(cv))) => {
                assert_eq!(cv.vault_id, vault_id);
            }
            other => panic!("expected CallerVault cap, got {:?}", other.is_some()),
        }
    }

    #[test]
    fn caller_cap_for_returns_none_when_slot_1_empty() {
        let t: CapTable<ProtocolCap> = CapTable::new();
        assert!(ProtocolCap::caller_cap_for(&t).is_none());
    }
}
