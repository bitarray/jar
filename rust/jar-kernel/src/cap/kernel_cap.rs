//! `KernelCap` — the protocol-cap payload type jar-kernel substitutes
//! into javm's `Cap::Protocol(P)`.
//!
//! Each running VM's javm cap-table is the kernel's per-invocation
//! Frame. Slots hold one of these variants:
//!
//! - `KernelCap::HostCall(u8)` — host-call selector. `ecalli N` on a
//!   slot holding `HostCall(N)` yields `KernelResult::ProtocolCall
//!   { slot: N }` to the host; `drive_invocation` dispatches to the
//!   matching handler.
//!
//! - `KernelCap::Registered { id, cap }` — projection of a σ-resident
//!   cap into the Frame. The `cap` is a `RegisteredCap`; the `id`
//!   stays valid across Frame ↔ Vault round-trips so cap_children
//!   bookkeeping survives the bounce.
//!
//! - Frame-only kinds (`HomeVaultRef`, `SelfId`, `CallerVault`,
//!   `CallerKernel`, `AttestationScope`, `Attestation`,
//!   `AttestationAggregate`) — kernel-injected per-frame markers with
//!   no σ presence and no `CapId`. They vanish at invocation teardown.
//!
//! The `ProtocolCapT` impl announces VaultRef-shaped caps as
//! foreign-frame handles so javm's resolve walk can cross into a
//! Vault's CNode through them, and produces a fresh `CallerVault`
//! at every CALL transition.

use crate::cap::{
    AttestationAggregateCap, AttestationCap, AttestationScopeCap, CallerKernelCap, CallerVaultCap,
    RegisteredCap, SelfCap, VaultRefCap, VaultRights,
};
use crate::types::{CapId, VaultId};
use javm::cap::ProtocolCapT;

/// Cap-table slot reserved for the kernel-cap payload at frame init
/// (host-call selector range is 4..=21; slot 32 sits comfortably above
/// it).
pub const KERNEL_CAP_SLOT: u8 = 32;

/// The protocol-cap payload type jar-kernel substitutes into javm's
/// `Cap::Protocol(P)`. See module-level docs.
#[derive(Clone, Debug)]
pub enum KernelCap {
    /// A host-call selector. `ecalli N` on a slot containing
    /// `HostCall(N)` yields `ProtocolCall { slot: N }` to the host.
    HostCall(u8),
    /// A capability with persistent identity in `σ.cap_registry`.
    /// Round-trips between Frame and a Vault preserve `id`.
    Registered { id: CapId, cap: RegisteredCap },
    // ---- Frame-only kinds ----
    //
    // No `CapId`, no σ presence. Kernel-injected at invocation init or
    // at CALL/REPLY transitions; reclaimed at frame teardown.
    /// Home-vault reference placed at MainFrame slot 1 by the kernel
    /// at invocation init. Same shape as `RegisteredCap::VaultRef` but
    /// with no CapId.
    HomeVaultRef(VaultRefCap),
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

impl KernelCap {
    /// Borrow the underlying `RegisteredCap`, if this cap projects from
    /// σ. Returns `None` for `HostCall` and any frame-only variant.
    pub fn as_registered(&self) -> Option<&RegisteredCap> {
        match self {
            KernelCap::Registered { cap, .. } => Some(cap),
            _ => None,
        }
    }

    /// CapId, if this cap is registered in σ.
    pub fn cap_id(&self) -> Option<CapId> {
        match self {
            KernelCap::Registered { id, .. } => Some(*id),
            _ => None,
        }
    }
}

impl ProtocolCapT for KernelCap {
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

    /// A `VaultRef`-shaped cap with `rights.read` is a foreign-frame
    /// handle: javm's resolve walk crosses through it into the named
    /// Vault's CNode. Both the σ-resident `Registered { cap:
    /// VaultRef }` projection and the frame-only `HomeVaultRef` qualify.
    fn as_foreign_frame(&self) -> Option<(VaultId, VaultRights)> {
        let vr = match self {
            KernelCap::HomeVaultRef(vr) => vr,
            KernelCap::Registered {
                cap: RegisteredCap::VaultRef(vr),
                ..
            } => vr,
            _ => return None,
        };
        if vr.rights.read {
            Some((vr.vault_id, vr.rights))
        } else {
            None
        }
    }

    /// Produce a fresh `CallerVault` cap for an internal CALL
    /// transition. Reads the caller VM's home VaultRef at MainFrame
    /// slot 1 and wraps its `vault_id`. Returns `None` if slot 1
    /// doesn't hold a HomeVaultRef — that should only happen on the
    /// bare Frame itself (which never executes guest code).
    fn caller_cap_for(caller_table: &javm::cap::CapTable<Self>) -> Option<javm::cap::Cap<Self>> {
        let home_vault_id = match caller_table.get(1) {
            Some(javm::cap::Cap::Protocol(KernelCap::HomeVaultRef(vr))) => vr.vault_id,
            _ => return None,
        };
        Some(javm::cap::Cap::Protocol(KernelCap::CallerVault(
            CallerVaultCap {
                vault_id: home_vault_id,
            },
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::{VaultRefCap, VaultRights};
    use javm::cap::{Cap, CapTable, ProtocolCapT};

    #[test]
    fn caller_cap_for_reads_home_vault_ref() {
        let mut t: CapTable<KernelCap> = CapTable::new();
        let vault_id = VaultId(42);
        t.set(
            1,
            Cap::Protocol(KernelCap::HomeVaultRef(VaultRefCap {
                vault_id,
                rights: VaultRights::ALL,
            })),
        );
        match KernelCap::caller_cap_for(&t) {
            Some(Cap::Protocol(KernelCap::CallerVault(cv))) => {
                assert_eq!(cv.vault_id, vault_id);
            }
            other => panic!("expected CallerVault cap, got {:?}", other.is_some()),
        }
    }

    #[test]
    fn caller_cap_for_returns_none_when_slot_1_empty() {
        let t: CapTable<KernelCap> = CapTable::new();
        assert!(KernelCap::caller_cap_for(&t).is_none());
    }
}
