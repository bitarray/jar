//! `ProtocolCap` — the protocol-cap payload type jar-kernel substitutes
//! into `javm::Cap::Protocol(P)`. The complete Frame cap type
//! (`javm::Cap<ProtocolCap>`) is exported as `crate::cap::Cap`.
//!
//! Each running VM's javm cap-table is the kernel's per-invocation
//! Frame. The `Protocol` arm of each slot holds one of these variants:
//!
//! - `ProtocolCap::HostCall(u8)` — host-call selector. `ecalli N` on a
//!   slot holding `HostCall(N)` yields `KernelResult::ProtocolCall
//!   { slot: N }` to the host; `drive_invocation` dispatches to the
//!   matching handler.
//!
//! - `ProtocolCap::Registered { id, cap }` — projection of a σ-resident
//!   cap into the Frame. The `cap` is a `RegCap`; the `id`
//!   stays valid across Frame ↔ Vault round-trips so cap_children
//!   bookkeeping survives the bounce.
//!
//! - Frame-only kinds (`HomeVaultRef`, `SelfId`, `CallerVault`,
//!   `CallerKernel`, `AttestationScope`, `Attestation`,
//!   `AttestationAggregate`) — kernel-injected per-frame markers with
//!   no σ presence and no `CapId`. They vanish at invocation teardown.
//!
//! The `ProtocolCap` impl announces VaultRef-shaped caps as
//! foreign-frame handles so javm's resolve walk can cross into a
//! Vault's CNode through them, and produces a fresh `CallerVault`
//! at every CALL transition.

use crate::cap::{
    AttestationAggregateCap, AttestationCap, AttestationScopeCap, CallerKernelCap, CallerVaultCap,
    RegCap, SelfCap, VaultRefCap, VaultRights,
};
use crate::types::{CapId, VaultId};
use javm::cap::ProtocolCap as ProtocolCapT;

/// Cap-table slot reserved for the kernel-cap payload at frame init
/// (host-call selector range is 4..=21; slot 32 sits comfortably above
/// it).
pub const KERNEL_CAP_SLOT: u8 = 32;

/// The protocol-cap payload type jar-kernel substitutes into javm's
/// `Cap::Protocol(P)`. See module-level docs.
#[derive(Clone, Debug)]
pub enum ProtocolCap {
    /// A host-call selector. `ecalli N` on a slot containing
    /// `HostCall(N)` yields `ProtocolCall { slot: N }` to the host.
    HostCall(u8),
    /// A capability with persistent identity in `σ.cap_registry`.
    /// Round-trips between Frame and a Vault preserve `id`.
    Registered { id: CapId, cap: RegCap },
    // ---- Frame-only kinds ----
    //
    // No `CapId`, no σ presence. Kernel-injected at invocation init or
    // at CALL/REPLY transitions; reclaimed at frame teardown.
    /// Home-vault reference placed at MainFrame slot 1 by the kernel
    /// at invocation init. Same shape as `RegCap::VaultRef` but
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

impl ProtocolCap {
    /// Borrow the underlying `RegCap`, if this cap projects from
    /// σ. Returns `None` for `HostCall` and any frame-only variant.
    pub fn as_registered(&self) -> Option<&RegCap> {
        match self {
            ProtocolCap::Registered { cap, .. } => Some(cap),
            _ => None,
        }
    }

    /// CapId, if this cap is registered in σ.
    pub fn cap_id(&self) -> Option<CapId> {
        match self {
            ProtocolCap::Registered { id, .. } => Some(*id),
            _ => None,
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

    /// A `VaultRef`-shaped cap with `rights.read` is a foreign-frame
    /// handle: javm's resolve walk crosses through it into the named
    /// Vault's CNode. Both the σ-resident `Registered { cap:
    /// VaultRef }` projection and the frame-only `HomeVaultRef` qualify.
    fn as_foreign_frame(&self) -> Option<(VaultId, VaultRights)> {
        let vr = match self {
            ProtocolCap::HomeVaultRef(vr) => vr,
            ProtocolCap::Registered {
                cap: RegCap::VaultRef(vr),
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
            Some(javm::cap::Cap::Protocol(ProtocolCap::HomeVaultRef(vr))) => vr.vault_id,
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
            Cap::Protocol(ProtocolCap::HomeVaultRef(VaultRefCap {
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
