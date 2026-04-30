//! `KernelCap` — the protocol-cap payload type jar-kernel substitutes
//! into javm's `Cap::Protocol(P)`.
//!
//! Each running VM's javm cap-table is the kernel's per-invocation
//! Frame. Slots hold one of three flavours:
//!
//! - `KernelCap::HostCall(u8)` — populated at VM init for the kernel's
//!   host-call selector range (4..=21 today). When the guest does
//!   `ecalli N`, javm yields `KernelResult::ProtocolCall { slot: N }`,
//!   the kernel's `drive_invocation` loop fetches the slot, sees a
//!   `HostCall(N)`, and dispatches the corresponding `HostCall`
//!   handler.
//!
//! - `KernelCap::Ephemeral(Capability)` — kernel-injected per-frame
//!   markers with no σ presence: `Gas`, `SelfId`, `CallerVault`,
//!   `CallerKernel`, plus the slot-1 home `VaultRef` the kernel
//!   places at VM init. These vanish at invocation teardown; they
//!   carry no `CapId` because they are not registered in
//!   `σ.cap_registry`.
//!
//! - `KernelCap::Registered { id, cap }` — caps with persistent
//!   identity in `σ.cap_registry`. Round-trips between Frame and a
//!   Vault CNode preserve `id` so `cap_holders` / `cap_children`
//!   bookkeeping stays consistent. All persistent cap variants
//!   (`VaultRef`, `Storage`, `Dispatch`, etc.) take this arm when
//!   they appear in a Frame.
//!
//! The `ProtocolCapT` impl makes javm-side mgmt ecallis (COPY, MOVE,
//! DROP) refuse to mutate slots that hold pinned kernel caps, and
//! announces VaultRef-shaped caps as foreign-frame handles so javm's
//! resolve walk can cross into a Vault's CNode through them.

use crate::cap::{Capability, VaultRights};
use crate::types::VaultId;
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
    /// A capability with no σ presence — kernel-injected per-frame
    /// (Gas / SelfId / CallerVault / CallerKernel) or per-VM init
    /// (slot-1 home VaultRef). Cannot be persisted to a Vault: any
    /// MOVE / COPY into a foreign frame is rejected by the host
    /// adapter (no `CapId` to register a holder under).
    Ephemeral(Capability),
    /// A capability with persistent identity in `σ.cap_registry`.
    /// `id` stays valid across Frame / Vault round-trips so that
    /// children / holders bookkeeping survives the bounce.
    Registered {
        id: crate::types::CapId,
        cap: Capability,
    },
}

impl KernelCap {
    /// Borrow the underlying `Capability`, regardless of arm. Returns
    /// `None` for `HostCall` (which has no `Capability` shape).
    pub fn as_capability(&self) -> Option<&Capability> {
        match self {
            KernelCap::HostCall(_) => None,
            KernelCap::Ephemeral(c) | KernelCap::Registered { cap: c, .. } => Some(c),
        }
    }

    /// CapId, if this cap is registered in σ.
    pub fn cap_id(&self) -> Option<crate::types::CapId> {
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
        match self {
            // Host-call selectors are stateless ids; copying them is
            // harmless (a guest that copies one just creates another
            // way to invoke the same host call).
            KernelCap::HostCall(_) => true,
            // Real caps inherit the pinning rules from `Capability`.
            // Pinned variants (Dispatch / Transact / Schedule) and
            // their refs must not be COPYed by the guest.
            KernelCap::Ephemeral(c) | KernelCap::Registered { cap: c, .. } => !c.is_pinned_or_ref(),
        }
    }

    fn is_movable(&self) -> bool {
        // MOVE is a transfer (no aliasing). We allow within a Frame for
        // every payload kind. Persistent placement is gated separately
        // by the Vault-side adapter (`fc_set` checks pinning + rights).
        true
    }

    fn is_droppable(&self) -> bool {
        true
    }

    /// A `VaultRef` with `rights.read` is a foreign-frame handle: javm's
    /// resolve walk crosses through it into the named Vault's CNode.
    /// Operation rights (Grant / Revoke / Derive / Initialize) are
    /// recorded at this step and consulted by the host adapter at the
    /// final step of the walk.
    fn as_foreign_frame(&self) -> Option<(VaultId, VaultRights)> {
        let cap = self.as_capability()?;
        match cap {
            Capability::VaultRef(c) if c.rights.read => Some((c.vault_id, c.rights)),
            _ => None,
        }
    }

    /// Produce a fresh `CallerCap` for an internal CALL transition.
    /// Reads the caller VM's home VaultRef at MainFrame slot 1 and
    /// wraps its `vault_id` as a `Capability::CallerVault`. Returns
    /// `None` if slot 1 doesn't hold a VaultRef-shaped Ephemeral
    /// cap — that should only happen on the bare Frame itself
    /// (which never executes guest code), so the call is a no-op.
    fn caller_cap_for(caller_table: &javm::cap::CapTable<Self>) -> Option<javm::cap::Cap<Self>> {
        use crate::cap::CallerVaultCap;
        let home_vault_id = match caller_table.get(1) {
            Some(javm::cap::Cap::Protocol(KernelCap::Ephemeral(Capability::VaultRef(vr)))) => {
                vr.vault_id
            }
            _ => return None,
        };
        Some(javm::cap::Cap::Protocol(KernelCap::Ephemeral(
            Capability::CallerVault(CallerVaultCap {
                vault_id: home_vault_id,
            }),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::{VaultRefCap, VaultRights};
    use javm::cap::{Cap, CapTable, ProtocolCapT};

    /// `caller_cap_for` reads the home VaultRef at MainFrame slot 1
    /// and produces a `CallerVault` cap wrapping the same vault_id.
    #[test]
    fn caller_cap_for_reads_home_vault_ref() {
        let mut t: CapTable<KernelCap> = CapTable::new();
        let vault_id = VaultId(42);
        t.set(
            1,
            Cap::Protocol(KernelCap::Ephemeral(Capability::VaultRef(VaultRefCap {
                vault_id,
                rights: VaultRights::ALL,
            }))),
        );
        match KernelCap::caller_cap_for(&t) {
            Some(Cap::Protocol(KernelCap::Ephemeral(Capability::CallerVault(cv)))) => {
                assert_eq!(cv.vault_id, vault_id);
            }
            other => panic!("expected CallerVault cap, got {:?}", other.is_some()),
        }
    }

    /// When slot 1 is empty (or doesn't hold a VaultRef), the hook
    /// returns `None` so javm leaves `BARE_CALLER_SLOT` as-stashed.
    #[test]
    fn caller_cap_for_returns_none_when_slot_1_empty() {
        let t: CapTable<KernelCap> = CapTable::new();
        assert!(KernelCap::caller_cap_for(&t).is_none());
    }
}
