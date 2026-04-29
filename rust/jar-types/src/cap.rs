//! Capability types.
//!
//! Per spec §01: capabilities are the kernel's authority primitive. They live
//! in CNode slots (persistent) or Frames (ephemeral). Two pinned variants
//! (Dispatch / Transact) carry a `born_in` CNode and may not move across
//! CNodes; their ephemeral counterparts (DispatchRef / TransactRef) live only
//! in Frames and are derived from a pinned source.

use crate::{CNodeId, CapId, KeyId, VaultId};

/// All capability variants. Persistent variants live in CNodes (and σ); the
/// two `*Ref` variants are ephemeral and live only in Frames.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Capability {
    /// Owner cap; immovable to a Frame; may not be granted to another CNode.
    Vault { vault_id: VaultId },

    /// Callable handle for `vault_initialize`; may also gate slot mutation
    /// (Grant / Revoke) on the target Vault.
    VaultRef {
        vault_id: VaultId,
        rights: VaultRights,
    },

    /// Persistent Dispatch entrypoint cap; pinned to `born_in`.
    Dispatch { vault_id: VaultId, born_in: CNodeId },

    /// Persistent Transact entrypoint cap; pinned to `born_in`.
    Transact { vault_id: VaultId, born_in: CNodeId },

    /// Persistent Schedule entrypoint cap; pinned to `born_in`. Kernel-fired
    /// once per block at this slot's position in σ.transact_space_cnode,
    /// with no body event input. Used for chain-author block_init /
    /// block_final / consensus / cleanup hooks. Never `cap_call`'d by
    /// userspace; not derivable to a callable ref.
    Schedule { vault_id: VaultId, born_in: CNodeId },

    /// Ephemeral Dispatch reference, derived from a `Dispatch`. Frame-only.
    DispatchRef { vault_id: VaultId },

    /// Ephemeral Transact reference, derived from a `Transact`. Frame-only.
    TransactRef { vault_id: VaultId },

    /// Reference to a CNode (used to grant slot positions).
    CNode { cnode_id: CNodeId },

    /// Storage authority over a Vault's key range.
    Storage {
        vault_id: VaultId,
        key_range: KeyRange,
        rights: StorageRights,
    },

    /// Resource cap (e.g. allocate a Vault, set quota).
    Resource(ResourceKind),

    /// Meta cap — manage another cap (Grant / Revoke / Derive permissions).
    Meta { op: MetaOp, over: CapId },

    /// Mode-blind attestation handle: kernel decides verify-vs-sign per call.
    AttestationCap { key: KeyId, scope: AttestationScope },

    /// Aggregate signature handle (BLS / threshold). Stubbed for now.
    AttestationAggregateCap { key: KeyId },

    /// Result handle: produce mode writes blob to result_trace; verify mode
    /// checks blob against trace at the bound index.
    ResultCap,
}

impl Capability {
    pub fn is_pinned_or_ref(&self) -> bool {
        matches!(
            self,
            Capability::Dispatch { .. }
                | Capability::Transact { .. }
                | Capability::Schedule { .. }
                | Capability::DispatchRef { .. }
                | Capability::TransactRef { .. }
        )
    }

    pub fn is_ephemeral(&self) -> bool {
        matches!(
            self,
            Capability::DispatchRef { .. } | Capability::TransactRef { .. }
        )
    }

    pub fn vault_id(&self) -> Option<VaultId> {
        match self {
            Capability::Vault { vault_id }
            | Capability::VaultRef { vault_id, .. }
            | Capability::Dispatch { vault_id, .. }
            | Capability::Transact { vault_id, .. }
            | Capability::Schedule { vault_id, .. }
            | Capability::DispatchRef { vault_id }
            | Capability::TransactRef { vault_id }
            | Capability::Storage { vault_id, .. } => Some(*vault_id),
            _ => None,
        }
    }
}

/// VaultRef rights. A bag of bits; uses a small struct rather than bitflags.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct VaultRights {
    pub initialize: bool,
    pub grant: bool,
    pub revoke: bool,
    pub derive: bool,
}

impl VaultRights {
    pub const ALL: VaultRights = VaultRights {
        initialize: true,
        grant: true,
        revoke: true,
        derive: true,
    };
    pub const INITIALIZE: VaultRights = VaultRights {
        initialize: true,
        grant: false,
        revoke: false,
        derive: false,
    };
}

/// Storage rights.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct StorageRights {
    pub read: bool,
    pub write: bool,
}

impl StorageRights {
    pub const RO: StorageRights = StorageRights {
        read: true,
        write: false,
    };
    pub const RW: StorageRights = StorageRights {
        read: true,
        write: true,
    };
}

/// Inclusive key prefix for Storage caps. An empty prefix grants the entire
/// vault's storage.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct KeyRange {
    pub prefix: Vec<u8>,
}

impl KeyRange {
    pub fn all() -> Self {
        Self { prefix: Vec::new() }
    }

    pub fn covers(&self, key: &[u8]) -> bool {
        key.starts_with(&self.prefix)
    }
}

/// Resource cap kinds. Quotas are kernel-tracked; placement/use is gated.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum ResourceKind {
    /// Authorizes creating a fresh Vault, with the given storage budget.
    CreateVault { quota_items: u64, quota_bytes: u64 },
    /// Authorizes setting quotas on the named Vault.
    SetQuota { target: VaultId },
    /// Authorizes preimage-store for the given budget.
    PreimageStore { items: u64, bytes: u64 },
}

/// Meta-op categories. Used for Meta caps that manage other caps.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum MetaOp {
    Grant,
    Revoke,
    Derive,
}

/// AttestationCap blob scope.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum AttestationScope {
    /// Userspace supplies the blob at `attest()` time.
    Direct,
    /// The blob is the surrounding container minus this trace entry; the
    /// kernel reconstructs (verifier) or fills in (proposer) post-execution.
    Sealing,
}

/// One entry in the kernel's cap registry.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct CapRecord {
    pub cap: Capability,
    /// Issuer cap-id (for derived caps); None for caps minted ex nihilo
    /// (e.g. genesis).
    pub issuer: Option<CapId>,
    /// Opaque kernel-side narrowing data. Userspace doesn't see this.
    pub narrowing: Vec<u8>,
}

/// A 256-slot capability table. Used for both Vault slots and σ-rooted CNodes.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct CNode {
    pub slots: [Option<CapId>; 256],
}

impl Default for CNode {
    fn default() -> Self {
        Self::new()
    }
}

impl CNode {
    pub fn new() -> Self {
        // Workaround for [Option<CapId>; 256] not being Default-derivable on
        // older rustc paths.
        const EMPTY: Option<CapId> = None;
        CNode {
            slots: [EMPTY; 256],
        }
    }

    pub fn get(&self, slot: u8) -> Option<CapId> {
        self.slots[slot as usize]
    }

    pub fn set(&mut self, slot: u8, cap: Option<CapId>) {
        self.slots[slot as usize] = cap;
    }

    pub fn iter(&self) -> impl Iterator<Item = (u8, CapId)> + '_ {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.map(|c| (i as u8, c)))
    }
}
