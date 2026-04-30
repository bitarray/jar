//! Capability variants.
//!
//! Per spec §01: capabilities are the kernel's authority primitive. They
//! live in CNode slots (persistent) or Frames (ephemeral). Two pinned
//! variants (Dispatch / Transact) carry a `born_in` CNode and may not move
//! across CNodes; their ephemeral counterparts (DispatchRef / TransactRef)
//! live only in Frames and are derived from a pinned source.
//!
//! Each variant is a named struct so generic code can pass a variant by
//! reference (e.g. `&DispatchCap`). The `Capability` enum wraps them as a
//! sum type.

use std::sync::Arc;

use crate::types::{CNodeId, CapId, KernelRole, KeyId, VaultId};

// -----------------------------------------------------------------------------
// Per-variant structs
// -----------------------------------------------------------------------------

/// Owner cap; immovable to a Frame; may not be granted to another CNode.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct VaultCap {
    pub vault_id: VaultId,
}

/// Callable handle for `vault_initialize`; may also gate slot mutation
/// (Grant / Revoke) on the target Vault.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct VaultRefCap {
    pub vault_id: VaultId,
    pub rights: VaultRights,
}

/// Persistent Dispatch entrypoint cap; pinned to `born_in`.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct DispatchCap {
    pub vault_id: VaultId,
    pub born_in: CNodeId,
}

/// Persistent Transact entrypoint cap; pinned to `born_in`.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct TransactCap {
    pub vault_id: VaultId,
    pub born_in: CNodeId,
}

/// Persistent Schedule entrypoint cap; pinned to `born_in`. Kernel-fired
/// once per block at this slot's position in σ.transact_space_cnode, with
/// no body event input. Used for chain-author block_init / block_final /
/// consensus / cleanup hooks. Never `cap_call`'d by userspace; not
/// derivable to a callable ref.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct ScheduleCap {
    pub vault_id: VaultId,
    pub born_in: CNodeId,
}

/// Ephemeral Dispatch reference, derived from a `Dispatch`. Frame-only.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct DispatchRefCap {
    pub vault_id: VaultId,
}

/// Ephemeral Transact reference, derived from a `Transact`. Frame-only.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct TransactRefCap {
    pub vault_id: VaultId,
}

/// Reference to a CNode (used to grant slot positions).
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct CNodeCap {
    pub cnode_id: CNodeId,
}

/// Resource cap (e.g. allocate a Vault, set quota).
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ResourceCap(pub ResourceKind);

/// Meta cap — manage another cap (Grant / Revoke / Derive permissions).
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct MetaCap {
    pub op: MetaOp,
    pub over: CapId,
}

/// Mode-blind attestation handle: kernel decides verify-vs-sign per call.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct AttestationCap {
    pub key: KeyId,
    pub scope: AttestationScope,
}

/// Aggregate signature handle (BLS / threshold). Stubbed for now.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct AttestationAggregateCap {
    pub key: KeyId,
}

/// Result handle: produce mode writes blob to result_trace; verify mode
/// checks blob against trace at the bound index.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct ResultCap;

/// Per-invocation gas budget. Lives at ephemeral sub-slot 3 by
/// convention. `MGMT_GAS_DERIVE` splits off a child cap; `MGMT_GAS_MERGE`
/// recombines. The JIT decrements `remaining` at safepoints (Phase 9).
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct GasCap {
    pub remaining: u64,
}

/// Persistent code capability. Holds a PVM program blob shared across
/// holders (multiple Vault slots, multiple invocations) via `Arc<[u8]>`.
/// The blob is immutable; its content hash is computed lazily for
/// state-root inclusion.
#[derive(Clone, Debug)]
pub struct CodeCap {
    pub blob: Arc<Vec<u8>>,
}

impl PartialEq for CodeCap {
    fn eq(&self, other: &Self) -> bool {
        // Pointer-equal Arcs are trivially equal; otherwise compare bytes.
        Arc::ptr_eq(&self.blob, &other.blob) || *self.blob == *other.blob
    }
}

impl Eq for CodeCap {}

/// Persistent data capability. Holds a fixed-size byte payload at 4 KiB
/// page granularity. Immutable + copyable + refcounted: COPY of a
/// persistent DataCap (Vault → Frame, Vault → Vault) shares the same
/// `Arc<Vec<u8>>` content; mutation requires creating a fresh DataCap
/// with new content (typically by writing to an ephemeral mapped copy
/// in a running Frame and MOVing the result back).
///
/// `page_count` is the logical size in 4 KiB pages; `content` may be
/// shorter than `page_count * 4096` if trailing zero pages are
/// implied — the kernel writes zero-padding when materializing into
/// ephemeral pages.
#[derive(Clone, Debug)]
pub struct DataCap {
    pub content: Arc<Vec<u8>>,
    pub page_count: u32,
}

impl PartialEq for DataCap {
    fn eq(&self, other: &Self) -> bool {
        self.page_count == other.page_count
            && (Arc::ptr_eq(&self.content, &other.content) || *self.content == *other.content)
    }
}

impl Eq for DataCap {}

/// Per-frame self identity. The kernel rewrites ephemeral sub-slot 2 on
/// every CALL/REPLY so the active VM's "who am I" is correct.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct SelfCap {
    pub vault_id: VaultId,
}

/// Per-frame caller (vault → vault sub-CALL). Lives at ephemeral
/// sub-slot 1 when the invocation came from another Vault VM.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct CallerVaultCap {
    pub vault_id: VaultId,
}

/// Per-frame caller (kernel-fired top-level invocation). Lives at
/// ephemeral sub-slot 1 when the invocation was kernel-initiated.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct CallerKernelCap {
    pub role: KernelRole,
}

// -----------------------------------------------------------------------------
// Capability sum type
// -----------------------------------------------------------------------------

/// All capability variants. Persistent variants live in CNodes (and σ); the
/// two `*Ref` variants are ephemeral and live only in Frames.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Capability {
    Vault(VaultCap),
    VaultRef(VaultRefCap),
    Code(CodeCap),
    Data(DataCap),
    Dispatch(DispatchCap),
    Transact(TransactCap),
    Schedule(ScheduleCap),
    DispatchRef(DispatchRefCap),
    TransactRef(TransactRefCap),
    CNode(CNodeCap),
    Resource(ResourceCap),
    Meta(MetaCap),
    AttestationCap(AttestationCap),
    AttestationAggregateCap(AttestationAggregateCap),
    ResultCap(ResultCap),
    /// Per-invocation gas budget — lives at ephemeral sub-slot 3.
    Gas(GasCap),
    /// Per-frame self-identity — lives at ephemeral sub-slot 2.
    SelfId(SelfCap),
    /// Per-frame caller (sub-CALL) — lives at ephemeral sub-slot 1.
    CallerVault(CallerVaultCap),
    /// Per-frame caller (kernel-initiated) — lives at ephemeral sub-slot 1.
    CallerKernel(CallerKernelCap),
}

impl Capability {
    pub fn is_pinned_or_ref(&self) -> bool {
        matches!(
            self,
            Capability::Dispatch(_)
                | Capability::Transact(_)
                | Capability::Schedule(_)
                | Capability::DispatchRef(_)
                | Capability::TransactRef(_)
        )
    }

    pub fn is_ephemeral(&self) -> bool {
        matches!(
            self,
            Capability::DispatchRef(_) | Capability::TransactRef(_)
        )
    }

    pub fn vault_id(&self) -> Option<VaultId> {
        match self {
            Capability::Vault(c) => Some(c.vault_id),
            Capability::VaultRef(c) => Some(c.vault_id),
            Capability::Dispatch(c) => Some(c.vault_id),
            Capability::Transact(c) => Some(c.vault_id),
            Capability::Schedule(c) => Some(c.vault_id),
            Capability::DispatchRef(c) => Some(c.vault_id),
            Capability::TransactRef(c) => Some(c.vault_id),
            _ => None,
        }
    }
}

// -----------------------------------------------------------------------------
// Variant-shape helpers
// -----------------------------------------------------------------------------

/// VaultRef rights. A bag of bits; uses a small struct rather than bitflags.
///
/// `read` gates *traversal* — a VaultRef without `read` cannot be used as a
/// cap-ref crossing point in javm's resolve walk (javm only crosses through
/// caps whose `as_foreign_frame()` returns `Some`, and for `KernelCap` that
/// requires `rights.read`). The other bits gate the operation at the
/// final-step VaultRef:
///
/// - `initialize` — `cap_call`-equivalent: spawn a VM running the Vault's manager.
/// - `grant`      — place a cap into a target slot (Frame → Vault MOVE / COPY destination).
/// - `revoke`     — remove a cap from a slot (Vault → Frame MOVE source, MGMT_DROP).
/// - `derive`     — produce a narrowed copy (MGMT_COPY source from a Vault).
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct VaultRights {
    pub read: bool,
    pub initialize: bool,
    pub grant: bool,
    pub revoke: bool,
    pub derive: bool,
}

impl VaultRights {
    pub const ALL: VaultRights = VaultRights {
        read: true,
        initialize: true,
        grant: true,
        revoke: true,
        derive: true,
    };
    pub const INITIALIZE: VaultRights = VaultRights {
        read: false,
        initialize: true,
        grant: false,
        revoke: false,
        derive: false,
    };
    /// Read-only traversal: lets a Vault's slots be reached for inspection
    /// or chaining onward, but no slot mutation.
    pub const READ: VaultRights = VaultRights {
        read: true,
        initialize: false,
        grant: false,
        revoke: false,
        derive: false,
    };
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

// -----------------------------------------------------------------------------
// CapRecord and CNode (cap-table)
// -----------------------------------------------------------------------------

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
