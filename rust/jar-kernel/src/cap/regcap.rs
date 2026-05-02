//! `RegCap` — σ-resident cap shapes that need `CapId`-based identity.
//!
//! Caps in this enum are stored in `σ.cap_registry` under a CapId. They
//! participate in derive provenance (`cap_children`) and are subject to
//! cascade revocation. A `Vault.slots[N]` entry of `SlotEntry::Cap(id)`
//! points at a record here.
//!
//! The set is intentionally narrow:
//!
//! - `Code` / `Data` — bulk resource grants whose blob/content is shared
//!   via Arc; CapId tracks identity for revocation and (rarely) sharing.
//! - `EventEndpoint` — referenced by `σ.transact_endpoints` /
//!   `σ.dispatch_endpoints`. Never appears in `vault.slots`.
//! - `Resource` — governance handle (CreateVault / SetQuota / ...).
//!
//! Notably **not** in RegCap:
//!
//! - `VaultRef` — value-type; identity is `(vault_id, rights)`. Stored
//!   inline in `vault.slots` via `SlotEntry::VaultRef`. No CapId.
//! - `Attestation` / `AttestationAggregate` — Frame-only; minted in
//!   verify, vanish at frame teardown. Live as top-level
//!   `ProtocolCap::Attestation` / `ProtocolCap::AttestationAggregate`.
//! - Frame-only context kinds (SelfId, Caller*, AttestationScope) —
//!   top-level `ProtocolCap` arms.

use std::sync::Arc;

use crate::types::{CapId, Hash, KernelRole, KeyId, Signature, VaultId};

// -----------------------------------------------------------------------------
// Per-variant structs
// -----------------------------------------------------------------------------

/// Callable handle for `vault_initialize`; may also gate slot mutation
/// (Grant / Revoke) on the target Vault. Value-type — identity is
/// `(vault_id, rights)`. Stored inline via `SlotEntry::VaultRef` and
/// projected into Frames as `ProtocolCap::VaultRef(_)`. Not in
/// `RegCap`; not registered in `cap_registry`.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct VaultRefCap {
    pub vault_id: VaultId,
    pub rights: VaultRights,
}

/// EventEndpoint cap. Lives in `σ.transact_endpoints` (on-chain) or
/// `σ.dispatch_endpoints` (off-chain) — referenced by CapId, stored
/// in `cap_registry`. Position in σ determines firing context; never
/// appears in `vault.slots`.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct EventEndpointCap {
    pub vault_id: VaultId,
    pub gas_budget: u64,
    pub memory_budget: u32,
}

/// Resource cap (governance handle: allocate Vault, set quota, etc.).
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ResourceCap(pub ResourceKind);

/// AttestationCap is the proof: existence in a verify Frame means the
/// kernel vouched that `key` signed `blob_hash`. Minted only inside
/// verify. Frame-only — no σ presence, no CapId.
///
/// `IDENTITY_KEY` (sentinel) collapses the prior ResultCap: an
/// AttestationCap with `key = IDENTITY_KEY` represents a kernel-vouched
/// computation output that needs no signature.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct AttestationCap {
    pub key: KeyId,
    pub blob_hash: Hash,
}

/// Aggregate signature handle (BLS / threshold). Stubbed for now;
/// preserved as a separate variant for future BLS-aggregate work.
/// Frame-only.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct AttestationAggregateCap {
    pub key: KeyId,
}

/// AttestationScope cap: kernel-managed; passed to verify in a Frame
/// slot. Its variant determines which pubkeys `mint_attest_cap` may
/// produce caps for.
///
/// - Network-arrived event verify: `Unlimited`.
/// - emit_event from apply_block (transact / Schedule context): `Unlimited`.
/// - emit_event from dispatch context: `Restricted` to the seen-set of
///   the source dispatch endpoint (tracked per (node, endpoint, cycle)).
///
/// Held in a Frame slot during verify; reclaimed at verify end.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum AttestationScopeCap {
    /// Any pubkey may be minted for.
    Unlimited,
    /// Restricted to the specified pubkeys.
    Restricted(Vec<KeyId>),
}

/// One signature entry in the attestation_trace. Stored per-event, per-
/// Schedule slot, or block-level cumulative (depending on context).
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct AttestationEntry {
    pub key: KeyId,
    pub blob_hash: Hash,
    pub signature: Signature,
}

impl AttestationEntry {
    pub fn is_reserved(&self) -> bool {
        self.signature.is_reserved()
    }
}

/// Persistent code capability. Holds a PVM program blob shared across
/// holders via `Arc<[u8]>`. Immutable; content hash is computed lazily
/// for state-root inclusion.
#[derive(Clone, Debug)]
pub struct CodeCap {
    pub blob: Arc<Vec<u8>>,
}

impl PartialEq for CodeCap {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.blob, &other.blob) || *self.blob == *other.blob
    }
}

impl Eq for CodeCap {}

/// Persistent data capability. Holds a fixed-size byte payload at 4 KiB
/// page granularity. Immutable + copyable + refcounted.
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

/// Per-frame caller (vault → vault sub-CALL).
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct CallerVaultCap {
    pub vault_id: VaultId,
}

/// Per-frame caller (kernel-fired top-level invocation).
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct CallerKernelCap {
    pub role: KernelRole,
}

// -----------------------------------------------------------------------------
// Sentinel pubkey for IDENTITY_KEY
// -----------------------------------------------------------------------------

/// Reserved sentinel pubkey for kernel-vouched attestations (no signer).
/// Used by `mint_attest_cap` to mint AttestationCaps that need no
/// signature — e.g., block_init's prior state-root commitment, or
/// any chain-author-defined "computation output the kernel vouches for"
/// (collapsed from prior ResultCap).
///
/// Concretely: empty KeyId. Real keys are non-empty.
pub fn identity_key() -> KeyId {
    KeyId(Vec::new())
}

/// Returns true iff the given key is the IDENTITY_KEY sentinel
/// (kernel-vouched, no signer).
pub fn is_identity_key(key: &KeyId) -> bool {
    key.0.is_empty()
}

// -----------------------------------------------------------------------------
// RegCap sum type (σ-resident, CapId-keyed)
// -----------------------------------------------------------------------------

/// σ-resident cap shapes — what `σ.cap_registry` stores under a CapId.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum RegCap {
    Code(CodeCap),
    Data(DataCap),
    /// Single endpoint cap shape replacing prior Transact/Dispatch/Schedule.
    /// Lives in `σ.{transact,dispatch}_endpoints`; never in `vault.slots`.
    EventEndpoint(EventEndpointCap),
    Resource(ResourceCap),
}

impl RegCap {
    pub fn vault_id(&self) -> Option<VaultId> {
        match self {
            RegCap::EventEndpoint(c) => Some(c.vault_id),
            _ => None,
        }
    }
}

// -----------------------------------------------------------------------------
// Variant-shape helpers
// -----------------------------------------------------------------------------

/// VaultRef rights. A bag of bits.
///
/// `read` gates *traversal*. `cap_indirection` gates write access.
/// `derive` gates narrowing; `initialize` gates spawning a Vault VM.
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
    /// Read-only traversal.
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
    CreateVault { quota_pages: u64 },
    SetQuota { target: VaultId },
    PreimageStore { pages: u64 },
}

// -----------------------------------------------------------------------------
// CapRecord, SlotEntry, CNode
// -----------------------------------------------------------------------------

/// One entry in the kernel's cap registry.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct CapRecord {
    pub cap: RegCap,
    pub issuer: Option<CapId>,
    pub narrowing: Vec<u8>,
}

/// What occupies one slot of a `Vault.slots` CNode. Heterogeneous so
/// that value-type caps (`VaultRef`) live inline alongside CapId
/// references to `cap_registry` records (`Code`, `Data`, `Resource`).
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum SlotEntry {
    /// Reference to a `cap_registry` record (Code / Data / Resource).
    /// Lazily revoked: a CapId pointing at a removed record surfaces
    /// `CapNotFound` on next access.
    Cap(CapId),
    /// Inline VaultRef value. Identity is `(vault_id, rights)`; not
    /// registered, not subject to cascade revocation.
    VaultRef(VaultRefCap),
}

/// A 256-slot capability table. Used for Vault.slots.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct CNode {
    pub slots: [Option<SlotEntry>; 256],
}

impl Default for CNode {
    fn default() -> Self {
        Self::new()
    }
}

impl CNode {
    pub fn new() -> Self {
        const EMPTY: Option<SlotEntry> = None;
        CNode {
            slots: [EMPTY; 256],
        }
    }

    pub fn get(&self, slot: u8) -> Option<&SlotEntry> {
        self.slots[slot as usize].as_ref()
    }

    pub fn set(&mut self, slot: u8, entry: Option<SlotEntry>) {
        self.slots[slot as usize] = entry;
    }

    pub fn iter(&self) -> impl Iterator<Item = (u8, &SlotEntry)> + '_ {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.as_ref().map(|e| (i as u8, e)))
    }
}
