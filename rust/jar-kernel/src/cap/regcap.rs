//! Cap shapes for the kernel.
//!
//! After the CapId-removal refactor, caps are pure value types stored
//! inline. There's no cap_registry: `vault.slots` holds `RegCap`
//! values directly, `σ.{transact,dispatch}_endpoints` hold
//! `EventEndpointCap` values directly. Bulk content (CodeCap blob,
//! DataCap content) shares storage via `Arc`.
//!
//! The cost: no cascade revocation. Granting a copy of a cap
//! transfers ownership of that copy; revoking the source is just
//! clearing the source slot. Chain-authors needing cascade can build
//! it explicitly atop a shared revocation token.

use std::sync::Arc;

use crate::types::{Hash, KernelRole, KeyId, Signature, VaultId};

// -----------------------------------------------------------------------------
// Per-variant structs
// -----------------------------------------------------------------------------

/// Callable handle for `vault_initialize`; may also gate slot mutation
/// (Grant / Revoke) on the target Vault. Identity is `(vault_id, rights)`.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct VaultRefCap {
    pub vault_id: VaultId,
    pub rights: VaultRights,
}

/// EventEndpoint cap. Lives in `σ.transact_endpoints` (on-chain) or
/// `σ.dispatch_endpoints` (off-chain). Position in σ determines firing
/// context. Never appears in `vault.slots`.
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
/// verify. Frame-only — never persisted.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct AttestationCap {
    pub key: KeyId,
    pub blob_hash: Hash,
}

/// Aggregate signature handle (BLS / threshold). Stubbed; preserved as
/// a separate variant for future BLS-aggregate work. Frame-only.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct AttestationAggregateCap {
    pub key: KeyId,
}

/// AttestationScope cap: kernel-managed; passed to verify in a Frame
/// slot. Its variant determines which pubkeys `mint_attest_cap` may
/// produce caps for.
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
/// holders via `Arc<Vec<u8>>`. Immutable.
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
/// page granularity. Immutable + shared via `Arc`.
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
/// signature. Concretely: empty KeyId. Real keys are non-empty.
pub fn identity_key() -> KeyId {
    KeyId(Vec::new())
}

/// Returns true iff the given key is the IDENTITY_KEY sentinel.
pub fn is_identity_key(key: &KeyId) -> bool {
    key.0.is_empty()
}

// -----------------------------------------------------------------------------
// RegCap — what occupies one slot of a Vault.slots CNode
// -----------------------------------------------------------------------------

/// Cap kinds eligible for placement in `vault.slots`. Pure value types
/// — no `CapId` indirection. Granting a copy of a `RegCap` transfers
/// ownership of the copy; the source remains independent.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum RegCap {
    VaultRef(VaultRefCap),
    Code(CodeCap),
    Data(DataCap),
    Resource(ResourceCap),
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
// CNode (cap-table)
// -----------------------------------------------------------------------------

/// A 256-slot capability table. Used for Vault.slots.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct CNode {
    pub slots: [Option<RegCap>; 256],
}

impl Default for CNode {
    fn default() -> Self {
        Self::new()
    }
}

impl CNode {
    pub fn new() -> Self {
        const EMPTY: Option<RegCap> = None;
        CNode {
            slots: [EMPTY; 256],
        }
    }

    pub fn get(&self, slot: u8) -> Option<&RegCap> {
        self.slots[slot as usize].as_ref()
    }

    pub fn set(&mut self, slot: u8, cap: Option<RegCap>) {
        self.slots[slot as usize] = cap;
    }

    pub fn iter(&self) -> impl Iterator<Item = (u8, &RegCap)> + '_ {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.as_ref().map(|c| (i as u8, c)))
    }
}
