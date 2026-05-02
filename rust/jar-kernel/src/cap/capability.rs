//! Capability variants.
//!
//! Per spec §01 (event-redesign): capabilities are the kernel's authority
//! primitive. They live in CNode slots (persistent) or Frames (ephemeral).
//!
//! In the event-redesign, the prior pinned `Dispatch` / `Transact` /
//! `Schedule` caps with `born_in` CNode references collapse into a single
//! `EventEndpointCap { vault_id, gas_budget, memory_budget }`. There is
//! no hierarchical cap-graph; the chain's public surface is two flat lists
//! `σ.transact_endpoints` and `σ.dispatch_endpoints` of EventEndpointCap
//! entries.
//!
//! AttestationCap is the proof itself — minted via `mint_attest_cap`
//! inside verify (cap's existence is the evidence). ResultCap collapses
//! into AttestationCap with the IDENTITY_KEY sentinel.
//!
//! AttestationAuthority is a kernel-managed cap passed to verify; its
//! scope determines which pubkeys mint_attest_cap may produce caps for.
//!
//! Each variant is a named struct so generic code can pass a variant by
//! reference. The `Capability` enum wraps them as a sum type.

use std::sync::Arc;

use crate::types::{CapId, Hash, KernelRole, KeyId, Signature, VaultId};

// -----------------------------------------------------------------------------
// Per-variant structs
// -----------------------------------------------------------------------------

/// Callable handle for `vault_initialize`; may also gate slot mutation
/// (Grant / Revoke) on the target Vault.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct VaultRefCap {
    pub vault_id: VaultId,
    pub rights: VaultRights,
}

/// EventEndpoint cap. Single shape replacing prior Transact / Dispatch /
/// Schedule cap variants. Lives in `σ.transact_endpoints` (on-chain) or
/// `σ.dispatch_endpoints` (off-chain). Position in σ determines firing
/// context. The Vault's manager handles both verify and process phases,
/// branching on `caller()` returning `Kernel(KernelRole::Verify)` or
/// `Kernel(KernelRole::Process)`.
///
/// Schedule slots are EventEndpointCaps that the kernel fires with no
/// body.events entry; identified by chain-author convention (typically
/// slot 0 of σ.transact_endpoints for block_init, last slot for
/// block_final, etc.).
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct EventEndpointCap {
    pub vault_id: VaultId,
    pub gas_budget: u64,
    pub memory_budget: u32,
}

/// Resource cap (e.g. allocate a Vault, set quota).
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ResourceCap(pub ResourceKind);

/// AttestationCap is the proof: existence means the kernel vouched that
/// `key` signed `blob_hash`. Minted only via `mint_attest_cap` inside
/// verify.
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
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct AttestationAggregateCap {
    pub key: KeyId,
}

/// AttestationAuthority cap: kernel-managed; passed to verify as a host
/// argument. Its scope determines which pubkeys mint_attest_cap may
/// produce caps for.
///
/// - Network-arrived event verify: scope is unlimited.
/// - emit_event from apply_block (transact / Schedule context): unlimited.
/// - emit_event from dispatch context: limited to seen-set of source
///   dispatch endpoint (kernel-tracked per (node, endpoint, cycle)).
///
/// The authority is held in a Frame slot during verify; reclaimed at
/// verify end.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct AttestationAuthorityCap {
    /// Authority scope. `None` = unlimited; `Some(set)` = restricted to
    /// the listed pubkeys.
    pub scope: AuthorityScope,
}

/// Scope of an AttestationAuthority cap.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum AuthorityScope {
    /// Unlimited: any pubkey may be minted for. Used for network event
    /// verify and apply_block-context emit verify.
    Unlimited,
    /// Restricted to the specified pubkeys. Used for dispatch-context
    /// emit verify.
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
// Capability sum type
// -----------------------------------------------------------------------------

/// All capability variants. Persistent variants live in σ.cap_registry
/// (and may be referenced by Vault.slots); ephemeral variants live only
/// in Frames.
///
/// Vault lifetime is tracked by reachability — a Vault is alive iff its
/// VaultId appears in `state.vaults` and at least one VaultRef in some
/// reachable Vault references it. There is no separate `Vault(owner)`
/// cap.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Capability {
    VaultRef(VaultRefCap),
    Code(CodeCap),
    Data(DataCap),
    /// Single endpoint cap shape replacing prior Transact/Dispatch/Schedule.
    EventEndpoint(EventEndpointCap),
    Resource(ResourceCap),
    Attestation(AttestationCap),
    AttestationAggregate(AttestationAggregateCap),
    /// Kernel-passed scope cap held in a Frame during verify.
    AttestationAuthority(AttestationAuthorityCap),
    /// Per-VM self-identity — pinned at MainFrame slot 2 (`SELF_SLOT`).
    SelfId(SelfCap),
    /// Per-frame caller (sub-CALL) — lives at ephemeral sub-slot 1.
    CallerVault(CallerVaultCap),
    /// Per-frame caller (kernel-initiated) — lives at ephemeral sub-slot 1.
    CallerKernel(CallerKernelCap),
}

impl Capability {
    pub fn vault_id(&self) -> Option<VaultId> {
        match self {
            Capability::VaultRef(c) => Some(c.vault_id),
            Capability::EventEndpoint(c) => Some(c.vault_id),
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
// CapRecord and CNode (cap-table)
// -----------------------------------------------------------------------------

/// One entry in the kernel's cap registry.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct CapRecord {
    pub cap: Capability,
    pub issuer: Option<CapId>,
    pub narrowing: Vec<u8>,
}

/// A 256-slot capability table. Used for both Vault slots and ephemeral Frames.
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
