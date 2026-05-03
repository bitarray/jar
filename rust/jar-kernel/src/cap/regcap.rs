//! Cap shapes for the kernel.
//!
//! Caps in σ (`RegCap`) are uniformly **references**: small fixed-size
//! triples that name a target object in one of σ's content registries
//! (`state.data_blobs`, `state.code_blobs`, `state.storage_quotas`,
//! `state.vaults`, `state.images`). Bulk content lives in the
//! registries, not in the cap.
//!
//! Per-cap variants:
//!
//! - `RegCap::VaultRef(VaultRefCap{vault_id, rights})` — reference into
//!   `state.vaults`.
//! - `RegCap::ImageRef(ImageRefCap{image_id, rights})` — reference into
//!   `state.images`.
//! - `RegCap::Code(CodeCap{code_id, byte_count})` — reference into
//!   `state.code_blobs`. Hash-addressed; identical bytes dedup.
//! - `RegCap::File(FileCap{file_id, byte_count})` — reference into
//!   `state.data_blobs`. Sequential `FileId`; file content is allowed
//!   to change over time (no auto-dedup).
//! - `RegCap::StorageQuota(QuotaCap{quota_id})` — reference into
//!   `state.storage_quotas`. Bytes balance lives in the entry; copying
//!   the cap doesn't multiply balance.
//! - `RegCap::Resource(ResourceCap)` — small value cap (governance
//!   handle).
//!
//! Cap copies share registry entries via refcounts. Granting a copy
//! bumps the refcount; dropping decrements; refcount → 0 frees the
//! entry and refunds bytes to the entry's `origin_quota` (for
//! File/Code).
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

/// Identity of an `Image` registered in `σ.images`. Allocated
/// monotonically by the kernel.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
pub struct ImageId(pub u64);

/// ImageRef rights — what the holder of an `ImageRefCap` may do
/// with the referenced Image. Mirrors `VaultRights` / `FrameRefRights`
/// in shape.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct ImageRefRights {
    /// CALL on the cap spawns a sub-VM by cloning the referenced
    /// Image into a fresh Frame.
    pub spawn: bool,
    /// Read the Image's slot metadata (cap kinds + page counts).
    pub introspect: bool,
    /// Derive a more narrowly-righted ImageRef pointing at the same
    /// Image.
    pub derive: bool,
}

impl ImageRefRights {
    pub const ALL: ImageRefRights = ImageRefRights {
        spawn: true,
        introspect: true,
        derive: true,
    };
    pub const SPAWN_ONLY: ImageRefRights = ImageRefRights {
        spawn: true,
        introspect: false,
        derive: false,
    };
}

/// Persistent reference to an Image in `σ.images`. CALL on this cap
/// spawns a sub-VM by cloning the referenced Image into a fresh
/// Frame (layer 2 of the call(Code)/call(Image)/call(Vault) stack).
/// Today the runtime spawn path is not wired — the σ shape is
/// established for v1; guest-callable spawn lands in a follow-up.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct ImageRefCap {
    pub image_id: ImageId,
    pub rights: ImageRefRights,
}

/// The program template — a snapshot of what a Frame's CapTable
/// should look like at vault_init. Lives in `σ.images`, identified by
/// `ImageId`, shared via `Arc` across vaults running the same
/// program.
///
/// Frame init clones this: walk `slots`, translate each `RegCap`
/// into a fresh ephemeral `Cap` in the new VM's CapTable.
/// `init_cap` names the slot whose `RegCap::Code` is the entry
/// program.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct Image {
    pub slots: CNode,
    pub init_cap: u8,
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

/// Identity of a code blob in `state.code_blobs`. Hash-addressed:
/// `CodeId(blake2b_256(blob_bytes))`. Identical bytes therefore share
/// one entry (auto-dedup) and one CodeId.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
pub struct CodeId(pub [u8; 32]);

/// Identity of a file blob in `state.data_blobs`. Monotonic u64 —
/// **not** content-hashed because file content is allowed to change
/// over a file's lifetime. A FileId names a specific file entry; two
/// files with identical content get distinct ids.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
pub struct FileId(pub u64);

/// Identity of a storage-quota entry in `state.storage_quotas`.
/// Monotonic u64.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
pub struct QuotaId(pub u64);

/// Persistent code capability. **Reference** into `state.code_blobs`.
/// The actual bytes live in the registry entry; this cap is just the
/// id + a cached byte_count.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct CodeCap {
    pub code_id: CodeId,
    pub byte_count: u64,
}

/// Persistent file capability ("disk file"). **Reference** into
/// `state.data_blobs`. The bytes live in the registry entry. Distinct
/// from javm's `Cap::Data` (ephemeral mapped pages); convert via
/// `host_open` (FileCap → DataCap, allocates ephemeral) and
/// `host_save` (DataCap → FileCap, mints fresh σ entry).
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct FileCap {
    pub file_id: FileId,
    pub byte_count: u64,
}

/// Persistent storage-quota capability. **Reference** into
/// `state.storage_quotas`. The bytes balance lives in the entry,
/// debited at object mint and refunded at refcount → 0. Copies of
/// this cap do not multiply balance — multiple references share one
/// entry, refcount-tracked.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct QuotaCap {
    pub quota_id: QuotaId,
}

/// Entry stored in `state.code_blobs[code_id]`. Refcount-tracked;
/// freed (and bytes refunded to `origin_quota`) at refcount → 0.
#[derive(Clone, Debug)]
pub struct CodeEntry {
    pub blob: Arc<Vec<u8>>,
    pub refcount: u32,
    /// QuotaEntry the bytes were debited from. Refund destination on
    /// free. If the origin quota has itself been freed by then, the
    /// refund is silently dropped.
    pub origin_quota: QuotaId,
}

impl PartialEq for CodeEntry {
    fn eq(&self, other: &Self) -> bool {
        self.refcount == other.refcount
            && self.origin_quota == other.origin_quota
            && (Arc::ptr_eq(&self.blob, &other.blob) || *self.blob == *other.blob)
    }
}

impl Eq for CodeEntry {}

/// Entry stored in `state.data_blobs[file_id]`. Refcount-tracked;
/// freed (and bytes refunded to `origin_quota`) at refcount → 0.
#[derive(Clone, Debug)]
pub struct FileEntry {
    pub content: Arc<Vec<u8>>,
    pub page_count: u32,
    pub refcount: u32,
    pub origin_quota: QuotaId,
}

impl PartialEq for FileEntry {
    fn eq(&self, other: &Self) -> bool {
        self.page_count == other.page_count
            && self.refcount == other.refcount
            && self.origin_quota == other.origin_quota
            && (Arc::ptr_eq(&self.content, &other.content) || *self.content == *other.content)
    }
}

impl Eq for FileEntry {}

/// Entry stored in `state.storage_quotas[quota_id]`. Holds the
/// available bytes balance and a refcount of `QuotaCap` references.
/// Quota entries themselves are not free — they're created at genesis
/// or via a future `mint_quota` op and live until refcount → 0.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct QuotaEntry {
    pub bytes: u64,
    pub refcount: u32,
}

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

/// Cap kinds eligible for placement in `vault.slots`. Each variant is
/// a small **reference** triple (id + small metadata). Bulk content
/// lives in `state.{data_blobs,code_blobs,storage_quotas,vaults,images}`.
/// Copies share registry entries via refcount.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum RegCap {
    VaultRef(VaultRefCap),
    Code(CodeCap),
    File(FileCap),
    ImageRef(ImageRefCap),
    Resource(ResourceCap),
    StorageQuota(QuotaCap),
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
