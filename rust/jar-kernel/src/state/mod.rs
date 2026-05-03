//! Kernel state (σ).
//!
//! σ contains: vaults (each with inline cap-bearing slots) plus flat
//! `Vec<EventEndpointCap>` lists for the public surfaces
//! (transact_endpoints, dispatch_endpoints).
//!
//! Caps live as values directly inside `vault.slots[N]: Option<RegCap>`
//! and inside the endpoint lists. No cap_registry, no CapId — pure
//! value-typed capability layer.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::cap::{CodeEntry, CodeId, FileEntry, FileId, Image, QuotaEntry, QuotaId};
use crate::types::{CNode, EventEndpointCap, ImageId, KResult, KernelError, KeyId, VaultId};

pub mod state_root;

/// A Vault is `{ image_id, slots }`:
///
/// - `image_id` references a program template in `state.images`. At
///   `vault.initialize`, the kernel resolves
///   `state.images[image_id]` and clones the Image's CapTable into a
///   fresh Frame. Multiple Vaults can share one Arc<Image> for
///   deduplication.
/// - `slots` is per-vault persistent storage — chain-author state.
///   Crucially, `slots` is NOT cloned into Frame at vault_init.
///   Guests reach it via the home VaultRef the kernel injects into
///   BareFrame, using the foreign-frame mechanism (MGMT_COPY in/out
///   through the VaultRef).
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct Vault {
    /// Reference into `state.images`. Used by `vault.initialize` to
    /// look up the program template.
    pub image_id: ImageId,
    /// Per-vault persistent storage. Foreign-frame from the active
    /// VM's perspective; never directly in MainFrame.
    pub slots: CNode,
}

impl Vault {
    pub fn new(image_id: ImageId) -> Self {
        Self {
            image_id,
            slots: CNode::default(),
        }
    }
}

/// Monotonic id counters maintained by the kernel directly.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct IdCounters {
    pub next_vault_id: u64,
    pub next_image_id: u64,
    /// FileIds are sequential — file content can change over a file's
    /// lifetime, so identity isn't tied to content (unlike CodeIds,
    /// which are content-hashed and need no counter).
    pub next_file_id: u64,
    pub next_quota_id: u64,
}

/// σ — the chain state.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct State {
    pub vaults: BTreeMap<VaultId, Arc<Vault>>,
    /// Image registry. Each Image is a program template referenced by
    /// `ImageId` from `RegCap::ImageRef` and (eventually) from
    /// `Vault.image_id`. Shared via `Arc` to deduplicate across vaults
    /// running the same program.
    pub images: BTreeMap<ImageId, Arc<Image>>,
    /// File-blob registry. Refcounted bulk-byte storage referenced by
    /// `RegCap::File`. Sequential id; each `allocate_file` mints a
    /// fresh entry (no auto-dedup — file content can change).
    pub data_blobs: BTreeMap<FileId, FileEntry>,
    /// Code-blob registry. Refcounted bulk-byte storage referenced by
    /// `RegCap::Code`. Hash-addressed via `CodeId` =
    /// `blake2b_256(blob)`; identical bytes share one entry.
    pub code_blobs: BTreeMap<CodeId, CodeEntry>,
    /// Storage-quota registry. Holds available bytes balances debited
    /// at file/code mint and refunded at refcount → 0. Referenced by
    /// `RegCap::StorageQuota`.
    pub storage_quotas: BTreeMap<QuotaId, QuotaEntry>,
    /// Inline EventEndpointCaps for on-chain endpoints (apply_block).
    /// Slot order = apply_block execution order. Mix of event-receiving
    /// and Schedule (kernel-fired) endpoints.
    pub transact_endpoints: Vec<EventEndpointCap>,
    /// Inline EventEndpointCaps for off-chain endpoints (per-cycle).
    pub dispatch_endpoints: Vec<EventEndpointCap>,
    /// PoA validator schedule. Block at `chain_index` is proposed by
    /// `validators[chain_index % validators.len()]`. Empty for chains
    /// that don't enforce proposer attestation (legacy fixtures).
    pub validators: Vec<KeyId>,
    /// Number of accepted blocks so far. Used to round-robin pick the
    /// expected proposer; incremented in `apply_block` on accept.
    pub chain_index: u64,
    pub id_counters: IdCounters,
}

impl State {
    /// Empty σ. Used as the starting point for genesis builders. Has no
    /// public-surface caps wired — the genesis builder must populate
    /// transact_endpoints and dispatch_endpoints.
    pub fn empty() -> Self {
        State {
            vaults: BTreeMap::new(),
            images: BTreeMap::new(),
            data_blobs: BTreeMap::new(),
            code_blobs: BTreeMap::new(),
            storage_quotas: BTreeMap::new(),
            transact_endpoints: Vec::new(),
            dispatch_endpoints: Vec::new(),
            validators: Vec::new(),
            chain_index: 0,
            id_counters: IdCounters::default(),
        }
    }

    /// Allocate the next monotonic ImageId.
    pub fn next_image_id(&mut self) -> ImageId {
        let id = self.id_counters.next_image_id;
        self.id_counters.next_image_id += 1;
        ImageId(id)
    }

    /// Allocate the next monotonic QuotaId.
    pub fn next_quota_id(&mut self) -> QuotaId {
        let id = self.id_counters.next_quota_id;
        self.id_counters.next_quota_id += 1;
        QuotaId(id)
    }

    /// Allocate the next monotonic FileId.
    fn next_file_id(&mut self) -> FileId {
        let id = self.id_counters.next_file_id;
        self.id_counters.next_file_id += 1;
        FileId(id)
    }

    // -------------------------------------------------------------
    // Quota management
    // -------------------------------------------------------------

    /// Insert a new `QuotaEntry` with `bytes` available and refcount=0.
    /// Used at genesis to pre-fund quotas. After this, the genesis
    /// builder typically places a `RegCap::StorageQuota(QuotaCap{quota_id})`
    /// somewhere in σ, which bumps the refcount to 1.
    pub fn insert_storage_quota(&mut self, bytes: u64) -> QuotaId {
        let id = self.next_quota_id();
        self.storage_quotas
            .insert(id, QuotaEntry { bytes, refcount: 0 });
        id
    }

    /// Bump refcount on a quota entry. Called whenever a `QuotaCap`
    /// referencing this id is materialised in σ or in Frame.
    pub fn bump_quota_refcount(&mut self, id: QuotaId) {
        if let Some(e) = self.storage_quotas.get_mut(&id) {
            e.refcount = e.refcount.saturating_add(1);
        }
    }

    /// Decrement refcount on a quota entry. Frees the entry at
    /// refcount → 0. The bytes balance, if any, is forfeit (a quota
    /// entry has no parent quota to refund to — it's a root).
    pub fn drop_quota_refcount(&mut self, id: QuotaId) {
        let remove = match self.storage_quotas.get_mut(&id) {
            Some(e) => {
                e.refcount = e.refcount.saturating_sub(1);
                e.refcount == 0
            }
            None => false,
        };
        if remove {
            self.storage_quotas.remove(&id);
        }
    }

    /// Try to debit `bytes` from `id`. Returns `true` on success,
    /// `false` if the entry doesn't exist or has insufficient balance.
    pub fn debit_quota(&mut self, id: QuotaId, bytes: u64) -> bool {
        match self.storage_quotas.get_mut(&id) {
            Some(e) if e.bytes >= bytes => {
                e.bytes -= bytes;
                true
            }
            _ => false,
        }
    }

    /// Credit `bytes` back to `id`. Silently no-op if the entry has
    /// been freed (the originating quota is gone — refund vanishes).
    pub fn credit_quota(&mut self, id: QuotaId, bytes: u64) {
        if let Some(e) = self.storage_quotas.get_mut(&id) {
            e.bytes = e.bytes.saturating_add(bytes);
        }
    }

    // -------------------------------------------------------------
    // File-blob management (sequential id, no dedup)
    // -------------------------------------------------------------

    /// Mint a fresh `FileId` and store `content` in `state.data_blobs`.
    /// Debits `content.len()` bytes from `quota_id`. Returns `None` if
    /// the quota doesn't exist or has insufficient balance.
    ///
    /// The returned id is unique across the lifetime of the chain;
    /// FileIds are never reused. Refcount starts at 1 (the caller is
    /// expected to install the resulting cap somewhere — that
    /// installation is the first reference).
    pub fn allocate_file(
        &mut self,
        content: Vec<u8>,
        page_count: u32,
        quota_id: QuotaId,
    ) -> Option<FileId> {
        let bytes = content.len() as u64;
        if !self.debit_quota(quota_id, bytes) {
            return None;
        }
        let id = self.next_file_id();
        self.data_blobs.insert(
            id,
            FileEntry {
                content: Arc::new(content),
                page_count,
                refcount: 1,
                origin_quota: quota_id,
            },
        );
        Some(id)
    }

    pub fn bump_file_refcount(&mut self, id: FileId) {
        if let Some(e) = self.data_blobs.get_mut(&id) {
            e.refcount = e.refcount.saturating_add(1);
        }
    }

    /// Decrement refcount; free the entry and refund bytes to its
    /// `origin_quota` at refcount → 0.
    pub fn drop_file_refcount(&mut self, id: FileId) {
        let entry = match self.data_blobs.get_mut(&id) {
            Some(e) => e,
            None => return,
        };
        entry.refcount = entry.refcount.saturating_sub(1);
        if entry.refcount == 0 {
            let origin = entry.origin_quota;
            let bytes = entry.content.len() as u64;
            self.data_blobs.remove(&id);
            self.credit_quota(origin, bytes);
        }
    }

    // -------------------------------------------------------------
    // Code-blob management (hash-addressed, dedup)
    // -------------------------------------------------------------

    /// Hash `blob` into a `CodeId`; insert into `state.code_blobs` if
    /// new (debiting `quota_id` for `blob.len()` bytes), or bump the
    /// refcount of the existing entry if the hash already exists.
    /// Returns `None` if a new entry is needed and the quota has
    /// insufficient balance.
    pub fn intern_code(&mut self, blob: Vec<u8>, quota_id: QuotaId) -> Option<CodeId> {
        let id = CodeId(crate::crypto::hash(&blob).0);
        if let Some(e) = self.code_blobs.get_mut(&id) {
            e.refcount = e.refcount.saturating_add(1);
            return Some(id);
        }
        let bytes = blob.len() as u64;
        if !self.debit_quota(quota_id, bytes) {
            return None;
        }
        self.code_blobs.insert(
            id,
            CodeEntry {
                blob: Arc::new(blob),
                refcount: 1,
                origin_quota: quota_id,
            },
        );
        Some(id)
    }

    pub fn bump_code_refcount(&mut self, id: CodeId) {
        if let Some(e) = self.code_blobs.get_mut(&id) {
            e.refcount = e.refcount.saturating_add(1);
        }
    }

    /// Decrement refcount; free the entry and refund bytes to its
    /// `origin_quota` at refcount → 0.
    pub fn drop_code_refcount(&mut self, id: CodeId) {
        let entry = match self.code_blobs.get_mut(&id) {
            Some(e) => e,
            None => return,
        };
        entry.refcount = entry.refcount.saturating_sub(1);
        if entry.refcount == 0 {
            let origin = entry.origin_quota;
            let bytes = entry.blob.len() as u64;
            self.code_blobs.remove(&id);
            self.credit_quota(origin, bytes);
        }
    }

    /// Return the expected proposer KeyId for the *next* block (the one
    /// being built or verified now). `None` if no validators are
    /// registered.
    pub fn expected_proposer(&self) -> Option<KeyId> {
        if self.validators.is_empty() {
            None
        } else {
            Some(self.validators[(self.chain_index as usize) % self.validators.len()].clone())
        }
    }

    pub fn vault(&self, id: VaultId) -> KResult<&Arc<Vault>> {
        self.vaults.get(&id).ok_or(KernelError::VaultNotFound(id))
    }

    /// Allocate the next monotonic VaultId.
    pub fn next_vault_id(&mut self) -> VaultId {
        let id = self.id_counters.next_vault_id;
        self.id_counters.next_vault_id += 1;
        VaultId(id)
    }
}
