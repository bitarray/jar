//! `KernelAssist` trait: the integration point for kernel-assisted
//! Instances (GasMeter, StorageQuota, YieldCatcher, plus the factory
//! caps that mint them).
//!
//! Per the v3 spec (README §22 "Kernel-assisted Instances"), certain
//! Cap::Instance values are recognized by their `image_hash_chain` as
//! kernel-internal. The kernel short-circuits their state access — no
//! bytecode dispatch, no endpoint walk. From userspace, those caps
//! still look like ordinary Cap::Instance values; the
//! special-cased path is invisible.
//!
//! For Stage 3, the integration crate doesn't own σ, so it can't
//! actually store kernel-internal state. Instead it asks an injected
//! `KernelAssist` impl for the state on every short-circuit. The
//! v3-jar-kernel that lands later will provide a σ-backed implementation;
//! v3 javm ships `InProcessKernelAssist` for tests and standalone use.

use core::fmt;
use std::collections::HashMap;
use std::sync::Arc;

use jar_cap::{Blake2b256, CapHash, DataCap, Hash, image::Image};

/// Identifier for a row in the kernel-internal GasMeter table.
/// Chain-chosen, not kernel-assigned (per spec §22).
pub type MeterId = u64;

/// Identifier for a row in the kernel-internal StorageQuota table.
pub type QuotaId = u64;

/// The integration point for kernel-assisted Instances.
///
/// Stage 3 wires the Vm to call these methods at:
/// - per-instruction gas debit (gas_meter_*),
/// - host_yield routing (yield_catcher_*),
/// - host_mint_data_cap quota debit (storage_quota_*),
/// - factory caps (SetGasMeter / SetStorageQuota / CreateYieldCatcher
///   endpoints — short-circuited via the kernel_image registry).
///
/// Methods on `&self` are reads; methods on `&mut self` are state
/// mutations. Atomic semantics where the spec requires it
/// (`*_set` returns the previous value).
pub trait KernelAssist {
    // ---- GasMeter (kernel:gasmeter) ----

    /// Read the remaining gas for `meter_id`. Missing entry → 0.
    fn gas_meter_get(&self, meter_id: MeterId) -> u64;

    /// Atomically `GasMeter[meter_id] := value`; return previous value
    /// (or 0 if no entry existed).
    fn gas_meter_set(&mut self, meter_id: MeterId, value: u64) -> u64;

    // ---- StorageQuota (kernel:storagequota) ----

    fn storage_quota_get(&self, quota_id: QuotaId) -> u64;
    fn storage_quota_set(&mut self, quota_id: QuotaId, value: u64) -> u64;

    // ---- YieldCatcher (kernel:yieldcatcher) ----

    /// Read the marker list for a YieldCatcher instance identified by
    /// `catcher_hash`. Order matters: routing walks the list and takes
    /// the first match.
    fn yield_catcher_markers(&self, catcher_hash: CapHash) -> Vec<CapHash>;

    /// Add a marker template to the catcher's list.
    fn yield_catcher_add(&mut self, catcher_hash: CapHash, marker_instance_hash: CapHash);

    /// Remove a marker template. No-op if absent.
    fn yield_catcher_remove(&mut self, catcher_hash: CapHash, marker_instance_hash: CapHash);

    /// Mint a fresh empty YieldCatcher. Returns its content hash
    /// (which the caller stores as a Cap::Instance[YieldCatcher]).
    fn yield_catcher_new(&mut self) -> CapHash;

    // ---- Image registry ----

    /// Look up the full `Image` value by its content hash.
    ///
    /// Used by `host_set_image` (Stage 3.9) to atomically reload the
    /// active Instance's program after an image swap. Default impl
    /// returns `None`, meaning the kernel-assist has no image
    /// registry; callers that need set_image (or set_image-style
    /// reloads) must override.
    ///
    /// Stage 4 jar-kernel-v3's σ-aware impl looks this up against
    /// `State.code_blobs`.
    fn image_lookup(&self, _content_hash: CapHash) -> Option<Arc<Image>> {
        None
    }

    // ---- Data blob registry ----

    /// Look up the raw bytes of a `Cap::Data` by its content hash.
    ///
    /// Used by:
    /// - `host_read_data_cap` (Stage 3.10) — read a Cap::Data's bytes
    ///   into mapped memory.
    /// - HALT-time mapped-region write-back — read prior content for
    ///   diff comparison (optimization; not used in the O(N) rehash
    ///   path).
    ///
    /// Default returns `None`. Stage 4 jar-kernel-v3 backs this with
    /// `State.data_blobs`.
    fn data_lookup(&self, _content_hash: CapHash) -> Option<Vec<u8>> {
        None
    }

    /// Store raw bytes; return the content hash for the resulting
    /// `Cap::Data`.
    ///
    /// Used by:
    /// - `host_mint_data_cap` (Stage 3.10) — mint a fresh Cap::Data
    ///   from memory bytes.
    /// - HALT-time mapped-region write-back — store re-hashed memory
    ///   for the new Cap::Data.
    ///
    /// Default no-ops (still returns a valid blake2b hash so call
    /// sites don't NPE; the bytes just aren't persisted). Stage 4
    /// jar-kernel-v3 inserts into `State.data_blobs`.
    fn data_store(&mut self, bytes: &[u8]) -> CapHash {
        Blake2b256::hash(bytes)
    }

    // ---- σ-resident File registry ----
    //
    // A v3 "FileCap" is a `Cap::Instance` with the well-known
    // `KernelImage::File` chain hash, whose `content_hash` carries
    // the `file_id` (low 8 bytes, little-endian — Stage 3 convention).
    // `host_open` materializes the file's bytes as an ephemeral
    // `Cap::Data`; `host_save` mints a fresh FileCap from a Cap::Data
    // after debiting StorageQuota.

    /// Materialize a σ-resident file as a `Cap::Data`. `None` if the
    /// file_id isn't registered. Stage 4 jar-kernel-v3 reads from
    /// `State.data_blobs` (refcount preserved).
    fn host_open(&mut self, _file_id: u64) -> Option<DataCap> {
        None
    }

    /// Mint a new file from `data` after debiting `quota_id`. Returns
    /// the new `file_id`. Stage 4 jar-kernel-v3 enforces the quota
    /// and writes σ. The Stage 3 default returns None.
    fn host_save(&mut self, _data: &DataCap, _quota_id: u64) -> Option<u64> {
        None
    }
}

/// In-process, in-memory `KernelAssist` impl. State lives in plain
/// `HashMap`s. Used by Stage 3's tests and as a runnable default
/// before `jar-kernel-v3` lands its σ-backed implementation.
///
/// Per spec §22, kernel-internal state is reset per block (the kernel
/// is stateless across blocks). This impl persists across `Vm`
/// invocations; the chain orchestrator that owns the `Vm` is
/// responsible for the block-boundary reset (see `reset_block_state`).
pub struct InProcessKernelAssist {
    gas_meters: HashMap<MeterId, u64>,
    storage_quotas: HashMap<QuotaId, u64>,
    yield_catchers: HashMap<CapHash, Vec<CapHash>>,
    /// Counter for fresh YieldCatcher hashes. Real impl would compute
    /// `Blake2b256::hash(epoch || nonce)` or similar; here we use a
    /// trivial monotonic counter (test-only).
    next_yc_nonce: u64,
    /// Image registry. Looked up by `image_lookup` to support
    /// `host_set_image`. Tests pre-register images that the running
    /// program will swap to.
    images: HashMap<CapHash, Arc<Image>>,
    /// Data blob registry (content_hash → bytes). `host_read_data_cap`
    /// resolves through this; `host_mint_data_cap` populates it.
    data_blobs: HashMap<CapHash, Vec<u8>>,
    /// σ-style file registry (file_id → DataCap). `host_open` reads
    /// through this; `host_save` mints monotonic file_ids.
    files: HashMap<u64, DataCap>,
    next_file_id: u64,
}

impl InProcessKernelAssist {
    pub fn new() -> Self {
        Self {
            gas_meters: HashMap::new(),
            storage_quotas: HashMap::new(),
            yield_catchers: HashMap::new(),
            next_yc_nonce: 0,
            images: HashMap::new(),
            data_blobs: HashMap::new(),
            files: HashMap::new(),
            next_file_id: 1,
        }
    }

    /// Reset all kernel-assisted state. The chain orchestrator calls
    /// this at block end per the v3 design (kernel is stateless across
    /// blocks).
    pub fn reset_block_state(&mut self) {
        self.gas_meters.clear();
        self.storage_quotas.clear();
        self.yield_catchers.clear();
        // Note: next_yc_nonce intentionally not reset — same-process
        // fresh catchers stay distinct even after block reset to
        // simplify test diagnostics.
    }

    /// Register an `Image` so `image_lookup` can resolve it. The key
    /// is the image's canonical content hash (`image_content_hash`).
    pub fn register_image(&mut self, content_hash: CapHash, image: Arc<Image>) {
        self.images.insert(content_hash, image);
    }

    /// Register raw data bytes under their hash; symmetric to
    /// `data_store`. Useful when seeding fixtures.
    pub fn register_data(&mut self, content_hash: CapHash, bytes: Vec<u8>) {
        self.data_blobs.insert(content_hash, bytes);
    }

    /// Register a FileId → DataCap mapping. `host_open` of the
    /// file_id returns the DataCap. Useful when seeding fixtures.
    pub fn register_file(&mut self, file_id: u64, data: DataCap) {
        self.files.insert(file_id, data);
        if file_id >= self.next_file_id {
            self.next_file_id = file_id + 1;
        }
    }
}

impl Default for InProcessKernelAssist {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for InProcessKernelAssist {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InProcessKernelAssist")
            .field("gas_meters", &self.gas_meters.len())
            .field("storage_quotas", &self.storage_quotas.len())
            .field("yield_catchers", &self.yield_catchers.len())
            .field("images", &self.images.len())
            .finish()
    }
}

impl KernelAssist for InProcessKernelAssist {
    fn gas_meter_get(&self, meter_id: MeterId) -> u64 {
        self.gas_meters.get(&meter_id).copied().unwrap_or(0)
    }

    fn gas_meter_set(&mut self, meter_id: MeterId, value: u64) -> u64 {
        self.gas_meters.insert(meter_id, value).unwrap_or(0)
    }

    fn storage_quota_get(&self, quota_id: QuotaId) -> u64 {
        self.storage_quotas.get(&quota_id).copied().unwrap_or(0)
    }

    fn storage_quota_set(&mut self, quota_id: QuotaId, value: u64) -> u64 {
        self.storage_quotas.insert(quota_id, value).unwrap_or(0)
    }

    fn yield_catcher_markers(&self, catcher_hash: CapHash) -> Vec<CapHash> {
        self.yield_catchers
            .get(&catcher_hash)
            .cloned()
            .unwrap_or_default()
    }

    fn yield_catcher_add(&mut self, catcher_hash: CapHash, marker_instance_hash: CapHash) {
        let entry = self.yield_catchers.entry(catcher_hash).or_default();
        if !entry.contains(&marker_instance_hash) {
            entry.push(marker_instance_hash);
        }
    }

    fn yield_catcher_remove(&mut self, catcher_hash: CapHash, marker_instance_hash: CapHash) {
        if let Some(entry) = self.yield_catchers.get_mut(&catcher_hash) {
            entry.retain(|m| *m != marker_instance_hash);
        }
    }

    fn yield_catcher_new(&mut self) -> CapHash {
        let nonce = self.next_yc_nonce;
        self.next_yc_nonce += 1;
        // Synthesize a fresh content hash by hashing the nonce; real
        // impl would derive from the chain context.
        let hash = Blake2b256::hash(&nonce.to_le_bytes());
        self.yield_catchers.insert(hash, Vec::new());
        hash
    }

    fn image_lookup(&self, content_hash: CapHash) -> Option<Arc<Image>> {
        self.images.get(&content_hash).cloned()
    }

    fn data_lookup(&self, content_hash: CapHash) -> Option<Vec<u8>> {
        self.data_blobs.get(&content_hash).cloned()
    }

    fn data_store(&mut self, bytes: &[u8]) -> CapHash {
        let hash = Blake2b256::hash(bytes);
        self.data_blobs.insert(hash, bytes.to_vec());
        hash
    }

    fn host_open(&mut self, file_id: u64) -> Option<DataCap> {
        self.files.get(&file_id).copied()
    }

    fn host_save(&mut self, data: &DataCap, quota_id: u64) -> Option<u64> {
        // Debit quota; return None if exhausted (caller traps).
        let q = self.storage_quotas.get(&quota_id).copied().unwrap_or(0);
        if q < data.size {
            return None;
        }
        self.storage_quotas.insert(quota_id, q - data.size);
        let id = self.next_file_id;
        self.next_file_id += 1;
        self.files.insert(id, *data);
        Some(id)
    }
}

// ---------------------------------------------------------------------
// Kernel image registry
// ---------------------------------------------------------------------

/// Identifies which kernel-assisted Image a given image_hash chain
/// refers to. Recognized by the registry's content-hash lookup.
///
/// The well-known image_hash values are placeholders for Stage 3 —
/// `Blake2b256::hash(b"kernel:name")`. Stage 4 jar-kernel-v3 will
/// finalize the canonical encoding when it actually constructs the
/// kernel-known `Image` values at chain genesis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KernelImage {
    GasMeter,
    StorageQuota,
    YieldCatcher,
    /// Per-Instance Gas{meter_id} unit handle. State: `meter_id: u64`.
    Gas,
    /// Per-Instance Quota{quota_id} unit handle.
    Quota,
    SetGasMeter,
    SetStorageQuota,
    MintGas,
    MintQuota,
    CreateYieldCatcher,
    OogMarker,
    StorageExhaustedMarker,
    /// Per-Instance File{file_id} handle: stable σ-resident reference
    /// produced by host_save / consumed by host_open. State:
    /// `file_id: u64`.
    File,
    /// Per-Instance HostOpen handle: kernel-issued cap that resolves
    /// to the `host_open` host call dispatch.
    HostOpen,
    /// Per-Instance HostSave handle: symmetric counterpart.
    HostSave,
}

/// Compute the placeholder image_hash for a kernel-assisted Image.
/// Stage 4 will replace these with the real chain-genesis-derived
/// hashes; for now they're stable strings hashed via Blake2b256 so the
/// Vm has a concrete value to match against.
const fn const_kernel_image_label(kind: KernelImage) -> &'static [u8] {
    match kind {
        KernelImage::GasMeter => b"kernel:gasmeter",
        KernelImage::StorageQuota => b"kernel:storagequota",
        KernelImage::YieldCatcher => b"kernel:yieldcatcher",
        KernelImage::Gas => b"kernel:gas",
        KernelImage::Quota => b"kernel:quota",
        KernelImage::SetGasMeter => b"kernel:set_gas_meter",
        KernelImage::SetStorageQuota => b"kernel:set_storage_quota",
        KernelImage::MintGas => b"kernel:mint_gas",
        KernelImage::MintQuota => b"kernel:mint_quota",
        KernelImage::CreateYieldCatcher => b"kernel:create_yield_catcher",
        KernelImage::OogMarker => b"kernel:oog_marker",
        KernelImage::StorageExhaustedMarker => b"kernel:storage_exhausted_marker",
        KernelImage::File => b"kernel:file",
        KernelImage::HostOpen => b"kernel:host_open",
        KernelImage::HostSave => b"kernel:host_save",
    }
}

/// Compute the well-known image_hash for a kernel-assisted Image.
pub fn kernel_image_hash(kind: KernelImage) -> CapHash {
    Blake2b256::hash(const_kernel_image_label(kind))
}

/// Look up a known kernel-assisted Image by its image_hash chain.
/// Returns `None` for a hash that doesn't match any kernel-known
/// Image (the common case — user Images are not kernel-assisted).
pub fn recognize_kernel_image(hash: CapHash) -> Option<KernelImage> {
    // Linear scan is fine: the registry has ~15 entries, lookup is
    // not on the hot path (only at Instance-entry / yield-route).
    [
        KernelImage::GasMeter,
        KernelImage::StorageQuota,
        KernelImage::YieldCatcher,
        KernelImage::Gas,
        KernelImage::Quota,
        KernelImage::SetGasMeter,
        KernelImage::SetStorageQuota,
        KernelImage::MintGas,
        KernelImage::MintQuota,
        KernelImage::CreateYieldCatcher,
        KernelImage::OogMarker,
        KernelImage::StorageExhaustedMarker,
        KernelImage::File,
        KernelImage::HostOpen,
        KernelImage::HostSave,
    ]
    .into_iter()
    .find(|kind| kernel_image_hash(*kind) == hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gas_meter_get_missing_returns_zero() {
        let k = InProcessKernelAssist::new();
        assert_eq!(k.gas_meter_get(42), 0);
    }

    #[test]
    fn gas_meter_set_returns_previous() {
        let mut k = InProcessKernelAssist::new();
        assert_eq!(k.gas_meter_set(1, 100), 0);
        assert_eq!(k.gas_meter_set(1, 200), 100);
        assert_eq!(k.gas_meter_get(1), 200);
    }

    #[test]
    fn storage_quota_round_trip() {
        let mut k = InProcessKernelAssist::new();
        assert_eq!(k.storage_quota_set(7, 1024), 0);
        assert_eq!(k.storage_quota_get(7), 1024);
        assert_eq!(k.storage_quota_set(7, 2048), 1024);
    }

    #[test]
    fn yield_catcher_add_and_read_markers() {
        let mut k = InProcessKernelAssist::new();
        let yc = k.yield_catcher_new();
        let m1 = [1u8; 32];
        let m2 = [2u8; 32];
        k.yield_catcher_add(yc, m1);
        k.yield_catcher_add(yc, m2);
        assert_eq!(k.yield_catcher_markers(yc), vec![m1, m2]);
    }

    #[test]
    fn yield_catcher_add_is_set_semantics() {
        let mut k = InProcessKernelAssist::new();
        let yc = k.yield_catcher_new();
        let m = [9u8; 32];
        k.yield_catcher_add(yc, m);
        k.yield_catcher_add(yc, m); // duplicate
        assert_eq!(k.yield_catcher_markers(yc).len(), 1);
    }

    #[test]
    fn yield_catcher_remove() {
        let mut k = InProcessKernelAssist::new();
        let yc = k.yield_catcher_new();
        let m = [3u8; 32];
        k.yield_catcher_add(yc, m);
        k.yield_catcher_remove(yc, m);
        assert!(k.yield_catcher_markers(yc).is_empty());
        // Removing absent is a no-op.
        k.yield_catcher_remove(yc, [9u8; 32]);
    }

    #[test]
    fn yield_catcher_new_returns_distinct_hashes() {
        let mut k = InProcessKernelAssist::new();
        let a = k.yield_catcher_new();
        let b = k.yield_catcher_new();
        assert_ne!(a, b);
    }

    #[test]
    fn reset_block_state_clears_meters_and_catchers() {
        let mut k = InProcessKernelAssist::new();
        k.gas_meter_set(1, 100);
        k.storage_quota_set(2, 200);
        let yc = k.yield_catcher_new();
        k.yield_catcher_add(yc, [4u8; 32]);

        k.reset_block_state();

        assert_eq!(k.gas_meter_get(1), 0);
        assert_eq!(k.storage_quota_get(2), 0);
        assert!(k.yield_catcher_markers(yc).is_empty());
    }

    #[test]
    fn kernel_image_hash_is_deterministic() {
        assert_eq!(
            kernel_image_hash(KernelImage::GasMeter),
            kernel_image_hash(KernelImage::GasMeter)
        );
    }

    #[test]
    fn kernel_images_have_distinct_hashes() {
        let all = [
            KernelImage::GasMeter,
            KernelImage::StorageQuota,
            KernelImage::YieldCatcher,
            KernelImage::Gas,
            KernelImage::Quota,
            KernelImage::SetGasMeter,
            KernelImage::SetStorageQuota,
            KernelImage::MintGas,
            KernelImage::MintQuota,
            KernelImage::CreateYieldCatcher,
            KernelImage::OogMarker,
            KernelImage::StorageExhaustedMarker,
            KernelImage::File,
            KernelImage::HostOpen,
            KernelImage::HostSave,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(
                    kernel_image_hash(*a),
                    kernel_image_hash(*b),
                    "{:?} vs {:?}",
                    a,
                    b
                );
            }
        }
    }

    #[test]
    fn recognize_known_image() {
        let h = kernel_image_hash(KernelImage::OogMarker);
        assert_eq!(recognize_kernel_image(h), Some(KernelImage::OogMarker));
    }

    #[test]
    fn recognize_unknown_image_is_none() {
        let h = Blake2b256::hash(b"user:my-cool-image");
        assert_eq!(recognize_kernel_image(h), None);
    }
}
