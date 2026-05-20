//! σ-aware [`javm::KernelAssist`] implementation.
//!
//! Stage C.3 wires the production-side kernel-assist hooks against
//! the canonical σ store. Compared with `javm::InProcessKernelAssist`
//! (which holds everything in plain HashMaps), this impl:
//!
//! - Holds the per-block ephemeral GasMeter / StorageQuota /
//!   YieldCatcher tables in memory (NOT in σ — per design these
//!   reset every block).
//! - `host_open` / `host_save` route through σ.data_blobs for
//!   file-id ↔ cache reference mapping.
//!
//! After the javm-cap consolidation (Commit 2 of the cap-type plan)
//! the kernel assist no longer carries image_lookup / data_lookup /
//! data_store — those are cache operations now. The jar-kernel needs
//! a Commit 3 follow-up to migrate `apply_event` onto the cache-driven
//! `Vm::invoke_cached` path; until then the data_payloads ↔ cache
//! adapter helpers below preserve test scaffolding behaviour without
//! sitting on the trait surface.

use std::collections::HashMap;

use javm::{KernelAssist, MeterId, QuotaId};
use javm_cap::{Blake2b256, CapHash, CapHashOrRef, Hash};

use crate::state::{DataBlob, FileId, State};

/// σ-aware KernelAssist. Holds a `&mut State` borrow for the
/// duration of a block apply.
pub struct SigmaKernelAssist<'a> {
    pub state: &'a mut State,
    /// Per-block ephemeral: gas meters reset at block start.
    gas_meters: HashMap<MeterId, u64>,
    /// Per-block ephemeral: storage quotas reset at block start.
    storage_quotas: HashMap<QuotaId, u64>,
    /// Per-block ephemeral: yield catcher marker lists. Stage 4
    /// jar-kernel uses native dispatch (Stage C.4) for YieldCatcher
    /// endpoints; this map backs that dispatcher.
    yield_catchers: HashMap<CapHash, Vec<CapHash>>,
    /// Monotonic nonce for `yield_catcher_new`.
    next_yc_nonce: u64,
}

impl<'a> SigmaKernelAssist<'a> {
    pub fn new(state: &'a mut State) -> Self {
        Self {
            state,
            gas_meters: HashMap::new(),
            storage_quotas: HashMap::new(),
            yield_catchers: HashMap::new(),
            next_yc_nonce: 0,
        }
    }

    /// Reset per-block ephemeral tables. Called at the start of each
    /// block apply; preserves σ.
    pub fn reset_block_state(&mut self) {
        self.gas_meters.clear();
        self.storage_quotas.clear();
        self.yield_catchers.clear();
    }

    /// Seed the root gas meter (meter_id 0) with the chain's
    /// block-wide gas budget.
    pub fn seed_root_gas(&mut self, budget: u64) {
        self.gas_meters.insert(0, budget);
    }

    /// Seed the root storage quota (quota_id 0).
    pub fn seed_root_quota(&mut self, budget: u64) {
        self.storage_quotas.insert(0, budget);
    }

    /// Look up raw bytes by content hash. Inherent helper kept for
    /// pre-cache callers (apply_event payload registration); Commit 3
    /// will migrate this to the cache.
    pub fn data_lookup(&self, content_hash: CapHash) -> Option<Vec<u8>> {
        self.state.data_payloads.get(&content_hash).cloned()
    }

    /// Store raw bytes under their content hash. Inherent helper
    /// kept for pre-cache callers.
    pub fn data_store(&mut self, bytes: &[u8]) -> CapHash {
        let hash = Blake2b256::hash(bytes);
        self.state
            .data_payloads
            .entry(hash)
            .or_insert_with(|| bytes.to_vec());
        hash
    }
}

impl<'a> KernelAssist for SigmaKernelAssist<'a> {
    // ---- Gas ----
    fn gas_meter_get(&self, meter_id: MeterId) -> u64 {
        self.gas_meters.get(&meter_id).copied().unwrap_or(0)
    }
    fn gas_meter_set(&mut self, meter_id: MeterId, value: u64) -> u64 {
        self.gas_meters.insert(meter_id, value).unwrap_or(0)
    }

    // ---- Quota ----
    fn storage_quota_get(&self, quota_id: QuotaId) -> u64 {
        self.storage_quotas.get(&quota_id).copied().unwrap_or(0)
    }
    fn storage_quota_set(&mut self, quota_id: QuotaId, value: u64) -> u64 {
        self.storage_quotas.insert(quota_id, value).unwrap_or(0)
    }

    // ---- YieldCatcher ----
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
        let hash = Blake2b256::hash(&nonce.to_le_bytes());
        self.yield_catchers.insert(hash, Vec::new());
        hash
    }

    // ---- File registry (σ-backed) ----
    fn host_open(&mut self, file_id: u64) -> Option<CapHashOrRef> {
        let blob = self.state.data_blobs.get(&FileId::from(file_id))?;
        // Surface the file's content hash as a cache reference;
        // jar-kernel callers stitch together a Cap::Data behind this
        // hash via the cache (Commit 3 wires the publish step).
        Some(CapHashOrRef::Hash(blob.content_hash))
    }

    fn host_save(&mut self, data: CapHashOrRef, quota_id: u64) -> Option<u64> {
        // Commit 3 will rewrite host_save to consult the cache for
        // the data size + content hash. For now we accept only the
        // Hash-form reference, debit a placeholder 1-byte charge,
        // and register the file_id → content_hash mapping.
        let content_hash = match data {
            CapHashOrRef::Hash(h) => h,
            CapHashOrRef::Ref(_) => return None,
        };

        let current = self.storage_quotas.get(&quota_id).copied().unwrap_or(0);
        if current < 1 {
            return None;
        }
        self.storage_quotas.insert(quota_id, current - 1);

        let file_id = self.state.counters.allocate_file_id();
        self.state.data_blobs.insert(
            file_id,
            DataBlob {
                content_hash,
                // Commit 3: read size from the cache. V1: zero.
                size: 0,
                refcount: 1,
                backing_quota: quota_id,
            },
        );
        Some(file_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_open_returns_data_cap_for_registered_file() {
        let mut state = State::new();
        // Seed σ with a file at file_id 1.
        state.data_payloads.insert([0x55; 32], b"hello".to_vec());
        state.data_blobs.insert(
            1,
            DataBlob {
                content_hash: [0x55; 32],
                size: 5,
                refcount: 1,
                backing_quota: 0,
            },
        );
        state.counters.next_file_id = 2;
        let mut ka = SigmaKernelAssist::new(&mut state);
        let data = ka.host_open(1).expect("registered file should resolve");
        assert_eq!(data, CapHashOrRef::Hash([0x55; 32]));
    }

    #[test]
    fn host_save_debits_quota_and_allocates_file_id() {
        let mut state = State::new();
        let mut ka = SigmaKernelAssist::new(&mut state);
        ka.seed_root_quota(1000);
        let payload = b"hello world";
        let hash = ka.data_store(payload);
        let file_id = ka.host_save(CapHashOrRef::Hash(hash), 0).unwrap();
        assert_eq!(file_id, 0); // first allocation
        // Commit 3 will plumb the real data size; for now the stub
        // debits a placeholder 1 byte.
        assert_eq!(ka.storage_quota_get(0), 999);
        assert_eq!(
            ka.state.data_blobs.get(&file_id).unwrap().content_hash,
            hash
        );
    }

    #[test]
    fn host_save_exhausted_quota_returns_none() {
        let mut state = State::new();
        let mut ka = SigmaKernelAssist::new(&mut state);
        // Quota 0 starts empty; any save should fail.
        let payload = b"too much";
        let hash = ka.data_store(payload);
        assert!(ka.host_save(CapHashOrRef::Hash(hash), 0).is_none());
    }

    #[test]
    fn data_round_trip_via_store_then_lookup() {
        let mut state = State::new();
        let mut ka = SigmaKernelAssist::new(&mut state);
        let hash = ka.data_store(b"abc");
        assert_eq!(ka.data_lookup(hash), Some(b"abc".to_vec()));
    }

    #[test]
    fn reset_block_state_clears_ephemeral_tables() {
        let mut state = State::new();
        let mut ka = SigmaKernelAssist::new(&mut state);
        ka.seed_root_gas(1000);
        ka.seed_root_quota(2000);
        ka.reset_block_state();
        assert_eq!(ka.gas_meter_get(0), 0);
        assert_eq!(ka.storage_quota_get(0), 0);
    }
}
