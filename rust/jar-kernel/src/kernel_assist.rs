//! σ-aware [`javm::KernelAssist`] implementation.
//!
//! Stage C.3 wires the production-side kernel-assist hooks against
//! the canonical σ store. Compared with `javm::InProcessKernelAssist`
//! (which holds everything in plain HashMaps), this impl:
//!
//! - Resolves `host_open` / `host_save` / `data_lookup` /
//!   `data_store` against `State` (`data_blobs` for per-file
//!   metadata, `data_payloads` for canonical byte payloads).
//! - Holds the per-block ephemeral GasMeter / StorageQuota /
//!   YieldCatcher tables in memory (NOT in σ — per design these
//!   reset every block).
//! - `image_lookup` returns `None` for now (set_image at runtime
//!   isn't exercised by the simple-chain demo). C.5 jar-kernel
//!   genesis registers the chain Image up-front via cnode slots
//!   rather than going through image_lookup.

use std::collections::HashMap;
use std::sync::Arc;

use javm::{KernelAssist, MeterId, QuotaId};
use javm_cap::{Blake2b256, CapHash, DataCap, Hash, image::Image};

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

    // ---- Image registry (not used by simple-chain demo) ----
    fn image_lookup(&self, _content_hash: CapHash) -> Option<Arc<Image>> {
        None
    }

    // ---- Data payloads (σ-backed) ----
    fn data_lookup(&self, content_hash: CapHash) -> Option<Vec<u8>> {
        self.state.data_payloads.get(&content_hash).cloned()
    }
    fn data_store(&mut self, bytes: &[u8]) -> CapHash {
        let hash = Blake2b256::hash(bytes);
        self.state
            .data_payloads
            .entry(hash)
            .or_insert_with(|| bytes.to_vec());
        hash
    }

    // ---- File registry (σ-backed) ----
    fn host_open(&mut self, file_id: u64) -> Option<DataCap> {
        let blob = self.state.data_blobs.get(&FileId::from(file_id))?;
        Some(DataCap {
            content_hash: blob.content_hash,
            size: blob.size,
        })
    }

    fn host_save(&mut self, data: &DataCap, quota_id: u64) -> Option<u64> {
        // 1. Debit storage quota.
        let current = self.storage_quotas.get(&quota_id).copied().unwrap_or(0);
        if current < data.size {
            return None;
        }
        self.storage_quotas.insert(quota_id, current - data.size);

        // 2. Allocate a fresh FileId.
        let file_id = self.state.counters.allocate_file_id();

        // 3. Insert into σ.data_blobs with refcount 1.
        self.state.data_blobs.insert(
            file_id,
            DataBlob {
                content_hash: data.content_hash,
                size: data.size,
                refcount: 1,
                backing_quota: quota_id,
            },
        );

        // Bytes are expected to already be in data_payloads (from a
        // prior data_store call inside host_mint_data_cap). If not,
        // the FileBlob references content that won't resolve via
        // data_lookup — caller bug.
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
        assert_eq!(data.content_hash, [0x55; 32]);
        assert_eq!(data.size, 5);
    }

    #[test]
    fn host_save_debits_quota_and_allocates_file_id() {
        let mut state = State::new();
        let mut ka = SigmaKernelAssist::new(&mut state);
        ka.seed_root_quota(1000);
        // Stage a Cap::Data (bytes already in σ via data_store).
        let payload = b"hello world";
        let hash = ka.data_store(payload);
        let data = DataCap {
            content_hash: hash,
            size: payload.len() as u64,
        };
        let file_id = ka.host_save(&data, 0).unwrap();
        assert_eq!(file_id, 0); // first allocation
        assert_eq!(ka.storage_quota_get(0), 1000 - payload.len() as u64);
        assert_eq!(
            ka.state.data_blobs.get(&file_id).unwrap().content_hash,
            hash
        );
    }

    #[test]
    fn host_save_exhausted_quota_returns_none() {
        let mut state = State::new();
        let mut ka = SigmaKernelAssist::new(&mut state);
        ka.seed_root_quota(3);
        let payload = b"too much";
        let hash = ka.data_store(payload);
        let data = DataCap {
            content_hash: hash,
            size: payload.len() as u64,
        };
        assert!(ka.host_save(&data, 0).is_none());
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
