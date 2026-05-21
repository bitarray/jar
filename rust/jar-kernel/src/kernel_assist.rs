//! σ-aware [`javm::KernelAssist`] implementation.
//!
//! After the javm-cap consolidation (Commits 1-3 of the cap-type
//! plan) the kernel assist holds only the ephemeral per-block kernel
//! state — gas meters, storage quotas, yield catchers, file_id ↔
//! cache-reference mapping. Cap content lives in σ's cache and is
//! looked up through there; this trait surface no longer reaches
//! into σ.
//!
//! `Vm::invoke_cached` resolves DataCap sizes before calling into
//! this trait, so `host_save` debits the actual logical byte size
//! while this type remains free of direct cache ownership.

use std::collections::HashMap;

use javm::{KernelAssist, MeterId, QuotaId};
use javm_cap::{Blake2b256, CapHash, CapHashOrRef, Hash};

/// σ-aware KernelAssist. Owns only ephemeral per-block kernel state.
pub struct SigmaKernelAssist {
    /// Per-block ephemeral: gas meters reset at block start.
    gas_meters: HashMap<MeterId, u64>,
    /// Per-block ephemeral: storage quotas reset at block start.
    storage_quotas: HashMap<QuotaId, u64>,
    /// Per-block ephemeral: yield catcher marker lists.
    yield_catchers: HashMap<CapHash, Vec<CapHash>>,
    /// Monotonic nonce for `yield_catcher_new`.
    next_yc_nonce: u64,
    /// file_id → cache reference. host_save mints fresh ids, host_open
    /// reads through this map.
    files: HashMap<u64, CapHashOrRef>,
    next_file_id: u64,
}

impl SigmaKernelAssist {
    pub fn new() -> Self {
        Self {
            gas_meters: HashMap::new(),
            storage_quotas: HashMap::new(),
            yield_catchers: HashMap::new(),
            next_yc_nonce: 0,
            files: HashMap::new(),
            next_file_id: 1,
        }
    }

    /// Reset per-block ephemeral tables. Called at the start of each
    /// block apply.
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

impl Default for SigmaKernelAssist {
    fn default() -> Self {
        Self::new()
    }
}

impl KernelAssist for SigmaKernelAssist {
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

    // ---- File registry ----
    fn host_open(&mut self, file_id: u64) -> Option<CapHashOrRef> {
        self.files.get(&file_id).copied()
    }

    fn host_save(&mut self, data: CapHashOrRef, quota_id: u64, size: u64) -> Option<u64> {
        let current = self.storage_quotas.get(&quota_id).copied().unwrap_or(0);
        if current < size {
            return None;
        }
        self.storage_quotas.insert(quota_id, current - size);
        let file_id = self.next_file_id;
        self.next_file_id += 1;
        self.files.insert(file_id, data);
        Some(file_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_save_debits_quota_and_allocates_file_id() {
        let mut ka = SigmaKernelAssist::new();
        ka.seed_root_quota(1000);
        let file_id = ka.host_save(CapHashOrRef::Hash([0u8; 32]), 0, 32).unwrap();
        assert_eq!(file_id, 1); // first allocation
        assert_eq!(ka.storage_quota_get(0), 968);
        assert_eq!(ka.host_open(file_id), Some(CapHashOrRef::Hash([0u8; 32])));
    }

    #[test]
    fn host_save_exhausted_quota_returns_none() {
        let mut ka = SigmaKernelAssist::new();
        // Quota 0 starts empty; any save should fail.
        assert!(ka.host_save(CapHashOrRef::Hash([0u8; 32]), 0, 1).is_none());
    }

    #[test]
    fn reset_block_state_clears_ephemeral_tables() {
        let mut ka = SigmaKernelAssist::new();
        ka.seed_root_gas(1000);
        ka.seed_root_quota(2000);
        ka.reset_block_state();
        assert_eq!(ka.gas_meter_get(0), 0);
        assert_eq!(ka.storage_quota_get(0), 0);
    }

    #[test]
    fn yield_catcher_round_trip() {
        let mut ka = SigmaKernelAssist::new();
        let yc = ka.yield_catcher_new();
        let marker = [0xAA; 32];
        ka.yield_catcher_add(yc, marker);
        assert_eq!(ka.yield_catcher_markers(yc), vec![marker]);
        ka.yield_catcher_remove(yc, marker);
        assert!(ka.yield_catcher_markers(yc).is_empty());
    }
}
