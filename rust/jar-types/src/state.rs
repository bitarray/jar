//! Kernel state (σ).
//!
//! σ contains: vaults, cnodes, cap_registry, four cap-id references for the
//! public surfaces (transact_space, dispatch_space, block_validation,
//! block_finalization), and bookkeeping (slot, recent_headers, monotonic
//! id counters).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::{CNode, CNodeId, CapId, CapRecord, Hash, KResult, KernelError, VaultId};

/// Persistent Vault unit. Contains code, slots, KV storage, quotas.
///
/// Wrapped in `Arc` inside σ so that a per-event snapshot can be cheap (the
/// outer `BTreeMap`s are cloned, but vault contents are only deep-cloned
/// on a `make_mut` write).
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Vault {
    pub code_hash: Hash,
    pub slots: CNode, // 256 cap slots
    pub storage: BTreeMap<Vec<u8>, Vec<u8>>,
    pub quota_items: u64,
    pub quota_bytes: u64,
    pub total_footprint: u64,
}

impl Vault {
    pub fn new(code_hash: Hash) -> Self {
        Vault {
            code_hash,
            slots: CNode::new(),
            storage: BTreeMap::new(),
            quota_items: 0,
            quota_bytes: 0,
            total_footprint: 0,
        }
    }

    /// Recompute footprint as the sum of (key_len + value_len) over all
    /// storage entries.
    pub fn recompute_footprint(&mut self) {
        self.total_footprint = self
            .storage
            .iter()
            .map(|(k, v)| (k.len() + v.len()) as u64)
            .sum();
    }
}

/// Monotonic id counters maintained by the kernel directly. Slot,
/// recent_headers, and any other chain-progression bookkeeping live in a
/// chain-author ChainHead Vault, not in σ.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct IdCounters {
    pub next_vault_id: u64,
    pub next_cnode_id: u64,
    pub next_cap_id: u64,
}

/// σ — the chain state.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct State {
    pub vaults: BTreeMap<VaultId, Arc<Vault>>,
    pub cnodes: BTreeMap<CNodeId, CNode>,
    pub cap_registry: BTreeMap<CapId, CapRecord>,
    /// Inverse index: parent cap-id → children. Cascade revocation walks this.
    pub cap_children: BTreeMap<CapId, BTreeSet<CapId>>,
    /// Inverse index: cap-id → CNode slots that hold it. Used to clear slots
    /// on revocation.
    pub cap_holders: BTreeMap<CapId, BTreeSet<(CNodeId, u8)>>,
    pub transact_space_cnode: CapId,
    pub dispatch_space_cnode: CapId,
    pub id_counters: IdCounters,
}

impl State {
    /// Empty σ. Used as the starting point for genesis builders. Has no
    /// public-surface caps wired — the genesis builder must set them.
    pub fn empty() -> Self {
        State {
            vaults: BTreeMap::new(),
            cnodes: BTreeMap::new(),
            cap_registry: BTreeMap::new(),
            cap_children: BTreeMap::new(),
            cap_holders: BTreeMap::new(),
            transact_space_cnode: CapId(0),
            dispatch_space_cnode: CapId(0),
            id_counters: IdCounters::default(),
        }
    }

    pub fn vault(&self, id: VaultId) -> KResult<&Arc<Vault>> {
        self.vaults.get(&id).ok_or(KernelError::VaultNotFound(id))
    }

    pub fn cnode(&self, id: CNodeId) -> KResult<&CNode> {
        self.cnodes.get(&id).ok_or(KernelError::CNodeNotFound(id))
    }

    pub fn cap_record(&self, id: CapId) -> KResult<&CapRecord> {
        self.cap_registry
            .get(&id)
            .ok_or(KernelError::CapNotFound(id))
    }

    /// Allocate the next monotonic VaultId.
    pub fn next_vault_id(&mut self) -> VaultId {
        let id = self.id_counters.next_vault_id;
        self.id_counters.next_vault_id += 1;
        VaultId(id)
    }

    /// Allocate the next monotonic CNodeId.
    pub fn next_cnode_id(&mut self) -> CNodeId {
        let id = self.id_counters.next_cnode_id;
        self.id_counters.next_cnode_id += 1;
        CNodeId(id)
    }

    /// Allocate the next monotonic CapId.
    pub fn next_cap_id(&mut self) -> CapId {
        let id = self.id_counters.next_cap_id;
        self.id_counters.next_cap_id += 1;
        CapId(id)
    }
}
