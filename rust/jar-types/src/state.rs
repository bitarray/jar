//! Kernel state (σ).
//!
//! σ contains: vaults, cnodes, cap_registry, four cap-id references for the
//! public surfaces (transact_space, dispatch_space, block_validation,
//! block_finalization), and bookkeeping (slot, recent_headers, monotonic
//! id counters).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::{CNode, CNodeId, CapId, CapRecord, Crypto, KResult, KernelError, VaultId};

/// Persistent Vault unit. Contains code, slots, KV storage, quotas.
///
/// Wrapped in `Arc` inside σ so that a per-event snapshot can be cheap (the
/// outer `BTreeMap`s are cloned, but vault contents are only deep-cloned
/// on a `make_mut` write).
///
/// Manual trait impls so bounds are on `C::Hash` rather than on `C`.
pub struct Vault<C: Crypto> {
    pub code_hash: C::Hash,
    pub slots: CNode, // 256 cap slots
    pub storage: BTreeMap<Vec<u8>, Vec<u8>>,
    pub quota_items: u64,
    pub quota_bytes: u64,
    pub total_footprint: u64,
}

impl<C: Crypto> Clone for Vault<C> {
    fn clone(&self) -> Self {
        Self {
            code_hash: self.code_hash,
            slots: self.slots.clone(),
            storage: self.storage.clone(),
            quota_items: self.quota_items,
            quota_bytes: self.quota_bytes,
            total_footprint: self.total_footprint,
        }
    }
}

impl<C: Crypto> PartialEq for Vault<C> {
    fn eq(&self, other: &Self) -> bool {
        self.code_hash == other.code_hash
            && self.slots == other.slots
            && self.storage == other.storage
            && self.quota_items == other.quota_items
            && self.quota_bytes == other.quota_bytes
            && self.total_footprint == other.total_footprint
    }
}

impl<C: Crypto> Eq for Vault<C> {}

impl<C: Crypto> core::fmt::Debug for Vault<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Vault")
            .field("code_hash", &self.code_hash)
            .field("slots", &self.slots)
            .field("storage", &self.storage)
            .field("quota_items", &self.quota_items)
            .field("quota_bytes", &self.quota_bytes)
            .field("total_footprint", &self.total_footprint)
            .finish()
    }
}

impl<C: Crypto> Vault<C> {
    pub fn new(code_hash: C::Hash) -> Self {
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
pub struct State<C: Crypto> {
    pub vaults: BTreeMap<VaultId, Arc<Vault<C>>>,
    pub cnodes: BTreeMap<CNodeId, CNode>,
    pub cap_registry: BTreeMap<CapId, CapRecord<C>>,
    /// Inverse index: parent cap-id → children. Cascade revocation walks this.
    pub cap_children: BTreeMap<CapId, BTreeSet<CapId>>,
    /// Inverse index: cap-id → CNode slots that hold it. Used to clear slots
    /// on revocation.
    pub cap_holders: BTreeMap<CapId, BTreeSet<(CNodeId, u8)>>,
    pub transact_space_cnode: CapId,
    pub dispatch_space_cnode: CapId,
    pub id_counters: IdCounters,
}

impl<C: Crypto> Clone for State<C> {
    fn clone(&self) -> Self {
        Self {
            vaults: self.vaults.clone(),
            cnodes: self.cnodes.clone(),
            cap_registry: self.cap_registry.clone(),
            cap_children: self.cap_children.clone(),
            cap_holders: self.cap_holders.clone(),
            transact_space_cnode: self.transact_space_cnode,
            dispatch_space_cnode: self.dispatch_space_cnode,
            id_counters: self.id_counters.clone(),
        }
    }
}

impl<C: Crypto> PartialEq for State<C> {
    fn eq(&self, other: &Self) -> bool {
        self.vaults == other.vaults
            && self.cnodes == other.cnodes
            && self.cap_registry == other.cap_registry
            && self.cap_children == other.cap_children
            && self.cap_holders == other.cap_holders
            && self.transact_space_cnode == other.transact_space_cnode
            && self.dispatch_space_cnode == other.dispatch_space_cnode
            && self.id_counters == other.id_counters
    }
}

impl<C: Crypto> Eq for State<C> {}

impl<C: Crypto> core::fmt::Debug for State<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("State")
            .field("vaults", &self.vaults)
            .field("cnodes", &self.cnodes)
            .field("cap_registry", &self.cap_registry)
            .field("cap_children", &self.cap_children)
            .field("cap_holders", &self.cap_holders)
            .field("transact_space_cnode", &self.transact_space_cnode)
            .field("dispatch_space_cnode", &self.dispatch_space_cnode)
            .field("id_counters", &self.id_counters)
            .finish()
    }
}

impl<C: Crypto> State<C> {
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

    pub fn vault(&self, id: VaultId) -> KResult<&Arc<Vault<C>>> {
        self.vaults.get(&id).ok_or(KernelError::VaultNotFound(id))
    }

    pub fn cnode(&self, id: CNodeId) -> KResult<&CNode> {
        self.cnodes.get(&id).ok_or(KernelError::CNodeNotFound(id))
    }

    pub fn cap_record(&self, id: CapId) -> KResult<&CapRecord<C>> {
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
