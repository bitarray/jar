//! Kernel state (σ).
//!
//! σ contains: vaults, cnodes, cap_registry, references for the public
//! surfaces (transact_space_cnode, dispatch_space_cnode), and bookkeeping
//! (monotonic id counters).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::types::{CNode, CNodeId, CapId, CapRecord, KResult, KernelError, VaultId};

pub mod cap_registry;
pub mod cnode;
pub mod code_blobs;
pub mod state_root;

/// Persistent Vault unit. After the unified-persistence refactor, a
/// Vault is a 256-slot CNode plus quotas. All persistent state — code,
/// byte data, references to other Vaults — lives as caps in the CNode.
/// There is no separate `code_hash` field, no `code_vault`, and no KV
/// `storage` map.
///
/// Wrapped in `Arc` inside σ so that copy-on-write of the outer
/// `BTreeMap` is cheap; only the modified Vault is deep-cloned on a
/// `make_mut` write.
///
/// `quota_items` / `quota_bytes` will be unified into `quota_pages` in
/// Step 8; for now they remain as legacy bookkeeping that no operation
/// increments since the storage path is gone.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct Vault {
    pub slots: CNode, // 256 cap slots — the persistent CNode
    pub quota_items: u64,
    pub quota_bytes: u64,
    pub total_footprint: u64,
}

/// Slot in `Vault.slots` that holds the Vault's entry CodeCap.
/// Step 8 will replace this with a per-Vault `init_cap: u8` field.
pub const CODE_CAP_SLOT: u8 = 0;

impl Vault {
    pub fn new() -> Self {
        Self::default()
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
