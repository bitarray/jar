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
pub mod vault_init;

/// Persistent Vault unit. After the unified-persistence refactor a Vault
/// is `{ slots, init_cap, quota_pages, total_pages }`. All persistent
/// state — code, byte data, references to other Vaults — lives as caps
/// in `slots`. There is no separate `code_hash` field, no `code_vault`,
/// and no KV `storage` map.
///
/// Wrapped in `Arc` inside σ so that copy-on-write of the outer
/// `BTreeMap` is cheap; only the modified Vault is deep-cloned on a
/// `make_mut` write.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct Vault {
    /// 256 cap slots — the persistent CNode.
    pub slots: CNode,
    /// Slot in `slots` whose CodeCap is the **initialize program**.
    /// `Vault.initialize` runs the CodeCap at this slot to bootstrap a
    /// fresh Frame; the init program decides what becomes the public
    /// Callable (returned via bare-Frame slot 4).
    pub init_cap: u8,
    /// Maximum total page footprint allowed for caps stored in `slots`.
    /// Counts pages of every CodeCap and DataCap reachable from `slots`.
    pub quota_pages: u64,
    /// Currently consumed page footprint. `total_pages ≤ quota_pages`.
    pub total_pages: u64,
}

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
