//! Kernel state (σ).
//!
//! σ contains: vaults, cnodes, cap_registry, flat lists for the public
//! surfaces (transact_endpoints, dispatch_endpoints), and bookkeeping
//! (monotonic id counters).
//!
//! Per the event-redesign: the prior `transact_space_cnode` /
//! `dispatch_space_cnode` (CNode CapIds) are replaced with flat
//! `Vec<CapId>` lists. Each entry is an EventEndpointCap.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::types::{CNode, CapId, CapRecord, KResult, KernelError, VaultId};

pub mod cap_registry;
pub mod code_blobs;
pub mod state_root;
pub mod vault_init;

/// Persistent Vault unit. After the unified-persistence refactor a Vault
/// is `{ slots, init_cap }`. All persistent state — code, byte data,
/// references to other Vaults — lives as caps in `slots`. There is no
/// separate `code_hash` field, no `code_vault`, and no KV `storage` map.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct Vault {
    /// 256 cap slots — the persistent CNode.
    pub slots: CNode,
    /// Slot in `slots` whose CodeCap is the **initialize program**.
    pub init_cap: u8,
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
    pub next_cap_id: u64,
}

/// σ — the chain state.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct State {
    pub vaults: BTreeMap<VaultId, Arc<Vault>>,
    pub cap_registry: BTreeMap<CapId, CapRecord>,
    /// Inverse index: parent cap-id → children. Cascade revocation walks this.
    pub cap_children: BTreeMap<CapId, BTreeSet<CapId>>,
    /// Flat list of EventEndpointCaps for on-chain endpoints (apply_block).
    /// Slot order = apply_block execution order. Mix of event-receiving
    /// and Schedule (kernel-fired) endpoints.
    pub transact_endpoints: Vec<CapId>,
    /// Flat list of EventEndpointCaps for off-chain endpoints (per-cycle).
    pub dispatch_endpoints: Vec<CapId>,
    pub id_counters: IdCounters,
}

impl State {
    /// Empty σ. Used as the starting point for genesis builders. Has no
    /// public-surface caps wired — the genesis builder must populate
    /// transact_endpoints and dispatch_endpoints.
    pub fn empty() -> Self {
        State {
            vaults: BTreeMap::new(),
            cap_registry: BTreeMap::new(),
            cap_children: BTreeMap::new(),
            transact_endpoints: Vec::new(),
            dispatch_endpoints: Vec::new(),
            id_counters: IdCounters::default(),
        }
    }

    pub fn vault(&self, id: VaultId) -> KResult<&Arc<Vault>> {
        self.vaults.get(&id).ok_or(KernelError::VaultNotFound(id))
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

    /// Allocate the next monotonic CapId.
    pub fn next_cap_id(&mut self) -> CapId {
        let id = self.id_counters.next_cap_id;
        self.id_counters.next_cap_id += 1;
        CapId(id)
    }
}
