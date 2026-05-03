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

use crate::cap::Image;
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
