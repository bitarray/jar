//! Runtime layer — `Hardware` trait + per-node off-chain state.
//!
//! The kernel core is a pure function over σ. The runtime supplies the
//! per-node concerns: signing keys, network outbox, off-chain aggregation
//! slots, javm code cache.

pub mod hardware;
pub mod in_memory;

use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;

use jar_types::{Crypto, SlotContent, VaultId};

pub use hardware::{Hardware, HwError, TracingEvent};
pub use in_memory::{InMemoryBus, InMemoryHardware, NetMessage};

/// Per-node off-chain state, **not** in σ. Slots persist across blocks but
/// are lost on restart. Bootstrap is chain-defined; we start with all slots
/// `Empty`.
pub struct NodeOffchain<C: Crypto> {
    pub slots: BTreeMap<VaultId, SlotContent<C>>,
    pub subscriptions: BTreeSet<VaultId>,
    /// javm code-cache; reused across handle_inbound_dispatch arrivals.
    pub code_cache: javm::CodeCache,
    _phantom: PhantomData<fn() -> C>,
}

impl<C: Crypto> Default for NodeOffchain<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: Crypto> NodeOffchain<C> {
    pub fn new() -> Self {
        Self {
            slots: BTreeMap::new(),
            subscriptions: BTreeSet::new(),
            code_cache: javm::CodeCache::new(),
            _phantom: PhantomData,
        }
    }

    pub fn slot(&self, ep: VaultId) -> &SlotContent<C> {
        self.slots.get(&ep).unwrap_or(&SlotContent::Empty)
    }

    pub fn set_slot(&mut self, ep: VaultId, content: SlotContent<C>) {
        if matches!(content, SlotContent::Empty) {
            self.slots.remove(&ep);
        } else {
            self.slots.insert(ep, content);
        }
    }
}
