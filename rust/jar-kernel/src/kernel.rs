//! `Kernel<H: Hardware>` — the kernel surface as a single struct.
//!
//! Wraps `H` (typically owned, possibly `Arc<H>` for shared use) and exposes
//! the four top-level kernel operations as methods:
//!
//! - `apply_block` — pure-function block-apply
//! - `handle_inbound_dispatch` — off-chain Dispatch step-2/step-3 driver
//! - `drain_for_body` — proposer's body assembly
//! - `state_root` — canonical state digest
//!
//! State is **borrowed per call**, not owned by Kernel. This matches the
//! existing free-function pattern, lets a binary keep one Kernel and many
//! State values (e.g., per fork), and avoids forcing State behind a `Mutex`
//! inside Kernel. `Kernel<H>` is cheap to share via `Arc<Kernel<H>>` when
//! cross-task sharing is needed.

use jar_types::{Block, BlockHash, Body, Event, KResult, State, VaultId};

use crate::apply_block::{ApplyBlockOutcome, apply_block};
use crate::dispatch::{InboundOutcome, handle_inbound_dispatch};
use crate::proposer::drain_for_body;
use crate::runtime::{Hardware, NodeOffchain};
use crate::state_root::state_root;

pub struct Kernel<H: Hardware> {
    hw: H,
}

impl<H: Hardware> Kernel<H> {
    /// Build a kernel that owns `hw`. `H` is typically `InMemoryHardware`
    /// for tests / in-process testnet; production builds plug their own
    /// `Hardware` impl. Wrap the returned Kernel in `Arc` for cross-task
    /// sharing.
    pub fn new(hw: H) -> Self {
        Self { hw }
    }

    /// Borrow the underlying hardware. Use sparingly — most kernel
    /// behavior should go through the methods below; this exists for
    /// runtime-side concerns (e.g., draining the tracing log).
    pub fn hardware(&self) -> &H {
        &self.hw
    }

    /// Apply a block. See [`apply_block::apply_block`] for semantics.
    pub fn apply_block(
        &self,
        state: &State<H>,
        parent: BlockHash<H>,
        block: &Block<H>,
    ) -> KResult<ApplyBlockOutcome<H>> {
        apply_block(state, parent, block, &self.hw)
    }

    /// Process one inbound Dispatch event. See
    /// [`dispatch::handle_inbound_dispatch`] for semantics.
    pub fn handle_inbound_dispatch(
        &self,
        node: &mut NodeOffchain<H>,
        state: &State<H>,
        entrypoint: VaultId,
        event: &Event<H>,
    ) -> KResult<InboundOutcome<H>> {
        handle_inbound_dispatch(node, state, entrypoint, event, &self.hw)
    }

    /// Drain off-chain slots into a proposer body. See
    /// [`proposer::drain_for_body`] for semantics.
    pub fn drain_for_body(&self, node: &NodeOffchain<H>, state: &State<H>) -> KResult<Body<H>> {
        drain_for_body(node, state)
    }

    /// Canonical state root over σ. Routes hashing through `self.hw.hash`.
    pub fn state_root(&self, state: &State<H>) -> H::Hash {
        state_root(state, &self.hw)
    }
}
