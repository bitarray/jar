//! `Kernel<H: Hardware>` — the kernel surface as a single struct.
//!
//! Wraps `H` (typically owned, possibly behind `Arc<Kernel<H>>` for shared
//! use) and exposes the four top-level kernel operations as methods:
//!
//! - `apply_block` — pure-function block-apply
//! - `handle_inbound_dispatch` — off-chain Dispatch step-2/step-3 driver
//! - `drain_for_body` — proposer's body assembly
//! - `state_root` — canonical state digest (kernel-static; kept as method
//!   for surface uniformity)
//! - `block_hash` — canonical block hash (kernel-static)
//!
//! State is **borrowed per call**, not owned by Kernel. This matches the
//! existing free-function pattern and lets a single Kernel serve many State
//! values (e.g., per fork). For cross-task sharing wrap `Arc<Kernel<H>>`,
//! not `Arc<H>` — the latter creates type-system grief (`Command<Arc<H>>`
//! ≠ `Command<H>`).

use jar_types::{Block, BlockHash, Body, Event, Hash, KResult, State, VaultId};

use crate::apply_block::{ApplyBlockOutcome, apply_block};
use crate::crypto;
use crate::dispatch::{InboundOutcome, handle_inbound_dispatch};
use crate::proposer::drain_for_body;
use crate::runtime::{Hardware, NodeOffchain};
use crate::state_root::state_root;

pub struct Kernel<H: Hardware> {
    hw: H,
}

impl<H: Hardware> Kernel<H> {
    /// Build a kernel that owns `hw`.
    pub fn new(hw: H) -> Self {
        Self { hw }
    }

    /// Borrow the underlying hardware. Use sparingly — most kernel
    /// behavior should go through the methods below.
    pub fn hardware(&self) -> &H {
        &self.hw
    }

    /// Apply a block. See [`apply_block::apply_block`] for semantics.
    pub fn apply_block(
        &self,
        state: &State,
        parent: BlockHash,
        block: &Block,
    ) -> KResult<ApplyBlockOutcome> {
        apply_block(state, parent, block, &self.hw)
    }

    /// Process one inbound Dispatch event. See
    /// [`dispatch::handle_inbound_dispatch`] for semantics.
    pub fn handle_inbound_dispatch(
        &self,
        node: &mut NodeOffchain,
        state: &State,
        entrypoint: VaultId,
        event: &Event,
    ) -> KResult<InboundOutcome> {
        handle_inbound_dispatch(node, state, entrypoint, event, &self.hw)
    }

    /// Drain off-chain slots into a proposer body.
    pub fn drain_for_body(&self, node: &NodeOffchain, state: &State) -> KResult<Body> {
        drain_for_body(node, state)
    }

    /// Canonical state root over σ. Kernel-static (no Hardware involvement).
    pub fn state_root(&self, state: &State) -> Hash {
        state_root(state)
    }

    /// Canonical hash of a block. Kernel-static; the chain's block-sealing
    /// AttestationCap reconstructs its sealing blob from this.
    pub fn block_hash(&self, block: &Block) -> Hash {
        crypto::block_hash(block)
    }
}
