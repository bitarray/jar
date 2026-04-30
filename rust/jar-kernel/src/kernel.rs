//! `Kernel<H: Hardware>` — the kernel surface, owning everything a node
//! needs to advance the chain.
//!
//! ```text
//! struct Kernel<H> {
//!     hw: H,
//!     last_state: State,
//!     last_block_hash: BlockHash,
//!     dispatches: NodeOffchain,
//! }
//! ```
//!
//! The kernel is **single-fork** — `last_state` and `last_block_hash`
//! describe the tip the kernel will build on. Multi-fork support is a
//! runtime-level concern (spin up multiple `Kernel`s, point each at a
//! different `block_hash` via `Kernel::new`). Hardware persists state
//! keyed by block hash; the kernel asks for it at construction.
//!
//! Lifecycle:
//!
//! - `Kernel::new(block_hash, hw)` — load state from hardware (genesis if
//!   `block_hash` is `None`). Subscribe to all top-level Dispatch
//!   entrypoints discovered in σ.
//! - `Kernel::dispatch(entrypoint, event)` — handle one inbound Dispatch
//!   event. Updates the in-memory dispatch list and emits any commands
//!   the step-2/step-3 pipeline produces.
//! - `Kernel::advance(block)` — produce a new block (`block = None`,
//!   draining the dispatch list into the body) or verify a received block
//!   (`block = Some(b)`). Updates `last_state` / `last_block_hash` and
//!   tells hardware to commit.
//!
//! Hardware ownership: the kernel **owns** `H` directly (no `Arc<H>`).
//! The runtime creates one `Kernel<H>` per node.

use crate::types::{
    Block, BlockHash, Capability, Event, Hash, KResult, KernelError, State, VaultId,
};

use crate::apply_block::{ApplyBlockOutcome, BlockOutcome, apply_block};
use crate::crypto;
use crate::dispatch::handle_inbound_dispatch;
use crate::proposer::drain_for_body;
use crate::runtime::{Hardware, NodeOffchain};
use crate::state::cap_registry;
use crate::state::state_root;

pub struct Kernel<H: Hardware> {
    hw: H,
    last_state: State,
    last_block_hash: BlockHash,
    dispatches: NodeOffchain,
}

/// Outcome of a successful `Kernel::advance`. The new tip is now
/// `(block_hash, block, state)`; emitted commands have already been
/// pushed to hardware.
#[derive(Debug)]
pub struct AdvanceOutcome {
    pub block: Block,
    pub block_hash: BlockHash,
    pub state_root: Hash,
    pub block_outcome: BlockOutcome,
}

impl<H: Hardware> Kernel<H> {
    /// Build a kernel positioned at the chain tip described by
    /// `block_hash`. `None` means "start at genesis" — hardware supplies
    /// the genesis state and the parent hash is `BlockHash::ZERO`. `Some(h)`
    /// asks hardware for the state previously committed against `h`;
    /// errors if hardware doesn't have it.
    ///
    /// Subscribes to all top-level Dispatch entrypoints discovered in σ.
    pub fn new(block_hash: Option<BlockHash>, hw: H) -> KResult<Self> {
        let (last_state, last_block_hash) = match block_hash {
            None => (hw.genesis_state(), BlockHash::ZERO),
            Some(h) => match hw.state_at(&h) {
                Some(s) => (s, h),
                None => {
                    return Err(KernelError::Internal(format!(
                        "hardware has no state at block {:?}",
                        h
                    )));
                }
            },
        };
        let dispatches = NodeOffchain::new();
        let kernel = Self {
            hw,
            last_state,
            last_block_hash,
            dispatches,
        };
        kernel.subscribe_dispatch_entrypoints()?;
        Ok(kernel)
    }

    /// Borrow the underlying hardware. Use sparingly — most kernel
    /// behavior should go through methods.
    pub fn hardware(&self) -> &H {
        &self.hw
    }

    /// Read accessor for the current tip's state.
    pub fn state(&self) -> &State {
        &self.last_state
    }

    /// Read accessor for the current tip's block hash. `BlockHash::ZERO`
    /// at genesis (before the first `advance`).
    pub fn last_block_hash(&self) -> BlockHash {
        self.last_block_hash
    }

    /// Handle one inbound Dispatch event at `entrypoint`. Runs step-2 +
    /// step-3 against `last_state` (RO via `SnapshotStorage`), updates the
    /// kernel-local dispatch list, and emits any `Dispatch` /
    /// `BroadcastLite` commands the pipeline produces.
    pub fn dispatch(&mut self, entrypoint: VaultId, event: &Event) -> KResult<()> {
        let outcome = handle_inbound_dispatch(
            &mut self.dispatches,
            &self.last_state,
            entrypoint,
            event,
            &self.hw,
        )?;
        for cmd in outcome.commands {
            self.hw.emit(cmd);
        }
        Ok(())
    }

    /// Build or verify a block.
    ///
    /// - `block = None` (proposer mode): drain the in-memory dispatch list
    ///   into a body, run apply_block on it, return the constructed block.
    /// - `block = Some(b)` (verifier mode): apply `b` against `last_state`
    ///   with parent linkage to `last_block_hash`. Returns `b` unchanged
    ///   on success.
    ///
    /// On success, advances `last_state` / `last_block_hash` and tells
    /// hardware to commit the new state. Emits a `Score` command (placeholder
    /// score = 1) so hardware knows about the new block.
    pub fn advance(&mut self, block: Option<Block>) -> KResult<AdvanceOutcome> {
        let block_in = match block {
            None => {
                let body = drain_for_body(&self.dispatches, &self.last_state)?;
                Block {
                    parent: self.last_block_hash,
                    body,
                }
            }
            Some(b) => b,
        };

        let ApplyBlockOutcome {
            state_next,
            block,
            commands,
            block_outcome,
            state_root: new_root,
            merkle_traces: _,
        } = apply_block(&self.last_state, self.last_block_hash, &block_in, &self.hw)?;

        // Commands first (Dispatch / BroadcastLite from inside the body).
        for cmd in commands {
            self.hw.emit(cmd);
        }

        if matches!(block_outcome, BlockOutcome::Accepted) {
            let block_hash = crypto::block_hash(&block);
            self.hw.commit_state(block_hash, state_next.clone());
            self.hw.score(block_hash, 1);
            self.last_state = state_next;
            self.last_block_hash = block_hash;
            Ok(AdvanceOutcome {
                block,
                block_hash,
                state_root: new_root,
                block_outcome,
            })
        } else {
            // Block panicked — state stays at the old tip; nothing committed.
            let block_hash = crypto::block_hash(&block);
            Ok(AdvanceOutcome {
                block,
                block_hash,
                state_root: new_root,
                block_outcome,
            })
        }
    }

    /// Canonical state-root over the current tip's σ. Convenience accessor.
    pub fn state_root(&self) -> Hash {
        state_root::state_root(&self.last_state)
    }

    /// Canonical block hash. Convenience accessor for `crypto::block_hash`.
    pub fn block_hash(&self, block: &Block) -> Hash {
        crypto::block_hash(block)
    }

    /// Walk σ.dispatch_space_cnode and tell hardware to subscribe to every
    /// top-level Dispatch entrypoint's lite-stream.
    fn subscribe_dispatch_entrypoints(&self) -> KResult<()> {
        let cnode_id = match &cap_registry::lookup(
            &self.last_state,
            self.last_state.dispatch_space_cnode,
        )?
        .cap
        {
            Capability::CNode(c) => c.cnode_id,
            _ => {
                return Err(KernelError::Internal(
                    "dispatch_space_cnode is not a CNode cap".into(),
                ));
            }
        };
        let cn = self.last_state.cnode(cnode_id)?;
        for (_, cap_id) in cn.iter() {
            if let Capability::Dispatch(c) = cap_registry::lookup(&self.last_state, cap_id)?.cap {
                self.hw.subscribe(c.vault_id);
            }
        }
        Ok(())
    }
}
