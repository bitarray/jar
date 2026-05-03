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
//! - `Kernel::dispatch(target_path, blob)` — handle one inbound Dispatch
//!   event. Updates the in-memory dispatch list and emits any commands
//!   the verify-then-process pipeline produces.
//! - `Kernel::advance(block)` — produce a new block (`block = None`,
//!   draining the dispatch list into the body) or verify a received block
//!   (`block = Some(b)`). Updates `last_state` / `last_block_hash` and
//!   tells hardware to commit.
//!
//! Hardware ownership: the kernel **owns** `H` directly (no `Arc<H>`).
//! The runtime creates one `Kernel<H>` per node.

use crate::pool::CycleRoll;
use crate::types::{Block, BlockHash, Body, BodyEvent, Hash, KResult, KernelError, State, VaultId};

use crate::apply_block::{ApplyBlockOutcome, BlockOutcome, apply_block};
use crate::crypto;
use crate::dispatch::handle_inbound;
use crate::runtime::{Hardware, NodeOffchain};
use crate::state::state_root;

// =============================================================================
// Kernel-loop runtime types (Caller / Command / KernelRole)
// =============================================================================

/// Returned by the `caller()` host call. Discriminates between Vault-to-Vault
/// sub-CALLs and kernel-fired top-level invocations.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Caller {
    /// Sub-CALL from another Vault VM.
    Vault(VaultId),
    /// Top-level invocation by the kernel — userspace branches on the role
    /// to discriminate verify vs process.
    Kernel(KernelRole),
}

/// Where in apply_block / off-chain pipeline a top-level invocation runs.
///
/// Per the event-redesign: every event-receiving endpoint is fired in
/// two phases — `Verify` (fresh per event, ro-σ, may panic) and
/// `Process` (one Vault per cycle, persistent state, rw-σ for
/// transact endpoints / ro-σ for dispatch).
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum KernelRole {
    /// Per-event verify phase. Fresh `Vault.initialize` each. ro-σ.
    /// May panic. May call `mint_attest_cap` and `setScore`.
    Verify,
    /// Per-cycle process phase. One `Vault.initialize` per cycle.
    /// Persistent state across calls. rw-σ for transact endpoints,
    /// ro-σ for dispatch endpoints. Cannot fail logic-wise.
    Process,
}

/// Runtime-side commands the kernel emits during execution. The runtime
/// applies these to hardware after `apply_block` (or `handle_inbound`)
/// returns.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Command {
    /// Send a wire dispatch to peers.
    Emit {
        target_path: Vec<u8>,
        blob: Vec<u8>,
        attestation_traces: Vec<crate::cap::AttestationEntry>,
    },
    /// Inform hardware about the consensus score of a candidate block —
    /// fork-choice input. Hardware stores it keyed by `block_hash`.
    Score { block_hash: BlockHash, score: u64 },
    /// Inform hardware that a block is finalized — its non-finalized
    /// siblings can be pruned.
    Finalize { block_hash: BlockHash },
}

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

    /// Handle one inbound dispatch event. `target_path` resolves into
    /// `σ.dispatch_endpoints` (4-byte LE u32 v1 wire format); `blob` is
    /// the opaque payload the target's verify parses.
    pub fn dispatch(&mut self, target_path: &[u8], blob: &[u8]) -> KResult<()> {
        let cmds = handle_inbound(
            &self.last_state,
            &mut self.dispatches,
            target_path,
            blob,
            &[],
            &self.hw,
        )?;
        for cmd in cmds {
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
        // Cycle boundary: drain the just-completed cycle's winners and
        // lift collision-deferred entries into the next cycle's pool.
        // Verifiers run roll_cycle for the same reason — to keep their
        // local pool aligned even when the rolled winners are discarded.
        let roll = self.dispatches.pool.roll_cycle();

        let block_in = match block {
            None => {
                let body = assemble_body(&self.last_state, &roll)?;
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
        } = apply_block(
            &self.last_state,
            self.last_block_hash,
            &block_in,
            &mut self.dispatches.pool,
            &self.hw,
        )?;

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

    /// Walk σ.dispatch_endpoints and tell hardware to subscribe to every
    /// dispatch endpoint.
    fn subscribe_dispatch_entrypoints(&self) -> KResult<()> {
        for ep in &self.last_state.dispatch_endpoints {
            self.hw.subscribe(ep.vault_id);
        }
        Ok(())
    }
}

// =============================================================================
// Proposer-side body assembly
// =============================================================================

/// Assemble a `Body` from a rolled pool. Walks `σ.transact_endpoints`
/// in slot order; for each endpoint with rolled winners, emits one
/// `BodyEvent` per winner. `target_path` encodes the slot index as
/// 4-byte little-endian u32 (matches `apply_block::resolve_target_path`).
///
/// Schedule slots have no body events; their kernel-fed traces live in
/// `body.schedule_attestation_traces` and are populated by the kernel
/// at apply time (Stage D), not by the proposer.
fn assemble_body(state: &State, roll: &CycleRoll) -> KResult<Body> {
    let mut events: Vec<BodyEvent> = Vec::new();
    for slot_idx in 0..state.transact_endpoints.len() {
        if let Some(entries) = roll.winners.get(&slot_idx) {
            let path = (slot_idx as u32).to_le_bytes().to_vec();
            for entry in entries {
                events.push(BodyEvent {
                    target_path: path.clone(),
                    blob: entry.blob.clone(),
                    attestation_traces: entry.attestation_traces.clone(),
                });
            }
        }
    }
    Ok(Body {
        events,
        ..Body::default()
    })
}
