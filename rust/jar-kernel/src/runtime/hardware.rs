//! Hardware abstraction.
//!
//! Each `Kernel<H>` owns one `H`. The runtime creates a fresh `Hardware`
//! per node — there is no `Arc<H>` blanket; cross-task sharing is done by
//! wrapping the `Kernel` in `Arc`, not the inner hardware.
//!
//! Hardware exposes only the operations that need external resources:
//!
//! - **state custody**: `genesis_state`, `state_at`, `commit_state`. The
//!   kernel uses these to load the starting state at construction and to
//!   persist post-block state. The internals (in-memory map vs on-disk
//!   db) are hardware-private.
//! - **secret-key custody**: `sign`, `holds_key`.
//! - **network outbox**: `emit`, `subscribe`.
//! - **fork-tree management**: `score`, `finalize`, `head`.
//! - **tracing**: `tracing_event` (no semantic effect; observability only).
//!
//! Crypto (hash, verify, block_hash) is kernel-static — see
//! `jar_kernel::crypto`.

use crate::types::{BlockHash, Command, Hash, KeyId, Signature, State, VaultId};

#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum HwError {
    #[error("hardware does not hold the requested key")]
    KeyAbsent,
    #[error("hardware sign failed: {0}")]
    SignFailure(String),
    #[error("hardware does not have state at block {0:?}")]
    StateAbsent(Hash),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TracingEvent {
    InvocationFault { reason: String },
    BlockPanic { reason: String },
}

pub trait Hardware: Send + Sync {
    // ---- state custody ----

    /// The chain's genesis state. Hardware was configured with this at
    /// construction time. Returned by `Kernel::new(None, …)`.
    fn genesis_state(&self) -> State;

    /// Look up the state previously committed against `block_hash`. Returns
    /// `None` if the hardware doesn't have it (block was never seen, was
    /// pruned, etc.).
    fn state_at(&self, block_hash: &Hash) -> Option<State>;

    /// Persist `(block_hash → state)`. Called by `Kernel::advance` after a
    /// successful block apply.
    fn commit_state(&self, block_hash: BlockHash, state: State);

    // ---- secret-key custody ----

    /// Whether this node holds the secret half of `key`. Decides
    /// proposer-vs-verifier per AttestationCap.
    fn holds_key(&self, key: &KeyId) -> bool;

    /// Sign `blob` with the secret half of `key`. Producer-mode AttestationCap.
    fn sign(&self, key: &KeyId, blob: &[u8]) -> Result<Signature, HwError>;

    // ---- network ----

    /// Emit a `Command` produced by `apply_block` /
    /// `handle_inbound_dispatch`. The runtime applies it (network broadcast,
    /// fork-tree update, …).
    fn emit(&self, cmd: Command);

    /// Subscribe to a Dispatch entrypoint's lite stream. The kernel calls
    /// this for each top-level Dispatch entrypoint discovered in σ at
    /// construction; hardware uses it to pre-register network filters.
    fn subscribe(&self, vault_id: VaultId) {
        let _ = vault_id;
    }

    // ---- fork tree ----

    /// Record the consensus score of a candidate block. Hardware uses this
    /// for fork choice; semantics are hardware-internal.
    fn score(&self, block_hash: BlockHash, score: u64) {
        let _ = (block_hash, score);
    }

    /// Mark a block finalized. Hardware can prune non-finalized siblings.
    fn finalize(&self, block_hash: BlockHash) {
        let _ = block_hash;
    }

    /// Current chain head per hardware's fork choice. `None` at genesis or
    /// before any block has been scored.
    fn head(&self) -> Option<BlockHash> {
        None
    }

    // ---- observability ----

    fn tracing_event(&self, ev: TracingEvent) {
        let _ = ev;
    }
}
