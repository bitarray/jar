//! Hardware abstraction.
//!
//! The kernel owns crypto (`hash`, `verify`, `block_hash` are kernel-static
//! in `jar_kernel::crypto`). Hardware exposes only the operations that need
//! external resources:
//!
//! - **secret-key custody**: `sign`, `holds_key` (the kernel can't sign without
//!   the validator node's private key material).
//! - **network outbox**: `emit` (Dispatch / BroadcastLite messages).
//! - **fork-tree management**: `score`, `finalize`, `head`. The kernel decides
//!   what's valid and what's finalized; hardware records and runs fork choice.
//! - **tracing**: `tracing_event` (no semantic effect; observability only).
//!
//! σ is **not** owned by Hardware — passed alongside as `&State` /
//! `&mut State`. Off-chain aggregation slots live in `NodeOffchain`, also
//! outside σ.

use jar_types::{BlockHash, Command, KeyId, Signature};

#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum HwError {
    #[error("hardware does not hold the requested key")]
    KeyAbsent,
    #[error("hardware sign failed: {0}")]
    SignFailure(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TracingEvent {
    InvocationFault { reason: String },
    BlockPanic { reason: String },
}

pub trait Hardware: Send + Sync {
    /// Whether this node holds the secret half of `key`. Decides
    /// proposer-vs-verifier per AttestationCap.
    fn holds_key(&self, key: &KeyId) -> bool;

    /// Sign `blob` with the secret half of `key`. Producer-mode AttestationCap.
    fn sign(&self, key: &KeyId, blob: &[u8]) -> Result<Signature, HwError>;

    /// Emit a `Command` produced by `apply_block` /
    /// `handle_inbound_dispatch`. The runtime applies it (network broadcast,
    /// fork-tree update, …).
    fn emit(&self, cmd: Command);

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

    fn tracing_event(&self, ev: TracingEvent) {
        let _ = ev;
    }
}
