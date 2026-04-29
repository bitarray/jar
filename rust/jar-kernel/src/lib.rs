//! JAR minimum-kernel.
//!
//! Implements the spec at `~/docs/minimum/`: capability-based microkernel
//! with a pure `apply_block` function plus an off-chain Dispatch pipeline.
//!
//! The kernel is split into:
//! - **State plumbing** — `cap_registry`, `cnode_ops`, `pinning`, `frame`, `snapshot`, `state_root`.
//! - **Host calls** — `host_calls` exposes the 16 calls the spec specifies.
//! - **Execution** — `invocation` drives a javm VM and routes ProtocolCall exits.
//! - **Block apply** — `apply_block` plus `transact`, `attest`, `reach`.
//! - **Dispatch pipeline** — `dispatch` (step-2 / step-3) plus `proposer` (slot drain).
//! - **Runtime** — `Hardware` trait + `InMemoryHardware` for tests.

#![forbid(unsafe_code)]

pub mod apply_block;
pub mod attest;
pub mod cap_registry;
pub mod cnode_ops;
pub mod dispatch;
pub mod frame;
pub mod genesis;
pub mod host_abi;
pub mod host_calls;
pub mod invocation;
pub mod pinning;
pub mod proposer;
pub mod reach;
pub mod runtime;
pub mod snapshot;
pub mod state_root;
pub mod storage;
pub mod transact;

pub use apply_block::{ApplyBlockOutcome, BlockOutcome, apply_block};
pub use dispatch::{InboundOutcome, handle_inbound_dispatch};
pub use proposer::drain_for_body;
pub use runtime::{Hardware, HwError, NodeOffchain};
pub use state_root::state_root;

pub use jar_types::{
    Block, Body, CNode, CNodeId, Caller, CapId, CapRecord, Capability, Command, Crypto, Event,
    Hash, KernelError, KernelRole, KeyId, MerkleProof, ResourceKind, Signature, Slot, SlotContent,
    State, StorageMode, Vault, VaultId,
};
