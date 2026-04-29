//! JAR minimum-kernel.
//!
//! Implements the spec at `~/docs/minimum/`: capability-based microkernel
//! with a pure `apply_block` function plus an off-chain Dispatch pipeline.
//!
//! The kernel is split into:
//! - **Crypto** — `crypto` module: kernel-static `hash`, `verify`, `block_hash`.
//! - **State plumbing** — `cap_registry`, `cnode_ops`, `pinning`, `frame`, `snapshot`, `state_root`.
//! - **Host calls** — `host_calls` exposes the 16 calls the spec specifies.
//! - **Execution** — `invocation` drives a javm VM and routes ProtocolCall exits.
//! - **Block apply** — `apply_block` plus `transact`, `attest`, `reach`.
//! - **Dispatch pipeline** — `dispatch` (step-2 / step-3) plus `proposer` (slot drain).
//! - **Runtime** — `Hardware` trait + `InMemoryHardware` for tests.
//!
//! Public surface: `Kernel<H>`. The free-standing `apply_block::apply_block`
//! etc. remain reachable through their submodule paths but are not
//! re-exported here.

#![forbid(unsafe_code)]

pub mod apply_block;
pub mod attest;
pub mod cap_registry;
pub mod cnode_ops;
pub mod crypto;
pub mod dispatch;
pub mod frame;
pub mod genesis;
pub mod host_abi;
pub mod host_calls;
pub mod invocation;
pub mod kernel;
pub mod pinning;
pub mod proposer;
pub mod reach;
pub mod runtime;
pub mod snapshot;
pub mod state_root;
pub mod storage;
pub mod transact;

pub use apply_block::{ApplyBlockOutcome, BlockOutcome};
pub use dispatch::InboundOutcome;
pub use kernel::Kernel;
pub use runtime::{Hardware, HwError, NodeOffchain};

pub use jar_types::{
    Block, Body, CNode, CNodeId, Caller, CapId, CapRecord, Capability, Command, Event, Hash,
    KernelError, KernelRole, KeyId, MerkleProof, ResourceKind, Signature, Slot, SlotContent, State,
    Vault, VaultId,
};
