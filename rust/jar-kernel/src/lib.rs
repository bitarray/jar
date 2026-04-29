//! JAR minimum-kernel.
//!
//! Implements the spec at `~/docs/minimum/`: capability-based microkernel
//! with a pure block-apply function plus an off-chain Dispatch pipeline.
//!
//! The kernel surface is `Kernel<H>`. A node creates one kernel per fork
//! it tracks, owns one `Hardware` impl directly (no `Arc<H>`), and drives
//! the kernel via:
//!
//! - `Kernel::new(block_hash, hw)` — load tip from hardware.
//! - `Kernel::dispatch(ep, event)` — handle inbound off-chain dispatch.
//! - `Kernel::advance(block)` — build (proposer) or verify (verifier) a
//!   new block; updates the tip and asks hardware to commit.
//!
//! Internals:
//! - **Crypto** — `crypto`: kernel-static `hash`, `verify`, `block_hash`.
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
pub mod code_blobs;
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

pub use apply_block::BlockOutcome;
pub use kernel::{AdvanceOutcome, Kernel};
pub use runtime::{Hardware, HwError};

pub use jar_types::{
    Block, Body, CNode, CNodeId, Caller, CapId, CapRecord, Capability, Command, Event, Hash,
    KernelError, KernelRole, KeyId, MerkleProof, ResourceKind, Signature, Slot, SlotContent, State,
    Vault, VaultId,
};
