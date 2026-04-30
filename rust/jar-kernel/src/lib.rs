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
//! Module map (struct + helpers grouped):
//! - `crypto` — Hash/KeyId/Signature primitives + `hash`, `verify`, `block_hash`.
//! - `runtime` — `Hardware` trait, `InMemoryHardware`, `NodeOffchain`.
//! - `state` — `State`, `Vault`, plus all σ mutators (cap_registry, cnode,
//!   storage, snapshot, state_root, code_blobs).
//! - `cap` — pinning rules + attest helpers.
//! - `vm` — VM driver + host calls.
//! - `apply_block`, `transact`, `dispatch`, `proposer`, `reach` — kernel
//!   loop phases.
//! - `genesis` — test fixture.
//! - `types` — type definitions (Capability enum, Block/Body, Event,
//!   sidecar entries) shared everywhere.

#![forbid(unsafe_code)]

pub mod apply_block;
pub mod cap;
pub mod crypto;
pub mod dispatch;
pub mod genesis;
pub mod kernel;
pub mod proposer;
pub mod reach;
pub mod runtime;
pub mod state;
pub mod transact;
pub mod types;
pub mod vm;

pub use apply_block::BlockOutcome;
pub use kernel::{AdvanceOutcome, Kernel};
pub use runtime::{Hardware, HwError};

pub use crate::types::*;
