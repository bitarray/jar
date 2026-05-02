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
//! - `Kernel::dispatch(target_path, blob)` — handle inbound off-chain
//!   dispatch.
//! - `Kernel::advance(block)` — build (proposer) or verify (verifier) a
//!   new block; updates the tip and asks hardware to commit.
//!
//! Module map:
//! - `types` — primitives (Hash/KeyId/VaultId/…) + umbrella re-exports.
//! - `block` — Block / Body / BodyEvent + sidecar trace shapes.
//! - `cap` — value-typed cap shapes (RegCap, ProtocolCap, …).
//! - `state` — σ (`State`, `Vault`, `IdCounters`) and state-root.
//! - `vm` — javm driver: `InvocationHost`, `vault_init`, foreign-frame
//!   slot ops, host-call handlers, ABI sentinels.
//! - `runtime` — `Hardware` trait, `InMemoryHardware`, `NodeOffchain`.
//! - `kernel` — `Kernel<H>` surface + `Caller` / `Command` /
//!   `KernelRole`.
//! - `apply_block`, `transact`, `dispatch` — kernel-loop phases.
//! - `crypto` — `hash`, `verify`, `block_hash`.
//! - `pool` — per-cycle setScore max-register + collision-defer.
//! - `genesis` — test fixture + `halt_blob()`.

#![forbid(unsafe_code)]

pub mod apply_block;
pub mod block;
pub mod cap;
pub mod crypto;
pub mod dispatch;
pub mod genesis;
pub mod kernel;
pub mod pool;
pub mod runtime;
pub mod state;
pub mod transact;
pub mod types;
pub mod vm;

pub use apply_block::BlockOutcome;
pub use kernel::{AdvanceOutcome, Kernel};
pub use runtime::{Hardware, HwError};

pub use crate::types::*;
