//! Runtime-side types — `Caller`, `Command`, `StorageMode`, `KernelRole`.

use crate::{Crypto, SlotContent, VaultId};

/// Three modes a Transact entrypoint can be invoked in. Off-chain Dispatch
/// invocations only use `RO` (or `None` for cheap admission checks).
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum StorageMode {
    /// No storage cap passed; pure-syntactic check only.
    None,
    /// Read-only: σ-read-with-merkle-proofs validation. Used during
    /// block_validation_cap, block_finalization_cap, and Dispatch step-2/
    /// step-3.
    Ro,
    /// Read-write: full σ-effect; only inside apply_block's transact phase.
    Rw,
}

impl StorageMode {
    pub fn is_writable(self) -> bool {
        matches!(self, StorageMode::Rw)
    }
}

/// Returned by the `caller()` host call. Discriminates between Vault-to-Vault
/// sub-CALLs and kernel-fired top-level invocations.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Caller {
    /// Sub-CALL from another Vault VM.
    Vault(VaultId),
    /// Top-level invocation by the kernel — userspace branches on the role
    /// to discriminate Transact vs Dispatch step-2 vs Dispatch step-3 vs
    /// the two block-policy hooks.
    Kernel(KernelRole),
}

/// Where in apply_block / off-chain pipeline a top-level invocation runs.
///
/// Chain-author event[0] / event[-1] handlers run as `TransactEntry`;
/// they're singled out only by their position in `body.events`, never
/// by the kernel.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum KernelRole {
    TransactEntry,
    AggregateStandalone, // Dispatch step-2
    AggregateMerge,      // Dispatch step-3
}

/// Runtime-side commands the kernel emits during execution. The runtime
/// applies these to hardware after `apply_block` (or `handle_inbound_dispatch`)
/// returns.
///
/// Manual trait impls so bounds land on `SlotContent<C>` rather than `C`.
pub enum Command<C: Crypto> {
    /// Send a Dispatch to peers (full stream).
    Dispatch {
        entrypoint: VaultId,
        payload: Vec<u8>,
        caps: Vec<u8>,
    },
    /// Broadcast a slot update on the lite stream of `entrypoint`.
    BroadcastLite {
        entrypoint: VaultId,
        content: SlotContent<C>,
    },
}

impl<C: Crypto> Clone for Command<C> {
    fn clone(&self) -> Self {
        match self {
            Command::Dispatch {
                entrypoint,
                payload,
                caps,
            } => Command::Dispatch {
                entrypoint: *entrypoint,
                payload: payload.clone(),
                caps: caps.clone(),
            },
            Command::BroadcastLite {
                entrypoint,
                content,
            } => Command::BroadcastLite {
                entrypoint: *entrypoint,
                content: content.clone(),
            },
        }
    }
}

impl<C: Crypto> PartialEq for Command<C> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Command::Dispatch {
                    entrypoint: e1,
                    payload: p1,
                    caps: c1,
                },
                Command::Dispatch {
                    entrypoint: e2,
                    payload: p2,
                    caps: c2,
                },
            ) => e1 == e2 && p1 == p2 && c1 == c2,
            (
                Command::BroadcastLite {
                    entrypoint: e1,
                    content: c1,
                },
                Command::BroadcastLite {
                    entrypoint: e2,
                    content: c2,
                },
            ) => e1 == e2 && c1 == c2,
            _ => false,
        }
    }
}

impl<C: Crypto> Eq for Command<C> {}

impl<C: Crypto> core::fmt::Debug for Command<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Command::Dispatch {
                entrypoint,
                payload,
                caps,
            } => f
                .debug_struct("Dispatch")
                .field("entrypoint", entrypoint)
                .field("payload", payload)
                .field("caps", caps)
                .finish(),
            Command::BroadcastLite {
                entrypoint,
                content,
            } => f
                .debug_struct("BroadcastLite")
                .field("entrypoint", entrypoint)
                .field("content", content)
                .finish(),
        }
    }
}
