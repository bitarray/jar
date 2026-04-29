//! Runtime-side types — `Caller`, `Command`, `StorageMode`, `KernelRole`.

use crate::{SlotContent, VaultId};

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
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Command {
    /// Send a Dispatch to peers (full stream).
    Dispatch {
        entrypoint: VaultId,
        payload: Vec<u8>,
        caps: Vec<u8>,
    },
    /// Broadcast a slot update on the lite stream of `entrypoint`.
    BroadcastLite {
        entrypoint: VaultId,
        content: SlotContent,
    },
}
