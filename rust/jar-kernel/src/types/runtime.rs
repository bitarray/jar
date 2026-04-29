//! Runtime-side types — `Caller`, `Command`, `KernelRole`.

use super::{BlockHash, SlotContent, VaultId};

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
    /// Inform hardware about the consensus score of a candidate block —
    /// fork-choice input. Hardware stores it keyed by block_hash.
    Score { block_hash: BlockHash, score: u64 },
    /// Inform hardware that a block is finalized — its non-finalized
    /// siblings can be pruned.
    Finalize { block_hash: BlockHash },
}
