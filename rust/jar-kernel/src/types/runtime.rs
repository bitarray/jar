//! Runtime-side types — `Caller`, `Command`, `KernelRole`.

use super::{BlockHash, VaultId};

/// Returned by the `caller()` host call. Discriminates between Vault-to-Vault
/// sub-CALLs and kernel-fired top-level invocations.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Caller {
    /// Sub-CALL from another Vault VM.
    Vault(VaultId),
    /// Top-level invocation by the kernel — userspace branches on the role
    /// to discriminate verify vs process.
    Kernel(KernelRole),
}

/// Where in apply_block / off-chain pipeline a top-level invocation runs.
///
/// Per the event-redesign: every event-receiving endpoint is fired in
/// two phases — `Verify` (fresh per event, ro-σ, may panic) and
/// `Process` (one Vault per cycle, persistent state, rw-σ for
/// transact endpoints / ro-σ for dispatch).
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum KernelRole {
    /// Per-event verify phase. Fresh Vault.initialize each. ro-σ.
    /// May panic. May call mint_attest_cap and setScore.
    Verify,
    /// Per-cycle process phase. One Vault.initialize per cycle.
    /// Persistent state across calls. rw-σ for transact endpoints,
    /// ro-σ for dispatch endpoints. Cannot fail logic-wise.
    Process,
}

/// Runtime-side commands the kernel emits during execution. The runtime
/// applies these to hardware after `apply_block` (or `handle_inbound_dispatch`)
/// returns.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Command {
    /// Send a wire dispatch to peers.
    Emit {
        target_path: Vec<u8>,
        blob: Vec<u8>,
        attestation_traces: Vec<crate::cap::AttestationEntry>,
    },
    /// Inform hardware about the consensus score of a candidate block —
    /// fork-choice input. Hardware stores it keyed by block_hash.
    Score { block_hash: BlockHash, score: u64 },
    /// Inform hardware that a block is finalized — its non-finalized
    /// siblings can be pruned.
    Finalize { block_hash: BlockHash },
}
