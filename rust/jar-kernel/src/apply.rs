//! Block apply driver.
//!
//! For each event in a block:
//! 1. Build a fresh chain cnode pre-populated with kernel-issued
//!    caps (kernel-caps are re-injected per event — the cnode is
//!    transient; persistent state lives in σ via FileCaps).
//! 2. Reflect the event payload as a `Cap::Data` at the chain's
//!    slot\[0\] scratchpad; pre-register the bytes in
//!    `σ.data_payloads` so the chain can resolve them via
//!    `host_read_data_cap`.
//! 3. Reset per-block ephemeral kernel-assist tables; seed root
//!    gas and storage quota.
//! 4. Drive the Vm over the chain Image / Instance / cnode.
//! 5. Translate the [`javm::CallResult`] into an [`EventOutcome`].
//!    Persistent state changes (host_save, etc) already landed in
//!    σ through SigmaKernelAssist's &mut State borrow.
//!
//! **Commit 2 of the cap-type consolidation removed
//! `Vm::run_instance`; jar-kernel's apply_event is shimmed out
//! pending Commit 3, which migrates it to `Vm::invoke_cached` over
//! a cache-resident chain image / instance.**

use std::sync::Arc;

use javm_cap::image::Image;
use javm_cap::legacy::{CNodeBackend, Cap, InstanceCap};

use crate::error::KernelError;
use crate::state::State;

/// One on-chain event in a block.
pub struct Event {
    /// Chain Image endpoint to invoke.
    pub endpoint_idx: u8,
    /// Raw payload bytes; delivered as a `Cap::Data` at the chain
    /// Instance's slot\[0\] before the call.
    pub payload: Vec<u8>,
}

/// A block: an ordered sequence of events the chain applies in
/// turn.
pub struct Block {
    pub events: Vec<Event>,
}

/// Outcome of one event apply.
#[derive(Debug)]
pub enum EventOutcome {
    Halt { return_value: u64, gas_used: u64 },
    Faulted { reason: String, gas_used: u64 },
    Paused { gas_used: u64 },
}

/// Apply one event against the chain Instance. Mutates `state`
/// (via host_save / data_store) and `chain_instance` (post-Halt).
/// The cnode is rebuilt fresh per event from `chain_cnode_factory`.
///
/// **STUB:** Commit 2 of the javm-cap consolidation removed
/// `Vm::run_instance`. Commit 3 will rewrite this function on top
/// of the cache-driven `Vm::invoke_cached` path; until then it
/// returns a "not yet migrated" KernelError.
pub fn apply_event(
    _state: &mut State,
    _chain_image: &Arc<Image>,
    _chain_instance: &mut InstanceCap,
    _chain_cnode_factory: &dyn Fn() -> Box<dyn CNodeBackend<Cap> + Send + Sync>,
    _event: &Event,
    _gas_budget: u64,
    _storage_quota: u64,
) -> Result<EventOutcome, KernelError> {
    // Commit 3 plumbs this through cache.publish_image / cache.publish_instance_blob
    // and Vm::invoke_cached. For now, surface a structured error.
    Err(KernelError::Vm(javm::VmError::Invariant(
        "apply_event: pending migration to Vm::invoke_cached (Commit 3)",
    )))
}

/// Apply a whole block.
pub fn apply_block(
    state: &mut State,
    chain_image: &Arc<Image>,
    chain_instance: &mut InstanceCap,
    chain_cnode_factory: &dyn Fn() -> Box<dyn CNodeBackend<Cap> + Send + Sync>,
    block: &Block,
    gas_per_event: u64,
    quota_per_event: u64,
) -> Result<Vec<EventOutcome>, KernelError> {
    let mut outcomes = Vec::with_capacity(block.events.len());
    for event in &block.events {
        outcomes.push(apply_event(
            state,
            chain_image,
            chain_instance,
            chain_cnode_factory,
            event,
            gas_per_event,
            quota_per_event,
        )?);
    }
    Ok(outcomes)
}
