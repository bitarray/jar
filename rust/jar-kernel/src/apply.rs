//! Block apply driver.
//!
//! For each event in a block:
//! 1. Build a fresh chain cnode pre-populated with kernel-issued
//!    caps (kernel-caps are re-injected per event — the cnode is
//!    transient; persistent state lives in σ via FileCaps).
//! 2. Reflect the event payload as a `Cap::Data` at the chain's
//!    slot[0] scratchpad; pre-register the bytes in
//!    `σ.data_payloads` so the chain can resolve them via
//!    `host_read_data_cap`.
//! 3. Reset per-block ephemeral kernel-assist tables; seed root
//!    gas and storage quota.
//! 4. Drive `Vm::run_instance` over the chain Image / Instance /
//!    cnode.
//! 5. Translate the [`javm::CallResult`] into an [`EventOutcome`].
//!    Persistent state changes (host_save, etc) already landed in
//!    σ through SigmaKernelAssist's &mut State borrow.

use std::sync::Arc;

use jar_cap::{Blake2b256, CNodeBackend, Cap, DataCap, Hash, InstanceCap, SlotIdx, image::Image};
use javm::{CallResult, KernelAssist as _, Vm};

use crate::error::KernelError;
use crate::kernel_assist::SigmaKernelAssist;
use crate::state::State;

/// One on-chain event in a block.
pub struct Event {
    /// Chain Image endpoint to invoke.
    pub endpoint_idx: u8,
    /// Raw payload bytes; delivered as a `Cap::Data` at the chain
    /// Instance's slot[0] before the call.
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
pub fn apply_event(
    state: &mut State,
    chain_image: &Arc<Image>,
    chain_instance: &mut InstanceCap,
    chain_cnode_factory: &dyn Fn() -> Box<dyn CNodeBackend<Cap> + Send + Sync>,
    event: &Event,
    gas_budget: u64,
    storage_quota: u64,
) -> Result<EventOutcome, KernelError> {
    // 1. Fresh cnode with kernel-issued caps; install event payload
    //    at slot[0] as a Cap::Data referencing the payload bytes.
    let mut cnode = chain_cnode_factory();
    let payload_hash = Blake2b256::hash(&event.payload);
    cnode.set(
        SlotIdx(0),
        Some(Cap::Data(DataCap {
            content_hash: payload_hash,
            size: event.payload.len() as u64,
        })),
    )?;

    // 2. Build the Vm + SigmaKernelAssist; reset ephemeral tables;
    //    seed gas/quota; register payload bytes so host_read_data_cap
    //    can resolve them.
    let mut ka = SigmaKernelAssist::new(state);
    ka.reset_block_state();
    ka.seed_root_gas(gas_budget);
    ka.seed_root_quota(storage_quota);
    ka.data_store(&event.payload);

    let mut vm = Vm::new(ka);

    // 3. Drive the interpreter.
    let result = vm.run_instance(
        *chain_instance,
        chain_image.clone(),
        cnode,
        event.endpoint_idx,
        gas_budget,
    )?;

    // 4. Translate. σ-resident mutations have already landed via
    //    the &mut State borrow inside ka.
    let outcome = match result {
        CallResult::Halt {
            return_value,
            gas_used,
            post_instance,
            ..
        } => {
            *chain_instance = post_instance;
            EventOutcome::Halt {
                return_value,
                gas_used,
            }
        }
        CallResult::Faulted {
            reason, gas_used, ..
        } => EventOutcome::Faulted {
            reason: format!("{:?}", reason),
            gas_used,
        },
        CallResult::Paused { gas_used, .. } => EventOutcome::Paused { gas_used },
    };
    Ok(outcome)
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
