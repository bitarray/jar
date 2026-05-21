//! Block apply driver.
//!
//! For each event in a block:
//! 1. Publish the event's `payload` as a `Cap::Data` blob in σ's
//!    cache via `publish_data_inline`.
//! 2. CoW-promote the chain's root cnode and rebind slot\[0\] to the
//!    payload's CapHash; settle to a fresh cnode hash.
//! 3. Republish the chain InstanceCap with the new root cnode hash;
//!    the chain instance's hash updates monotonically per event.
//! 4. Drive `Vm::invoke_cached(&mut σ.caps, chain_instance_hash, ...)`.
//! 5. Translate `CallResult` → `EventOutcome`. Post-HALT, the call's
//!    `post_instance_hash` becomes the new `chain_instance_hash`.

use javm::{InProcessKernelAssist, Vm};
use javm_cap::{Cap, CapHash, CapHashOrRef, SlotIdx};
use javm_exec::ExitReason;

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

/// Apply one event against the chain Instance. Mutates `state.caps`
/// and advances `chain_instance_hash` to a fresh value reflecting the
/// post-call state.
///
/// The Vm is borrowed mutably for the duration of this call — the
/// caller is expected to maintain a long-lived Vm across blocks (the
/// image cache lives there).
pub fn apply_event(
    state: &mut State,
    vm: &mut Vm<InProcessKernelAssist>,
    chain_instance_hash: &mut CapHash,
    event: &Event,
    gas_budget: u64,
    _storage_quota: u64,
) -> Result<EventOutcome, KernelError> {
    // 1. Publish the event payload as a DataCap.
    let payload_hash = state.caps.publish_data_inline(&event.payload)?;

    // 2. Snapshot the chain instance's identifying fields (image hash
    //    chain, image hash, current cnode hash) plus its memory layout
    //    (mem_size, rw_overlays). We rebuild a new instance below
    //    referencing the new cnode hash + the same memory layout.
    let (image_hash_chain, image_hash, root_cnode_hash, mem_size, overlay_bufs, regs, pc) = {
        let inst_cap = state
            .caps
            .get(CapHashOrRef::Hash(*chain_instance_hash))
            .ok_or(KernelError::Invariant(
                "apply_event: chain instance missing in cache",
            ))?;
        match inst_cap {
            Cap::Instance(inst) => {
                let cnode_hash = match inst.root_cnode {
                    CapHashOrRef::Hash(h) => h,
                    CapHashOrRef::Ref(_) => {
                        return Err(KernelError::Invariant(
                            "apply_event: chain instance root_cnode unsettled",
                        ));
                    }
                };
                let overlays: Vec<(u32, Vec<u8>)> = inst
                    .rw_overlays
                    .iter()
                    .map(|o| (o.start, o.bytes.iter().copied().collect::<Vec<u8>>()))
                    .collect();
                (
                    inst.image_hash_chain,
                    inst.image_hash,
                    cnode_hash,
                    inst.mem_size,
                    overlays,
                    inst.regs,
                    inst.pc,
                )
            }
            _ => {
                return Err(KernelError::Invariant(
                    "apply_event: chain instance hash does not resolve to Cap::Instance",
                ));
            }
        }
    };

    // CoW-promote the cnode and rebind slot[0].
    let working_cnode_ref = state.caps.get_mut(CapHashOrRef::Hash(root_cnode_hash))?;
    let cnode_mut =
        match state
            .caps
            .instance_mut(working_cnode_ref)
            .ok_or(KernelError::Invariant(
                "apply_event: promoted cnode missing in instances tier",
            ))? {
            Cap::CNode(cn) => cn,
            _ => {
                return Err(KernelError::Invariant(
                    "apply_event: chain root cnode is not Cap::CNode",
                ));
            }
        };
    cnode_mut.set(SlotIdx(0), Some(CapHashOrRef::Hash(payload_hash)))?;

    // Settle the cnode (graduates the entry back into blobs at its new
    // content hash).
    let new_root_cnode_hash = state.caps.settle(CapHashOrRef::Ref(working_cnode_ref))?;

    // 3. Republish the chain Instance referencing the new cnode and
    //    the preserved memory layout / regs / PC.
    let overlay_slices: Vec<(u32, &[u8])> = overlay_bufs
        .iter()
        .map(|(s, b)| (*s, b.as_slice()))
        .collect();
    let new_chain_instance_hash = state.caps.publish_instance_blob(
        image_hash_chain,
        image_hash,
        new_root_cnode_hash,
        &overlay_slices,
        mem_size,
        regs,
        pc,
        0,
    )?;

    // 4. Drive the Vm.
    let result = vm.invoke_cached(
        &mut state.caps,
        new_chain_instance_hash,
        event.endpoint_idx,
        [0u64; 4],
        gas_budget,
    )?;

    // 5. Translate to EventOutcome and update chain_instance_hash.
    Ok(match result {
        javm::CallResult::Halt {
            return_value,
            post_instance_hash,
            gas_used,
            ..
        } => {
            *chain_instance_hash = post_instance_hash;
            EventOutcome::Halt {
                return_value,
                gas_used,
            }
        }
        javm::CallResult::Faulted {
            reason, gas_used, ..
        } => {
            // Faulted events leave the chain instance at the pre-call
            // hash (we still record the slot[0] payload bump, so the
            // instance hash post-fault is the one we just published).
            *chain_instance_hash = new_chain_instance_hash;
            EventOutcome::Faulted {
                reason: format_fault(reason),
                gas_used,
            }
        }
        javm::CallResult::Paused { gas_used, .. } => {
            *chain_instance_hash = new_chain_instance_hash;
            EventOutcome::Paused { gas_used }
        }
    })
}

fn format_fault(reason: ExitReason) -> String {
    match reason {
        ExitReason::Trap => "trap".into(),
        ExitReason::Panic => "panic".into(),
        ExitReason::OutOfGas => "out-of-gas".into(),
        ExitReason::PageFault(addr) => format!("page-fault@{addr:#x}"),
        ExitReason::HostCall(idx) => format!("host-call:{idx}"),
        ExitReason::Ecall => "ecall".into(),
        ExitReason::Halt => "halt".into(),
    }
}

/// Apply a whole block.
pub fn apply_block(
    state: &mut State,
    vm: &mut Vm<InProcessKernelAssist>,
    chain_instance_hash: &mut CapHash,
    block: &Block,
    gas_per_event: u64,
    quota_per_event: u64,
) -> Result<Vec<EventOutcome>, KernelError> {
    let mut outcomes = Vec::with_capacity(block.events.len());
    for event in &block.events {
        outcomes.push(apply_event(
            state,
            vm,
            chain_instance_hash,
            event,
            gas_per_event,
            quota_per_event,
        )?);
    }
    Ok(outcomes)
}
