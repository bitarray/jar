//! Top-level `Kernel` API.
//!
//! Wraps σ, the chain instance hash, and a long-lived Vm into a
//! single handle. Consumers (tests, the simple-chain end-to-end demo)
//! call `Kernel::from_genesis` + `Kernel::apply` and observe state
//! via `Kernel::state` / `Kernel::state_root`.

use javm::{InProcessKernelAssist, Vm};
use javm_cap::CapHash;
use javm_cap::image::Image;

use crate::apply::{Block, EventOutcome, apply_block};
use crate::error::KernelError;
use crate::genesis::{Genesis, genesis};
use crate::state::{State, state_root};

/// A v3 chain instance: σ + the chain instance hash + a long-lived
/// Vm (so the image cache survives across events).
pub struct Kernel {
    state: State,
    chain_instance_hash: CapHash,
    vm: Vm<InProcessKernelAssist>,
}

impl Kernel {
    /// Bootstrap from a chain Image.
    pub fn from_genesis(chain_image: Image) -> Self {
        let Genesis {
            state,
            chain_instance_hash,
            chain_image_hash: _,
            root_cnode_hash: _,
        } = genesis(chain_image).expect("genesis must succeed for a valid chain image");

        Self {
            state,
            chain_instance_hash,
            vm: Vm::new(InProcessKernelAssist::new()),
        }
    }

    /// Apply a block. Returns per-event outcomes; the post-block
    /// state-root is available via [`Kernel::state_root`].
    pub fn apply(
        &mut self,
        block: &Block,
        gas_per_event: u64,
        quota_per_event: u64,
    ) -> Result<Vec<EventOutcome>, KernelError> {
        apply_block(
            &mut self.state,
            &mut self.vm,
            &mut self.chain_instance_hash,
            block,
            gas_per_event,
            quota_per_event,
        )
    }

    /// Read-only σ.
    pub fn state(&self) -> &State {
        &self.state
    }

    /// Current state-root.
    pub fn state_root(&self) -> CapHash {
        state_root(&self.state)
    }

    /// Current chain instance hash (advances monotonically as events
    /// land).
    pub fn chain_instance_hash(&self) -> CapHash {
        self.chain_instance_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi;
    use crate::apply::{Block, Event};
    use javm_cap::image::Image;
    use std::collections::BTreeMap;

    fn minimal_chain_image() -> Image {
        // Program: load_imm_64 φ[7] = 42; ecalli 0 (HALT).
        let mut endpoints = BTreeMap::new();
        endpoints.insert(
            0,
            javm_cap::image::EndpointDef {
                entry_pc: 0,
                arg_registers: 0,
                arg_cnode_size: 0,
                initial_regs: BTreeMap::new(),
            },
        );
        // Instruction starts at bytes 0 (load_imm_64) and 10 (ecalli).
        // Packed bitmask (LSB-first): byte 0 = bit 0 set = 0x01;
        // byte 1 = bit 2 set = 0x04.
        Image {
            code: vec![20u8, 7, 42, 0, 0, 0, 0, 0, 0, 0, 10, 0],
            packed_bitmask: vec![0x01, 0x04],
            jump_table: Vec::new(),
            endpoints,
            memory_mappings: Vec::new(),
            gas_slots: vec![abi::BARE_GAS_SLOT],
            quota_slots: vec![abi::BARE_QUOTA_SLOT],
            pinned_slots: BTreeMap::new(),
            initial_slots: BTreeMap::new(),
            yield_marker_slot: Some(abi::BARE_YIELD_CATCHER_SLOT),
        }
    }

    #[test]
    fn kernel_from_genesis_yields_deterministic_state_root() {
        let k1 = Kernel::from_genesis(minimal_chain_image());
        let k2 = Kernel::from_genesis(minimal_chain_image());
        assert_eq!(k1.state_root(), k2.state_root());
    }

    #[test]
    fn kernel_apply_advances_state_root_via_payload_publish() {
        // The minimal_chain_image program halts with 42 (or traps,
        // depending on bytecode validity). Regardless of the exit
        // status, the event payload gets published as a DataCap in σ
        // before the call — that publish alone changes state_root.
        let mut kernel = Kernel::from_genesis(minimal_chain_image());
        let root_0 = kernel.state_root();

        let block = Block {
            events: vec![Event {
                endpoint_idx: 0,
                payload: b"hello".to_vec(),
            }],
        };
        let outcomes = kernel.apply(&block, 10_000, 10_000).unwrap();
        let root_1 = kernel.state_root();

        assert_ne!(root_0, root_1);
        assert_eq!(outcomes.len(), 1);
    }

    #[test]
    fn kernel_apply_replay_is_deterministic() {
        // Same chain image, same block → same post-apply root.
        let mut k1 = Kernel::from_genesis(minimal_chain_image());
        let mut k2 = Kernel::from_genesis(minimal_chain_image());
        let block = || Block {
            events: vec![Event {
                endpoint_idx: 0,
                payload: b"replay-determinism".to_vec(),
            }],
        };
        let _ = k1.apply(&block(), 10_000, 10_000).unwrap();
        let _ = k2.apply(&block(), 10_000, 10_000).unwrap();
        assert_eq!(k1.state_root(), k2.state_root());
    }
}
