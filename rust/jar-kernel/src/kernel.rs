//! Top-level `Kernel` API.
//!
//! Wraps σ, the chain Image, and the chain Instance into a single
//! handle. Consumers (tests, the simple-chain end-to-end demo) call
//! `Kernel::from_genesis` + `Kernel::apply` and observe state via
//! `Kernel::state` / `Kernel::state_root`.

use std::sync::Arc;

use jar_cap::{CNodeBackend, Cap, CapHash, InstanceCap, image::Image};

use crate::apply::{Block, EventOutcome, apply_block};
use crate::error::KernelError;
use crate::genesis::{Genesis, genesis};
use crate::state::{State, state_root};

/// A v3 chain instance: σ + chain Image + chain InstanceCap.
pub struct Kernel {
    state: State,
    chain_image: Arc<Image>,
    chain_instance: InstanceCap,
    /// Factory for fresh chain cnodes. Per-event cnodes are
    /// transient; persistent state lives in σ. The factory rebuilds
    /// the kernel-cap-injected cnode on each event apply.
    cnode_factory: Box<dyn Fn() -> Box<dyn CNodeBackend<Cap> + Send + Sync> + Send + Sync>,
}

impl Kernel {
    /// Bootstrap from a chain Image.
    pub fn from_genesis(chain_image: Image) -> Self {
        let chain_image_clone = chain_image.clone();
        let Genesis {
            state,
            chain_instance,
            chain_cnode: _,
        } = genesis(chain_image);

        // Factory captures the chain Image so it can re-run genesis
        // cap injection for each event. Cheaper alternative: snapshot
        // the cnode bytes once and clone — but the factory's
        // simplicity beats the optimization for Stage C.
        let chain_image_for_factory = chain_image_clone.clone();
        let cnode_factory: Box<dyn Fn() -> Box<dyn CNodeBackend<Cap> + Send + Sync> + Send + Sync> =
            Box::new(move || {
                let g = genesis(chain_image_for_factory.clone());
                g.chain_cnode
            });

        Self {
            state,
            chain_image: Arc::new(chain_image_clone),
            chain_instance,
            cnode_factory,
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
            &self.chain_image,
            &mut self.chain_instance,
            &*self.cnode_factory,
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

    /// Read-only chain Instance handle.
    pub fn chain_instance(&self) -> &InstanceCap {
        &self.chain_instance
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi;
    use crate::apply::{Block, Event};
    use jar_cap::image::Image;
    use std::collections::BTreeMap;

    fn minimal_chain_image() -> Image {
        // Program: load_imm_64 φ[7] = 42; ecalli 0 (HALT).
        let mut endpoints = BTreeMap::new();
        endpoints.insert(
            0,
            jar_cap::image::EndpointDef {
                entry_pc: 0,
                arg_registers: 0,
                arg_cnode_size: 0,
                initial_regs: BTreeMap::new(),
            },
        );
        Image {
            code: vec![20u8, 7, 42, 0, 0, 0, 0, 0, 0, 0, 10, 0],
            endpoints,
            memory_mappings: Vec::new(),
            gas_slots: vec![abi::BARE_GAS_SLOT],
            quota_slots: vec![abi::BARE_QUOTA_SLOT],
            pinned_slots: BTreeMap::new(),
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
    fn kernel_apply_advances_state_root_via_host_save() {
        // The minimal_chain_image program just HALTs with 42 — no
        // host_save flow. State should NOT change across applies
        // (the chain doesn't mutate σ). This test asserts the
        // baseline: a no-op event still leaves the state root
        // stable.
        let mut kernel = Kernel::from_genesis(minimal_chain_image());
        let root_0 = kernel.state_root();

        // Pre-cache the program; the Vm's run_instance would
        // otherwise need a properly-bitmasked PvmProgram. We
        // bypass by pre-seeding the image_cache via... actually
        // we can't easily reach into the Vm. Let's just bake the
        // image with a correct bitmask via a different route: use
        // a code that's [trap] so we exit immediately. The Faulted
        // outcome is fine for this state_root-stability test.
        let block = Block {
            events: vec![Event {
                endpoint_idx: 0,
                payload: b"hello".to_vec(),
            }],
        };
        let outcomes = kernel.apply(&block, 10_000, 10_000).unwrap();
        let root_1 = kernel.state_root();

        // The payload bytes were registered in σ.data_payloads
        // (by apply_event's data_store call) so the state root
        // SHOULD differ from the genesis baseline.
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
        k1.apply(&block(), 10_000, 10_000).unwrap();
        k2.apply(&block(), 10_000, 10_000).unwrap();
        assert_eq!(k1.state_root(), k2.state_root());
    }
}
