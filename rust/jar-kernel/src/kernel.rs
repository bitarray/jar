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
