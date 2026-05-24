//! JAR v3 kernel.
//!
//! Composes the foundational cap system (`javm-cap`), the pure
//! execution engine (`javm-exec`), and the integration crate
//! (`javm`) into the chain-side kernel: σ state, block apply,
//! state-root, kernel-assisted Instance impls, host_open/host_save.
//!
//! σ is a [`javm_cap::TypedCache<Global>`] plus the validator set; cap
//! content (Images, Data, CNodes, Instances) lives in the cache and
//! is content-addressed by [`javm_cap::CapHash`]. `apply_event`
//! publishes the event payload as a DataCap, rebinds the chain root
//! cnode's slot\[0\] to it, and drives [`javm::Vm::invoke_cached`].

pub mod abi;
pub mod apply;
pub mod error;
pub mod genesis;
pub mod kernel;
pub mod kernel_assist;
pub mod state;

pub use apply::{Block, Event, EventOutcome, apply_block, apply_event};
pub use error::KernelError;
pub use genesis::{Genesis, genesis};
pub use kernel::Kernel;
pub use kernel_assist::SigmaKernelAssist;
pub use state::{State, ValidatorKey, state_root};
