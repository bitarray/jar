//! JAR v3 kernel.
//!
//! Composes the foundational cap system (`jar-cap`), the pure
//! execution engine (`javm-exec`), and the integration crate
//! (`javm`) into the chain-side kernel: σ state, block apply,
//! state-root, kernel-assisted Instance impls, host_open/host_save.
//!
//! See `~/docs/minimum-v3/implementation/architecture.md` (Layer 4
//! — `jar-kernel`) for the design.
//!
//! Stage 4 of the v3 implementation. Built incrementally:
//!
//! - C.1 (this commit): crate scaffold + module declarations.
//! - C.2: `State` + `state_root` via SCALE + blake2b.
//! - C.3: `SigmaKernelAssist` — σ-aware [`javm::KernelAssist`] impl.
//! - C.4: Native kernel-assisted Instance dispatch.
//! - C.5: Genesis + kernel cap injection.
//! - C.6: Block apply driver.
//! - C.7: σ data_blob refcount + drop-time refund.
//! - C.8: Public `Kernel` API.

pub mod abi;
pub mod error;
pub mod kernel_assist;
pub mod state;

pub use error::KernelError;
pub use kernel_assist::SigmaKernelAssist;
pub use state::{
    CodeId, DataBlob, FileId, IdCounters, State, ValidatorKey, VaultId, VaultRecord, state_root,
};
