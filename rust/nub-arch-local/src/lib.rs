//! In-process `Arch` impl: simulates the CPU + MMU substrate with
//! Rust data structures. Runs directly in the host process; no
//! sandbox, no cross-compilation.
//!
//! Today this is a **stub** — every invoke returns a fixed
//! deterministic result so the trait wiring + crate boundaries can
//! be exercised end-to-end. Real JAVM invocation (using `javm::Vm`)
//! lands in a follow-up commit, once `javm`'s `KernelAssist` shape
//! is reconciled with the nub state-ownership model.

use nub_kernel::{Arch, CapHash, InstanceRef, InvokeOptions, InvokeOutcome};

/// In-process Arch backend.
#[derive(Default)]
pub struct LocalArch {
    state_root: CapHash,
}

impl LocalArch {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Stub error type for the skeleton — the local backend cannot fail
/// today. Replace with a real error enum when invocation lands.
#[derive(Debug)]
pub enum LocalArchError {}

impl Arch for LocalArch {
    type Error = LocalArchError;

    fn invoke(
        &mut self,
        _target: InstanceRef,
        _endpoint: u16,
        _args: &[u8],
        _opts: InvokeOptions,
    ) -> Result<InvokeOutcome, Self::Error> {
        Ok(InvokeOutcome {
            return_value: 42,
            gas_used: 0,
        })
    }

    fn state_root(&self) -> CapHash {
        self.state_root
    }
}

// `#[cfg(test)] mod tests` deferred until the LocalArch stub is
// replaced with a real javm-driven invocation (Stage 3). Asserting
// that the stub returns 42 today carries no signal.
