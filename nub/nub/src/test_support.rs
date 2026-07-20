//! Test/bench driver infra for [`Nub`]: raw RPC dispatch for fn_ids
//! not exposed through the typed API. Hyperlight backend only.
//!
//! The test/bench guest-blob constructors live with the personality
//! entrypoint crates (e.g. `javm::Nub::hyperlight_tests`), which own
//! the blobs.
//!
//! Gated on the `test-support` Cargo feature, enabled by downstream
//! test/bench consumers via their own `test-support` feature edge
//! (e.g. `javm`'s `test-support = ["nub/test-support"]`).

use anyhow::Result;

use crate::{Backend, Nub, Personality};

impl<P: Personality> Nub<P> {
    /// Raw RPC dispatch. Sends `payload` to the guest's `fn_id`
    /// handler and returns the response bytes verbatim. Test/bench
    /// callers use this for FN_IDs not exposed through the typed
    /// API. Returns `Err` for the Local backend (no guest to call).
    pub fn call_raw(&self, fn_id: u32, payload: &[u8]) -> Result<Vec<u8>> {
        let mut backend = self
            .inner
            .backend
            .lock()
            .expect("Nub backend mutex poisoned");
        match &mut *backend {
            Backend::Hyperlight(h) => h
                .sandbox
                .call_raw(fn_id, payload)
                .map_err(|e| anyhow::anyhow!("call_raw: {e}")),
            Backend::Local(_) => Err(anyhow::anyhow!("call_raw not supported on Local backend")),
        }
    }

    /// Test-only raw RPC dispatch on a selected vCPU lane. This is still the
    /// serialized control-plane ring path, not the production concurrent invoke
    /// queue.
    pub fn call_raw_on_vcpu(
        &self,
        vcpu_index: usize,
        fn_id: u32,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let mut backend = self
            .inner
            .backend
            .lock()
            .expect("Nub backend mutex poisoned");
        match &mut *backend {
            Backend::Hyperlight(h) => h
                .sandbox
                .call_raw_on_vcpu(vcpu_index, fn_id, payload)
                .map_err(|e| anyhow::anyhow!("call_raw_on_vcpu: {e}")),
            Backend::Local(_) => Err(anyhow::anyhow!(
                "call_raw_on_vcpu not supported on Local backend"
            )),
        }
    }
}
