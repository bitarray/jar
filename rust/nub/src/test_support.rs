//! Test/bench driver infra for [`Nub`].
//!
//! Provides:
//! - [`Nub::hyperlight_tests`]: borrow the singleton `javm-guest-x86-tests`
//!   guest binary (production RPCs + test-only fns like
//!   `nub_smoke`).
//! - [`Nub::hyperlight_benches`]: borrow the singleton `javm-guest-x86-benches`
//!   guest binary (production RPCs + bench probes like
//!   `bench_arc_page_alloc`).
//! - [`Nub::call_raw`]: raw RPC dispatch for fn_ids not exposed
//!   through the typed API. Hyperlight backend only.
//!
//! Gated on the `test-support` Cargo feature, enabled by downstream
//! test/bench consumers via their own `test-support` feature edge
//! (e.g. `javm`'s `test-support = ["nub/test-support"]`).

use anyhow::Result;

use crate::{Backend, HyperlightBlob, HyperlightNubGuard, Nub, NubOptions};

const TESTS_BLOB_PATH: &str = env!("NUB_ARCH_X86_TESTS_BLOB");
const BENCHES_BLOB_PATH: &str = env!("NUB_ARCH_X86_BENCHES_BLOB");

impl Nub {
    /// Borrow the Hyperlight-backed singleton running the
    /// `javm-guest-x86-tests` guest binary. Same production RPCs as
    /// [`Nub::hyperlight`] plus the test-only guest functions
    /// (whose FN_IDs live in the guest crates' `test_abi` modules).
    pub fn hyperlight_tests() -> Result<HyperlightNubGuard> {
        Self::hyperlight_tests_with_options(NubOptions::default())
    }

    pub fn hyperlight_tests_with_options(options: NubOptions) -> Result<HyperlightNubGuard> {
        Self::hyperlight_with_blob(
            HyperlightBlob {
                label: "test",
                path: TESTS_BLOB_PATH,
            },
            options,
        )
    }

    /// Borrow the Hyperlight-backed singleton running the
    /// `javm-guest-x86-benches` guest binary. Same production RPCs as
    /// [`Nub::hyperlight`] plus the bench probes (FN_IDs in the guest
    /// crates' `test_abi` modules).
    pub fn hyperlight_benches() -> Result<HyperlightNubGuard> {
        Self::hyperlight_benches_with_options(NubOptions::default())
    }

    pub fn hyperlight_benches_with_options(options: NubOptions) -> Result<HyperlightNubGuard> {
        Self::hyperlight_with_blob(
            HyperlightBlob {
                label: "bench",
                path: BENCHES_BLOB_PATH,
            },
            options,
        )
    }

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
            Backend::Local { .. } => {
                Err(anyhow::anyhow!("call_raw not supported on Local backend"))
            }
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
            Backend::Local { .. } => Err(anyhow::anyhow!(
                "call_raw_on_vcpu not supported on Local backend"
            )),
        }
    }
}
