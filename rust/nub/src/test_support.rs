//! Test/bench driver infra for [`Nub`].
//!
//! Provides:
//! - [`Nub::hyperlight_tests`]: borrow the singleton `nub-arch-x86-tests`
//!   guest binary (production RPCs + test-only fns like
//!   `nub_smoke`).
//! - [`Nub::hyperlight_benches`]: borrow the singleton `nub-arch-x86-benches`
//!   guest binary (production RPCs + bench probes like
//!   `bench_arc_page_alloc`).
//! - [`Nub::call_raw`]: raw RPC dispatch for fn_ids not exposed
//!   through the typed API. Hyperlight backend only.
//!
//! Gated on the `test-support` Cargo feature, which is
//! auto-enabled for `cargo test -p nub` and `cargo bench -p nub`
//! via the self-referencing dev-dep in `Cargo.toml`.

use anyhow::Result;

use crate::{Backend, HyperlightBlob, HyperlightNubGuard, Nub};

const TESTS_BLOB_PATH: &str = env!("NUB_ARCH_X86_TESTS_BLOB");
const BENCHES_BLOB_PATH: &str = env!("NUB_ARCH_X86_BENCHES_BLOB");

impl Nub {
    /// Borrow the Hyperlight-backed singleton running the
    /// `nub-arch-x86-tests` guest binary. Same production RPCs as
    /// [`Nub::hyperlight`] plus the test-only guest functions
    /// (whose FN_IDs live in [`nub_arch_x86::test_abi`]).
    pub fn hyperlight_tests() -> Result<HyperlightNubGuard> {
        Self::hyperlight_with_blob(HyperlightBlob {
            label: "test",
            path: TESTS_BLOB_PATH,
        })
    }

    /// Borrow the Hyperlight-backed singleton running the
    /// `nub-arch-x86-benches` guest binary. Same production RPCs as
    /// [`Nub::hyperlight`] plus the bench probes (FN_IDs in
    /// [`nub_arch_x86::test_abi`]).
    pub fn hyperlight_benches() -> Result<HyperlightNubGuard> {
        Self::hyperlight_with_blob(HyperlightBlob {
            label: "bench",
            path: BENCHES_BLOB_PATH,
        })
    }

    /// Raw RPC dispatch. Sends `payload` to the guest's `fn_id`
    /// handler and returns the response bytes verbatim. Test/bench
    /// callers use this for FN_IDs not exposed through the typed
    /// API. Returns `Err` for the Local backend (no guest to call).
    pub fn call_raw(&mut self, fn_id: u32, payload: &[u8]) -> Result<Vec<u8>> {
        match &mut self.backend {
            Backend::Hyperlight(h) => h
                .sandbox
                .call_raw(fn_id, payload)
                .map_err(|e| anyhow::anyhow!("call_raw: {e}")),
            Backend::Local { .. } => {
                Err(anyhow::anyhow!("call_raw not supported on Local backend"))
            }
        }
    }
}
