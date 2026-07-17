//! Test/bench driver infra for [`Nub`].
//!
//! Provides:
//! - [`Nub::hyperlight_tests`]: borrow the singleton
//!   `javm-guest-x86-tests` guest binary (production RPCs + test-only
//!   fns like `nub_smoke`).
//! - [`Nub::hyperlight_benches`]: borrow the singleton
//!   `javm-guest-x86-benches` guest binary (production RPCs + bench
//!   probes like `bench_arc_page_alloc`).
//! - [`Nub::call_raw`] / [`Nub::call_raw_on_vcpu`]: raw RPC dispatch
//!   for fn_ids not exposed through the typed API. Hyperlight backend
//!   only.
//!
//! Gated on the `test-support` Cargo feature, which is auto-enabled
//! for `cargo test -p javm` and `cargo bench -p javm` via the
//! self-referencing dev-dep in `Cargo.toml`.

use anyhow::Result;

use crate::{HyperlightNubGuard, Nub, NubOptions};

impl Nub {
    /// Borrow the Hyperlight-backed singleton running the
    /// `javm-guest-x86-tests` guest binary. Same production RPCs as
    /// [`Nub::hyperlight`] plus the test-only guest functions.
    pub fn hyperlight_tests() -> Result<HyperlightNubGuard> {
        Ok(Self {
            inner: nub::Nub::hyperlight_tests()?,
        })
    }

    pub fn hyperlight_tests_with_options(options: NubOptions) -> Result<HyperlightNubGuard> {
        Ok(Self {
            inner: nub::Nub::hyperlight_tests_with_options(options)?,
        })
    }

    /// Borrow the Hyperlight-backed singleton running the
    /// `javm-guest-x86-benches` guest binary. Same production RPCs as
    /// [`Nub::hyperlight`] plus the bench probes.
    pub fn hyperlight_benches() -> Result<HyperlightNubGuard> {
        Ok(Self {
            inner: nub::Nub::hyperlight_benches()?,
        })
    }

    pub fn hyperlight_benches_with_options(options: NubOptions) -> Result<HyperlightNubGuard> {
        Ok(Self {
            inner: nub::Nub::hyperlight_benches_with_options(options)?,
        })
    }

    /// Raw RPC dispatch. Sends `payload` to the guest's `fn_id`
    /// handler and returns the response bytes verbatim. Returns `Err`
    /// for the Local backend (no guest to call).
    pub fn call_raw(&self, fn_id: u32, payload: &[u8]) -> Result<Vec<u8>> {
        self.inner.call_raw(fn_id, payload)
    }

    /// Test-only raw RPC dispatch on a selected vCPU lane (the
    /// serialized control-plane ring path, not the production
    /// concurrent invoke queue).
    pub fn call_raw_on_vcpu(
        &self,
        vcpu_index: usize,
        fn_id: u32,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        self.inner.call_raw_on_vcpu(vcpu_index, fn_id, payload)
    }
}
