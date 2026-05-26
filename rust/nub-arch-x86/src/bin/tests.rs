//! Test guest binary for `nub-arch-x86`.
//!
//! Same kernel modules + production RPCs as the production bin
//! (via `extern crate nub_arch_x86`), plus test-only guest
//! functions whose FN_IDs live in [`nub_arch_x86::test_abi`].

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
extern crate alloc;
#[cfg(target_os = "none")]
extern crate hyperlight_guest_bin;
#[cfg(target_os = "none")]
extern crate nub_arch_x86;

#[cfg(target_os = "none")]
mod test_fns {
    use alloc::vec::Vec;
    use hyperlight_guest_bin::guest_function;
    use nub_arch_x86::test_abi::FN_ID_TEST_SMOKE;

    /// Smoke probe. Returns rkyv-encoded `42u64`. Used by
    /// `nub/tests/test_bin_smoke.rs` to verify the test bin loads
    /// and the RPC plumbing works end-to-end.
    #[guest_function(fn_id = FN_ID_TEST_SMOKE)]
    pub fn nub_smoke(_input: &[u8]) -> Vec<u8> {
        let v: u64 = 42;
        rkyv::to_bytes::<rkyv::rancor::Error>(&v)
            .expect("rkyv-encode u64")
            .into_vec()
    }
}

#[cfg(not(target_os = "none"))]
fn main() {}
