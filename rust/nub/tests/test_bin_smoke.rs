//! End-to-end smoke for the `nub-arch-x86-tests` guest binary.
//!
//! Loads the test guest binary via [`Nub::hyperlight_tests`],
//! calls the `nub_smoke` RPC, and verifies it returns `42u64`.
//! Together with `tests/smoke.rs` (which exercises the production
//! `invoke_cached` path), this gives us coverage of both the
//! production and test guest binaries.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use nub::Nub;
use nub_arch_x86::test_abi::FN_ID_TEST_SMOKE;
use rkyv::primitive::ArchivedU64;

#[test]
fn test_bin_smoke_returns_42() {
    let mut nub = Nub::hyperlight_tests().expect("hyperlight tests bin");
    let bytes = nub.call_raw(FN_ID_TEST_SMOKE, &[]).expect("smoke rpc");
    let mut aligned = rkyv::util::AlignedVec::<16>::with_capacity(bytes.len());
    aligned.extend_from_slice(&bytes);
    let archived =
        rkyv::access::<ArchivedU64, rkyv::rancor::Error>(aligned.as_slice()).expect("rkyv access");
    assert_eq!(archived.to_native(), 42);
}
