//! Javm-private FN_ID constants for the test guest binary.
//!
//! Band policy: the nub substrate owns fn_id space `[0, 0x100)`
//! (production ids in `nub-arch-x86-abi`, generic probes in
//! `nub_arch_x86::test_abi`); each personality owns `[0x100, ...)`.
//! These ids are exposed only by the `javm-guest-x86-tests` binary;
//! host-side test drivers import them via this lib.

/// Javm scheduler probe: runs two top-level invokes through one in-guest
/// `KernelScheduler` (`call_loop::run_two_for_test`). Payload is two raw
/// `InvokePacket`s concatenated; output is rkyv-encoded
/// `[InvocationResult; 2]`.
pub const FN_ID_TEST_INVOKE_TWO_SERIAL: u32 = 0x100;
