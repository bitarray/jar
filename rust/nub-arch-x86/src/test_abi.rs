//! FN_ID constants for the test/bench guest binaries.
//!
//! These are not part of the production RPC surface — they live in
//! `nub-arch-x86` (not `nub-arch-x86-abi`) and are only exposed by
//! the `nub-arch-x86-tests` and `nub-arch-x86-benches` binaries.
//! Host-side test/bench code (in `nub/tests/`, `nub/benches/`, etc.)
//! imports these constants via the lib.

/// Smoke probe — returns 42u64 rkyv-encoded.
pub const FN_ID_TEST_SMOKE: u32 = 100;

/// Test-only scheduler probe. Payload is two raw `InvokePacket`s concatenated;
/// output is rkyv-encoded `[InvocationResult; 2]`.
pub const FN_ID_TEST_INVOKE_TWO_SERIAL: u32 = 101;

/// Bench: allocate `N` × `Arc<Page>` where `Page` is a 4 KiB
/// page-aligned block.
///
/// - Input: `u32` LE = `N`.
/// - Output: `u64` LE = elapsed RDTSC cycles total. The host
///   divides by `N` to get per-Arc cost.
pub const FN_ID_BENCH_ARC_PAGE_ALLOC: u32 = 200;
