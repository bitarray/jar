//! FN_ID constants for personality-independent test/bench guest probes.
//!
//! Band policy: the nub substrate owns fn_id space `[0, 0x100)`
//! (production ids in `nub-arch-x86-abi`, generic probes here); each
//! personality owns `[0x100, ...)` in its own `test_abi` (e.g.
//! `javm_guest_x86::test_abi`). The probes below are RPC-plumbing /
//! allocator checks with no personality dependency — nub defines the
//! id + contract; the personality's test/bench binaries host the
//! registrations (only personality crates produce guest binaries).

/// Smoke probe — returns 42u64 rkyv-encoded.
pub const FN_ID_TEST_SMOKE: u32 = 100;

/// Bench: allocate `N` × `Arc<Page>` where `Page` is a 4 KiB
/// page-aligned block.
///
/// - Input: `u32` LE = `N`.
/// - Output: `u64` LE = elapsed RDTSC cycles total. The host
///   divides by `N` to get per-Arc cost.
pub const FN_ID_BENCH_ARC_PAGE_ALLOC: u32 = 200;
