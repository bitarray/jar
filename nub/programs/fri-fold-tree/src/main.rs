#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

nub_rt::bump_allocator!(256 * 1024);

/// Endpoint 0 — the original single-shot entry.
///
/// Byte-for-byte what it always was. The pinned `(return_value, gas)`
/// vectors in nub-bench and javm-guest-tests address this endpoint, so
/// its instruction stream must not move; endpoints 1 and 2 below are
/// strictly additive.
#[cfg(target_os = "none")]
#[nub_rt::endpoint(0)]
fn entry(_args_len: u64) -> u64 {
    bench_fri_fold_tree::fri_fold_tree_bench() as u64
}

/// Endpoint 1 — `initialize`: one-time setup, returns 0.
///
/// Present so every program exposes the same two-entry ABI even when,
/// as here, there is nothing to set up.
#[cfg(target_os = "none")]
#[nub_rt::endpoint(1)]
fn initialize(_args_len: u64) -> u64 {
    reset_heap();
    0
}

/// Endpoint 2 — `run`: the measured body, safe to invoke repeatedly on
/// one instance.
///
/// This is what endpoint 0 cannot be: it resets the arena first, so a
/// caller can measure steady-state execution instead of paying a fresh
/// address space per invocation.
#[cfg(target_os = "none")]
#[nub_rt::endpoint(2)]
fn run(_args_len: u64) -> u64 {
    reset_heap();
    bench_fri_fold_tree::fri_fold_tree_bench() as u64
}

#[cfg(not(target_os = "none"))]
fn main() {}
