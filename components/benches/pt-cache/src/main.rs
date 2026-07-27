#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

use bench_pt_cache as _;
use subsoil as _;

#[cfg(target_os = "none")]
mod kernel_abi;

/// Image slot `derive_spawn` reads to find the child's image. Left
/// empty in this guest, so the kernel falls back to the running
/// frame's own image — the child `B` is another Instance of *this*
/// image, entered at the echo endpoint.
#[cfg(target_os = "none")]
const SLOT_IMAGE: u8 = 3;

/// Slot the spawned child `B` lives in (`Owned`); HALT folds the
/// updated child back here after each CALL, so it stays resident.
#[cfg(target_os = "none")]
const SLOT_CHILD: u8 = 6;

/// Endpoint index of the echo function — what the caller CALLs.
#[cfg(target_os = "none")]
const ECHO_ENDPOINT: u8 = 1;

/// Endpoint 0 — caller `A`. Spawn the resident child `B` once, then
/// `host_call` its echo endpoint `n` times, summing the echoes.
/// Returns `Σ_{i<n} i = n·(n−1)/2`, which the harness checks. The
/// accumulator stays in a register (no data-region store), so `A`
/// triggers no CoW of its own — the run measures only the per-CALL
/// frame round-trip into the resident `B`.
#[cfg(target_os = "none")]
#[subsoil::endpoint(0)]
fn caller(n: u64) -> u64 {
    use kernel_abi::*;

    // Mint the resident child once. host_call below moves it out and
    // HALT folds it back into SLOT_CHILD, so every iteration re-CALLs
    // the same B.
    unsafe { host_derive_spawn(SLOT_IMAGE, 0, SLOT_CHILD) };

    let mut acc = 0u64;
    let mut i = 0u64;
    while i < n {
        acc = acc.wrapping_add(unsafe { host_call_ret(SLOT_CHILD, ECHO_ENDPOINT, i) });
        i += 1;
    }
    acc
}

/// Endpoint 1 — echo `B`. Return the caller-threaded argument
/// (`φ[7]`) unchanged. No data-region access ⇒ no CoW, no
/// per-instance page-table delta.
#[cfg(target_os = "none")]
#[subsoil::endpoint(1)]
fn echo(arg: u64) -> u64 {
    arg
}

#[cfg(not(target_os = "none"))]
fn main() {}
