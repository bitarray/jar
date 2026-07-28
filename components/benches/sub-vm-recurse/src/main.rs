#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

use bench_sub_vm_recurse as _;
use nub_rt as _;

#[cfg(target_os = "none")]
mod kernel_abi;

/// Slot holding `Hash(Cap::Image)` for this guest itself — the bench
/// harness pre-populates the top Instance's cnode with the recursive
/// image's hash here, and the in-kernel HOST_CALL handler inherits
/// it into every spawned child's cnode, so each recursion level
/// finds the same image to spawn again.
#[cfg(target_os = "none")]
const SLOT_IMAGE_RECURSE: u8 = 3;

/// Slot the in-kernel `derive_spawn` writes the child's chain hash
/// to; the next `host_call` reads from here.
#[cfg(target_os = "none")]
const SLOT_CHILD: u8 = 6;

#[cfg(target_os = "none")]
const CHILD_ENDPOINT: u8 = 0;

#[cfg(target_os = "none")]
#[nub_rt::endpoint(0)]
fn javm_main(depth: u64) -> u64 {
    use kernel_abi::*;

    if depth == 0 {
        return 0;
    }

    // Derive a fresh Cap::Instance from the recursive image. The
    // kernel's transient-instances table records this; the next
    // host_call resolves SLOT_CHILD against that table.
    unsafe { host_derive_spawn(SLOT_IMAGE_RECURSE, 0, SLOT_CHILD) };

    // CALL the child with `depth - 1`. The kernel maps the parent's
    // φ[9] (a2) onto the child's φ[7] (a0), so the child sees the
    // decremented depth as its `_args_len` argument.
    unsafe { host_call_with_arg(SLOT_CHILD, CHILD_ENDPOINT, depth - 1) };

    // Return depth — bench's host driver mostly ignores the value
    // (it measures wall time), but keep it non-zero so an accidental
    // halt-without-recurse falls out as zero on the harness side.
    depth
}

#[cfg(not(target_os = "none"))]
fn main() {}
