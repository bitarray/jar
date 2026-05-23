#![cfg_attr(target_env = "javm", no_std)]
#![cfg_attr(target_env = "javm", no_main)]

use bench_sub_vm_data_recurse as _;
use subsoil as _;

#[cfg(target_env = "javm")]
mod kernel_abi;

/// 64 KiB pinned-slot RO blob. Compile-time `.rodata` initialisation
/// gives the linker a stable section to map; subsoil picks it up
/// and emits a `MemoryMapping` pointing at a pinned `Cap::Data`.
#[cfg(all(target_env = "javm", target_os = "none"))]
static RO_DATA: [u8; RO_DATA_SIZE] = make_ro_pattern();
#[cfg(all(target_env = "javm", target_os = "none"))]
const RO_DATA_SIZE: usize = 65536;

#[cfg(all(target_env = "javm", target_os = "none"))]
const fn make_ro_pattern() -> [u8; RO_DATA_SIZE] {
    let mut arr = [0u8; RO_DATA_SIZE];
    let mut i = 0;
    while i < RO_DATA_SIZE {
        arr[i] = (i & 0xFF) as u8;
        i += 1;
    }
    arr
}

/// 4 KiB initial-slot RW blob — exercises the CoW write path. The
/// non-zero initialiser keeps the linker from collapsing it into
/// `.bss` (which would render the slot ephemeral, not CoW-armed).
#[cfg(all(target_env = "javm", target_os = "none"))]
static mut RW_DATA: [u8; RW_DATA_SIZE] = make_rw_init();
#[cfg(all(target_env = "javm", target_os = "none"))]
const RW_DATA_SIZE: usize = 4096;

#[cfg(all(target_env = "javm", target_os = "none"))]
const fn make_rw_init() -> [u8; RW_DATA_SIZE] {
    let mut arr = [0u8; RW_DATA_SIZE];
    let mut i = 0;
    while i < RW_DATA_SIZE {
        arr[i] = 0xAA;
        i += 1;
    }
    arr
}

#[cfg(all(target_env = "javm", target_os = "none"))]
const SLOT_IMAGE_RECURSE: u8 = 3;

#[cfg(all(target_env = "javm", target_os = "none"))]
const SLOT_CHILD: u8 = 6;

#[cfg(all(target_env = "javm", target_os = "none"))]
const CHILD_ENDPOINT: u8 = 0;

/// One read sample per 64 bytes — keeps the bench fast while still
/// touching every page in the 64 KiB pinned RO blob (16 pages × 64
/// samples = 1024 reads per level).
#[cfg(all(target_env = "javm", target_os = "none"))]
const RO_STRIDE: usize = 64;

#[cfg(all(target_env = "javm", target_os = "none"))]
#[subsoil::endpoint(0)]
fn javm_main(depth: u64) -> u64 {
    use kernel_abi::*;

    // Sum every RO_STRIDE-th byte of the pinned RO mapping. The
    // direct-mapping change (Commit 2) makes these reads pull
    // straight from the shared cache page; without it every
    // recursion level memcpy'd the 64 KiB into its private mem_buf.
    let mut sum: u64 = 0;
    let ptr = (&raw const RO_DATA) as *const u8;
    let mut i = 0usize;
    while i < RO_DATA_SIZE {
        // SAFETY: `i < RO_DATA_SIZE` and ptr is the start of the static.
        sum = sum.wrapping_add(unsafe { *ptr.add(i) } as u64);
        i += RO_STRIDE;
    }

    // Single CoW-triggering write into the initial-slot RW blob.
    // Commit 4 catches this fault, allocates a fresh page, copies
    // from the cap, rewrites the PTE writable, and tracks the dirty
    // page in `frame.dirty_pages` for the auto-mint step (Commit 5).
    // The follow-up read folds RW_DATA into the return value so the
    // linker can't dead-code-eliminate the whole static.
    let wptr = (&raw mut RW_DATA) as *mut u8;
    // SAFETY: `wptr` is the start of `RW_DATA`, aligned 4 KiB by
    // virtue of being a 4 KiB static.
    unsafe { core::ptr::write_volatile(wptr, (depth & 0xFF) as u8) };
    sum = sum.wrapping_add(unsafe { core::ptr::read_volatile(wptr) } as u64);

    if depth == 0 {
        return sum;
    }

    // Derive + CALL a child; child sees `depth - 1` in φ[7].
    unsafe { host_derive_spawn(SLOT_IMAGE_RECURSE, 0, SLOT_CHILD) };
    unsafe { host_call_with_arg(SLOT_CHILD, CHILD_ENDPOINT, depth - 1) };

    sum
}

#[cfg(not(target_env = "javm"))]
fn main() {}
