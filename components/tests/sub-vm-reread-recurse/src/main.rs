#![cfg_attr(target_env = "javm", no_std)]
#![cfg_attr(target_env = "javm", no_main)]

use subsoil as _;
use test_sub_vm_reread_recurse as _;

#[cfg(target_env = "javm")]
mod kernel_abi;

/// 64 KiB pinned-slot RO blob — `RO_DATA[i] = i & 0xFF`. subsoil emits a
/// pinned `MemoryMapping` over this `.rodata` static; the kernel maps the
/// backing `Cap::Data` read-only into every frame's page table.
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

/// 4 KiB initial-slot RW blob — non-zero initialiser keeps the linker from
/// collapsing it into `.bss` (which would make the slot ephemeral, not
/// CoW-armed).
#[cfg(all(target_env = "javm", target_os = "none"))]
static mut RW_DATA: [u8; RW_DATA_SIZE] = make_rw_init();
#[cfg(all(target_env = "javm", target_os = "none"))]
const RW_DATA_SIZE: usize = 4096;

#[cfg(all(target_env = "javm", target_os = "none"))]
const fn make_rw_init() -> [u8; RW_DATA_SIZE] {
    [0xAA; RW_DATA_SIZE]
}

#[cfg(all(target_env = "javm", target_os = "none"))]
const SLOT_IMAGE_RECURSE: u8 = 3;
#[cfg(all(target_env = "javm", target_os = "none"))]
const SLOT_CHILD: u8 = 6;
#[cfg(all(target_env = "javm", target_os = "none"))]
const CHILD_ENDPOINT: u8 = 0;
#[cfg(all(target_env = "javm", target_os = "none"))]
const RO_STRIDE: usize = 64;

/// Sum every `RO_STRIDE`-th byte of the pinned RO mapping (touches every page
/// of the 64 KiB blob → materializes its RO unit). Constant per level
/// (`= 256 × (0+64+128+192) = 98_304`).
#[cfg(all(target_env = "javm", target_os = "none"))]
#[inline(never)]
fn ro_sum() -> u64 {
    let mut sum: u64 = 0;
    let ptr = (&raw const RO_DATA) as *const u8;
    let mut i = 0usize;
    while i < RO_DATA_SIZE {
        // SAFETY: `i < RO_DATA_SIZE`, `ptr` is the start of the static.
        sum = sum.wrapping_add(unsafe { *ptr.add(i) } as u64);
        i += RO_STRIDE;
    }
    sum
}

/// Read byte 0 of the RW page.
#[cfg(all(target_env = "javm", target_os = "none"))]
#[inline(never)]
fn rw_read() -> u64 {
    let wptr = (&raw mut RW_DATA) as *const u8;
    // SAFETY: `wptr` is the start of the 4 KiB `RW_DATA` static.
    unsafe { core::ptr::read_volatile(wptr) as u64 }
}

/// CoW-write byte 0 of the RW page.
#[cfg(all(target_env = "javm", target_os = "none"))]
#[inline(never)]
fn rw_write(v: u8) {
    let wptr = (&raw mut RW_DATA) as *mut u8;
    // SAFETY: `wptr` is the start of the 4 KiB `RW_DATA` static.
    unsafe { core::ptr::write_volatile(wptr, v) };
}

/// Recurse, **re-reading memory after the child returns**.
///
/// Down: read the RO blob + CoW-write & read the RW page (materializes this
/// level's RO unit and CoW page). After `host_call` returns and this level
/// resumes: re-read both, exercising the category-#3 path on the way up too.
/// Each level's charge is therefore identical, so total gas is affine in depth
/// (the property `tests/sub_vm_gas_parity.rs` pins).
///
/// Returns a deterministic fold so the harness can value-check the run:
///   * depth 0    → `RO_SUM + (depth & 0xFF)`
///   * depth > 0  → `2*RO_SUM + 2*(depth & 0xFF)`  (the post-resume re-reads).
#[cfg(all(target_env = "javm", target_os = "none"))]
#[subsoil::endpoint(0)]
fn javm_main(depth: u64) -> u64 {
    use kernel_abi::*;

    let mut acc = ro_sum();
    rw_write((depth & 0xFF) as u8);
    acc = acc.wrapping_add(rw_read());

    if depth == 0 {
        return acc;
    }

    unsafe { host_derive_spawn(SLOT_IMAGE_RECURSE, 0, SLOT_CHILD) };
    unsafe { host_call_with_arg(SLOT_CHILD, CHILD_ENDPOINT, depth - 1) };

    // Post-resume re-read: exercises category-#3 on the way up.
    acc = acc.wrapping_add(ro_sum());
    acc = acc.wrapping_add(rw_read());
    acc
}

#[cfg(not(target_env = "javm"))]
fn main() {}
