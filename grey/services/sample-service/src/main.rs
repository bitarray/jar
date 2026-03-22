//! Sample JAM service compiled to RISC-V for transpilation to PVM.
//!
//! - **Refine**: echoes input payload as output (identity)
//! - **Accumulate**: writes [0x42] to storage key [0x01] via host_write
//!
//! All entry points are in global_asm to prevent the compiler from
//! optimizing them away. Host call convention: t0 = host call ID before ecall.

#![no_std]
#![no_main]

use core::arch::global_asm;

global_asm!(
    // === _start: default entry ===
    ".global _start",
    ".type _start, @function",
    "_start:",
    "j refine",      // jump to refine by default

    // === refine: echo input as output ===
    // a0 = input_ptr, a1 = input_len (already set by PVM)
    // Just return — a0, a1 are the output.
    ".global refine",
    ".type refine, @function",
    "refine:",
    "ret",

    // === accumulate: write marker to storage ===
    // Allocate stack, store key/value, call host_write, return
    ".global accumulate",
    ".type accumulate, @function",
    "accumulate:",
    "addi sp, sp, -16",     // allocate 16 bytes on stack
    "sd ra, 8(sp)",         // save return address
    "li t0, 0x01",          // key byte
    "sb t0, 0(sp)",         // store at sp+0
    "li t0, 0x42",          // value byte
    "sb t0, 8(sp)",         // store at sp+8
    // host_write(key_ptr=sp, key_len=1, val_ptr=sp+8, val_len=1)
    "mv a0, sp",            // a0 = key_ptr
    "li a1, 1",             // a1 = key_len
    "addi a2, sp, 8",       // a2 = val_ptr
    "li a3, 1",             // a3 = val_len
    "li t0, 4",             // host call ID = 4 (host_write)
    "ecall",                // invoke host
    // Clean up and return
    "ld ra, 8(sp)",         // restore ra
    "addi sp, sp, 16",      // deallocate stack
    "ret",
);

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
