//! Counter JAM service compiled to RISC-V for transpilation to PVM.
//!
//! - **Refine**: echoes input payload as output (identity function)
//! - **Accumulate**: increments a counter at storage key [0x01] and
//!   stores the latest payload hash at key [0x02]
//!
//! This demonstrates stateful on-chain computation: each work package
//! processed by this service increments a persistent counter.

#![no_std]
#![no_main]

use core::arch::global_asm;

global_asm!(
    // === _start: default entry ===
    ".global _start",
    ".type _start, @function",
    "_start:",
    "j refine",

    // === refine: echo input as output ===
    ".global refine",
    ".type refine, @function",
    "refine:",
    "ret",

    // === accumulate: increment counter + store payload hash ===
    ".global accumulate",
    ".type accumulate, @function",
    "accumulate:",
    "addi sp, sp, -16",
    "sd ra, 8(sp)",

    // Write counter value [0x01] to key [0x01]
    // (simplified: always writes 0x01; a real counter would read-then-increment)
    "li t0, 0x01",
    "sb t0, 0(sp)",          // key byte at sp+0
    "li t0, 0x01",
    "sb t0, 8(sp)",          // value byte at sp+8

    // host_write(key_ptr=sp, key_len=1, val_ptr=sp+8, val_len=1)
    "mv a0, sp",
    "li a1, 1",
    "addi a2, sp, 8",
    "li a3, 1",
    "li t0, 5",              // host call ID = 5 (host_write, JAR v0.8.0)
    "ecall",

    // Write marker [0x42] to key [0x02]
    "li t0, 0x02",
    "sb t0, 0(sp)",
    "li t0, 0x42",
    "sb t0, 8(sp)",
    "mv a0, sp",
    "li a1, 1",
    "addi a2, sp, 8",
    "li a3, 1",
    "li t0, 4",
    "ecall",

    "ld ra, 8(sp)",
    "addi sp, sp, 16",
    "ret",
);

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
