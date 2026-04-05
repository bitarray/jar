//! Bootstrap no-op JAM service for spec accumulate test vectors.
//!
//! Identical behavior to `spec-minimal` but produces a distinct blob hash
//! (via a distinguishing .rodata byte) so that test vectors can use two
//! different service code hashes.
//!
//! - **Refine**: returns immediately (identity)
//! - **Accumulate**: returns immediately (no host calls, no state changes)

#![cfg_attr(target_env = "javm", no_std)]
#![cfg_attr(target_env = "javm", no_main)]

#[cfg(target_env = "javm")]
mod service {
    use core::arch::global_asm;

    // Single entrypoint. φ[7]=op. Both are no-ops.
    // Load a distinguishing constant so the blob hash differs from minimal.
    global_asm!(
        ".global _start",
        ".type _start, @function",
        "_start:",
        "li t0, 0x42",    // distinguish from minimal blob
        "li t0, 255",     // ecalli(0xFF) = REPLY
        "ecall",
        "unimp",          // trap if resumed
    );

    #[panic_handler]
    fn panic(_: &core::panic::PanicInfo) -> ! {
        loop {}
    }
}

#[cfg(not(target_env = "javm"))]
fn main() {}
