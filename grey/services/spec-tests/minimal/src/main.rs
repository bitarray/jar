//! Minimal no-op JAM service for spec accumulate test vectors.
//!
//! - **Refine**: returns immediately (identity)
//! - **Accumulate**: returns immediately (no host calls, no state changes)

#![cfg_attr(target_env = "javm", no_std)]
#![cfg_attr(target_env = "javm", no_main)]

#[cfg(target_env = "javm")]
mod service {
    use core::arch::global_asm;

    // Single entrypoint. φ[7]=op (0=refine, 1=accumulate). Both are no-ops.
    global_asm!(
        ".global _start",
        ".type _start, @function",
        "_start:",
        "li t0, 255", // ecalli(0xFF) = REPLY
        "ecall",
        "unimp", // trap if resumed
    );

    #[panic_handler]
    fn panic(_: &core::panic::PanicInfo) -> ! {
        loop {}
    }
}

#[cfg(not(target_env = "javm"))]
fn main() {}
