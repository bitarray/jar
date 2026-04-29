//! Halt smoke fixture for the JAR minimum kernel.
//!
//! Issues `ecalli 0` (CALL the IPC slot = REPLY) immediately. At root level
//! this halts the VM with `KernelResult::Halt(φ[7])`.

#![cfg_attr(target_env = "javm", no_std)]
#![cfg_attr(target_env = "javm", no_main)]

#[cfg(target_env = "javm")]
mod service {
    use core::arch::global_asm;

    global_asm!(
        ".global _start",
        ".type _start, @function",
        "_start:",
        "li t0, 0",
        "ecall",
        "unimp",
    );

    #[panic_handler]
    fn panic(_: &core::panic::PanicInfo) -> ! {
        loop {}
    }
}

#[cfg(not(target_env = "javm"))]
fn main() {}
