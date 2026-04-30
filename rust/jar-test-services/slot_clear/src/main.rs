//! Slot-clear smoke fixture for the JAR minimum kernel.
//!
//! Phase-aware: φ[7] (a0) at entry encodes the phase set by the kernel —
//! 0 = step-2 (`AggregateStandalone`) → halt without slot side-effects.
//! 1 = step-3 (`AggregateMerge`) → ecalli 19 (`HostCall::SlotClear`), then halt.
//!
//! The two ecallis at the tail are: `ecalli 19` (SlotClear → ProtocolCall to
//! the host) and `ecalli 0` (CALL IPC slot = REPLY = halt at root).

#![cfg_attr(target_env = "javm", no_std)]
#![cfg_attr(target_env = "javm", no_main)]

#[cfg(target_env = "javm")]
mod service {
    use core::arch::global_asm;

    global_asm!(
        ".global _start",
        ".type _start, @function",
        "_start:",
        "li t1, 1",
        "bne a0, t1, 1f",
        "li t0, 19",
        "ecall",
        "1:",
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
