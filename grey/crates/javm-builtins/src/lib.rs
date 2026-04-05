//! Shared builtins for freestanding RISC-V service crates.
//!
//! Provides compiler builtins (memset, memcpy, memcmp), a panic handler,
//! and an entry point macro for JAVM/PolkaVM targets.
//!
//! All symbols are gated behind `cfg(target_os = "none")` — on host this
//! crate is empty. Services force-link it via `use javm_builtins as _;`.

#![no_std]

// -- Compiler builtins (freestanding targets only) ----------------------------

#[cfg(target_os = "none")]
mod builtins {
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn memset(dst: *mut u8, val: i32, n: usize) -> *mut u8 {
        let mut i = 0;
        while i < n {
            unsafe { *dst.add(i) = val as u8 };
            i += 1;
        }
        dst
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
        let mut i = 0;
        while i < n {
            unsafe { *dst.add(i) = *src.add(i) };
            i += 1;
        }
        dst
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
        let mut i = 0;
        while i < n {
            let a = unsafe { *s1.add(i) };
            let b = unsafe { *s2.add(i) };
            if a != b {
                return a as i32 - b as i32;
            }
            i += 1;
        }
        0
    }
}

// -- Panic handler (freestanding targets only) --------------------------------

#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe {
        core::arch::asm!("li a0, 0xDEAD", "unimp", options(noreturn));
    }
}

// -- Entry point macro --------------------------------------------------------

/// Generate a `_start` entry point for JAVM and PolkaVM targets.
///
/// On JAVM: `_start` calls the named function, then terminates via
/// `ecalli(0xFF)` (REPLY to kernel), followed by `unimp` (trap if resumed).
/// On PolkaVM: `_start` is `unimp` (polkavm uses exported functions directly).
/// On host: expands to nothing.
///
/// Usage: `javm_builtins::javm_entry!(my_bench_fn);`
#[macro_export]
macro_rules! javm_entry {
    ($fn_name:ident) => {
        #[cfg(target_env = "javm")]
        core::arch::global_asm!(
            ".global _start",
            "_start:",
            // a0=φ[7]=op, a1=φ[8]=args_base, a2=φ[9]=args_len — passed directly
            concat!("call ", stringify!($fn_name)),
            // REPLY to kernel: li t0, 255; ecall → transpiles to ecalli(0xFF)
            "li t0, 255",
            "ecall",
            "unimp", // trap if somehow resumed after REPLY
        );
        #[cfg(target_env = "polkavm")]
        core::arch::global_asm!(".global _start", "_start:", "unimp",);
    };
}
