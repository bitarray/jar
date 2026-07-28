//! Guest-side runtime support for PVM2 programs.
//!
//! Provides compiler builtins (memset, memcpy, memcmp), a panic
//! handler, and a default trap `_start` (so guests link without
//! defining one themselves).
//!
//! Programs that need `alloc` get it from
//! [`bump_allocator!`](crate::bump_allocator), which installs a
//! resettable bump arena.
//!
//! Personality-free: a program built against this crate is a plain
//! PVM2 program. Whether the engine running it has a capability system
//! is not its concern.
//!
//! Guests declare their entry points via the
//! `#[nub_rt::endpoint(N)]` attribute (from `nub-rt-macro`).
//! Each annotation emits a per-endpoint trampoline that calls the
//! user fn and halts; the kernel enters trampolines via
//! `endpoints[N].entry_pc`. `_start` (PC=0) is never an intended
//! entry — it traps via `unimp` if ever reached.
//!
//! All freestanding-only symbols are gated behind `cfg(target_os =
//! "none")` — on host this crate is empty. Services force-link it via
//! `use nub_rt as _;`.
//!
//! `target_os = "none"` is the freestanding-target test throughout;
//! the guest target JSON sets it. The RISC-V-specific bits (panic
//! handler, `_start`) additionally require `target_arch = "riscv64"`,
//! because `x86_64-unknown-none` is also `target_os = "none"` and
//! must never see this crate's `unimp`.

#![no_std]

pub mod alloc;

pub use nub_rt_macro::endpoint;

/// Descriptor written into the `.nub.endpoints` ELF section by the
/// [`endpoint`] attribute macro. `nub-linker` reads this section at
/// link time and turns each record into a
/// `nub_program::ProgramBlob::endpoints` entry.
///
/// Layout is `#[repr(C)]` so the linker can decode the section as a
/// flat array of fixed-size records. On RISC-V64 the function pointer
/// occupies 8 bytes, followed by 8 bytes of metadata, for a total
/// stride of 16 bytes.
#[repr(C)]
pub struct EndpointDescriptor {
    /// RISC-V address of the endpoint function. The linker maps this
    /// to a PVM PC via its instruction-mapping table.
    pub fn_ptr: fn(u64) -> u64,
    /// Endpoint index (key in the program's `endpoints` map).
    pub index: u8,
    /// Number of register args the caller supplies.
    pub arg_registers: u8,
    /// Opaque metadata byte, passed through to
    /// `nub_program::Endpoint::arg_meta`. nub does not interpret it; a
    /// personality may (JAVM reads it as the arg-cnode size).
    pub arg_meta: u8,
    /// Reserved for alignment / future expansion.
    pub _pad: [u8; 5],
}

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

// The `_start` trampoline and the endpoint ABI below are RISC-V-only by
// construction — they emit `unimp`. Fail loudly rather than silently
// dropping a panic handler if this is ever built for some *other*
// freestanding target.
//
// `bpf` is admitted as a second freestanding arch purely so the
// benchmark kernels can be cross-compiled for Solana's sBPF in
// `bench-compare`. That build uses only `mod builtins` above — sBPF has
// no libc, and Solana's `sol_memcpy_` is a platform-tools syscall we
// cannot call — and its own entry shim, never `_start` or
// `#[nub_rt::endpoint]`. `compile_error!` emits no code, so widening
// this leaves every existing target byte-identical.
#[cfg(all(
    target_os = "none",
    not(any(target_arch = "riscv64", target_arch = "bpf"))
))]
compile_error!("nub_rt supports the freestanding riscv64 (PVM2) and bpf (sBPF) guest targets only");

#[cfg(all(target_os = "none", target_arch = "riscv64"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe {
        core::arch::asm!("li a0, 0xDEAD", "unimp", options(noreturn));
    }
}

/// sBPF has no trap instruction reachable from Rust, so a panic spins.
/// The VM's instruction meter is what actually stops it — and a
/// benchmark kernel that panics is a bug we want to see as a timeout
/// rather than a silent wrong answer.
#[cfg(all(target_os = "none", target_arch = "bpf"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

// -- Default `_start` ---------------------------------------------------------
//
// The linker picks `_start` as the default ELF entry symbol. Guests
// never expect PC=0 to be entered at runtime — the kernel always
// enters via `endpoints[N].entry_pc` (a trampoline emitted by
// `#[nub_rt::endpoint(N)]`). This default `_start` exists only to
// satisfy the linker and traps loudly if ever reached.
#[cfg(all(target_os = "none", target_arch = "riscv64"))]
core::arch::global_asm!(
    ".section .text._start, \"ax\", @progbits",
    ".global _start",
    "_start:",
    "  unimp",
);
