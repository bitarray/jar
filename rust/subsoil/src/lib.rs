//! Guest-side runtime support library for JAVM chain Images.
//!
//! Provides compiler builtins (memset, memcpy, memcmp), a panic
//! handler, and a default trap `_start` (so guests link without
//! defining one themselves).
//!
//! Guests declare their entry points via the
//! `#[subsoil::endpoint(N)]` attribute (from `subsoil-derive`).
//! Each annotation emits a per-endpoint trampoline that calls the
//! user fn and halts; the kernel enters trampolines via
//! `endpoints[N].entry_pc`. `_start` (PC=0) is never an intended
//! entry — it traps via `unimp` if ever reached.
//!
//! All freestanding-only symbols are gated behind `cfg(target_os =
//! "none")` — on host this crate is empty. Services force-link it via
//! `use subsoil as _;`.

#![no_std]

pub use subsoil_derive::endpoint;

/// Descriptor written into the `.subsoil.endpoints` ELF section by
/// the [`endpoint`] attribute macro. The JAVM transpiler reads this
/// section at link time and uses each entry to populate the chain
/// Image's `endpoints: BTreeMap<u8, EndpointDef>` field.
///
/// Layout is `#[repr(C)]` so the transpiler can decode the section
/// as a flat array of fixed-size records. On RISC-V64 the function
/// pointer occupies 8 bytes, followed by 8 bytes of metadata, for a
/// total stride of 16 bytes.
#[repr(C)]
pub struct EndpointDescriptor {
    /// RISC-V address of the endpoint function. The transpiler maps
    /// this to a PVM PC via its instruction-mapping table.
    pub fn_ptr: fn(u64) -> u64,
    /// Endpoint index (key in the chain Image's `endpoints` map).
    pub index: u8,
    /// Caller-supplied register-arg count (per Image::EndpointDef).
    pub arg_registers: u8,
    /// Caller-supplied arg-cnode size (per Image::EndpointDef).
    pub arg_cnode_size: u8,
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

#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe {
        core::arch::asm!("li a0, 0xDEAD", "unimp", options(noreturn));
    }
}

// -- Default `_start` ---------------------------------------------------------
//
// The linker picks `_start` as the default ELF entry symbol. Guests
// never expect PC=0 to be entered at runtime — the kernel always
// enters via `endpoints[N].entry_pc` (a trampoline emitted by
// `#[subsoil::endpoint(N)]`). This default `_start` exists only to
// satisfy the linker and traps loudly if ever reached.
#[cfg(target_env = "javm")]
core::arch::global_asm!(
    ".section .text._start, \"ax\", @progbits",
    ".global _start",
    "_start:",
    "  unimp",
);
