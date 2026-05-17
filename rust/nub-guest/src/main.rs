//! Bare-metal Hyperlight guest for the `nub` ring-0 spike.
//!
//! Built with `build-nub` → `cargo build --target=x86_64-unknown-none`.
//! Links against `hyperlight-guest-bin` with `default-features = false`
//! (no picolibc, no C). Entry point is `entrypoint` (provided by
//! `hyperlight-guest-bin`), which initialises the heap + GDT + IDT
//! then calls `hyperlight_main`. We don't define `hyperlight_main`
//! ourselves; the weak default in `hyperlight-guest-bin` is fine.
//!
//! Guest functions are registered via `#[guest_function]`, which
//! uses `linkme` to slot them into a static `GuestFunctionRegister`
//! at compile time. The host invokes them by name via Hyperlight's
//! `OUT`-port + shared-memory function-call ABI.
//!
//! On host targets (target_os != "none") this crate compiles to a
//! trivial empty `main` so `cargo build --workspace` succeeds
//! without dragging hyperlight-guest deps onto host platforms.
//! Only `cargo build --target=x86_64-unknown-none` produces a real
//! Hyperlight guest binary.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
extern crate alloc;
#[cfg(target_os = "none")]
extern crate hyperlight_guest_bin;

#[cfg(target_os = "none")]
use hyperlight_guest_bin::guest_function;

// === A1: smoke =============================================================

/// Trivial round-trip. Host calls; guest returns 42.
/// Validates that build-nub + hyperlight-guest-bin link cleanly
/// and Hyperlight's host-callable ABI works end-to-end.
#[cfg(target_os = "none")]
#[guest_function("smoke")]
fn smoke() -> u64 {
    42
}

// === B1: read control registers ============================================

/// Read CR0, CR4, EFER and pack a summary u64. Confirms ring 0 +
/// long mode + paging are active.
///
/// Packed return value (LE bytes 0..6 used):
/// * byte 0: CR0 low byte — PE=bit0, MP=bit1, ET=bit4, NE=bit5, WP=bit16(?), AM=bit18
/// * byte 1: CR0 high byte (just the PG bit at bit 31 of CR0 → high byte top bit)
/// * byte 2: CR4 low byte — PAE=bit5, OSFXSR=bit9
/// * byte 3: CR4 high byte
/// * byte 4: EFER low byte — SCE=bit0
/// * byte 5: EFER high byte — LME=bit8, LMA=bit10, NX=bit11
///
/// Decoder runs on the host side and prints a human summary.
#[cfg(target_os = "none")]
#[guest_function("read_cregs")]
fn read_cregs() -> u64 {
    let cr0: u64;
    let cr4: u64;
    let efer_lo: u32;
    let efer_hi: u32;
    unsafe {
        core::arch::asm!(
            "mov {0}, cr0",
            "mov {1}, cr4",
            "mov ecx, 0xC0000080",
            "rdmsr",
            out(reg) cr0,
            out(reg) cr4,
            out("eax") efer_lo,
            out("edx") efer_hi,
            out("ecx") _,
        );
    }
    let efer = (efer_lo as u64) | ((efer_hi as u64) << 32);

    // Pack: bytes 0..2 = CR0 low 16 bits, byte 2 = CR0 PG bit indicator,
    // bytes 3..5 = CR4 low 16 bits, bytes 6..8 = EFER low 16 bits.
    // Use a simple LE encoding so the host can decode without parsing
    // bit-by-bit.
    let cr0_bits = (cr0 & 0xFFFF) | (((cr0 >> 31) & 1) << 16); // include PG bit
    let cr4_bits = cr4 & 0xFFFF;
    let efer_bits = efer & 0xFFFF;

    cr0_bits | (cr4_bits << 24) | (efer_bits << 40)
}

// === B2: read CS selector → confirm CPL=0 =================================

/// Read the CS segment register's low 3 bits = (RPL, TI, ...).
/// The bottom 2 bits are CPL. CPL=0 confirms ring 0.
#[cfg(target_os = "none")]
#[guest_function("read_cs_cpl")]
fn read_cs_cpl() -> u64 {
    let cs: u64;
    unsafe {
        core::arch::asm!("mov {0:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags));
    }
    cs & 0b11
}

// === Linker stubs ==========================================================

/// `hyperlight_guest_bin::generic_init` unconditionally calls
/// `srand` to seed picolibc's PRNG. With `default-features = false`
/// (no `libc` feature) there is no picolibc to provide that
/// symbol. We don't use libc rand-functions, so a no-op stub is
/// sufficient to satisfy the linker.
#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
pub extern "C" fn srand(_seed: u32) {}

#[cfg(not(target_os = "none"))]
fn main() {}
