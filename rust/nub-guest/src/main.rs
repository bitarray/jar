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
mod guest {
    use core::sync::atomic::{AtomicU64, Ordering};

    use hyperlight_common::vmem::{BasicMapping, MappingKind, PAGE_SIZE};
    use hyperlight_guest_bin::exception::arch::{Context, ExceptionInfo, HANDLERS};
    use hyperlight_guest_bin::guest_function;

    // === A1: smoke ============================================================

    /// Trivial round-trip. Host calls; guest returns 42.
    /// Validates that build-nub + hyperlight-guest-bin link cleanly
    /// and Hyperlight's host-callable ABI works end-to-end.
    #[guest_function("smoke")]
    pub fn smoke() -> u64 {
        42
    }

    // === B1: read control registers ==========================================

    /// Read CR0, CR4, EFER and pack a summary u64. Confirms ring 0 +
    /// long mode + paging are active.
    #[guest_function("read_cregs")]
    pub fn read_cregs() -> u64 {
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

        let cr0_bits = (cr0 & 0xFFFF) | (((cr0 >> 31) & 1) << 16); // include PG bit
        let cr4_bits = cr4 & 0xFFFF;
        let efer_bits = efer & 0xFFFF;

        cr0_bits | (cr4_bits << 24) | (efer_bits << 40)
    }

    // === B2: read CS selector → confirm CPL=0 ================================

    /// Read CS's RPL bits. CPL=0 confirms ring 0.
    #[guest_function("read_cs_cpl")]
    pub fn read_cs_cpl() -> u64 {
        let cs: u64;
        unsafe {
            core::arch::asm!(
                "mov {0:x}, cs",
                out(reg) cs,
                options(nomem, nostack, preserves_flags),
            );
        }
        cs & 0b11
    }

    // === C1: in-guest #PF round-trip =========================================
    //
    // We install our own page-fault handler at `HANDLERS[14]`,
    // deliberately touch an unmapped page (0x9000_0000), and verify
    // that the handler runs *in-guest* (no VM-exit to the host) by:
    //
    //   1. mapping a fresh phys page at the faulting vaddr,
    //   2. returning `true` so the CPU retries the faulting access,
    //   3. observing the write succeeded (read back the magic value).
    //
    // Reports the rdtsc cycle delta between "before touch" and
    // "after touch" — i.e., the round-trip cost of an in-guest #PF.

    /// Number of times the #PF handler fired during the current call.
    /// Cleared at the start of each `pf_roundtrip()`.
    static PF_COUNT: AtomicU64 = AtomicU64::new(0);

    /// Target vaddr touched by the test. Chosen to be safely above
    /// hyperlight's default guest mappings (heap is around 0x200000+
    /// in the existing layout).
    const TEST_VADDR: u64 = 0x9000_0000;

    fn pf_handler(
        _exception_number: u64,
        _info: *mut ExceptionInfo,
        _ctx: *mut Context,
        gva: u64,
    ) -> bool {
        PF_COUNT.fetch_add(1, Ordering::SeqCst);

        // Map a fresh physical page at the faulting page-aligned address,
        // writable. The handler then returns true so the CPU re-executes
        // the faulting instruction.
        let page_va = gva & !(PAGE_SIZE as u64 - 1);
        let phys = unsafe { hyperlight_guest::prim_alloc::alloc_phys_pages(1) };
        unsafe {
            hyperlight_guest_bin::paging::map_region(
                phys,
                page_va as *mut u8,
                PAGE_SIZE as u64,
                MappingKind::Basic(BasicMapping {
                    readable: true,
                    writable: true,
                    executable: false,
                }),
            );
        }
        true
    }

    /// Install a #PF handler, touch an unmapped page, expect handler
    /// to run in-guest and fix up the mapping. Returns the rdtsc
    /// cycle delta around the faulting write.
    ///
    /// Packed: low 48 bits = cycle delta, high 16 bits = handler count.
    /// Host validates: handler count == 1, readback == 0xCAFEBABE.
    #[guest_function("pf_roundtrip")]
    pub fn pf_roundtrip() -> u64 {
        // Install our handler at the #PF slot (vector 14).
        let handler_addr = pf_handler as *const () as u64;
        HANDLERS[14].store(handler_addr, Ordering::Release);
        PF_COUNT.store(0, Ordering::SeqCst);

        // Touch the unmapped page. First write traps; handler maps it;
        // CPU retries; write succeeds.
        let test_ptr: *mut u64 = TEST_VADDR as *mut u64;
        let t1 = unsafe { core::arch::x86_64::_rdtsc() };
        unsafe {
            core::ptr::write_volatile(test_ptr, 0xCAFE_BABE);
        }
        let t2 = unsafe { core::arch::x86_64::_rdtsc() };

        let cycles = t2 - t1;
        let count = PF_COUNT.load(Ordering::SeqCst);
        (count << 48) | (cycles & 0x0000_FFFF_FFFF_FFFF)
    }

    /// Read back the value written to `TEST_VADDR` during the
    /// `pf_roundtrip` test. Used by the host to confirm the page is
    /// now mapped + the write went through.
    #[guest_function("pf_readback")]
    pub fn pf_readback() -> u64 {
        let test_ptr: *const u64 = TEST_VADDR as *const u64;
        unsafe { core::ptr::read_volatile(test_ptr) }
    }
}

// === Linker stubs =========================================================

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
