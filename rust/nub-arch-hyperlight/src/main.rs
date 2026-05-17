//! Nub Arch implementation for Hyperlight: a bare-metal guest binary
//! that runs the kernel on real CPU + MMU. Today this crate hosts the
//! ring-0 spike test functions that proved the Hyperlight substrate
//! works; the actual `Arch` impl plus the kernel will land in
//! follow-up commits.
//!
//! Built with `nub-build` → `cargo build --target=x86_64-unknown-none`.
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
    /// Validates that nub-build + hyperlight-guest-bin link cleanly
    /// and Hyperlight's host-callable ABI works end-to-end.
    #[guest_function("smoke")]
    pub fn smoke() -> u64 {
        42
    }

    // === nub-handle skeleton smoke ===========================================

    /// Skeleton stand-in for the Nub-handle `invoke` RPC. The host's
    /// `Nub::new_hyperlight().invoke(...)` calls into this. Returns 42
    /// to match `nub_arch_local::LocalArch`'s stubbed return value, so
    /// both backends look identical to the test harness. Real
    /// invocation dispatch — driven by `Kernel<HyperlightArch>` in the
    /// guest — lands in a follow-up commit.
    #[guest_function("nub_smoke")]
    pub fn nub_smoke() -> u64 {
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

    // === C2: CR3 read/write (self-swap) ======================================
    //
    // Demonstrates that the guest can manipulate the page-table base
    // register at ring 0. We read CR3, write it back to itself (a
    // TLB flush no-op), and read it again. Returns the CR3 value if
    // both reads agree; 0 otherwise.
    //
    // A real microkernel uses CR3 swaps to switch between sub-Instance
    // address spaces. Proving the instruction works is what we need
    // here; the prototype doesn't build a second page table.

    #[guest_function("cr3_self_swap")]
    pub fn cr3_self_swap() -> u64 {
        let cr3_before: u64;
        let cr3_after: u64;
        unsafe {
            core::arch::asm!(
                "mov {0}, cr3",
                "mov cr3, {0}",
                "mov {1}, cr3",
                out(reg) cr3_before,
                out(reg) cr3_after,
                options(nostack, preserves_flags),
            );
        }
        if cr3_before == cr3_after && cr3_before != 0 {
            cr3_before
        } else {
            0
        }
    }

    // === D1: per-call latency bench ===========================================
    //
    // Measures rdtsc cycles for `n` host-callable function invocations.
    // The actual measurement happens host-side; this function exists
    // only as a no-op target to drive the call loop. Returns 0.

    #[guest_function("noop")]
    pub fn noop() -> u64 {
        0
    }

    // === D2: CoW round-trip ===================================================
    //
    // Remap an existing (already-mapped) page as read-only, write to
    // it, observe the in-guest #PF handler flip it back to writable,
    // CPU retries, write succeeds. This is the per-page cost of
    // `mgmt_copy` divergence — the actual CoW flip, distinct from
    // the demand-paging cost measured in C1.
    //
    // Uses the page we mapped during pf_roundtrip (TEST_VADDR is now
    // a normally-mapped writable page).

    fn cow_handler(
        _exception_number: u64,
        _info: *mut ExceptionInfo,
        _ctx: *mut Context,
        gva: u64,
    ) -> bool {
        PF_COUNT.fetch_add(1, Ordering::SeqCst);

        // Find the existing physical mapping for the faulting page
        // and re-establish it as writable. We're not actually
        // copying anything (CoW would normally copy the page); we
        // just flip the writable bit. That's the "fast path" cost.
        let page_va = gva & !(PAGE_SIZE as u64 - 1);
        let mappings: alloc::vec::Vec<_> =
            hyperlight_guest_bin::paging::virt_to_phys(page_va).collect();
        if let Some(m) = mappings.first() {
            unsafe {
                hyperlight_guest_bin::paging::map_region(
                    m.phys_base,
                    page_va as *mut u8,
                    PAGE_SIZE as u64,
                    MappingKind::Basic(BasicMapping {
                        readable: true,
                        writable: true,
                        executable: false,
                    }),
                );
            }
        }
        true
    }

    /// Pre-condition: `pf_roundtrip` has already run, so `TEST_VADDR`
    /// is mapped writable. We re-map it read-only, install the CoW
    /// handler, write to it, expect handler to flip RO→RW, retry,
    /// succeed. Returns the cycle delta around the faulting write.
    #[guest_function("cow_roundtrip")]
    pub fn cow_roundtrip() -> u64 {
        // Find existing mapping, re-map as read-only.
        let page_va = TEST_VADDR;
        let mappings: alloc::vec::Vec<_> =
            hyperlight_guest_bin::paging::virt_to_phys(page_va).collect();
        let Some(m) = mappings.first() else {
            return u64::MAX; // mapping not found — pf_roundtrip didn't run?
        };
        unsafe {
            hyperlight_guest_bin::paging::map_region(
                m.phys_base,
                page_va as *mut u8,
                PAGE_SIZE as u64,
                MappingKind::Basic(BasicMapping {
                    readable: true,
                    writable: false,
                    executable: false,
                }),
            );
            // Flush TLB by reloading CR3.
            let cr3: u64;
            core::arch::asm!("mov {0}, cr3; mov cr3, {0}", out(reg) cr3);
            let _ = cr3;
        }

        // Install the CoW handler at #PF.
        let handler_addr = cow_handler as *const () as u64;
        HANDLERS[14].store(handler_addr, Ordering::Release);
        PF_COUNT.store(0, Ordering::SeqCst);

        // Trigger CoW write fault.
        let test_ptr: *mut u64 = TEST_VADDR as *mut u64;
        let t1 = unsafe { core::arch::x86_64::_rdtsc() };
        unsafe {
            core::ptr::write_volatile(test_ptr, 0xDEAD_BEEF);
        }
        let t2 = unsafe { core::arch::x86_64::_rdtsc() };

        let cycles = t2 - t1;
        let count = PF_COUNT.load(Ordering::SeqCst);
        (count << 48) | (cycles & 0x0000_FFFF_FFFF_FFFF)
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
