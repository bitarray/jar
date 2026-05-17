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
mod bump;
#[cfg(target_os = "none")]
mod jit_run;
#[cfg(target_os = "none")]
mod paging;
#[cfg(target_os = "none")]
mod ring3;
#[cfg(target_os = "none")]
mod segments;

#[cfg(target_os = "none")]
mod guest {
    use crate::bump::BumpArena;
    use crate::paging::{self, PageTable, Perm};
    use crate::ring3;
    use crate::segments;
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

    // === A2: int 0x80 IDT handler ===========================================

    /// Counter incremented by the int 0x80 handler. Tests inspect
    /// this after triggering `int 0x80` to verify the patched IDT
    /// is being used.
    static INT80_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Rust-side body of the int 0x80 handler. Called by the asm
    /// stub `nub_int80_stub` (see `global_asm!` below) after
    /// register state is saved. Increments the counter and returns;
    /// the asm stub restores state and `iretq`s.
    #[unsafe(no_mangle)]
    pub extern "C" fn nub_int80_rust() {
        INT80_COUNTER.fetch_add(1, Ordering::SeqCst);
    }

    // Assembly stub for vector 0x80. Saves caller-saved registers,
    // calls `nub_int80_rust`, restores, `iretq`s. Tagged `.global`
    // so the IDT can take its address.
    core::arch::global_asm!(
        ".global nub_int80_stub",
        "nub_int80_stub:",
        "    push rax",
        "    push rcx",
        "    push rdx",
        "    push rdi",
        "    push rsi",
        "    push r8",
        "    push r9",
        "    push r10",
        "    push r11",
        // Align stack to 16 before sysv64 call (we've pushed 9*8 = 72
        // bytes; 72 + 8 (return addr already on stack from int) = 80;
        // 80 mod 16 = 0. Good).
        "    call nub_int80_rust",
        "    pop r11",
        "    pop r10",
        "    pop r9",
        "    pop r8",
        "    pop rsi",
        "    pop rdi",
        "    pop rdx",
        "    pop rcx",
        "    pop rax",
        "    iretq",
    );

    unsafe extern "C" {
        fn nub_int80_stub();
    }

    /// Install our `int 0x80` handler at DPL=3 and trigger the
    /// interrupt from ring 0. Returns the counter delta — should be 1.
    #[guest_function("int80_smoke")]
    pub fn int80_smoke() -> u64 {
        let before = INT80_COUNTER.load(Ordering::SeqCst);
        // SAFETY: nub_int80_stub is a well-formed handler stub.
        unsafe {
            let _idt = segments::install_dpl3_handler(0x80, nub_int80_stub as *const () as u64, 0);
        }
        // SAFETY: int 0x80 dispatches through the IDT entry we just installed.
        unsafe {
            core::arch::asm!("int 0x80", options(nostack, preserves_flags));
        }
        let after = INT80_COUNTER.load(Ordering::SeqCst);
        after - before
    }

    // === A3: page table smoke ================================================

    /// Build a fresh PageTable, map a user-accessible page at a known
    /// VA pointing at a phys page we just stuffed with a magic value,
    /// CR3 to the new PML4, read the value back through the user VA,
    /// CR3 back to the original. Returns the readback value.
    ///
    /// Expected: `0xCAFEBABE_DEADBEEF`.
    #[guest_function("page_table_smoke")]
    pub fn page_table_smoke() -> u64 {
        // Arena now backs onto scratch phys pages, so PA↔VA is a
        // constant offset and PML4 entries we install can hold real PAs.
        let arena = match BumpArena::new(crate::bump::SMOKE_CAPACITY) {
            Some(a) => a,
            None => return 0xDEAD_0001,
        };

        // Stage the magic value into a phys page through its scratch VA.
        let phys = unsafe { hyperlight_guest::prim_alloc::alloc_phys_pages(1) };
        let magic: u64 = 0xCAFE_BABE_DEAD_BEEF;
        let stage_va = match paging::pa_to_va(phys) {
            Some(v) => v,
            None => return 0xDEAD_0002,
        };
        // SAFETY: scratch is mapped writable kernel-only at stage_va.
        unsafe {
            core::ptr::write_volatile(stage_va as *mut u64, magic);
        }

        let mut pt = match PageTable::new_in(&arena) {
            Some(p) => p,
            None => return 0xDEAD_0003,
        };

        // Add a user-RW mapping at a VA way above any pre-existing
        // mapping. 32 << 39 = 16 TiB — PML4 index 32, unmapped in
        // Hyperlight's default layout.
        const USER_VA: u64 = 32u64 << 39;
        const _: () = assert!(USER_VA < (1u64 << 47));
        if pt
            .map(USER_VA, phys, PAGE_SIZE as u64, Perm::user_rw())
            .is_none()
        {
            return 0xDEAD_0004;
        }

        let new_cr3 = match pt.cr3() {
            Some(v) => v,
            None => return 0xDEAD_0005,
        };
        let old_cr3 = paging::read_cr3();

        // SAFETY: new_cr3 PML4 was seeded from the current PML4 so
        // kernel code / stack / heap mappings survive the swap.
        unsafe {
            paging::write_cr3(new_cr3);
        }

        // SAFETY: we just installed a user-RW mapping at USER_VA → phys.
        let readback = unsafe { core::ptr::read_volatile(USER_VA as *const u64) };

        // SAFETY: restore original CR3.
        unsafe {
            paging::write_cr3(old_cr3);
        }

        readback
    }

    // === B2: javm-recompiler-x86 link smoke ==================================

    /// Compile a single-instruction PVM program with the in-kernel
    /// recompiler. Returns the size of the produced native code
    /// (must be > 0 to prove the codegen path runs).
    ///
    /// Doesn't *execute* the code yet — that's C3. This smoke only
    /// validates that javm-recompiler-x86 links cleanly into the
    /// no_std guest binary and the codegen path runs to completion.
    #[guest_function("recomp_link_smoke")]
    pub fn recomp_link_smoke() -> u64 {
        // PVM `trap` (opcode 0); bitmask says PC=0 is an instruction start.
        let code = [0u8];
        let bitmask = [1u8];
        let jump_table: [u32; 0] = [];

        let helpers = javm_recompiler_x86::codegen::HelperFns {
            mem_read_u8: 0,
            mem_read_u16: 0,
            mem_read_u32: 0,
            mem_read_u64: 0,
            mem_write_u8: 0,
            mem_write_u16: 0,
            mem_write_u32: 0,
            mem_write_u64: 0,
            sbrk_helper: 0,
        };

        let compiler = javm_recompiler_x86::codegen::Compiler::new(
            &bitmask,
            &jump_table,
            helpers,
            code.len(),
            false, // use_mmap (irrelevant in no_std; always Vec)
            javm_exec::gas_cost::DEFAULT_MEM_CYCLES,
        );
        let result = compiler.compile(&code, &bitmask);
        result.native_code.len() as u64
    }

    // === C3: run JIT'd code at ring 3 ========================================

    /// Compile a PVM `ecalli 42` program, run it at ring 3 through
    /// the in-kernel JIT path, return `(exit_reason << 32) | exit_arg`.
    ///
    /// Expected: `(4 << 32) | 42` — exit_reason=4 (HostCall),
    /// exit_arg=42 (the ecalli imm).
    #[guest_function("c3_jit_run_smoke")]
    pub fn c3_jit_run_smoke() -> u64 {
        // PVM `ecalli 42`: opcode 10, imm 42.
        let code = [10u8, 42];
        let bitmask = [1u8, 0];
        let jump_table: [u32; 0] = [];

        let info = match unsafe { crate::jit_run::run_pvm(&code, &bitmask, &jump_table, 1_000) } {
            Some(i) => i,
            None => return 0xDEAD_BEEF_DEAD_BEEF,
        };
        ((info.exit_reason as u64) << 32) | (info.exit_arg as u64)
    }

    // === C2: program memory mapping from DataLayout ==========================

    /// Map a chunk of phys pages user-RW at a known user VA, populate
    /// them with three regions (arg / ro / rw) via their scratch VAs,
    /// CR3-swap to the new PT, read back the three regions through the
    /// user VA, swap back. Returns a packed result: the XOR of the
    /// three readback bytes — must equal 0xAA ^ 0xBB ^ 0xCC.
    #[guest_function("c2_program_mem_smoke")]
    pub fn c2_program_mem_smoke() -> u64 {
        // Mini "DataLayout": three single-byte regions at distinct
        // offsets inside a 4 KiB program memory.
        const ARG_OFF: u32 = 0x010;
        const RO_OFF: u32 = 0x100;
        const RW_OFF: u32 = 0x800;
        let mem_pa = unsafe { hyperlight_guest::prim_alloc::alloc_phys_pages(1) };
        let stage_va = match paging::pa_to_va(mem_pa) {
            Some(v) => v,
            None => return 0xDEAD_0001,
        };
        // Populate the three bytes through the scratch VA.
        // SAFETY: a freshly allocated 4 KiB phys page mapped writable
        // at stage_va.
        unsafe {
            core::ptr::write_volatile((stage_va + ARG_OFF as u64) as *mut u8, 0xAA);
            core::ptr::write_volatile((stage_va + RO_OFF as u64) as *mut u8, 0xBB);
            core::ptr::write_volatile((stage_va + RW_OFF as u64) as *mut u8, 0xCC);
        }

        // Map at a user VA in our fresh PageTable.
        let arena = match BumpArena::new(crate::bump::SMOKE_CAPACITY) {
            Some(a) => a,
            None => return 0xDEAD_0002,
        };
        let mut pt = match PageTable::new_in(&arena) {
            Some(p) => p,
            None => return 0xDEAD_0003,
        };
        const PROG_BASE: u64 = 33u64 << 39; // PML4 idx 33
        if pt
            .map(PROG_BASE, mem_pa, PAGE_SIZE as u64, Perm::user_rw())
            .is_none()
        {
            return 0xDEAD_0004;
        }
        let new_cr3 = match pt.cr3() {
            Some(v) => v,
            None => return 0xDEAD_0005,
        };
        let old_cr3 = paging::read_cr3();
        // SAFETY: new PML4 carries the kernel half from old CR3.
        unsafe { paging::write_cr3(new_cr3) };
        // SAFETY: PROG_BASE..+4096 was just mapped user-RW.
        let a = unsafe { core::ptr::read_volatile((PROG_BASE + ARG_OFF as u64) as *const u8) };
        let b = unsafe { core::ptr::read_volatile((PROG_BASE + RO_OFF as u64) as *const u8) };
        let c = unsafe { core::ptr::read_volatile((PROG_BASE + RW_OFF as u64) as *const u8) };
        unsafe { paging::write_cr3(old_cr3) };

        (a ^ b ^ c) as u64
    }

    // === C1: in-kernel JIT codegen + executable mapping ======================

    /// Compile a PVM program, allocate a phys page for the native
    /// code, copy bytes into it, map the page user-RX in a fresh
    /// PageTable. Returns (native_byte_count << 16) | rounded_pages.
    ///
    /// Doesn't execute the code (that's C3); only validates the
    /// in-kernel compile → map pipeline.
    #[guest_function("c1_jit_compile_smoke")]
    pub fn c1_jit_compile_smoke() -> u64 {
        // PVM `trap`.
        let code = [0u8];
        let bitmask = [1u8];
        let jump_table: [u32; 0] = [];

        let helpers = javm_recompiler_x86::codegen::HelperFns {
            mem_read_u8: 0,
            mem_read_u16: 0,
            mem_read_u32: 0,
            mem_read_u64: 0,
            mem_write_u8: 0,
            mem_write_u16: 0,
            mem_write_u32: 0,
            mem_write_u64: 0,
            sbrk_helper: 0,
        };
        let compiler = javm_recompiler_x86::codegen::Compiler::new(
            &bitmask,
            &jump_table,
            helpers,
            code.len(),
            false,
            javm_exec::gas_cost::DEFAULT_MEM_CYCLES,
        );
        let result = compiler.compile(&code, &bitmask);
        let native = &result.native_code;
        if native.is_empty() {
            return 0xDEAD_0001;
        }

        // Allocate enough phys pages to fit the code.
        let n_pages = native.len().div_ceil(PAGE_SIZE as usize);
        let exec_pa = unsafe { hyperlight_guest::prim_alloc::alloc_phys_pages(n_pages as u64) };
        let stage_va = match paging::pa_to_va(exec_pa) {
            Some(v) => v,
            None => return 0xDEAD_0002,
        };
        // SAFETY: scratch is mapped writable kernel-only at stage_va;
        // we own these freshly allocated phys pages.
        unsafe {
            core::ptr::copy_nonoverlapping(native.as_ptr(), stage_va as *mut u8, native.len());
        }

        // Build a per-invocation page table; map the exec region user-RX.
        let arena = match BumpArena::new(crate::bump::SMOKE_CAPACITY) {
            Some(a) => a,
            None => return 0xDEAD_0003,
        };
        let mut pt = match PageTable::new_in(&arena) {
            Some(p) => p,
            None => return 0xDEAD_0004,
        };
        const USER_CODE_VA: u64 = 32u64 << 39;
        let pages_bytes = (n_pages * PAGE_SIZE as usize) as u64;
        if pt
            .map(USER_CODE_VA, exec_pa, pages_bytes, Perm::user_rx())
            .is_none()
        {
            return 0xDEAD_0005;
        }

        // Pack: high 48 bits = native byte count, low 16 = n_pages.
        ((native.len() as u64) << 16) | (n_pages as u64)
    }

    // === A4: ring-3 entry smoke ==============================================

    /// Drop to ring 3, run a 7-byte stub that does
    /// `mov eax, 0x1337; int 0x81`, return the captured user-mode RAX.
    ///
    /// Validates: GDT extension with user CS/DS, IDT vector 0x81 at
    /// DPL=3, iretq → ring 3, ring-3 → ring-0 trap via int 0x81,
    /// kernel-side longjmp back to caller, value transfer through RAX,
    /// per-invocation PageTable with both kernel-half and user-half
    /// mappings.
    #[guest_function("ring3_smoke")]
    pub fn ring3_smoke() -> u64 {
        let arena = match BumpArena::new(crate::bump::SMOKE_CAPACITY) {
            Some(a) => a,
            None => return 0xDEAD_0001,
        };

        // User code + user stack live in scratch GPA; the user-VA
        // mapping points back to those PAs via the new PageTable.
        let code_pa = unsafe { hyperlight_guest::prim_alloc::alloc_phys_pages(1) };
        let stack_pa = unsafe { hyperlight_guest::prim_alloc::alloc_phys_pages(1) };

        // Stage the ring-3 stub through the scratch VA of the code page.
        let code_stage_va = match paging::pa_to_va(code_pa) {
            Some(v) => v,
            None => return 0xDEAD_0002,
        };
        // mov eax, 0x1337  → B8 37 13 00 00
        // int 0x81         → CD 81
        const STUB: [u8; 7] = [0xB8, 0x37, 0x13, 0x00, 0x00, 0xCD, 0x81];
        // SAFETY: stage_va is a writable kernel mapping of the page.
        unsafe {
            core::ptr::copy_nonoverlapping(STUB.as_ptr(), code_stage_va as *mut u8, STUB.len());
        }

        // Build the per-invocation page table. Map user code at
        // USER_CODE_VA (RX, user) and user stack at USER_STACK_VA (RW,
        // user). The stack page is mapped as one 4 KiB page; the user
        // RSP starts at the top of that page.
        const USER_CODE_VA: u64 = 32u64 << 39; // 16 TiB, PML4 idx 32
        const USER_STACK_BASE: u64 = USER_CODE_VA + 0x1000;
        let user_stack_top = USER_STACK_BASE + PAGE_SIZE as u64;

        let mut pt = match PageTable::new_in(&arena) {
            Some(p) => p,
            None => return 0xDEAD_0003,
        };
        if pt
            .map(USER_CODE_VA, code_pa, PAGE_SIZE as u64, Perm::user_rx())
            .is_none()
        {
            return 0xDEAD_0004;
        }
        if pt
            .map(USER_STACK_BASE, stack_pa, PAGE_SIZE as u64, Perm::user_rw())
            .is_none()
        {
            return 0xDEAD_0005;
        }
        let new_cr3 = match pt.cr3() {
            Some(v) => v,
            None => return 0xDEAD_0006,
        };

        // Install the user segments + ring-3 exit gate. Idempotent.
        // SAFETY: ring-0 mutation of GDT/IDT; serialised by Hyperlight.
        unsafe {
            ring3::install_ring3_exit_gate();
        }

        // SAFETY: code + stack mappings are valid in `new_cr3`;
        // kernel-half mappings were copied from the live PML4 so
        // kernel code + stack survive the swap.
        let rax = unsafe { ring3::nub_enter_ring3(USER_CODE_VA, user_stack_top, new_cr3) };

        // The stub stored 0x1337 in EAX.
        rax & 0xFFFF
    }

    // === A1: bump arena smoke ================================================

    /// Allocate two blocks, reset, allocate one block, return a
    /// packed status: `(first_addr_aligned << 8) | reuses_first`.
    /// `reuses_first` is `1` iff the post-reset allocation starts at
    /// the same offset as the first allocation (proves `reset`
    /// rewinds the cursor).
    #[guest_function("bump_smoke")]
    pub fn bump_smoke() -> u64 {
        let arena = match BumpArena::new(crate::bump::SMOKE_CAPACITY) {
            Some(a) => a,
            None => return 0,
        };
        let a = match arena.alloc(0x100, 0x10) {
            Some(p) => p.as_ptr() as usize,
            None => return 0,
        };
        // alignment: low 4 bits must be zero.
        let aligned = (a & 0xF) == 0;
        let _b = match arena.alloc(0x100, 0x10) {
            Some(p) => p.as_ptr() as usize,
            None => return 0,
        };
        arena.reset();
        let c = match arena.alloc(0x100, 0x10) {
            Some(p) => p.as_ptr() as usize,
            None => return 0,
        };
        let reuses = c == a;
        ((aligned as u64) << 1) | (reuses as u64)
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
