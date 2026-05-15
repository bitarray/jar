//! Shared builtins for freestanding RISC-V service crates.
//!
//! Provides compiler builtins (memset, memcpy, memcmp), a panic handler,
//! an entry point macro for JAVM/PolkaVM targets, and the `map_args`
//! runtime helper that moves the kernel-allocated args DATA cap from
//! bare-Frame slot 4 into the guest's main-frame CapTable and maps it
//! into the guest address space.
//!
//! All freestanding-only symbols are gated behind `cfg(target_os =
//! "none")` — on host this crate is empty. Services force-link it via
//! `use javm_builtins as _;`.

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
/// On JAVM: `_start` calls the named function with `a0 = φ[7] =
/// args_len` (kernel-set by `kernel.set_args`), then terminates via
/// `ecalli(0x00)` (REPLY to kernel via IPC slot 0).
/// On PolkaVM: `_start` is `unimp` (polkavm uses exported functions
/// directly).
/// On host: expands to nothing.
///
/// The user function signature is `fn(args_len: u64) -> u64`. To read
/// the args bytes, the user calls
/// [`javm_builtins::map_args`](crate::map_args) with the same
/// `args_len`.
///
/// Usage: `javm_builtins::javm_entry!(my_bench_fn);`
#[macro_export]
macro_rules! javm_entry {
    ($fn_name:ident) => {
        #[cfg(target_env = "javm")]
        core::arch::global_asm!(
            ".global _start",
            "_start:",
            // a0 = φ[7] = args_len. The kernel placed the args DATA
            // cap (if any) at bare-Frame slot 4; user code calls
            // `javm_builtins::map_args(args_len)` to MOVE+MAP it and
            // get a `&[u8]`.
            concat!("call ", stringify!($fn_name)),
            // REPLY to kernel via IPC slot 0
            "li t0, 0",
            "ecall",
            "unimp", // trap if somehow resumed after REPLY
        );
        #[cfg(target_env = "polkavm")]
        core::arch::global_asm!(".global _start", "_start:", "unimp",);
    };
}

// -- Args helper --------------------------------------------------------------

/// Map the kernel-supplied args DATA cap into guest address space and
/// return a slice over its bytes. See [`InvocationKernel::set_args`]
/// for the kernel side: the kernel allocates a fresh DATA cap, writes
/// the host's bytes into its backing pages, and places it at
/// bare-Frame slot 4. The guest is responsible for the MOVE +
/// MGMT_MAP steps because the kernel rule "MGMT_MAP only on caps
/// held in a VM's persistent Frame" requires the cap to live in the
/// active VM's main frame before mapping.
///
/// Steps:
/// 1. MGMT_MOVE: bare-Frame[4] → main-frame[`ARGS_SLOT`].
/// 2. MGMT_MAP: main-frame[`ARGS_SLOT`] @ `args_base_page`, RW, all
///    pages.
/// 3. Return `&[u8]` of length `args_len` at the mapped byte address.
///
/// `args_base_page` is chosen as `(_end + JAVM_HEAP_BYTES + 4095) /
/// 4096` — one page past the program's heap top. `_end` is the LLD
/// linker-emitted symbol pointing to the end of `.bss`;
/// `JAVM_HEAP_BYTES` matches the transpiler's hard-coded
/// `heap_pages = 16` (`javm-transpiler::linker::heap_pages`). If the
/// transpiler's heap size ever changes, this constant must be
/// updated in lockstep.
///
/// Returns `&[]` if `args_len == 0` (no MOVE/MAP performed). On
/// freestanding targets only — host expansion is a stub.
///
/// # Safety
/// Issues `ecall`s that mutate kernel state. Must be called at most
/// once per invocation; subsequent calls would attempt to MOVE from
/// an already-empty bare-Frame slot 4 and fail with `RESULT_WHAT`.
/// Cache the returned slice if multiple readers need the bytes.
#[cfg(all(target_env = "javm", target_os = "none"))]
pub fn map_args(args_len: u64) -> &'static [u8] {
    if args_len == 0 {
        return &[];
    }

    // Heap size assumed by the transpiler (`javm-transpiler::linker.rs:
    // heap_pages = 16`). Args must live above the heap top.
    const JAVM_HEAP_BYTES: u64 = 16 * 4096;
    const ARGS_SLOT: u64 = 69;

    unsafe extern "C" {
        static _end: u8;
    }
    let end_addr = (&raw const _end) as u64;
    let args_base_addr = (end_addr + JAVM_HEAP_BYTES).next_multiple_of(4096);
    let args_base_page = args_base_addr / 4096;
    let page_count = args_len.div_ceil(4096);

    // Cap-ref encoding (see `javm_legacy::kernel::resolve_cap_ref`):
    //   - direct slot N in the active VM:    `N` (8 bits)
    //   - slot N in the bare Frame:          `N << 8` (cross slot 0
    //     of active VM to bare Frame, then access slot N)
    let bare_frame_slot_4: u64 = 4 << 8; // = 0x400
    let main_frame_args: u64 = ARGS_SLOT;

    // MGMT_MOVE: subject = bare-Frame[4], object = main-frame[ARGS_SLOT].
    //   φ[11] = MGMT_MOVE = 6
    //   φ[12] = (subject << 32) | object
    let move_refs: u64 = (bare_frame_slot_4 << 32) | main_frame_args;
    unsafe {
        core::arch::asm!(
            // CSR 0x800 marker: tells the transpiler the next ecall
            // is a PVM ecall (management op), not ecalli (CALL cap).
            "csrw 0x800, zero",
            "ecall",
            in("a4") 6u64,            // φ[11] = MGMT_MOVE
            in("a5") move_refs,        // φ[12] = (subject << 32) | object
            // Kernel may overwrite a0..a5 with result code; mark all clobbered.
            lateout("a0") _, lateout("a1") _, lateout("a2") _,
            lateout("a3") _, lateout("a4") _, lateout("a5") _,
        );
    }

    // MGMT_MAP: subject = main-frame[ARGS_SLOT], all pages, RW.
    //   φ[7]  = base_offset = args_base_page
    //   φ[8]  = page_offset = 0
    //   φ[9]  = page_count
    //   φ[10] = access = 1 (RW)
    //   φ[11] = MGMT_MAP = 2
    //   φ[12] = (subject << 32) | 0
    let map_refs: u64 = main_frame_args << 32;
    unsafe {
        core::arch::asm!(
            "csrw 0x800, zero",
            "ecall",
            in("a0") args_base_page,
            in("a1") 0u64,
            in("a2") page_count,
            in("a3") 1u64,
            in("a4") 2u64,
            in("a5") map_refs,
            lateout("a0") _, lateout("a1") _, lateout("a2") _,
            lateout("a3") _, lateout("a4") _, lateout("a5") _,
        );
    }

    // SAFETY: kernel mapped `page_count` pages of args bytes at
    // `args_base_addr` with RW access. The slice lives for the rest
    // of the invocation (until the kernel tears down the window).
    unsafe { core::slice::from_raw_parts(args_base_addr as *const u8, args_len as usize) }
}

/// Host-side stub. Always returns an empty slice; meaningful only on
/// the JAVM freestanding target.
#[cfg(not(all(target_env = "javm", target_os = "none")))]
pub fn map_args(_args_len: u64) -> &'static [u8] {
    &[]
}
