//! SIGSEGV-based memory bounds checking for the recompiler.
//!
//! When the `signals` feature is enabled, memory accesses in JIT code skip
//! software bounds checks. Instead, guard pages (PROT_NONE) beyond heap_top
//! trigger SIGSEGV, which this handler intercepts and redirects to the
//! existing exit sequence via ucontext modification (no longjmp).

use std::cell::Cell;
use std::ptr::null_mut;
use std::sync::Once;

use super::JitContext;
use super::codegen::EXIT_PAGE_FAULT;

/// Per-thread state accessible from the signal handler.
#[repr(C)]
pub struct SignalState {
    /// Start of native code region (absolute address).
    pub code_start: usize,
    /// End of native code region (exclusive).
    pub code_end: usize,
    /// Absolute address of exit_label in native code.
    pub exit_label_addr: usize,
    /// Pointer to JitContext (for writing exit_reason/exit_arg/pc).
    pub ctx_ptr: *mut JitContext,
    /// Trap table: sorted by native_offset. (native_offset, pvm_pc).
    pub trap_table: Vec<(u32, u32)>,
}

// SAFETY: SignalState is only accessed by the owning thread (set before JIT call,
// read by signal handler on same thread, cleared after JIT call).
unsafe impl Send for SignalState {}

thread_local! {
    pub static SIGNAL_STATE: Cell<*mut SignalState> = const { Cell::new(null_mut()) };
}

static INIT: Once = Once::new();
// SAFETY: sigaction is a POD struct — zero-initialized is a valid (SIG_DFL) state.
// Accessed only inside Once::call_once (write) and from the signal handler (read)
// after initialization is complete.
static mut PREV_SIGSEGV: libc::sigaction = unsafe { std::mem::zeroed() };

/// Ensure the SIGSEGV handler is installed (once per process).
pub fn ensure_installed() {
    // SAFETY: Both install functions use OS APIs (sigaction, sigaltstack, mmap)
    // which are safe to call once at startup. Once::call_once guarantees this
    // runs exactly once across all threads.
    INIT.call_once(|| unsafe {
        install_sigaltstack();
        install_handler();
    });
}

unsafe fn install_handler() {
    // SAFETY: sigaction() is called with a properly initialized sigaction struct.
    // The handler pointer is a valid extern "C" fn with the correct signature.
    // PREV_SIGSEGV is written once here (protected by Once) and only read afterward.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
        sa.sa_sigaction = sigsegv_handler as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        let r = libc::sigaction(libc::SIGSEGV, &sa, &raw mut PREV_SIGSEGV);
        assert_eq!(
            r,
            0,
            "sigaction(SIGSEGV) failed: {}",
            std::io::Error::last_os_error()
        );
    }
}

unsafe fn install_sigaltstack() {
    // SAFETY: mmap allocates a fresh anonymous mapping with a guard page at the
    // bottom (PROT_NONE) and stack space above (PROT_READ|PROT_WRITE).
    // The allocation is intentionally leaked — it lives for the process lifetime.
    // sigaltstack() is called with a valid stack pointer and size.
    unsafe {
        // Check if an adequate alternate stack already exists.
        let mut old: libc::stack_t = std::mem::zeroed();
        libc::sigaltstack(std::ptr::null(), &mut old);
        const MIN_STACK: usize = 64 * 4096; // 256KB
        if old.ss_flags & libc::SS_DISABLE == 0 && old.ss_size >= MIN_STACK {
            return; // Already have a sufficient stack.
        }

        let page_size: usize = 4096;
        let alloc_size = page_size + MIN_STACK; // guard page + stack
        let ptr = libc::mmap(
            null_mut(),
            alloc_size,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        assert_ne!(ptr, libc::MAP_FAILED, "mmap for sigaltstack failed");

        // Make the stack portion (after the guard page) read-write.
        let stack_ptr = (ptr as usize + page_size) as *mut libc::c_void;
        libc::mprotect(stack_ptr, MIN_STACK, libc::PROT_READ | libc::PROT_WRITE);

        let new_stack = libc::stack_t {
            ss_sp: stack_ptr,
            ss_flags: 0,
            ss_size: MIN_STACK,
        };
        let r = libc::sigaltstack(&new_stack, null_mut());
        assert_eq!(
            r,
            0,
            "sigaltstack failed: {}",
            std::io::Error::last_os_error()
        );
        // Intentionally leak the allocation — it lives for the process lifetime.
    }
}

/// SIGSEGV handler: intercepts page faults from JIT code and redirects to the
/// exit sequence. Only handles faults at registered trap sites within our
/// native code region; all others are delegated to the previous handler.
unsafe extern "C" fn sigsegv_handler(
    signum: libc::c_int,
    _siginfo: *mut libc::siginfo_t,
    ucontext: *mut libc::c_void,
) {
    // SAFETY: Called by the OS signal mechanism with valid siginfo/ucontext pointers.
    // SIGNAL_STATE is thread-local and set by the calling thread before JIT entry.
    // state_ptr is only non-null during JIT execution on this thread.
    // The ucontext cast is valid on x86-64 Linux (ucontext_t layout).
    // ctx_ptr points to a live JitContext owned by the same thread's call stack.
    // Modifying REG_RIP redirects execution to exit_label (our code, not arbitrary).
    unsafe {
        let state_ptr = SIGNAL_STATE.with(|cell| cell.get());
        if state_ptr.is_null() {
            delegate_to_previous(signum, _siginfo, ucontext);
            return;
        }
        let state = &*state_ptr;

        // Read faulting PC from ucontext.
        let cx = &mut *(ucontext as *mut libc::ucontext_t);
        let pc = cx.uc_mcontext.gregs[libc::REG_RIP as usize] as usize;

        // Check if the faulting PC is within our JIT code region.
        if pc < state.code_start || pc >= state.code_end {
            delegate_to_previous(signum, _siginfo, ucontext);
            return;
        }

        // Binary search the trap table for this native offset.
        let native_offset = (pc - state.code_start) as u32;
        let pvm_pc = match state
            .trap_table
            .binary_search_by_key(&native_offset, |&(off, _)| off)
        {
            Ok(idx) => state.trap_table[idx].1,
            Err(_) => {
                // PC is in our code but not at a registered trap site — real bug.
                delegate_to_previous(signum, _siginfo, ucontext);
                return;
            }
        };

        // Read the guest fault address from RDX (SCRATCH register).
        let guest_addr = cx.uc_mcontext.gregs[libc::REG_RDX as usize] as u32;

        // Write trap info into JitContext.
        let ctx = &mut *state.ctx_ptr;
        ctx.exit_reason = EXIT_PAGE_FAULT;
        ctx.exit_arg = guest_addr;
        ctx.pc = pvm_pc;

        // Redirect execution to exit_label (saves regs + ret to Rust).
        cx.uc_mcontext.gregs[libc::REG_RIP as usize] = state.exit_label_addr as i64;
    }
}

unsafe fn delegate_to_previous(
    signum: libc::c_int,
    siginfo: *mut libc::siginfo_t,
    context: *mut libc::c_void,
) {
    // SAFETY: PREV_SIGSEGV was initialized by install_handler (protected by Once).
    // The transmute calls convert the sa_sigaction field to the appropriate function
    // pointer type based on SA_SIGINFO flag — matching how the OS would call it.
    // If the previous handler is SIG_DFL/SIG_IGN, we restore it and let the
    // signal re-fire with default behavior (typically process termination).
    unsafe {
        let prev = PREV_SIGSEGV;
        if prev.sa_flags & libc::SA_SIGINFO != 0 {
            let handler: extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void) =
                std::mem::transmute(prev.sa_sigaction);
            handler(signum, siginfo, context);
        } else if prev.sa_sigaction == libc::SIG_DFL || prev.sa_sigaction == libc::SIG_IGN {
            // Restore default handler and let the signal re-fire.
            libc::sigaction(signum, &prev, null_mut());
        } else {
            let handler: extern "C" fn(libc::c_int) = std::mem::transmute(prev.sa_sigaction);
            handler(signum);
        }
    }
}
