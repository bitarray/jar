//! Ring-3 entry trampoline + symmetric exit handler.
//!
//! Drops the kernel into ring 3 at a chosen entry point, on a chosen
//! user stack, with a chosen page table. The user code returns to the
//! kernel by issuing `int 0x81`; the IDT handler skips the normal
//! `iretq` return and instead "long-jumps" back to the call site of
//! [`enter_ring3`], yielding the value the ring-3 code left in RAX.
//!
//! ## Control flow
//!
//! ```text
//!   kernel                                          ring 3
//!   ------                                          ------
//!   enter_ring3(entry, stack, cr3)
//!     push callee-saved                              .
//!     save current cr3 & rsp                         .
//!     mov cr3, new_cr3                               .
//!     iretq with frame [USER_SS|3, stack,            .
//!                       RFLAGS, USER_CS|3, entry]    .
//!     ............................................ entry:
//!                                                    mov rax, <retval>
//!                                                    int 0x81
//!     ring3_exit_stub:  (CPU loads IST1 stack)       .
//!       mov [USER_RAX], rax                          .
//!       mov rsp, [KERNEL_RESUME_RSP]                 .
//!       mov cr3, [SAVED_CR3]                         .
//!       jmp resume                                   .
//!     resume:                                        .
//!       pop callee-saved                             .
//!       mov rax, [USER_RAX]                          .
//!       ret
//! ```
//!
//! Notes:
//!
//! * **IST=1 for vector 0x81.** Hyperlight already sets up an
//!   exception stack at `MAX_GVA - SCRATCH_TOP_EXN_STACK_OFFSET + 1`
//!   and points TSS.IST1 at it. Using IST=1 means we don't need to
//!   touch TSS.RSP0; the interrupt frame lands on the exception
//!   stack and we abandon it after copying RAX out.
//! * **Single-shot.** The static `KERNEL_RESUME_RSP` / `SAVED_CR3` /
//!   `USER_EXIT_RAX` are global and so this code is *not* reentrant.
//!   Stage 2.2 only has one active invocation at a time (Hyperlight
//!   serialises host calls), but if we later add nested PVM
//!   invocations we'll need to thread these through a per-call
//!   context.

#![cfg(target_os = "none")]

use core::sync::atomic::{AtomicU64, Ordering};

/// Vector for the ring-3 exit gate.
pub const RING3_EXIT_VECTOR: u8 = 0x81;

/// Saved kernel RSP at the point of `iretq` in [`enter_ring3`].
/// The exit stub overwrites RSP with this value before jumping to
/// the resume label.
#[unsafe(no_mangle)]
pub static KERNEL_RESUME_RSP: AtomicU64 = AtomicU64::new(0);

/// Saved kernel CR3 at the point of CR3 swap in [`enter_ring3`].
/// The exit stub restores this before jumping to resume.
#[unsafe(no_mangle)]
pub static SAVED_CR3: AtomicU64 = AtomicU64::new(0);

/// Ring-3 RAX at the moment of the exit trap. Copied out by the
/// exit stub before the kernel reentry path tears down the
/// interrupt frame.
#[unsafe(no_mangle)]
pub static USER_EXIT_RAX: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" {
    /// Drop to ring 3 at `entry_va`, on stack `stack_va`, with page
    /// table `new_cr3` loaded. Returns the user-mode RAX captured at
    /// the next `int 0x81`.
    ///
    /// # Safety
    /// `entry_va` must reference a user-RX mapping in `new_cr3`;
    /// `stack_va` must reference a user-RW mapping (top of the user
    /// stack); `new_cr3` must be a valid PML4 PA whose kernel-half
    /// entries cover the kernel code/data + scratch.
    pub fn nub_enter_ring3(entry_va: u64, stack_va: u64, new_cr3: u64) -> u64;

    /// IDT handler for vector 0x81. Installed by
    /// [`install_ring3_exit_gate`].
    pub fn nub_ring3_exit_stub();
}

// === enter_ring3 + exit-stub assembly =====================================
//
// We hand-write the trampoline because:
//
//   * `iretq` to ring 3 must push exactly the frame the CPU expects
//     (SS, RSP, RFLAGS, CS, RIP) in reverse order onto the kernel
//     stack;
//   * the exit path can't `iretq` back to the kernel — it'd land us
//     at the `int 0x81` instruction in ring-3 — so it does a
//     `mov rsp, ...; jmp resume` longjmp instead.
//
// The two halves communicate via the three `AtomicU64` statics
// above; we use `mov [sym + rip]` (RIP-relative) for `pic`-correct
// addressing.
core::arch::global_asm!(
    ".global nub_enter_ring3",
    ".global nub_ring3_exit_stub",
    "nub_enter_ring3:",
    // RDI = entry_va, RSI = stack_va, RDX = new_cr3.
    "    push rbx",
    "    push rbp",
    "    push r12",
    "    push r13",
    "    push r14",
    "    push r15",
    // Snapshot current cr3 + rsp so the exit stub can restore.
    "    mov rax, cr3",
    "    mov qword ptr [rip + {saved_cr3}], rax",
    "    mov qword ptr [rip + {resume_rsp}], rsp",
    // Swap to the per-invocation page table.
    "    mov cr3, rdx",
    // Push iretq frame: SS, RSP, RFLAGS, CS, RIP (last push popped first).
    "    push {user_ss}",
    "    push rsi",
    "    push 0x202",   // RFLAGS: IF=1 + reserved bit
    "    push {user_cs}",
    "    push rdi",
    "    iretq",
    "nub_ring3_exit_stub:",
    // CPU just dispatched int 0x81 from ring 3 onto the IST1 stack.
    // RAX still holds the ring-3 value; persist it.
    "    mov qword ptr [rip + {user_rax}], rax",
    // Restore the kernel context and longjmp back to the resume label
    // inside nub_enter_ring3.
    "    mov rax, qword ptr [rip + {saved_cr3}]",
    "    mov cr3, rax",
    "    mov rsp, qword ptr [rip + {resume_rsp}]",
    "    jmp 2f",
    // Resume label: pop callee-saved, load user RAX, return.
    "2:",
    "    pop r15",
    "    pop r14",
    "    pop r13",
    "    pop r12",
    "    pop rbp",
    "    pop rbx",
    "    mov rax, qword ptr [rip + {user_rax}]",
    "    ret",
    saved_cr3 = sym SAVED_CR3,
    resume_rsp = sym KERNEL_RESUME_RSP,
    user_rax = sym USER_EXIT_RAX,
    user_cs = const crate::segments::USER_CODE_SEL as u64,
    user_ss = const crate::segments::USER_DATA_SEL as u64,
);

/// Install the ring-3 exit gate at vector 0x81 (DPL=3, IST=1).
///
/// Calling this also extends the GDT with the user CS/DS selectors
/// (via [`crate::segments::install_user_segments`]) if they aren't
/// already there. The combined effect is that on first call we set
/// up everything ring-3 entry needs.
///
/// # Safety
/// Safe to call from kernel mode (CPL=0). Modifying GDT/IDT is a
/// privileged operation; the caller is responsible for not invoking
/// this from an interrupt handler (which would race against the
/// current CPU's GDTR/IDTR pointer).
pub unsafe fn install_ring3_exit_gate() {
    // SAFETY: ring-0 GDT/IDT mutation; see module-level docs.
    unsafe {
        crate::segments::install_user_segments();
        let _ = crate::segments::install_dpl3_handler(
            RING3_EXIT_VECTOR,
            nub_ring3_exit_stub as *const () as u64,
            1, // IST=1, run on the pre-existing exception stack
        );
    }
    // Reset captured state from any prior call.
    KERNEL_RESUME_RSP.store(0, Ordering::SeqCst);
    SAVED_CR3.store(0, Ordering::SeqCst);
    USER_EXIT_RAX.store(0, Ordering::SeqCst);
}
