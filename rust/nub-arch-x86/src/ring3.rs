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
//!       swapgs                                       .
//!       mov gs:[USER_RAX], rax                       .
//!       mov rsp, gs:[KERNEL_RESUME_RSP]              .
//!       mov cr3, gs:[SAVED_CR3]                      .
//!       jmp resume                                   .
//!     resume:                                        .
//!       pop callee-saved                             .
//!       mov rax, gs:[USER_RAX]                       .
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
//! * **Lane-local state.** [`prepare_ring3_entry`] points GS at the active
//!   lane's [`Ring3LaneRaw`]. The entry/exit assembly stores its saved kernel
//!   RSP, saved CR3, and user RAX through GS, so two vCPUs can take the exit
//!   gate without racing on a process-global slot. Both `GSBase` and
//!   `KernelGSBase` are set to the same state pointer, and the exit stub starts
//!   with `swapgs`, because Hyperlight's exception path can leave the active GS
//!   side swapped before the final `int 0x81`.

use core::cell::UnsafeCell;
use core::mem::offset_of;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::execution_lane::{ExecutionLane, MAX_EXECUTION_LANES};

/// Vector for the ring-3 exit gate.
pub const RING3_EXIT_VECTOR: u8 = 0x81;

#[repr(C, align(64))]
struct Ring3LaneRaw {
    lane_index: u64,
    /// Saved kernel RSP at the point of `iretq` in [`nub_enter_ring3`].
    kernel_resume_rsp: u64,
    /// Saved kernel CR3 at the point of CR3 swap in [`nub_enter_ring3`].
    saved_cr3: u64,
    /// Ring-3 RAX at the moment of the exit trap.
    user_exit_rax: u64,
}

struct Ring3LaneState {
    raw: UnsafeCell<Ring3LaneRaw>,
}

// SAFETY: each lane writes only its own slot after `prepare_ring3_entry`
// selects it, and the assembly accesses the selected slot through GS on that
// same vCPU. Cross-lane sharing is by static address only.
unsafe impl Sync for Ring3LaneState {}

impl Ring3LaneState {
    const fn new() -> Self {
        Self {
            raw: UnsafeCell::new(Ring3LaneRaw {
                lane_index: u64::MAX,
                kernel_resume_rsp: 0,
                saved_cr3: 0,
                user_exit_rax: 0,
            }),
        }
    }

    fn ptr(&self) -> *mut Ring3LaneRaw {
        self.raw.get()
    }

    /// # Safety
    /// The caller must ensure this state belongs to the currently entering
    /// vCPU lane, so no other CPU is concurrently mutating the same raw fields.
    unsafe fn reset_for_entry(&self, lane: ExecutionLane) {
        let raw = self.raw.get();
        unsafe {
            (*raw).lane_index = lane.index() as u64;
            (*raw).kernel_resume_rsp = 0;
            (*raw).saved_cr3 = 0;
            (*raw).user_exit_rax = 0;
        }
    }
}

static RING3_LANES: [Ring3LaneState; MAX_EXECUTION_LANES] =
    [const { Ring3LaneState::new() }; MAX_EXECUTION_LANES];

const LANE_INDEX_OFFSET: usize = offset_of!(Ring3LaneRaw, lane_index);
const KERNEL_RESUME_RSP_OFFSET: usize = offset_of!(Ring3LaneRaw, kernel_resume_rsp);
const SAVED_CR3_OFFSET: usize = offset_of!(Ring3LaneRaw, saved_cr3);
const USER_EXIT_RAX_OFFSET: usize = offset_of!(Ring3LaneRaw, user_exit_rax);

const IA32_GS_BASE: u32 = 0xC000_0101;
const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;

unsafe fn write_msr(msr: u32, value: u64) {
    let lo = value as u32;
    let hi = (value >> 32) as u32;
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") lo,
            in("edx") hi,
            options(nostack, preserves_flags)
        );
    }
}

unsafe fn write_gs_bases(base: u64) {
    unsafe {
        write_msr(IA32_GS_BASE, base);
        // Hyperlight exception machinery may use `swapgs` while handling a
        // ring3 #PF. Keep both sides pointed at the same lane state; the
        // int-0x81 stub still starts with `swapgs`, which makes the active side
        // correct even if a prior exception left it swapped.
        write_msr(IA32_KERNEL_GS_BASE, base);
    }
}

/// Return the lane selected by the current GS base. Valid while running in the
/// ring3 entry/exit path or its exception handlers after [`prepare_ring3_entry`]
/// has run on this vCPU.
pub fn current_execution_lane() -> ExecutionLane {
    let lane: u64;
    unsafe {
        core::arch::asm!(
            "mov {}, qword ptr gs:[{offset}]",
            out(reg) lane,
            offset = const LANE_INDEX_OFFSET,
            options(nostack, preserves_flags, readonly)
        );
    }
    ExecutionLane::new(lane as usize)
}

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
// The two halves communicate through the active lane's GS-base state. Rust sets
// GS to a `Ring3LaneRaw` before entry; the interrupt gate runs on the same vCPU
// and therefore sees the same GS base.
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
    "    mov qword ptr gs:[{saved_cr3}], rax",
    "    mov qword ptr gs:[{resume_rsp}], rsp",
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
    // If an earlier exception path left GS swapped back to the user side, bring
    // the lane state into active GS before touching gs:[...].
    "    swapgs",
    // RAX still holds the ring-3 value; persist it.
    "    mov qword ptr gs:[{user_rax}], rax",
    // Restore the kernel context and longjmp back to the resume label
    // inside nub_enter_ring3.
    "    mov rax, qword ptr gs:[{saved_cr3}]",
    "    mov cr3, rax",
    "    mov rsp, qword ptr gs:[{resume_rsp}]",
    "    jmp 2f",
    // Resume label: pop callee-saved, load user RAX, return.
    "2:",
    "    pop r15",
    "    pop r14",
    "    pop r13",
    "    pop r12",
    "    pop rbp",
    "    pop rbx",
    "    mov rax, qword ptr gs:[{user_rax}]",
    "    ret",
    saved_cr3 = const SAVED_CR3_OFFSET,
    resume_rsp = const KERNEL_RESUME_RSP_OFFSET,
    user_rax = const USER_EXIT_RAX_OFFSET,
    user_cs = const crate::segments::USER_CODE_SEL as u64,
    user_ss = const crate::segments::USER_DATA_SEL as u64,
);

/// Prepare the current vCPU to enter ring 3 on `lane`.
///
/// Installs the shared exit gate once, resets the selected lane's scratch
/// fields, and points GS at that lane's state so the assembly entry/exit path
/// is reentrant across vCPUs.
///
/// # Safety
/// Safe to call from kernel mode (CPL=0). The caller must pass the lane owned
/// by the currently running vCPU.
pub unsafe fn prepare_ring3_entry(lane: ExecutionLane) {
    lane.assert_in_range();
    unsafe { install_ring3_exit_gate() };
    let state = &RING3_LANES[lane.index()];
    unsafe {
        state.reset_for_entry(lane);
        write_gs_bases(state.ptr() as u64);
    }
}

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
    // First-call-only: install GDT user segments + patch IDT entry
    // for the ring-3 exit vector. Both `install_user_segments` and
    // `install_dpl3_handler` `Box::leak` ~4 KiB of memory (the new
    // IDT + descriptor) on every call — re-running them per
    // invocation leaked 4106 B/iter (confirmed via `talc::counters`).
    // The installed IDT is shared across all invocations; nothing
    // about it depends on per-call state.
    static INSTALLED: AtomicBool = AtomicBool::new(false);
    if !INSTALLED.swap(true, Ordering::AcqRel) {
        // SAFETY: ring-0 GDT/IDT mutation; see module-level docs.
        unsafe {
            crate::segments::install_user_segments();
            let _ = crate::segments::install_dpl3_handler(
                RING3_EXIT_VECTOR,
                nub_ring3_exit_stub as *const () as u64,
                1, // IST=1, run on the pre-existing exception stack
            );
        }
    }
}
