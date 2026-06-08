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
//! * **IST=1 for vector 0x81.** [`prepare_ring3_entry`] installs a
//!   lane-local TSS whose IST1 points at the active vCPU lane's private
//!   exception stack. Using IST=1 means we don't need to touch TSS.RSP0;
//!   the interrupt frame lands on that lane's exception stack and we abandon
//!   it after copying RAX out.
//! * **Lane-local state.** [`prepare_ring3_entry`] points GS at the active
//!   lane's [`Ring3LaneRaw`]. The entry/exit assembly stores its saved kernel
//!   RSP, saved CR3, and user RAX through GS, so two vCPUs can take the exit
//!   gate without racing on a process-global slot. Both `GSBase` and
//!   `KernelGSBase` are set to the same state pointer, and the exit stub starts
//!   with `swapgs`, because Hyperlight's exception path can leave the active GS
//!   side swapped before the final `int 0x81`.

use core::cell::UnsafeCell;
use core::mem::{offset_of, size_of};
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Once;

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

#[repr(C, align(8))]
#[derive(Clone, Copy)]
struct GdtEntry {
    limit_low: u16,
    base_low: u16,
    base_middle: u8,
    access: u8,
    flags_limit: u8,
    base_high: u8,
}

impl GdtEntry {
    const fn new(base: u32, limit: u32, access: u8, flags: u8) -> Self {
        Self {
            limit_low: (limit & 0xffff) as u16,
            base_low: (base & 0xffff) as u16,
            base_middle: ((base >> 16) & 0xff) as u8,
            access,
            flags_limit: (((limit >> 16) & 0x0f) as u8) | ((flags & 0x0f) << 4),
            base_high: ((base >> 24) & 0xff) as u8,
        }
    }

    const fn user(access: u8, flags: u8) -> Self {
        Self {
            limit_low: 0,
            base_low: 0,
            base_middle: 0,
            access,
            flags_limit: (flags & 0x0f) << 4,
            base_high: 0,
        }
    }

    const fn tss(base: u64, limit: u32) -> [Self; 2] {
        [
            Self {
                limit_low: (limit & 0xffff) as u16,
                base_low: (base & 0xffff) as u16,
                base_middle: ((base >> 16) & 0xff) as u8,
                access: 0x89,
                flags_limit: ((limit >> 16) & 0x0f) as u8,
                base_high: ((base >> 24) & 0xff) as u8,
            },
            Self {
                limit_low: ((base >> 32) & 0xffff) as u16,
                base_low: ((base >> 48) & 0xffff) as u16,
                base_middle: 0,
                access: 0,
                flags_limit: 0,
                base_high: 0,
            },
        ]
    }
}

#[repr(C, packed)]
struct Tss {
    _rsvd0: [u8; 4],
    _rsp0: u64,
    _rsp1: u64,
    _rsp2: u64,
    _rsvd1: [u8; 8],
    ist1: u64,
    _ist2: u64,
    _ist3: u64,
    _ist4: u64,
    _ist5: u64,
    _ist6: u64,
    _ist7: u64,
    _rsvd2: [u8; 10],
    _iomap_base: u16,
}

impl Tss {
    const fn new() -> Self {
        Self {
            _rsvd0: [0; 4],
            _rsp0: 0,
            _rsp1: 0,
            _rsp2: 0,
            _rsvd1: [0; 8],
            ist1: 0,
            _ist2: 0,
            _ist3: 0,
            _ist4: 0,
            _ist5: 0,
            _ist6: 0,
            _ist7: 0,
            _rsvd2: [0; 10],
            _iomap_base: size_of::<Tss>() as u16,
        }
    }
}

#[repr(C, align(16))]
struct LaneCpuControl {
    gdt: [GdtEntry; 7],
    tss: Tss,
}

impl LaneCpuControl {
    const fn new() -> Self {
        Self {
            gdt: [GdtEntry::new(0, 0, 0, 0); 7],
            tss: Tss::new(),
        }
    }
}

struct LaneCpuControlCell {
    raw: UnsafeCell<LaneCpuControl>,
}

unsafe impl Sync for LaneCpuControlCell {}

impl LaneCpuControlCell {
    const fn new() -> Self {
        Self {
            raw: UnsafeCell::new(LaneCpuControl::new()),
        }
    }
}

static LANE_CPU: [LaneCpuControlCell; MAX_EXECUTION_LANES] =
    [const { LaneCpuControlCell::new() }; MAX_EXECUTION_LANES];
static LANE_CPU_READY: [AtomicBool; MAX_EXECUTION_LANES] =
    [const { AtomicBool::new(false) }; MAX_EXECUTION_LANES];
static RING3_LANE_READY: [AtomicBool; MAX_EXECUTION_LANES] =
    [const { AtomicBool::new(false) }; MAX_EXECUTION_LANES];

const TSS_SEL: u16 = 0x18;

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

fn lane_exception_stack_top(lane: usize) -> u64 {
    nub_host_common::layout::MAX_GVA as u64 - nub_host_common::layout::SCRATCH_TOP_EXN_STACK_OFFSET
        + 1
        - lane as u64 * nub_host_common::layout::VCPU_EXCEPTION_STACK_STRIDE
}

/// Install the lane-local GDT/TSS for the current vCPU.
///
/// Hyperlight's boot path starts every vCPU with lane 0's post-boot SREGs, so
/// all lanes initially share one TSS and therefore one IST1 stack. Concurrent
/// ring-3 exits and page faults need independent IST storage; otherwise two
/// vCPUs can scribble over the same interrupt frames. We keep the selector
/// layout identical to the boot GDT, but point the TSS descriptor at
/// per-lane storage and load TR once for that lane.
///
/// # Safety
/// Must run in ring 0 on the vCPU represented by `lane`, before that lane
/// enters ring 3. A lane must not call this concurrently with itself.
unsafe fn install_lane_cpu_control(lane: ExecutionLane) {
    let idx = lane.index();
    if LANE_CPU_READY[idx].load(Ordering::Acquire) {
        return;
    }

    let ctrl = LANE_CPU[idx].raw.get();
    let tss_ptr = unsafe { ptr::addr_of_mut!((*ctrl).tss) };
    unsafe {
        ptr::write(tss_ptr, Tss::new());
        ptr::addr_of_mut!((*tss_ptr).ist1).write_unaligned(lane_exception_stack_top(idx));
    }

    let tss_base = tss_ptr as u64;
    let tss_limit = (size_of::<Tss>() - 1) as u32;
    let tss = GdtEntry::tss(tss_base, tss_limit);
    let gdt = [
        GdtEntry::new(0, 0, 0, 0),
        GdtEntry::new(0, 0, 0x9A, 0xA),
        GdtEntry::new(0, 0, 0x92, 0xC),
        tss[0],
        tss[1],
        GdtEntry::user(0xFA, 0xA),
        GdtEntry::user(0xF2, 0xC),
    ];
    unsafe {
        ptr::addr_of_mut!((*ctrl).gdt).write(gdt);
        let gdtr = crate::segments::GdtDescriptor {
            limit: (size_of::<[GdtEntry; 7]>() - 1) as u16,
            base: ptr::addr_of!((*ctrl).gdt) as u64,
        };
        crate::segments::lgdt(&gdtr);
        core::arch::asm!("ltr ax", in("ax") TSS_SEL, options(nostack, preserves_flags));
    }

    LANE_CPU_READY[idx].store(true, Ordering::Release);
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
    let state = &RING3_LANES[lane.index()];
    if !RING3_LANE_READY[lane.index()].load(Ordering::Acquire) {
        unsafe {
            install_lane_cpu_control(lane);
            install_ring3_exit_gate();
            write_gs_bases(state.ptr() as u64);
        }
        RING3_LANE_READY[lane.index()].store(true, Ordering::Release);
    }
    unsafe {
        state.reset_for_entry(lane);
        // GS base is not persistent across top-level guest entries in the
        // Hyperlight/KVM path, so refresh it every time even though the
        // lane-local GDT/TSS/IDT setup above is stable.
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
    // The IDT storage allocation is process-global, but GDTR/IDTR are vCPU
    // registers. Every lane must reload its GDT limit (for USER_CS/USER_DS)
    // and IDT base (for vector 0x81), while the ~4 KiB IDT buffer is created
    // only once.
    static RING3_IDT: Once<&'static crate::segments::IdtDescriptor> = Once::new();

    // SAFETY: ring-0 GDT/IDT mutation; see module-level docs.
    unsafe {
        crate::segments::install_user_segments();
        let descriptor = RING3_IDT.call_once(|| {
            crate::segments::install_dpl3_handler(
                RING3_EXIT_VECTOR,
                nub_ring3_exit_stub as *const () as u64,
                1, // IST=1, run on the lane-local exception stack
            )
        });
        crate::segments::lidt(descriptor);
    }
}
