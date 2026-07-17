//! Kernel-personality seam: what the generic guest kernel ([`crate::task`],
//! [`crate::jit_run`]) needs from a pluggable state/cap system. javm-cap is
//! one implementation ([`crate::call_loop`]). Exactly one personality per
//! guest binary: enforced structurally by `register_guest_kernel!` and
//! asserted at runtime in `jit_run::install_handlers`.

extern crate alloc;

use alloc::vec::Vec;

use crate::execution_lane::ExecutionLane;
use crate::jit_run::{ExitInfo, FrameRuntime};
use crate::task::{Flow, StackEntry, TaskCtx};

/// Content hash of a published state object (javm: `CapHash`). Local alias
/// for A2; unifies with `nub-kernel::ObjHash` at phase B.
pub type ObjHash = [u8; 32];

/// Persisted PVM register file width. Matches
/// [`crate::jit_run::ExitInfo::regs`] and `javm_cap::NUM_REGS`
/// (const-asserted in `call_loop`).
pub const NUM_REGS: usize = 13;

/// Source of a guest data page for materialization.
///
/// `Pa` = a live slab's physical address; `Zero` = shared zero page (the
/// substrate substitutes `ZERO_PAGE.pa()`); `Missing` = PVM fault.
pub enum PageSource {
    Pa(u64),
    Zero,
    Missing,
}

/// Paged frame memory the CoW #PF handler materializes from (javm:
/// `DataCap`). Implemented on a personality-owned type (javm:
/// `#[repr(transparent)] JavmMem(DataCap)`) so the impl survives the B1
/// crate split (orphan rule).
pub trait FrameMem: Sized {
    /// Privately-owned CoW page pending publication into the overlay
    /// (javm: `Arc<javm_cap::PageBytes>`).
    type CowPage;

    /// Source of data-extent page `page_idx` (index from the data base).
    fn page_source(&self, page_idx: usize) -> PageSource;

    /// Whether `page_idx` is privately CoW'd (present in the overlay).
    fn overlay_has(&self, page_idx: u32) -> bool;

    /// Allocate a page-aligned private copy of `src` (len ==
    /// `paging::PAGE_SIZE`); return it plus its physical address. Does NOT
    /// publish. Publication is separate so the substrate keeps the exact op
    /// order: alloc/copy → `pt_map_leaf` → `invlpg` → commit — a map failure
    /// after alloc leaves the overlay untouched.
    /// javm: `Arc<PageBytes::from_page_copy_unhashed>` + `paging::va_to_pa`.
    fn alloc_cow_page(src: &[u8]) -> Option<(Self::CowPage, u64)>;

    /// Publish a CoW'd page into the overlay at `page_idx`.
    fn commit_overlay_page(&mut self, page_idx: u32, page: Self::CowPage);
}

/// Disjoint mutable views of one frame's execution state — a field-level
/// split borrow through ONE `&mut self` call ([`ExecFrame::parts`]).
///
/// SOUNDNESS: all six refs derive from one `&mut self` and are pairwise
/// disjoint fields, so holding them simultaneously is a plain split borrow.
/// [`crate::task::run_one_entry`] converts `mem`/`mat_state`/`ro_units` to
/// raw pointers immediately (ending those `&mut` uses) and keeps `runtime`
/// as a live `&mut` across `enter_frame`. A single `parts()` call — rather
/// than per-field accessor methods — is required: sequential `&mut self`
/// accessor calls would invalidate previously extracted raw pointers under
/// Stacked Borrows.
pub struct FrameParts<'a, M: FrameMem> {
    pub pc: &'a mut u64,
    pub regs: &'a mut [u64; NUM_REGS],
    pub mem: &'a mut M,
    pub mat_state: &'a mut Vec<u8>,
    pub ro_units: &'a mut Vec<u32>,
    pub runtime: &'a mut Option<FrameRuntime>,
}

/// One executable kernel frame (javm: `KernelFrame`).
pub trait ExecFrame {
    type Mem: FrameMem;

    /// Split-borrowed access to the frame's execution state.
    fn parts(&mut self) -> FrameParts<'_, Self::Mem>;

    /// Personality top-half of runtime construction: resolve the image,
    /// build the materialization ranges, call
    /// [`crate::jit_run::build_frame_runtime`]. Called lazily by
    /// [`crate::task::run_one_entry`] when `parts().runtime` is `None`.
    fn build_runtime(&self, lane: ExecutionLane) -> Result<FrameRuntime, u32>;
}

/// Guest-side state-object store (javm: `state_cache::CACHE` via
/// `JavmStore`).
pub trait GuestStore: Sync {
    /// Decode + validate + hash + insert one published object.
    fn put_object(&self, bytes: &[u8]) -> Result<ObjHash, u32>;

    /// Post-invoke housekeeping (javm: `CACHE.sweep_instances()`).
    fn sweep(&self) {}

    /// Drop all compiled-image artifacts (javm: walk the cap directory
    /// clearing `CapCache::Image` slots).
    fn evict_jit(&self) {}

    /// Idempotent boot-info publication (javm: `state_cache::init_directory_va`).
    fn init_boot_info(&self) {}

    /// Raw bytes of the personality's boot-info block.
    fn boot_info_bytes(&self) -> Vec<u8>;
}

/// A guest-kernel personality: the pluggable state/cap system driving the
/// generic task skeleton ([`crate::task::KernelTask`]). The skeleton owns
/// the loop mechanics (stack, gas banking, ring-3 entry); the personality
/// owns frame construction, gas-sourcing policy, and every exit-class hook.
pub trait GuestPersonality: Sized + 'static {
    type Frame: ExecFrame;
    type MeterKey: Ord + Clone;
    type EntryMeta: Default;
    type Store: GuestStore + 'static;

    fn store() -> &'static Self::Store;

    /// Build the root frame + its entry metadata for a top-level invoke.
    fn build_root_frame(
        root: &ObjHash,
        endpoint_idx: u32,
        args: [u64; 4],
    ) -> Result<(Self::Frame, Self::EntryMeta), u32>;

    /// Gas-sourcing policy: the active meter for the entry at `idx`.
    /// `None` = host budget.
    fn active_meter(stack: &[StackEntry<Self>], idx: usize) -> Option<Self::MeterKey>;

    /// `EXIT_HALT`.
    fn on_halt(ctx: &mut TaskCtx<'_, Self>, info: &ExitInfo) -> Result<Flow, u32>;

    /// `EXIT_HOST_CALL` | `EXIT_ECALL`, `op` pre-extracted by the skeleton
    /// (`exit_arg` for HOST_CALL, `regs[11]` for ECALL). The personality
    /// owns the ecall-floor + frame-cost gas gate AND all OP_* semantics.
    fn on_ecall(ctx: &mut TaskCtx<'_, Self>, op: u32, info: &ExitInfo) -> Result<Flow, u32>;

    /// Every other exit (OOG/PageFault/Panic/Trap). Default: bubble
    /// verbatim.
    fn on_exit(ctx: &mut TaskCtx<'_, Self>, info: &ExitInfo) -> Result<Flow, u32> {
        Ok(ctx.done(
            info.exit_reason,
            info.exit_arg,
            info.regs[7],
            [0u8; nub_arch_x86_abi::SCRATCHPAD_HEAD_LEN],
        ))
    }
}
