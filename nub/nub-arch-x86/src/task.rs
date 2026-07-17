//! Generic guest-kernel task skeleton: the personality-independent CALL/HALT
//! loop mechanics.
//!
//! A [`KernelTask`] drives one top-level invocation as a resumable loop.
//! Each [`KernelTask::poll_once`]:
//!
//!   1. Reconciles the task gas bank for the (possibly new) top entry
//!      ([`GuestPersonality::active_meter`] → [`TaskGasState::reconcile`]).
//!   2. Runs one ring-3 cycle on the top entry's frame via [`run_one_entry`]
//!      ([`crate::jit_run::enter_frame`]), then mirrors the JIT's post-exit
//!      regs/pc back into the frame.
//!   3. Classifies the exit and dispatches to the personality
//!      ([`GuestPersonality::on_halt`] / [`GuestPersonality::on_ecall`] /
//!      [`GuestPersonality::on_exit`]), which mutates the stack/gas through
//!      [`TaskCtx`] and either resumes the loop ([`Flow::Resume`]) or
//!      produces the final [`LoopOutcome`] ([`Flow::Done`]).
//!
//! The stack drives control transfer: the personality's CALL pushes an
//! [`EntryKind::Instance`], a routed yield pushes an
//! [`EntryKind::Reference`], and HALT/resume pop. Exactly one entry — the
//! top — is *Running*; every entry below it is *Waiting*. What the entries
//! mean (frames, owners, catch-sets, gas scopes) is personality state,
//! carried opaquely in [`StackEntry::meta`].

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use nub_recompiler_x86::codegen::{EXIT_ECALL, EXIT_HALT, EXIT_HOST_CALL};
use nub_arch_x86_abi::SCRATCHPAD_HEAD_LEN;

use crate::execution_lane::ExecutionLane;
use crate::jit_run::{self, ExitInfo};
use crate::personality::{ExecFrame, GuestPersonality, ObjHash};

pub type TaskId = u64;

/// Scheduler/task bookkeeping failure (a task missing from the ready map).
/// Value-identical to `call_loop`'s `ERR_PENDING_ORIGIN_INVARIANT` (74),
/// which covered this scheduler path before the split — kept equal so the
/// host-visible error code is unchanged.
const ERR_TASK_BOOKKEEPING: u32 = 74;

/// Successful loop result — what the host RPC returns to the bench
/// driver. On guest-side panic the loop returns `Err(code)` instead
/// and `nub_invoke_cached` packs the code into `exit_arg`.
pub struct LoopOutcome {
    pub exit_reason: u32,
    pub exit_arg: u32,
    pub return_value: u64,
    pub gas_remaining: i64,
    /// Effective bytes of the running Instance's scratchpad (slot[0]) region
    /// head at top HALT (see [`SCRATCHPAD_HEAD_LEN`]). Read from the top
    /// frame's owned mem (overlay-then-backing); zero on a non-clean exit.
    /// The host surfaces this as the uncompressed run result.
    pub scratchpad_head: [u8; SCRATCHPAD_HEAD_LEN],
}

/// What a personality exit hook tells the task loop to do next.
pub enum Flow {
    /// Keep polling — the stack top (possibly changed) runs next.
    Resume,
    /// The task is complete; surface this outcome to the host.
    Done(LoopOutcome),
}

/// What a kernel call-stack entry runs.
pub enum EntryKind<P: GuestPersonality> {
    /// A fresh invocation of an Instance — owns the running frame.
    /// Pushed by CALL; popped (and reflected) by HALT. Boxed so the stack
    /// `Vec` element stays pointer-sized: a frame is large (~500 B) and a
    /// `Reference` carries no frame, so an inline variant would bloat every
    /// stack slot. One alloc per CALL is negligible beside the per-frame
    /// page table build.
    Instance(Box<P::Frame>),
    /// A **yield activation**: re-runs an earlier [`EntryKind::Instance`]
    /// (the one at [`StackEntry::target`]) at its post-CALL continuation. It
    /// carries no frame of its own — running the top of the stack runs the
    /// *referent's* frame — so one Instance shares a single PC/regs/mem
    /// across its InstanceEntry and every ReferenceEntry (spec §3
    /// "same-instance entries share PC"). Pushed by a routed yield; popped
    /// by resume.
    Reference,
}

/// One entry on the in-kernel call stack.
pub struct StackEntry<P: GuestPersonality> {
    pub kind: EntryKind<P>,
    /// Index of the [`EntryKind::Instance`] whose frame this entry runs: its
    /// **own** index for an InstanceEntry, the **referent's** index for a
    /// ReferenceEntry. Lower-or-equal to the entry's own index and stable
    /// (entries below the top never move while the top exists).
    pub target: usize,
    /// Canonical Instance identity: an InstanceEntry gets a fresh id at
    /// CALL; a ReferenceEntry copies its referent's id, so every stack entry
    /// of one Instance compares equal. Kept for status/debug accounting.
    pub instance_id: u64,
    /// Personality-owned entry metadata (javm: owner edge + catch-set + gas
    /// scope). Opaque to the skeleton.
    pub meta: P::EntryMeta,
}

impl<P: GuestPersonality> StackEntry<P> {
    /// A fresh InstanceEntry at stack position `index` carrying a new
    /// `instance_id`. `target` is its own index (it runs its own frame);
    /// the metadata starts at its default and is stamped by the CALL site.
    pub fn instance(frame: P::Frame, index: usize, instance_id: u64) -> Self {
        Self::instance_with_meta(frame, index, instance_id, P::EntryMeta::default())
    }

    /// [`Self::instance`] with explicit metadata (the root push, whose meta
    /// the personality resolves before the entry exists).
    pub fn instance_with_meta(
        frame: P::Frame,
        index: usize,
        instance_id: u64,
        meta: P::EntryMeta,
    ) -> Self {
        StackEntry {
            kind: EntryKind::Instance(Box::new(frame)),
            target: index,
            instance_id,
            meta,
        }
    }
}

/// GAS MODEL (single reconciliation point). `live_gas` always holds the live
/// balance of the running frame's active meter. `meters[k]` is authoritative
/// for every non-active meter, while `host_budget` is the banked unmetered
/// scope. Every CALL/HALT/yield/resume/drop changes the top through one
/// poll boundary, so this one task-local state object catches all gas scope
/// changes.
pub struct TaskGasState<K: Ord + Clone> {
    pub meters: BTreeMap<K, i64>,
    pub live_gas: i64,
    pub host_budget: i64,
    pub root_active: Option<K>,
    pub current_active: Option<K>,
}

impl<K: Ord + Clone> TaskGasState<K> {
    pub fn new(root_active: Option<K>, initial_gas: i64) -> Self {
        let mut meters = BTreeMap::new();
        if let Some(k) = &root_active {
            meters.insert(k.clone(), initial_gas);
        }
        Self {
            meters,
            live_gas: initial_gas,
            host_budget: initial_gas,
            root_active: root_active.clone(),
            current_active: root_active,
        }
    }

    /// Reconcile the live balance when the active meter changes between loop
    /// iterations (the caller resolves `new_active` via
    /// [`GuestPersonality::active_meter`]).
    pub fn reconcile(&mut self, new_active: Option<K>) {
        reconcile_active(
            &self.current_active,
            &new_active,
            &mut self.live_gas,
            &mut self.host_budget,
            &mut self.meters,
        );
        self.current_active = new_active;
    }

    pub fn root_remaining(&self) -> i64 {
        root_remaining(
            &self.root_active,
            &self.current_active,
            self.live_gas,
            self.host_budget,
            &self.meters,
        )
    }
}

/// Reconcile the threaded `gas` (the live balance of the running frame's
/// active meter) when the active meter changes between loop iterations: bank
/// the OLD active scope's balance, load the NEW scope's. `meters[k]` is
/// authoritative for every non-active meter; `host_budget` holds the banked
/// host scope (the host-budgeted top + its loaned descendants, active ==
/// `None`). Aliasing falls out for free: a descendant naming the same meter
/// has the SAME active meter, so no swap happens and it shares the live
/// balance — no double-spend.
fn reconcile_active<K: Ord + Clone>(
    old: &Option<K>,
    new: &Option<K>,
    gas: &mut i64,
    host_budget: &mut i64,
    meters: &mut BTreeMap<K, i64>,
) {
    if old == new {
        return;
    }
    match old {
        Some(k) => {
            meters.insert(k.clone(), *gas);
        }
        None => *host_budget = *gas,
    }
    *gas = match new {
        Some(k) => meters.get(k).copied().unwrap_or(0),
        None => *host_budget,
    };
}

/// The RPC's ROOT-scope remaining gas — what a break surfaces to the host
/// (which harvests it into the top-level meter). The live `gas` when the
/// root scope is the running frame's active meter, else the root scope's
/// banked balance: `meters[root]` for a metered root, or `host_budget` for a
/// host-budgeted top.
fn root_remaining<K: Ord + Clone>(
    root: &Option<K>,
    current: &Option<K>,
    gas: i64,
    host_budget: i64,
    meters: &BTreeMap<K, i64>,
) -> i64 {
    if current == root {
        gas
    } else {
        match root {
            Some(k) => meters.get(k).copied().unwrap_or(0),
            None => host_budget,
        }
    }
}

pub enum TaskPoll {
    Pending,
    Done(LoopOutcome),
}

/// `&mut` to the frame the entry at `idx` runs, following a ReferenceEntry
/// to its referent InstanceEntry. The referent is always an `Instance` (a
/// Reference's `target` only ever names an InstanceEntry).
pub fn frame_at_mut<P: GuestPersonality>(stack: &mut [StackEntry<P>], idx: usize) -> &mut P::Frame {
    let target = stack[idx].target;
    match &mut stack[target].kind {
        EntryKind::Instance(f) => f,
        EntryKind::Reference => unreachable!("ReferenceEntry.target must be an InstanceEntry"),
    }
}

/// Shared-borrow companion of [`frame_at_mut`].
pub fn frame_at<P: GuestPersonality>(stack: &[StackEntry<P>], idx: usize) -> &P::Frame {
    let target = stack[idx].target;
    match &stack[target].kind {
        EntryKind::Instance(f) => f,
        EntryKind::Reference => unreachable!("ReferenceEntry.target must be an InstanceEntry"),
    }
}

/// The task state a personality exit hook may touch: the stack (push/pop/
/// truncate), the gas bank, and the Instance-id allocator. Field-disjoint
/// `&mut`s so hooks can borrow the stack and the gas bank simultaneously.
pub struct TaskCtx<'a, P: GuestPersonality> {
    pub lane: ExecutionLane,
    pub stack: &'a mut Vec<StackEntry<P>>,
    pub gas: &'a mut TaskGasState<P::MeterKey>,
    pub next_iid: &'a mut u64,
}

impl<P: GuestPersonality> TaskCtx<'_, P> {
    /// Stack top at hook entry (== poll_once's `top_idx`: the stack is
    /// unchanged between phase 1 and hook dispatch).
    pub fn top_idx(&self) -> usize {
        self.stack.len() - 1
    }

    /// Build a terminal outcome carrying the task's root-scope remaining
    /// gas.
    pub fn done(
        &self,
        exit_reason: u32,
        exit_arg: u32,
        return_value: u64,
        scratchpad_head: [u8; SCRATCHPAD_HEAD_LEN],
    ) -> Flow {
        Flow::Done(LoopOutcome {
            exit_reason,
            exit_arg,
            return_value,
            gas_remaining: self.gas.root_remaining(),
            scratchpad_head,
        })
    }
}

/// One top-level invocation as a resumable kernel task. The task owns
/// exactly one physical caller stack, one task-local gas bank, and one
/// monotonic Instance id allocator.
pub struct KernelTask<P: GuestPersonality> {
    id: TaskId,
    lane: ExecutionLane,
    stack: Vec<StackEntry<P>>,
    next_iid: u64,
    gas_state: TaskGasState<P::MeterKey>,
}

impl<P: GuestPersonality> KernelTask<P> {
    pub fn new(
        id: TaskId,
        lane: ExecutionLane,
        root: &ObjHash,
        endpoint_idx: u32,
        args: [u64; 4],
        initial_gas: i64,
    ) -> Result<Self, u32> {
        let (frame, meta) = P::build_root_frame(root, endpoint_idx, args)?;
        let mut stack: Vec<StackEntry<P>> = Vec::with_capacity(8);
        // Monotonic Instance identity. The top-level invocation is instance
        // 0; every CALL mints the next id.
        stack.push(StackEntry::instance_with_meta(frame, 0, 0, meta));
        let next_iid = 1;

        // The TOP frame's active meter, if declared, is the task's root
        // scope. A top with no meter is host-budgeted.
        let root_active = P::active_meter(&stack, 0);
        let gas_state = TaskGasState::new(root_active, initial_gas);
        Ok(Self {
            id,
            lane,
            stack,
            next_iid,
            gas_state,
        })
    }

    fn poll_once(&mut self) -> Result<TaskPoll, u32> {
        let top_idx = self.stack.len() - 1;
        // Reconcile the active meter for the (possibly new) top frame.
        let new_active = P::active_meter(&self.stack, top_idx);
        self.gas_state.reconcile(new_active);

        // Phase 1: run one ring-3 entry on the top entry's frame (an
        // InstanceEntry runs its own frame; a ReferenceEntry runs its
        // referent's — the same Instance, sharing one PC/regs/mem).
        let info = {
            let frame = frame_at_mut(&mut self.stack, top_idx);
            run_one_entry(self.lane, frame, self.gas_state.live_gas)?
        };
        self.gas_state.live_gas = info.gas_remaining;

        // Mirror the JIT's post-exit state back into the running frame.
        {
            let p = frame_at_mut(&mut self.stack, top_idx).parts();
            *p.regs = info.regs;
            *p.pc = info.pc as u64;
        }

        // Phase 2: exit-class dispatch to the personality.
        let mut ctx = TaskCtx {
            lane: self.lane,
            stack: &mut self.stack,
            gas: &mut self.gas_state,
            next_iid: &mut self.next_iid,
        };
        let flow = match info.exit_reason {
            EXIT_HALT => P::on_halt(&mut ctx, &info)?,
            EXIT_HOST_CALL | EXIT_ECALL => {
                let op = if info.exit_reason == EXIT_HOST_CALL {
                    info.exit_arg
                } else {
                    info.regs[11] as u32
                };
                P::on_ecall(&mut ctx, op, &info)?
            }
            _ => P::on_exit(&mut ctx, &info)?,
        };
        Ok(match flow {
            Flow::Resume => TaskPoll::Pending,
            Flow::Done(outcome) => TaskPoll::Done(outcome),
        })
    }

    pub fn run_to_completion(&mut self) -> Result<LoopOutcome, u32> {
        loop {
            match self.poll_once()? {
                TaskPoll::Pending => {}
                TaskPoll::Done(outcome) => return Ok(outcome),
            }
        }
    }
}

/// Cooperative per-lane scheduler: many task stacks can be resident for one
/// execution lane, but exactly one task is active on that lane at any
/// instant. Switching only happens at existing ring-3 exits. Multi-vCPU
/// Hyperlight runs one worker per lane; each worker submits into its lane's
/// persistent scheduler. Cross-lane task migration and work stealing remain
/// future scheduler work.
pub struct KernelScheduler<P: GuestPersonality> {
    lane: ExecutionLane,
    next_task_id: TaskId,
    tasks: BTreeMap<TaskId, KernelTask<P>>,
    completed: BTreeMap<TaskId, LoopOutcome>,
    ready: VecDeque<TaskId>,
}

impl<P: GuestPersonality> KernelScheduler<P> {
    pub fn new(lane: ExecutionLane) -> Self {
        Self {
            lane,
            next_task_id: 0,
            tasks: BTreeMap::new(),
            completed: BTreeMap::new(),
            ready: VecDeque::new(),
        }
    }

    pub fn submit_invoke(
        &mut self,
        root: &ObjHash,
        endpoint_idx: u32,
        args: [u64; 4],
        initial_gas: i64,
    ) -> Result<TaskId, u32> {
        let id = self.next_task_id;
        self.next_task_id += 1;
        let task = KernelTask::new(id, self.lane, root, endpoint_idx, args, initial_gas)?;
        self.tasks.insert(id, task);
        self.ready.push_back(id);
        Ok(id)
    }

    pub fn run_until_result(&mut self, target: TaskId) -> Result<LoopOutcome, u32> {
        if let Some(outcome) = self.completed.remove(&target) {
            return Ok(outcome);
        }
        while let Some(id) = self.ready.pop_front() {
            let mut task = self.tasks.remove(&id).ok_or(ERR_TASK_BOOKKEEPING)?;
            debug_assert_eq!(task.id, id);
            match task.poll_once()? {
                TaskPoll::Pending => {
                    self.tasks.insert(id, task);
                    self.ready.push_back(id);
                }
                TaskPoll::Done(outcome) if id == target => return Ok(outcome),
                TaskPoll::Done(outcome) => {
                    self.completed.insert(id, outcome);
                }
            }
            if let Some(outcome) = self.completed.remove(&target) {
                return Ok(outcome);
            }
        }
        Err(ERR_TASK_BOOKKEEPING)
    }
}

pub struct LaneSchedulerCell<P: GuestPersonality> {
    pub scheduler: spin::Mutex<Option<KernelScheduler<P>>>,
}

impl<P: GuestPersonality> LaneSchedulerCell<P> {
    pub const fn new() -> Self {
        Self {
            scheduler: spin::Mutex::new(None),
        }
    }
}

impl<P: GuestPersonality> Default for LaneSchedulerCell<P> {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: a `KernelScheduler` may contain live `FrameRuntime`s, which are
// lane-affine raw page-table/JIT pointers and deliberately not `Send`. The
// personality's static table is indexed by lane, and the host owns each lane
// with exactly one KVM worker thread; the spin lock guards accidental
// same-lane re-entry. We mark the cell `Sync` without making the scheduler
// or runtime generally sendable.
unsafe impl<P: GuestPersonality> Sync for LaneSchedulerCell<P> {}

/// Run exactly one ring-3 cycle for `frame`. The first call on a frame
/// builds its runtime ([`ExecFrame::build_runtime`] — the page table);
/// subsequent calls (parent resumes after a child HALT) reuse it — the
/// runtime is never evicted, so it is built exactly once per frame. Frame
/// mem + `mat_state` persist across re-entries — the parent's writes and
/// gas history survive the child's execution.
pub fn run_one_entry<F: ExecFrame>(
    lane: ExecutionLane,
    frame: &mut F,
    gas: i64,
) -> Result<ExitInfo, u32> {
    if frame.parts().runtime.is_none() {
        let rt = frame.build_runtime(lane)?;
        *frame.parts().runtime = Some(rt);
    }
    let p = frame.parts();
    let pc = *p.pc as u32;
    let regs = *p.regs;
    // Raw-pointer discipline: all refs come from ONE `parts()` call and are
    // pairwise disjoint; the three casts end their `&mut` uses immediately,
    // while `p.runtime` stays a live `&mut` across `enter_frame` (see
    // [`crate::personality::FrameParts`]). While the JIT runs against the
    // runtime's PT, the #PF handler CoWs guest writes into the frame mem's
    // overlay and advances `mat_state` / `ro_units` in place.
    let overlay_sink: *mut F::Mem = p.mem;
    let mat_state_ptr: *mut u8 = p.mat_state.as_mut_ptr();
    let mat_state_len = p.mat_state.len() as u64;
    let ro_units: *mut Vec<u32> = p.ro_units;
    let rt = p.runtime.as_mut().expect("just built");
    let info = unsafe {
        jit_run::enter_frame::<F::Mem>(
            lane,
            rt,
            gas,
            pc,
            regs,
            overlay_sink,
            mat_state_ptr,
            mat_state_len,
            ro_units,
        )
    };
    Ok(info)
}

/// Drive the CALL/HALT loop until either the top frame HALTs (clean exit)
/// or the JIT signals an unrecoverable condition (page fault, gas
/// exhaustion, ...). See the module docs for the loop body.
pub fn run_top<P: GuestPersonality>(
    root: &ObjHash,
    endpoint_idx: u32,
    args: [u64; 4],
    initial_gas: i64,
) -> Result<LoopOutcome, u32> {
    run_top_on_lane::<P>(
        ExecutionLane::PRIMARY,
        root,
        endpoint_idx,
        args,
        initial_gas,
    )
}

pub fn run_top_on_lane<P: GuestPersonality>(
    lane: ExecutionLane,
    root: &ObjHash,
    endpoint_idx: u32,
    args: [u64; 4],
    initial_gas: i64,
) -> Result<LoopOutcome, u32> {
    // The production ABI submits exactly one top-level invoke per worker/lane
    // call. Drive that task directly so the hot CALL/HALT path does not pay
    // the cooperative scheduler's map/queue churn on every ring-3 exit. The
    // scheduler stays available for the personality's test-only two-task
    // probe and for future batch/async guest entry points.
    let mut task = KernelTask::<P>::new(0, lane, root, endpoint_idx, args, initial_gas)?;
    task.run_to_completion()
}
