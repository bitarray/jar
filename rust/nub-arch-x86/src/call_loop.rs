//! In-kernel CALL/HALT loop driving the in-sandbox sub-VM lifecycle.
//!
//! `nub_invoke_cached` calls [`run_top`] with a top-level
//! `Cap::Instance` hash + endpoint. We build a [`KernelFrame`] from
//! the published cap state, push it on an in-memory `Vec` stack, then
//! iterate:
//!
//!   1. Run one ring-3 cycle via [`crate::jit_run::enter_frame`].
//!   2. On `EXIT_HALT` (or `EXIT_HOST_CALL` with `exit_arg == 0` —
//!      `subsoil`'s endpoint trampoline issues `li t0, 0; ecall`,
//!      which the transpiler emits as PVM `ecalli 0`): pop. If the
//!      stack is empty, return; otherwise reflect the child's φ[7]
//!      into the parent's φ[7].
//!   3. On `EXIT_HOST_CALL` / `EXIT_ECALL` with a recognised host op
//!      (`DERIVE_SPAWN` = 18, `HOST_CALL` = 26): dispatch in-place.
//!      MGMT ops (`COPY` etc.) are accepted as no-ops in V1 — the
//!      bench guest doesn't need them.
//!   4. Anything else terminates the loop and returns the exit code
//!      to the host.
//!
//! ## V1 simplifications
//!
//! - **No mem snapshotting across CALL/HALT.** Each frame entry
//!   allocates fresh per-invocation memory from the image's overlays;
//!   on resume after a child HALT, the parent's mem is rebuilt the
//!   same way it was on first entry. Bench guests that don't write
//!   memory (the recursive-spawn bench) see no observable change.
//!
//! - **Sub-VM instances live in `cache.instances`.** `derive_spawn`
//!   publishes a fresh `Cap::Instance` via
//!   [`crate::state_cache::publish_transient_instance`]; the returned
//!   `CapRef` goes into the parent's cnode slot. `host_call` then
//!   resolves `cnode[slot]: CapHashOrRef` via
//!   `CACHE.get(CapHashOrRef::…)` on the heap-resident directory,
//!   yielding either a host-pre-published blob or a kernel-derived
//!   instance. Refcount on each entry is bumped by the resolution and
//!   decremented when the [`KernelFrame`] drops, so the cache slot
//!   stays pinned for the frame's lifetime.
//!
//! - **Per-frame cnode snapshot.** Top frame's cnode is seeded from
//!   the running `Cap::Instance`'s `root_cnode` (now walkable from
//!   the guest after the SSZ `SparseList` allocator-genericity
//!   change); child frames inherit the parent's cnode entries. The
//!   in-frame cnode is mutable (slot writes via `derive_spawn`); the
//!   underlying `Cap::CNode` in the cache is read-only. A follow-up
//!   commit will migrate writes into the cache via `cap_make_mut` so
//!   the cnode lives entirely in cache.instances.
//!
//! ## Data-flow principle and dirty pages
//!
//! Per [`website/content/spec/discussions/data-flow-principle.md`][df],
//! JAR's foundational invariant is **single-mutator-per-state-unit
//! at any moment**: effects can only follow explicit data flow.
//! Two in-flight invocations never share a mutator on the same
//! state, and one invocation's mutations are never visible to
//! another except through a deliberate data-flow event (a return
//! value, an explicit cnode-slot move, etc.).
//!
//! What this means for [`KernelFrame::dirty_pages`]:
//!
//! - The CoW #PF handler ([`crate::jit_run::jit_pf_handler`])
//!   allocates a fresh page on every guest write to a CoW-armed
//!   mapping and records the page on the running frame's
//!   `dirty_pages` vector. That page is the frame's own working
//!   memory — it lets the frame read its own writes within ring 3.
//!
//! - On frame pop the dirty pages are **dropped**, not propagated.
//!   F1's modifications to its mem region do not appear in F0's
//!   cnode or memory automatically; F1 must hand them up through
//!   an explicit data-flow channel. Today that channel is `φ[7]`
//!   (the return value reflected by [`pop_and_reflect`]). The spec
//!   intent for cap-shaped returns is a designated
//!   scratchpad-cnode slot the child writes and the parent
//!   explicitly moves into its own cnode; not yet implemented.
//!
//! - The `source_hash` / `source_slot` fields on [`DirtyPage`] and
//!   [`CowRange`] are populated by the #PF handler but currently
//!   unused — they're the metadata the future scratchpad mechanism
//!   will need.
//!
//! Early drafts of this codepath included an "auto-mint" step that
//! published the dirty pages as a fresh `Cap::Data` and rewrote
//! the parent's cnode slot when a source-hash match held. That was
//! a side-channel from child to parent — it violated the
//! data-flow invariant by propagating effects without a
//! corresponding move. It was reverted; this comment exists so the
//! mistake isn't re-made.
//!
//! [df]: ../../../../website/content/spec/discussions/data-flow-principle.md

#![cfg(target_os = "none")]

extern crate alloc;

use alloc::vec::Vec;

use javm_cap::cache::CapHashOrRef;
use javm_cap::cap::Cap;
use javm_cap::hash::{Blake2b256, Hash};
use javm_cap::slot::Key;
use javm_cap::{CNodeCap, CapHash, NUM_REGS};

use crate::jit_run::{self, ExitInfo, FrameRuntime};
use crate::page_alloc::PageBuf;
use crate::paging;
use crate::state_cache::{CACHE, publish_transient_instance};

const EXIT_HALT: u32 = 0;
const EXIT_OOG: u32 = 2;
const EXIT_HOST_CALL: u32 = 4;
const EXIT_ECALL: u32 = 6;
/// Guest trap (deliberate or host-rejected op). Matches the interpreter's
/// `ExitReason::Trap` and the JIT codegen's `EXIT_TRAP` ABI value, so a
/// host-side rejection (e.g. a pinned-slot write) surfaces identically.
const EXIT_TRAP: u32 = 7;

const OP_REPLY: u32 = 0;
const OP_DERIVE_SPAWN: u32 = 18;
const OP_HOST_CALL: u32 = 26;

const MAX_DEPTH: usize = 32_768;
/// Maximum number of concurrently-resident [`FrameRuntime`]s. Each
/// runtime keeps ~48 KiB of pages alive (page table + mem/ctx/stack
/// buffers); bounding this at 256 caps the in-kernel footprint at
/// ~12 MiB even for pathologically deep recursion.
///
/// On each push, the frame at depth `stack.len() - RUNTIME_CACHE_CAP`
/// is evicted: that frame is about to fall outside the cached window
/// and will rebuild its runtime on resume. For depth ≤ cap, no
/// eviction — every frame keeps its cached PT + bufs across the
/// inevitable child-HALT → parent-resume cycle.
const RUNTIME_CACHE_CAP: usize = 256;

// Error codes returned to the host as InvocationResult.exit_arg when
// the call loop bails out. The byte stays small so a hex dump in the
// host bench output is easy to read.
const ERR_INSTANCE_NOT_FOUND: u32 = 21;
const ERR_INSTANCE_KIND: u32 = 22;
const ERR_IMAGE_NOT_FOUND: u32 = 23;
const ERR_IMAGE_KIND: u32 = 24;
const ERR_ENDPOINT_OOB: u32 = 25;
const ERR_DERIVE_SLOT_OOB: u32 = 31;
// Code 32 was `ERR_DERIVE_PUBLISH`, reserved for a publish-OOM path
// that no longer exists: `publish_transient_instance` is infallible
// (talc OOM panics rather than returning). Skip the value to keep
// the existing error-code mapping stable.
const ERR_HOST_CALL_SLOT_EMPTY: u32 = 40;
const ERR_JIT_FAILED: u32 = 50;
const ERR_DEPTH_LIMIT: u32 = 51;
const ERR_MAP_BAD_KIND: u32 = 60;

/// One stack frame on the in-kernel call stack. Holds the
/// identifiers for the Image and Instance caps the frame runs
/// against (plus per-frame mutable PVM state and the ring-3
/// resources cache). The caps themselves live in the heap-resident
/// [`CACHE`] (`CacheDirectory<FixedState>`); the frame re-looks
/// them up under the cache lock on access. V1 invariant: nothing
/// evicts directory entries mid-RPC, so a hash that resolved at
/// frame build resolves the same way for the frame's lifetime.
pub struct KernelFrame {
    /// Content hash of the Image cap this frame runs. Resolved via
    /// `CACHE.lock().get(CapHashOrRef::Hash(image_hash))` at each access.
    image_hash: CapHash,
    /// Image's chain hash. Used by `derive_spawn` to compute the
    /// child's chain. Cached locally to avoid a cap deref per
    /// derive.
    image_hash_chain: CapHash,
    /// Resolution key for the running Instance — either a content-
    /// addressed blob (Hash) for host-published top-level instances,
    /// or an identity-addressed slot (Ref) for kernel-derived
    /// sub-VMs.
    instance: CapHashOrRef,
    /// Live PVM register file. Written by the JIT on every entry/
    /// exit.
    regs: [u64; NUM_REGS],
    /// Current PVM PC. Same lifecycle as `regs`.
    pc: u32,
    /// Per-frame cnode snapshot: the radix kv-map (`Hasher(Key) ->
    /// CapHashOrRef`) seeded from the running `Cap::Instance`'s image
    /// (pinned/initial) and grown by `derive_spawn`. No fixed slot count —
    /// a normal `CNodeCap`. CNode ops run only in the call-loop dispatch
    /// (ring 0 after the JIT context switch), so the kernel-heap `RadixMap`
    /// is live; the JIT-compiled guest code never touches this directly.
    cnode: CNodeCap,
    /// Slot keys this frame's image declares pinned (read-only), sorted —
    /// the recompiler's mirror of the interpreter's
    /// `InstanceEntry.pinned_slots`. A write to one of these (e.g. a
    /// `derive_spawn` dst) must trap, matching the interpreter's
    /// `OpError::SlotPinned`. Sorted (image pinned slots are emitted sorted),
    /// so membership is a `binary_search`.
    pinned: Vec<Key>,
    /// CoW-allocated fresh pages, populated by `jit_pf_handler` on
    /// the first write to each page of a copy-on-write `MatRange`. Per
    /// the data-flow principle (see module doc), these are frame-local
    /// working memory and are dropped at frame pop without
    /// propagation. (The cap-backed `MatRange` list itself lives in the
    /// frame's [`FrameRuntime`], built with resolved PAs in
    /// [`build_runtime`].)
    dirty_pages: Vec<DirtyPage>,
    /// Per-frame ring-3 resources (PT + mem/ctx/stack buffers).
    /// Lazily built on the first [`run_one_entry`] for this frame
    /// and reused across every subsequent re-entry. Cuts N
    /// PageTable + 3 PageBuf allocations for a depth-N recursion.
    runtime: Option<FrameRuntime>,
}

/// One cap-backed data mapping projected into the guest address space,
/// lazily materialized (category #3). The #PF handler scans this list
/// when a guest access faults inside ring 3; a hit identifies the page's
/// source PA + kind (pinned read-only vs unpinned copy-on-write), so the
/// handler can page it in (read) or copy-on-write it (write) and charge.
/// Pages NOT covered by any `MatRange` are ephemeral (backed directly by
/// the frame's private `mem_buf`).
#[derive(Clone, Copy, Debug)]
pub struct MatRange {
    pub start: u32,
    pub end: u32,
    /// Window `[pas_off, pas_off + pas_len)` into the frame's `mat_pas` arena:
    /// one source physical address per page in `[start, end)`. A dense DataCap's
    /// pages are independent page-aligned slabs (not one contiguous buffer), so
    /// each page resolves its own PA; an absent / zero (`Empty`) page maps to the
    /// frame's shared zero page. `MatRange` stays `Copy` (it is published to the
    /// #PF handler by pointer), so the PAs live in the frame-owned arena rather
    /// than inline.
    pub pas_off: u32,
    pub pas_len: u32,
    /// [`javm_exec::mat::PageKind`] as a `u8`: pinned slots are
    /// `PinnedCapRo` (a write hard-faults), initial slots are
    /// `UnpinnedCapCow` (a write copies-on-write).
    pub kind: u8,
    pub source_hash: CapHash,
    /// The V1 single-byte source slot (diagnostics only). `u8` not `Key`
    /// so `MatRange` stays `Copy` (it is published to the #PF handler by
    /// pointer).
    pub source_slot: u8,
}

/// One CoW-allocated dirty page. Owned by `KernelFrame.dirty_pages`
/// and dropped at frame pop. The metadata fields are dead-code-allowed
/// today: they're retained scaffolding for a possible future explicit
/// scratchpad-cnode mechanism, not the reverted auto-mint step.
#[allow(dead_code)]
pub struct DirtyPage {
    pub guest_va: u32,
    pub source_hash: CapHash,
    pub source_slot: u8,
    /// 4 KiB page holding the dirtied contents. Page's PA is what
    /// the PTE currently points at; on auto-mint we read these bytes
    /// to build the fresh `Cap::Data`.
    pub page: PageBuf,
}

/// Successful loop result — what the host RPC returns to the bench
/// driver. On guest-side panic the loop returns `Err(code)` instead
/// and `nub_invoke_cached` packs the code into `exit_arg`.
pub struct LoopOutcome {
    pub exit_reason: u32,
    pub exit_arg: u32,
    pub return_value: u64,
    pub gas_remaining: i64,
}

/// Drive the CALL/HALT loop until either the top frame HALTs (clean
/// exit) or the JIT signals an unrecoverable condition (page fault,
/// gas exhaustion, …). See module docs for the loop body.
///
/// Cap lookups go through the heap-resident [`CACHE`] static. Each
/// lookup takes the cache's spinlock; we keep lock scopes tight
/// (clone out the fields we need, drop the guard) so other guest-mode
/// lookups can proceed concurrently.
pub fn run_top(
    instance_hash: &CapHash,
    endpoint_idx: u32,
    args: [u64; 4],
    initial_gas: i64,
) -> Result<LoopOutcome, u32> {
    let top = build_frame_from_published(instance_hash, endpoint_idx, args)?;
    let mut stack: Vec<KernelFrame> = Vec::with_capacity(8);
    stack.push(top);
    let mut gas = initial_gas;

    let outcome = loop {
        // Phase 1: run one ring-3 entry on the top frame.
        let info = {
            let frame = stack.last_mut().expect("stack non-empty");
            run_one_entry(frame, gas)?
        };
        gas = info.gas_remaining;
        // Mirror the JIT's post-exit state back into the top frame.
        {
            let frame = stack.last_mut().expect("stack non-empty");
            frame.regs = info.regs;
            frame.pc = info.pc;
        }

        // Phase 2: classify the exit. Borrow scopes are kept tight so
        // we can mutate `stack` (push/pop) inside each arm.
        match info.exit_reason {
            EXIT_HALT => {
                if pop_and_reflect(&mut stack, info.regs[7]) {
                    break LoopOutcome {
                        exit_reason: info.exit_reason,
                        exit_arg: info.exit_arg,
                        return_value: info.regs[7],
                        gas_remaining: gas,
                    };
                }
            }
            EXIT_HOST_CALL | EXIT_ECALL => {
                // ecall block: charge its dynamic cost (check-before-
                // charge) BEFORE doing the work, matching the interpreter's
                // per-ecall charge. On OOG the block is not done and gas is
                // unchanged; the resume point is the ecall's OWN pc
                // (info.pc is the next instruction; custom-0 is 4-byte) —
                // surfacing that pc rides on the deferred recoverable-yield
                // layer, like the in-code block OOG (gas-cost.md §3).
                let is_ecalli = info.exit_reason == EXIT_HOST_CALL;
                let ecall_cost = javm_exec::gas_const::ecall_dynamic_cost(is_ecalli) as i64;
                if gas < ecall_cost {
                    break LoopOutcome {
                        exit_reason: EXIT_OOG,
                        exit_arg: 0,
                        return_value: info.regs[7],
                        gas_remaining: gas,
                    };
                }
                gas -= ecall_cost;

                let op = if info.exit_reason == EXIT_HOST_CALL {
                    info.exit_arg
                } else {
                    info.regs[11] as u32
                };
                match op {
                    OP_REPLY if pop_and_reflect(&mut stack, info.regs[7]) => {
                        // Preserve the JIT exit shape so the host bench
                        // harness, which asserts `(reason=4, arg=0)` for
                        // the subsoil trampoline halt, doesn't trip.
                        break LoopOutcome {
                            exit_reason: info.exit_reason,
                            exit_arg: info.exit_arg,
                            return_value: info.regs[7],
                            gas_remaining: gas,
                        };
                    }
                    OP_REPLY => {
                        // Stack still has frames; the parent picks up at
                        // the next iter with the child's φ[7] reflected.
                    }
                    OP_DERIVE_SPAWN => {
                        let trapped = {
                            let frame = stack.last_mut().expect("non-empty");
                            dispatch_derive_spawn(frame)?
                        };
                        if trapped {
                            // Pinned dst → guest trap, mirroring the interpreter.
                            break LoopOutcome {
                                exit_reason: EXIT_TRAP,
                                exit_arg: 0,
                                return_value: info.regs[7],
                                gas_remaining: gas,
                            };
                        }
                    }
                    OP_HOST_CALL => {
                        if stack.len() >= MAX_DEPTH {
                            return Err(ERR_DEPTH_LIMIT);
                        }
                        let child = {
                            let parent = stack.last().expect("non-empty");
                            dispatch_host_call(parent)?
                        };
                        // Bound the resident-runtime set to the top
                        // RUNTIME_CACHE_CAP frames. After the new child
                        // is pushed, the frame at depth (len -
                        // RUNTIME_CACHE_CAP) is the one just falling
                        // outside the window — evict its runtime so
                        // talc reclaims the ~48 KiB of pages it held.
                        // That frame will rebuild its runtime when it
                        // eventually resumes.
                        if stack.len() >= RUNTIME_CACHE_CAP {
                            let evict_idx = stack.len() - RUNTIME_CACHE_CAP;
                            stack[evict_idx].runtime = None;
                        }
                        stack.push(child);
                    }
                    // Anything else (MGMT ops, SET_IMAGE, HOST_YIELD,
                    // arbitrary `ecalli imm`, …) is not in-kernel-
                    // handled in V1: bubble it up to the host with
                    // the JIT's reported exit reason/arg verbatim.
                    // Mirrors pre-call-loop behaviour so unit tests
                    // that fire `ecalli imm` and check `(reason=4,
                    // arg=imm)` keep passing.
                    _ => {
                        break LoopOutcome {
                            exit_reason: info.exit_reason,
                            exit_arg: info.exit_arg,
                            return_value: info.regs[7],
                            gas_remaining: gas,
                        };
                    }
                }
            }
            _ => {
                // PageFault (3), Panic (1), OOG (2), Trap (7), …
                break LoopOutcome {
                    exit_reason: info.exit_reason,
                    exit_arg: info.exit_arg,
                    return_value: info.regs[7],
                    gas_remaining: gas,
                };
            }
        }
    };

    // Drop the stack BEFORE we hand the outcome back. Dropping each
    // frame releases its `CapHashOrRef::Ref(CapRef)` clones,
    // decrementing the inner Arc strong counts; the actual reclaim of
    // any orphaned transient instances happens via
    // `CACHE.sweep_instances()` in `nub_invoke_cached` after this
    // returns.
    drop(stack);
    Ok(outcome)
}

/// Run exactly one ring-3 cycle for `frame`. The first call on a
/// frame builds [`FrameRuntime`] (PT + mem/ctx/stack pages, mem
/// populated from overlays); subsequent calls (parent resumes after
/// a child HALT) reuse the cached runtime. Frame mem persists across
/// re-entries — the parent's writes survive the child's execution.
fn run_one_entry(frame: &mut KernelFrame, gas: i64) -> Result<ExitInfo, u32> {
    if frame.runtime.is_none() {
        let rt = build_runtime(frame)?;
        frame.runtime = Some(rt);
    }
    let pc = frame.pc;
    let regs = frame.regs;
    let dirty_sink: *mut Vec<DirtyPage> = &mut frame.dirty_pages;
    let rt = frame.runtime.as_mut().expect("just built");
    let info = unsafe { jit_run::enter_frame(rt, gas, pc, regs, dirty_sink) };
    Ok(info)
}

/// Build the per-frame ring-3 runtime. Every pinned + initial slot
/// mapping projects directly into the per-call PT; initial slots are
/// armed for CoW via `frame.cow_ranges` and flipped writable by the
/// #PF handler on first write. Instance `rw_overlays` (per-instance
/// state, not page-aligned) still memcpy into the mem_buf.
///
/// Looks the image and any cap-backed slices up under one
/// `DIRECTORY` lock scope. The PAs installed in the PT stay valid
/// for the frame's lifetime per the V1 invariant (no eviction mid-
/// RPC) even after this function returns and the guard is dropped.
fn build_runtime(frame: &KernelFrame) -> Result<FrameRuntime, u32> {
    // CacheDirectory is interior-mutable; each `get` takes the inner
    // spin::Mutex briefly and returns an `Arc<Cap>`. We keep the Arc
    // locals alive for the duration of the function so any borrowed
    // slices (used to compute PAs for direct PT mapping) stay valid.
    // Blobs are never evicted in V0, so the PAs remain valid for the
    // frame's lifetime past return.
    let img_arc = CACHE
        .get(CapHashOrRef::Hash(frame.image_hash))
        .ok_or(ERR_IMAGE_NOT_FOUND)?;
    let img = match &*img_arc {
        Cap::Image(i) => i,
        _ => return Err(ERR_IMAGE_KIND),
    };

    // Pinned mappings (RO, direct-map) become `PinnedCapRo` `MatRange`s pushed
    // first, so they take precedence over the catch-all RW range in
    // `mat_range_for`. Classification uses `ImageCap::mapping_is_pinned` —
    // identical to the interpreter drivers (`javm`, `nub-arch-local`), so the
    // engines agree on which VAs are read-only.
    let mut mat_ranges: Vec<MatRange> = Vec::new();
    // Per-page source PAs for the cap-backed ranges (a dense DataCap's pages are
    // non-contiguous slabs); each `MatRange` indexes a window into this arena.
    let mut mat_pas: Vec<u64> = Vec::new();
    // Shared per-frame zero page: the source for `Empty` (absent / zero) memory
    // pages, mapped RO or CoW'd-from-zero on write. Owned by the `FrameRuntime`
    // so its PA stays valid for the frame's life; never written through (RO maps;
    // a write CoWs a fresh private page), so aliasing it across pages is safe.
    let zero_page = PageBuf::new(paging::PAGE_SIZE).ok_or(ERR_JIT_FAILED)?;
    let zero_pa = zero_page.pa();

    // Executable code region: a `PinnedCapRo` lazily-materialized region at the
    // fixed CODE_BASE, sourced from its physical address `code_pa`. Code is
    // excluded from `mem_size` (the data extent).
    let (code_base, code_bytes) = img.code_mapping().ok_or(ERR_IMAGE_KIND)?;
    let code_pa = paging::va_to_pa(code_bytes.as_ptr() as u64).ok_or(ERR_MAP_BAD_KIND)?;

    // The Instance's RW memory is a dense `DataCap` (`inst.mem`) covering the
    // whole data extent, holding both initial and pinned content at their VAs
    // with page-aligned slabs (kept alive in CACHE for the frame's life by the
    // no-eviction V1 invariant). Source every data page from it: pinned VA
    // ranges as `PinnedCapRo`, everything else (initial + ephemeral, the latter
    // backed by `Empty` → zero page) as one catch-all `UnpinnedCapCow` range.
    let data_base = javm_cap::layout::DATA_BASE;
    let mut mem_size = data_base;
    let inst_arc = CACHE.get(frame.instance.clone());
    if let Some(arc) = inst_arc.as_deref()
        && let Cap::Instance(inst) = arc
    {
        let mem = &inst.mem;
        let extent = mem.content_len() as u32;
        mem_size = data_base.saturating_add(extent);
        let pages = (extent / paging::PAGE_SIZE as u32) as usize;

        // Pinned mappings → PinnedCapRo ranges (pushed first → precedence).
        for m in img.mappings.iter() {
            if m.path().is_empty() || !img.mapping_is_pinned(m.start as u32) {
                continue;
            }
            let span = (m.size as u32).next_multiple_of(paging::PAGE_SIZE as u32);
            let n = (span / paging::PAGE_SIZE as u32) as usize;
            if n == 0 {
                continue;
            }
            let base_page =
                ((m.start as u32).saturating_sub(data_base) / paging::PAGE_SIZE as u32) as usize;
            let pas_off = mat_pas.len() as u32;
            for k in 0..n {
                mat_pas.push(mem_page_pa(mem, base_page + k, zero_pa)?);
            }
            mat_ranges.push(MatRange {
                start: m.start as u32,
                end: (m.start as u32).saturating_add(span),
                pas_off,
                pas_len: n as u32,
                kind: javm_exec::mat::PageKind::PinnedCapRo.as_u8(),
                source_hash: [0u8; 32],
                source_slot: m.path().first().map_or(0, |k| k.diag_id() as u8),
            });
        }

        // Catch-all RW range over the whole extent (initial + ephemeral).
        if pages > 0 {
            let pas_off = mat_pas.len() as u32;
            for i in 0..pages {
                mat_pas.push(mem_page_pa(mem, i, zero_pa)?);
            }
            mat_ranges.push(MatRange {
                start: data_base,
                end: mem_size,
                pas_off,
                pas_len: pages as u32,
                kind: javm_exec::mat::PageKind::UnpinnedCapCow.as_u8(),
                source_hash: [0u8; 32],
                source_slot: 0,
            });
        }
    }

    // PVM2: `code` is raw RV+C+custom-0 bytes (produced by
    // `javm_transpiler::linker::link_elf`). The JIT cache
    // predecodes the bytes once and builds the dense dispatch table
    // (block-start validation folded in).
    //
    // SAFETY: image and any cap-backed slices live in the heap-
    // resident DIRECTORY/INSTANCES; PAs survive the guard drop per
    // the no-eviction V1 invariant.
    unsafe {
        jit_run::build_frame_runtime(
            &frame.image_hash,
            code_bytes,
            code_base,
            code_pa,
            frame.pc,
            mem_size,
            mat_ranges,
            mat_pas,
            zero_page,
        )
    }
    .ok_or(ERR_JIT_FAILED)
}

/// Source physical address of page `i` of `mem` (a dense `DataCap`): a present
/// slab's PA, or the shared `zero_pa` for an `Empty` (absent / zero) page. V1
/// never mints `Missing`.
fn mem_page_pa(mem: &javm_cap::DataCap, i: usize, zero_pa: u64) -> Result<u64, u32> {
    match mem.page_slot(i) {
        javm_cap::PageSlot::Loaded(pr) => {
            paging::va_to_pa(pr.bytes.as_ptr() as u64).ok_or(ERR_MAP_BAD_KIND)
        }
        javm_cap::PageSlot::Empty => Ok(zero_pa),
        javm_cap::PageSlot::Missing(_) => Err(ERR_MAP_BAD_KIND),
    }
}

/// Pop the top frame; if a parent exists, reflect the popped child's
/// `return_value` into the parent's φ[7]. Returns `true` when the
/// stack has been drained — the RPC caller uses this to know it's
/// time to hand a result back to the host. The dropped frame's
/// `CapHashOrRef::Ref(CapRef)` clones decrement their strong counts
/// automatically; the per-RPC scratch sweep in `nub_invoke_cached`
/// (after `run_top` returns) reclaims any orphaned `cache.instances`
/// slots.
fn pop_and_reflect(stack: &mut Vec<KernelFrame>, return_value: u64) -> bool {
    let _popped = stack.pop().expect("non-empty");
    if stack.is_empty() {
        return true;
    }
    let parent = stack.last_mut().unwrap();
    parent.regs[7] = return_value;
    false
}

/// `host_derive_spawn(image_slot=φ[7], cnode_slot=φ[8],
/// dst_slot=φ[9])`. V1: ignores `cnode_slot` (no prepared cnode
/// support — the child inherits the parent's cnode at CALL time).
/// Computes `child_chain = blake2b(running.chain, image_hash)`,
/// publishes a fresh `Cap::Instance` into the heap-resident
/// [`CACHE`]'s instances tier via
/// [`crate::state_cache::publish_transient_instance`], and writes
/// the resulting `CapRef` into the parent's `dst_slot`.
/// Returns `Ok(true)` if the spawn must trap the guest (the `dst_slot` is
/// pinned — a write to a read-only slot), matching the interpreter's
/// `OpError::SlotPinned → ExitReason::Trap`. `Ok(false)` on a normal spawn.
fn dispatch_derive_spawn(frame: &mut KernelFrame) -> Result<bool, u32> {
    // V1 single-byte ABI: each slot is the 1-byte key `gpr & 0xFF`.
    let image_slot = Key::from((frame.regs[7] & 0xFF) as u8);
    let _cnode_slot = (frame.regs[8] & 0xFF) as u8;
    let dst_slot = Key::from((frame.regs[9] & 0xFF) as u8);

    // Reject a write to a pinned (read-only) slot — the interpreter rejects
    // this and traps (javm/src/ecall.rs); the recompiler must agree or the
    // engines fork on `derive_spawn(dst=<pinned>)`.
    if frame.pinned.binary_search(&dst_slot).is_ok() {
        return Ok(true);
    }

    let image_hash = match frame.cnode.get(&image_slot) {
        Some(CapHashOrRef::Hash(h)) => h,
        Some(CapHashOrRef::Ref(_)) | None => frame.image_hash,
    };
    let child_chain = Blake2b256::hash_pair(&frame.image_hash_chain, &image_hash);

    let cap = Cap::Instance(javm_cap::cap::instance::InstanceCap {
        image_hash_chain: child_chain,
        image_hash,
        root_cnode: CapHashOrRef::Hash([0u8; 32]),
        mem: javm_cap::DataCap::empty(),
        regs: [0u64; NUM_REGS],
        pc: 0,
        gas_remaining: 0,
    });
    let child_ref = publish_transient_instance(cap);
    // CNode ops run in ring-0 dispatch (kernel heap live); `set` on the
    // unbounded radix map is infallible here.
    frame
        .cnode
        .set(&dst_slot, Some(CapHashOrRef::Ref(child_ref)))
        .map_err(|_| ERR_DERIVE_SLOT_OOB)?;
    Ok(false)
}

/// `host_call(instance_slot=φ[7], endpoint_idx=φ[8])`. Reads the
/// target instance ref from the parent's cnode, builds a fresh
/// [`KernelFrame`] for the child. Parent's φ[9..=12] become child's
/// φ[7..=10] (arg-passing convention — used by the recursive-spawn
/// bench to thread the remaining depth count).
fn dispatch_host_call(parent: &KernelFrame) -> Result<KernelFrame, u32> {
    let instance_slot = Key::from((parent.regs[7] & 0xFF) as u8);
    let endpoint_idx = (parent.regs[8] & 0xFF) as u32;
    let target = parent
        .cnode
        .get(&instance_slot)
        .ok_or(ERR_HOST_CALL_SLOT_EMPTY)?;

    // Arg-passing convention: parent's φ[9..=10] → child's φ[7..=8].
    // φ[11] holds the ecall op-code on a kernel-mode ecall exit (not
    // a usable arg), and φ[12] is reserved; both default to 0 for
    // the child. The bench guest threads `depth` through φ[9] alone.
    let args = [parent.regs[9], parent.regs[10], 0, 0];

    let mut child = build_frame_from_cap(target, endpoint_idx, args)?;

    // Child inherits the parent's cnode entries that the child's
    // image didn't pre-populate. Per the data-flow principle every
    // copy is a real copy: Hash entries copy the hash directly
    // (cheap), Ref entries are NOT cloned in V1 — they propagate
    // the parent's ref into the child without bumping the cache.
    // This matches today's bench semantics; once the scratchpad-cnode
    // return mechanism lands, inherited Ref slots should go through
    // `cache.clone_instance` so each frame's cnode owns its own
    // CapRef and mutations don't accidentally cross-share.
    //
    // The cnode is a radix map keyed by `Hasher(Key)`; iterate the
    // parent's physical (key, value) entries and copy each one the child
    // doesn't already hold. Operating at the physical-key level is exact —
    // each logical slot maps to one physical key — and needs no logical-key
    // reverse map. For Ref(CapRef) slots the clone bumps the inner Arc so the
    // child's cnode keeps the instance alive while it runs.
    for (phys_key, val) in parent.cnode.slots.iter() {
        if child.cnode.slots.get(phys_key).is_none() {
            child.cnode.slots.insert(*phys_key, val.clone());
        }
    }
    Ok(child)
}

/// Build a frame from a `Cap::Instance` published in the heap-
/// resident [`CACHE`] (the top-level invocation path; also used
/// by `host_call` when the cnode slot points at a host-pre-published
/// instance hash).
fn build_frame_from_published(
    instance_hash: &CapHash,
    endpoint_idx: u32,
    args: [u64; 4],
) -> Result<KernelFrame, u32> {
    let arc = CACHE
        .get(CapHashOrRef::Hash(*instance_hash))
        .ok_or(ERR_INSTANCE_NOT_FOUND)?;
    let (image_hash, image_hash_chain, inst_regs) = match &*arc {
        Cap::Instance(i) => (i.image_hash, i.image_hash_chain, i.regs),
        _ => return Err(ERR_INSTANCE_KIND),
    };
    build_frame_inner(
        image_hash,
        image_hash_chain,
        CapHashOrRef::Hash(*instance_hash),
        endpoint_idx,
        args,
        Some(&inst_regs),
    )
}

/// Build a frame from a `Cap::Instance` resident in the kernel-
/// derived (`Ref`-keyed) tier of [`CACHE`].
fn build_frame_from_instance_ref(
    ref_id: javm_cap::CapRef,
    endpoint_idx: u32,
    args: [u64; 4],
) -> Result<KernelFrame, u32> {
    let arc = CACHE
        .get(CapHashOrRef::Ref(ref_id.clone()))
        .ok_or(ERR_INSTANCE_NOT_FOUND)?;
    let (image_hash, image_hash_chain) = match &*arc {
        Cap::Instance(i) => (i.image_hash, i.image_hash_chain),
        _ => return Err(ERR_INSTANCE_KIND),
    };
    build_frame_inner(
        image_hash,
        image_hash_chain,
        CapHashOrRef::Ref(ref_id),
        endpoint_idx,
        args,
        None,
    )
}

/// Dispatch on `CapHashOrRef` — used by `dispatch_host_call`.
fn build_frame_from_cap(
    target: CapHashOrRef,
    endpoint_idx: u32,
    args: [u64; 4],
) -> Result<KernelFrame, u32> {
    match target {
        CapHashOrRef::Hash(h) => build_frame_from_published(&h, endpoint_idx, args),
        CapHashOrRef::Ref(r) => build_frame_from_instance_ref(r, endpoint_idx, args),
    }
}

/// Core frame builder: reads the image cap to seed regs/pc/cnode +
/// CoW ranges, stores only IDs on the frame (no `CapHandle` pins).
fn build_frame_inner(
    image_hash: CapHash,
    image_hash_chain: CapHash,
    instance: CapHashOrRef,
    endpoint_idx: u32,
    args: [u64; 4],
    inst_regs: Option<&[u64; NUM_REGS]>,
) -> Result<KernelFrame, u32> {
    let img_arc = CACHE
        .get(CapHashOrRef::Hash(image_hash))
        .ok_or(ERR_IMAGE_NOT_FOUND)?;
    let img = match &*img_arc {
        Cap::Image(i) => i,
        _ => return Err(ERR_IMAGE_KIND),
    };

    let endpoint = endpoint_idx as usize;
    if endpoint >= img.endpoints.len() {
        return Err(ERR_ENDPOINT_OOB);
    }
    let ep = &img.endpoints[endpoint];

    let mut regs = ep.initial_regs;
    if let Some(inst_regs) = inst_regs {
        for (i, v) in inst_regs.iter().enumerate() {
            if *v != 0 {
                regs[i] = *v;
            }
        }
    }
    for (i, v) in args.iter().enumerate() {
        regs[7 + i] = *v;
    }
    let pc = ep.entry_pc as u32;

    let mut cnode = CNodeCap::new();
    for e in img.pinned.iter() {
        cnode
            .set(&e.slot, Some(CapHashOrRef::Hash(e.cap_hash)))
            .map_err(|_| ERR_JIT_FAILED)?;
    }
    for e in img.initial.iter() {
        if cnode.get(&e.slot).is_none() {
            cnode
                .set(&e.slot, Some(CapHashOrRef::Hash(e.cap_hash)))
                .map_err(|_| ERR_JIT_FAILED)?;
        }
    }
    // Pinned-slot set for write rejection (sorted: `img.pinned` is emitted
    // sorted by `image_cap`). Mirrors `javm` `build_entry`.
    let pinned: Vec<Key> = img.pinned.iter().map(|e| e.slot.clone()).collect();

    // The cap-backed mappings (their PAs + pinned/initial kind) are
    // resolved in `build_runtime` when the per-frame runtime is built;
    // nothing mapping-related is needed on the frame itself.
    Ok(KernelFrame {
        image_hash,
        image_hash_chain,
        instance,
        regs,
        pc,
        cnode,
        pinned,
        dirty_pages: Vec::new(),
        runtime: None,
    })
}
