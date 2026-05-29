//! In-kernel CALL/HALT loop driving the in-sandbox sub-VM lifecycle.
//!
//! `nub_invoke_cached` calls [`run_top`] with a top-level
//! `Cap::Instance` hash + endpoint. We build a [`KernelFrame`] from
//! the published cap state, push it on an in-memory `Vec` stack, then
//! iterate:
//!
//!   1. Run one ring-3 cycle via [`crate::jit_run::run_pvm_with_mem`].
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
//!   [`state_cache::publish_instance`]; the returned `CapRef` goes
//!   into the parent's cnode slot. `host_call` then resolves
//!   `cnode[slot]: CapHashOrRef` via [`state_cache::lookup_handle`],
//!   yielding either a host-pre-published blob or a kernel-derived
//!   instance. Refcount on each entry is bumped by the lookup and
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

use alloc::vec;
use alloc::vec::Vec;

use javm_cap::cache::CapHashOrRef;
use javm_cap::cap::Cap;
use javm_cap::hash::{Blake2b256, Hash};
use javm_cap::slot::SlotIdx;
use javm_cap::{CapHash, NUM_REGS};

use crate::jit_run::{self, DirectMap, ExitInfo, FrameRuntime, MemRegion};
use crate::page_alloc::PageBuf;
use crate::paging;
use crate::state_cache::{CACHE, publish_transient_instance};

const EXIT_HALT: u32 = 0;
const EXIT_HOST_CALL: u32 = 4;
const EXIT_ECALL: u32 = 6;

const OP_REPLY: u32 = 0;
const OP_DERIVE_SPAWN: u32 = 18;
const OP_HOST_CALL: u32 = 26;

const CNODE_SLOTS: usize = 256;
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
const ERR_MAP_PAGED_UNSUPPORTED: u32 = 61;

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
    /// Per-frame cnode snapshot. Each slot holds a `CapHashOrRef`
    /// (blob hash for image pinned/initial entries; instance ref
    /// for kernel-derived transient instances) or `None`.
    cnode: Vec<Option<CapHashOrRef>>,
    /// CoW-armed guest VA ranges — the initial-slot mappings whose
    /// pages can be copy-on-write'd on guest writes. Published to
    /// the #PF handler at `enter_frame` time so it can recognise
    /// legitimate write faults and remap.
    cow_ranges: Vec<CowRange>,
    /// CoW-allocated fresh pages, populated by `jit_pf_handler` on
    /// the first write to each page of a CoW range. Per the data-
    /// flow principle (see module doc), these are frame-local
    /// working memory and are dropped at frame pop without
    /// propagation.
    dirty_pages: Vec<DirtyPage>,
    /// Per-frame ring-3 resources (PT + mem/ctx/stack buffers).
    /// Lazily built on the first [`run_one_entry`] for this frame
    /// and reused across every subsequent re-entry. Cuts N
    /// PageTable + 3 PageBuf allocations for a depth-N recursion.
    runtime: Option<FrameRuntime>,
}

/// One CoW-armed VA range. The #PF handler scans this list when a
/// guest write faults inside ring 3; a hit triggers the CoW protocol
/// (allocate a fresh page, memcpy from the cap, rewrite the PTE
/// writable, record the dirty page).
#[derive(Clone, Copy, Debug)]
pub struct CowRange {
    pub start: u32,
    pub end: u32,
    pub source_hash: CapHash,
    pub source_slot: SlotIdx,
}

/// One CoW-allocated dirty page. Owned by `KernelFrame.dirty_pages`
/// until auto-mint consumes it (next commit). For now fields stay
/// dead-code-allowed; the next commit reads them.
#[allow(dead_code)]
pub struct DirtyPage {
    pub guest_va: u32,
    pub source_hash: CapHash,
    pub source_slot: SlotIdx,
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
                        let frame = stack.last_mut().expect("non-empty");
                        dispatch_derive_spawn(frame)?;
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

    // Drop the stack BEFORE we hand the outcome back. Frames hold no
    // refcounted handles into the heap-resident directory (V0: no
    // scratch sweep, no eviction), so this is just a Vec drop.
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
    let cow_ranges: &[CowRange] = frame.cow_ranges.as_slice();
    let dirty_sink: *mut Vec<DirtyPage> = &mut frame.dirty_pages;
    let rt = frame.runtime.as_mut().expect("just built");
    let info = unsafe { jit_run::enter_frame(rt, gas, pc, regs, cow_ranges, dirty_sink) };
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

    // Classify slots: pinned (RO, direct-map) vs initial (RW with
    // CoW arming). Pinned slot indices are recorded so the initial
    // walk can skip them — initial entries that collide with a
    // pinned slot are ignored.
    let mut pinned_slot = [false; CNODE_SLOTS];
    let mut initial_slot = [false; CNODE_SLOTS];
    for e in img.pinned.iter() {
        let s = e.slot.get() as usize;
        if s < CNODE_SLOTS {
            pinned_slot[s] = true;
        }
    }
    for e in img.initial.iter() {
        let s = e.slot.get() as usize;
        if s < CNODE_SLOTS && !pinned_slot[s] {
            initial_slot[s] = true;
        }
    }

    let mut direct_maps: Vec<DirectMap> = Vec::with_capacity(img.mappings.len() + 1);
    let mut mem_size: u32 = 0;

    // Executable code region: RO direct-map at the fixed CODE_BASE. The
    // code lives in the Image's page-aligned `ImageCap.code`, so it maps
    // straight in like a pinned data cap — and is *excluded* from
    // mem_size (the flat RW buffer): code sits at CODE_BASE, clear of
    // the data layout, and must not inflate the per-call alloc.
    let (code_base, code_bytes) = img.code_mapping().ok_or(ERR_IMAGE_KIND)?;
    {
        let pa = paging::va_to_pa(code_bytes.as_ptr() as u64).ok_or(ERR_MAP_BAD_KIND)?;
        // `code_bytes.len()` is the real code length; the backing
        // allocation is page-aligned and page-size-rounded (zeroed
        // tail). Map the page-rounded extent so the PT mapping covers
        // whole pages — the trailing zero bytes are RO and unreachable.
        let map_size = (code_bytes.len() as u32).next_multiple_of(paging::PAGE_SIZE as u32);
        direct_maps.push(DirectMap {
            start: code_base,
            pa,
            size: map_size,
        });
    }

    // Keep Arcs alive for the data-cap lookups so the slice references
    // we feed to direct_maps stay valid until function return.
    let mut data_arcs: Vec<alloc::sync::Arc<Cap>> = Vec::new();
    for m in img.mappings.iter() {
        // `img.mappings` describes data/slot regions only; code is
        // direct-mapped above at CODE_BASE and never extends the flat
        // RW buffer.
        let end = (m.start + m.size) as u32;
        if end > mem_size {
            mem_size = end;
        }
        if m.source_path_len == 0 {
            continue;
        }
        let src_slot = m.source_path[0].get() as usize;
        if src_slot >= CNODE_SLOTS || !(pinned_slot[src_slot] || initial_slot[src_slot]) {
            continue;
        }
        let target_hash = match frame.cnode.get(src_slot) {
            Some(Some(CapHashOrRef::Hash(h))) => *h,
            _ => continue,
        };
        let data_arc = CACHE
            .get(CapHashOrRef::Hash(target_hash))
            .ok_or(ERR_HOST_CALL_SLOT_EMPTY)?;
        // Validate kind + DataContent variant before stashing the Arc.
        match &*data_arc {
            Cap::Data(d) => match &d.content {
                javm_cap::DataContent::Inline(_) => {}
                javm_cap::DataContent::Paged { .. } => return Err(ERR_MAP_PAGED_UNSUPPORTED),
            },
            _ => return Err(ERR_MAP_BAD_KIND),
        }
        data_arcs.push(data_arc);
        // SAFETY-ish: data_arcs[last] is the Arc we just pushed; its
        // Cap::Data::Inline bytes have a stable address. Resolve PA
        // from the bytes' VA.
        let bytes = match data_arcs.last().unwrap().as_ref() {
            Cap::Data(d) => match &d.content {
                javm_cap::DataContent::Inline(bs) => bs.as_slice(),
                _ => unreachable!("validated above"),
            },
            _ => unreachable!("validated above"),
        };
        let pa = paging::va_to_pa(bytes.as_ptr() as u64).ok_or(ERR_MAP_BAD_KIND)?;
        let size = (m.size as u32).min(bytes.len() as u32);
        if size == 0 {
            continue;
        }
        direct_maps.push(DirectMap {
            start: m.start as u32,
            pa,
            size,
        });
    }

    // Instance rw_overlays: per-instance evolved state. Both top-level
    // (Hash) and kernel-derived (Ref) instances live in the same
    // CacheDirectory; `CACHE.get(CapHashOrRef)` does the dispatch.
    //
    // Up to three overlays are propagated to the JIT (its arg / ro
    // / rw mem regions). Anything beyond that is ignored — matches
    // pre-rewrite behaviour.
    let mut overlay_bufs: [(u32, Vec<u8>); 3] = [(0, Vec::new()), (0, Vec::new()), (0, Vec::new())];
    let mut n = 0usize;
    let inst_arc = CACHE.get(frame.instance.clone());
    if let Some(arc) = inst_arc.as_ref()
        && let Cap::Instance(inst) = &**arc
    {
        for ov in inst.rw_overlays.iter() {
            let end = ov.start.saturating_add(ov.bytes.len() as u32);
            if end > mem_size {
                mem_size = end;
            }
            if n < overlay_bufs.len() && !ov.bytes.is_empty() {
                overlay_bufs[n].0 = ov.start;
                overlay_bufs[n].1.clear();
                overlay_bufs[n].1.extend_from_slice(ov.bytes.as_slice());
                n += 1;
            }
        }
        if inst.mem_size > mem_size {
            mem_size = inst.mem_size;
        }
    }

    let arg: (u32, &[u8]) = (overlay_bufs[0].0, overlay_bufs[0].1.as_slice());
    let ro: (u32, &[u8]) = (overlay_bufs[1].0, overlay_bufs[1].1.as_slice());
    let rw: (u32, &[u8]) = (overlay_bufs[2].0, overlay_bufs[2].1.as_slice());

    // PVM2: `code` is raw RV+C+custom-0 bytes (produced by
    // `javm_transpiler::linker::link_elf`). The JIT cache
    // predecodes the bytes once and populates the BB region with
    // the valid-PC set.
    //
    // SAFETY: image and any cap-backed slices live in the heap-
    // resident DIRECTORY/INSTANCES; PAs survive the guard drop per
    // the no-eviction V1 invariant.
    unsafe {
        jit_run::build_frame_runtime(
            &frame.image_hash,
            code_bytes,
            code_base,
            frame.pc,
            mem_size,
            MemRegion {
                start: arg.0,
                data: arg.1,
            },
            MemRegion {
                start: ro.0,
                data: ro.1,
            },
            MemRegion {
                start: rw.0,
                data: rw.1,
            },
            &direct_maps,
        )
    }
    .ok_or(ERR_JIT_FAILED)
}

/// Pop the top frame; if a parent exists, reflect the popped child's
/// `return_value` into the parent's φ[7]. Returns `true` when the
/// stack has been drained — the RPC caller uses this to know it's
/// time to hand a result back to the host. The dropped frame's
/// `CapHandle`s decrement their refcounts automatically; the per-
/// RPC scratch sweep at end of `run_top` reclaims any orphaned
/// `cache.instances` slots.
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
fn dispatch_derive_spawn(frame: &mut KernelFrame) -> Result<(), u32> {
    let image_slot = (frame.regs[7] & 0xFF) as usize;
    let _cnode_slot = (frame.regs[8] & 0xFF) as usize;
    let dst_slot = (frame.regs[9] & 0xFF) as usize;

    if image_slot >= CNODE_SLOTS || dst_slot >= CNODE_SLOTS {
        return Err(ERR_DERIVE_SLOT_OOB);
    }
    let image_hash = match frame.cnode[image_slot] {
        Some(CapHashOrRef::Hash(h)) => h,
        Some(CapHashOrRef::Ref(_)) | None => frame.image_hash,
    };
    let child_chain = Blake2b256::hash_pair(&frame.image_hash_chain, &image_hash);

    let cap = Cap::Instance(javm_cap::cap::instance::InstanceCap {
        image_hash_chain: child_chain,
        image_hash,
        root_cnode: CapHashOrRef::Hash([0u8; 32]),
        rw_overlays: Vec::new(),
        mem_size: 0,
        regs: [0u64; NUM_REGS],
        pc: 0,
        gas_remaining: 0,
    });
    let child_ref = publish_transient_instance(cap);
    frame.cnode[dst_slot] = Some(CapHashOrRef::Ref(child_ref));
    Ok(())
}

/// `host_call(instance_slot=φ[7], endpoint_idx=φ[8])`. Reads the
/// target instance ref from the parent's cnode, builds a fresh
/// [`KernelFrame`] for the child. Parent's φ[9..=12] become child's
/// φ[7..=10] (arg-passing convention — used by the recursive-spawn
/// bench to thread the remaining depth count).
fn dispatch_host_call(parent: &KernelFrame) -> Result<KernelFrame, u32> {
    let instance_slot = (parent.regs[7] & 0xFF) as usize;
    let endpoint_idx = (parent.regs[8] & 0xFF) as u32;
    if instance_slot >= CNODE_SLOTS {
        return Err(ERR_HOST_CALL_SLOT_EMPTY);
    }
    let target = parent.cnode[instance_slot]
        .clone()
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
    for (i, slot) in parent.cnode.iter().enumerate() {
        if child.cnode[i].is_none() {
            // Clone the CapHashOrRef. For Ref(CapRef) slots this
            // bumps the inner Arc strong count — the child's
            // cnode keeps the instance alive while the child runs.
            child.cnode[i] = slot.clone();
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

    let mut cnode: Vec<Option<CapHashOrRef>> = vec![None; CNODE_SLOTS];
    for e in img.pinned.iter() {
        let s = e.slot.get() as usize;
        if s < CNODE_SLOTS {
            cnode[s] = Some(CapHashOrRef::Hash(e.cap_hash));
        }
    }
    for e in img.initial.iter() {
        let s = e.slot.get() as usize;
        if s < CNODE_SLOTS && cnode[s].is_none() {
            cnode[s] = Some(CapHashOrRef::Hash(e.cap_hash));
        }
    }

    // Compute cow_ranges: every mapping whose source slot is an
    // initial slot (not pinned) gets armed for CoW.
    let mut pinned_slot = [false; CNODE_SLOTS];
    let mut initial_slot = [false; CNODE_SLOTS];
    for e in img.pinned.iter() {
        let s = e.slot.get() as usize;
        if s < CNODE_SLOTS {
            pinned_slot[s] = true;
        }
    }
    for e in img.initial.iter() {
        let s = e.slot.get() as usize;
        if s < CNODE_SLOTS && !pinned_slot[s] {
            initial_slot[s] = true;
        }
    }
    let mut cow_ranges = Vec::new();
    for m in img.mappings.iter() {
        if m.source_path_len == 0 {
            continue;
        }
        let src_slot_raw = m.source_path[0].get();
        let src_slot = src_slot_raw as usize;
        if src_slot >= CNODE_SLOTS || !initial_slot[src_slot] {
            continue;
        }
        let target_hash = match cnode.get(src_slot) {
            Some(Some(CapHashOrRef::Hash(h))) => *h,
            _ => continue,
        };
        cow_ranges.push(CowRange {
            start: m.start as u32,
            end: (m.start + m.size) as u32,
            source_hash: target_hash,
            source_slot: SlotIdx(src_slot_raw),
        });
    }

    Ok(KernelFrame {
        image_hash,
        image_hash_chain,
        instance,
        regs,
        pc,
        cnode,
        cow_ranges,
        dirty_pages: Vec::new(),
        runtime: None,
    })
}
