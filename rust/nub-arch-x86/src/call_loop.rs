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

#![cfg(target_os = "none")]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use javm_cap::cap::{Cap, CapHashOrRef};
use javm_cap::hash::{Blake2b256, Hash};
use javm_cap::{CapHash, CapRef, NUM_REGS};
use nub_host_common::cache::TalcAlloc;

use crate::jit_run::{self, ExitInfo, FrameRuntime, MemRegion};
use crate::state_cache::{self, CapHandle};

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
const ERR_CACHE_MAP: u32 = 20;
const ERR_INSTANCE_NOT_FOUND: u32 = 21;
const ERR_INSTANCE_KIND: u32 = 22;
const ERR_IMAGE_NOT_FOUND: u32 = 23;
const ERR_IMAGE_KIND: u32 = 24;
const ERR_ENDPOINT_OOB: u32 = 25;
const ERR_ENDPOINT_UNDEFINED: u32 = 26;
const ERR_DERIVE_SLOT_OOB: u32 = 31;
const ERR_DERIVE_PUBLISH: u32 = 32;
const ERR_HOST_CALL_SLOT_EMPTY: u32 = 40;
const ERR_JIT_FAILED: u32 = 50;
const ERR_DEPTH_LIMIT: u32 = 51;

/// One stack frame on the in-kernel call stack. Carries refcount-
/// pinning handles to the Image blob and the Instance entry (blob
/// or ref), plus per-frame mutable PVM state and the ring-3
/// resources cache.
///
/// All immutable image data (code/bitmask/jump_table/endpoints/
/// mappings/pinned/initial) is read on demand through `image.cap`
/// — no per-frame copies.
pub struct KernelFrame {
    /// Refcount-pinned handle on the `Cap::Image` blob this frame
    /// runs against. Dropped automatically on frame teardown.
    image: CapHandle<TalcAlloc>,
    /// Cached content-hash of the image. Used as the cnode-slot
    /// fallback in `derive_spawn` and as the JIT-cache key in
    /// `build_frame_runtime`.
    image_hash: CapHash,
    /// Image's chain hash. Read by `derive_spawn` to compute the
    /// child's chain. Cached locally to avoid an instance deref per
    /// derive.
    image_hash_chain: CapHash,
    /// Refcount-pinned handle on the `Cap::Instance` entry — blob
    /// for host-pre-published top-level instances, instance-slot
    /// for kernel-derived sub-VMs. Drop releases the slot back to
    /// the cache for reuse.
    #[allow(dead_code)]
    instance: CapHandle<TalcAlloc>,
    /// Live PVM register file. Written by the JIT on every entry/
    /// exit; settled back to the instance at HALT in Phase 4.
    regs: [u64; NUM_REGS],
    /// Current PVM PC. Same lifecycle as `regs`.
    pc: u32,
    /// Per-frame cnode snapshot. Each slot holds a `CapHashOrRef`
    /// (blob hash for image pinned/initial entries; instance ref
    /// for kernel-derived transient instances) or `None`.
    cnode: Vec<Option<CapHashOrRef>>,
    /// Per-frame ring-3 resources (PT + mem/ctx/stack buffers).
    /// Lazily built on the first [`run_one_entry`] for this frame
    /// and reused across every subsequent re-entry. Cuts N
    /// PageTable + 3 PageBuf allocations for a depth-N recursion.
    runtime: Option<FrameRuntime>,
}

/// Drop-guard that triggers the per-RPC scratch sweep on the way
/// out of [`run_top`], regardless of how the loop returns (clean
/// HALT, propagated `Err`, or any path that unwinds locals). Lives
/// at the top of the function so it drops AFTER the per-RPC
/// `Vec<KernelFrame>` stack — any `CapHandle` held inside a frame
/// decrements its refcount before [`state_cache::clear_scratch`]
/// observes the entries.
struct ScratchGuard;

impl Drop for ScratchGuard {
    fn drop(&mut self) {
        state_cache::clear_scratch();
    }
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
pub fn run_top(
    instance_hash: &CapHash,
    endpoint_idx: u32,
    args: [u64; 4],
    initial_gas: i64,
) -> Result<LoopOutcome, u32> {
    state_cache::ensure_mapped().map_err(|_| ERR_CACHE_MAP)?;

    // `_scratch_guard` is declared BEFORE `stack` so its `Drop` runs
    // AFTER the stack is dropped — frame-held `CapHandle`s release
    // their refcounts first, then the per-RPC scratch sweep frees
    // any guest-published cache entries whose refcounts have fallen
    // to 1 (the scratch tracker's own reference). See
    // [`state_cache::clear_scratch`] for the refcount safety net.
    let _scratch_guard = ScratchGuard;

    let top = build_frame_from_published(instance_hash, endpoint_idx, args)?;
    let mut stack: Vec<KernelFrame> = Vec::with_capacity(8);
    stack.push(top);
    let mut gas = initial_gas;

    loop {
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
                    // Top frame halted — pass the JIT's own exit
                    // reason through so callers that distinguish
                    // EXIT_HALT (explicit) from EXIT_HOST_CALL(0)
                    // (REPLY trampoline) see the right code.
                    return Ok(LoopOutcome {
                        exit_reason: info.exit_reason,
                        exit_arg: info.exit_arg,
                        return_value: info.regs[7],
                        gas_remaining: gas,
                    });
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
                        return Ok(LoopOutcome {
                            exit_reason: info.exit_reason,
                            exit_arg: info.exit_arg,
                            return_value: info.regs[7],
                            gas_remaining: gas,
                        });
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
                        return Ok(LoopOutcome {
                            exit_reason: info.exit_reason,
                            exit_arg: info.exit_arg,
                            return_value: info.regs[7],
                            gas_remaining: gas,
                        });
                    }
                }
            }
            _ => {
                // PageFault (3), Panic (1), OOG (2), Trap (7), …
                return Ok(LoopOutcome {
                    exit_reason: info.exit_reason,
                    exit_arg: info.exit_arg,
                    return_value: info.regs[7],
                    gas_remaining: gas,
                });
            }
        }
    }
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
    let rt = frame.runtime.as_mut().expect("just built");
    let info = unsafe { jit_run::enter_frame(rt, gas, frame.pc, frame.regs) };
    Ok(info)
}

/// Build the per-frame ring-3 runtime. Reads image bytes via the
/// frame's `CapHandle`, resolves the active mem overlays from image
/// `mappings` + cnode, and calls into [`jit_run::build_frame_runtime`].
fn build_runtime<'a>(frame: &'a KernelFrame) -> Result<FrameRuntime, u32> {
    let img = image_cap(&frame.image)?;

    // Collect at most three (start, &[u8]) regions to feed mem-
    // population. Today's bench guest has no DataCap mappings; this
    // walk is a no-op in that case. Top-level frames sourced from a
    // host-published Instance with `rw_overlays` may carry mem-baked
    // content there.
    let mut regions: [(u32, &'a [u8]); 3] = [(0, &[]), (0, &[]), (0, &[])];
    let mut n = 0usize;
    let mut mem_size: u32 = 0;

    // First: any host-published rw_overlays (instance-baked content).
    if let Some(inst) = instance_cap(&frame.instance) {
        for ov in inst.rw_overlays.iter() {
            let end = ov.start.saturating_add(ov.bytes.len() as u32);
            if end > mem_size {
                mem_size = end;
            }
            if n < regions.len() && !ov.bytes.is_empty() {
                regions[n] = (ov.start, ov.bytes.as_slice());
                n += 1;
            }
        }
        if inst.mem_size > mem_size {
            mem_size = inst.mem_size;
        }
    }

    // Then: image mappings resolved through the per-frame cnode.
    // Only blob-hash slot entries yield mappable data; transient
    // instance refs in the cnode are sub-VM children, not data.
    for m in img.mappings.iter() {
        let end = (m.start + m.size) as u32;
        if end > mem_size {
            mem_size = end;
        }
        if m.source_path_len == 0 {
            continue;
        }
        let src_slot = m.source_path[0].get() as usize;
        let Some(Some(target)) = frame.cnode.get(src_slot) else {
            continue;
        };
        let target_hash = match target {
            CapHashOrRef::Hash(h) => *h,
            CapHashOrRef::Ref(_) => continue,
        };
        if let Some(Cap::Data(d)) = state_cache::lookup_cap(&target_hash)
            && let javm_cap::DataContent::Inline(bytes) = &d.content
            && !bytes.is_empty()
            && n < regions.len()
        {
            regions[n] = (m.start as u32, bytes.as_slice());
            n += 1;
        }
    }

    let [arg, ro, rw] = regions;

    // `img.bitmask` is the packed form (1 bit per code byte);
    // `build_frame_runtime` / `Compiler::new` expect the unpacked
    // form (1 byte per code byte). Unpack into a local Vec — the
    // jit_cache copies the result into the per-Image arena on first
    // compile and reuses it thereafter, so this allocation only
    // matters on cache miss.
    let bitmask = javm_exec::unpack_bitmask(img.bitmask.as_slice(), img.code.len());

    // SAFETY: caller keeps `frame.image` alive for the runtime's
    // lifetime (it's owned by the frame). Code/jt slices come from
    // the cap-resident memory and live as long as `frame.image`.
    unsafe {
        jit_run::build_frame_runtime(
            &frame.image_hash,
            img.code.as_slice(),
            &bitmask,
            img.jump_table.as_slice(),
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
/// publishes a fresh `Cap::Instance` to `cache.instances` via
/// [`state_cache::publish_instance`], and writes the resulting
/// `CapRef` into the parent's `dst_slot`.
fn dispatch_derive_spawn(frame: &mut KernelFrame) -> Result<(), u32> {
    let image_slot = (frame.regs[7] & 0xFF) as usize;
    let _cnode_slot = (frame.regs[8] & 0xFF) as usize;
    let dst_slot = (frame.regs[9] & 0xFF) as usize;

    if image_slot >= CNODE_SLOTS || dst_slot >= CNODE_SLOTS {
        return Err(ERR_DERIVE_SLOT_OOB);
    }
    // Cnode-slot fallback: empty slots default to the running
    // frame's own image_hash. Matches the recursive-spawn bench
    // exactly and is reasonable for any caller that wants to
    // re-enter its own program with fresh state.
    let image_hash = match frame.cnode[image_slot] {
        Some(CapHashOrRef::Hash(h)) => h,
        Some(CapHashOrRef::Ref(_)) | None => frame.image_hash,
    };
    let child_chain = Blake2b256::hash_pair(&frame.image_hash_chain, &image_hash);

    let child_inst = build_transient_instance_cap(image_hash, child_chain);
    let child_ref = state_cache::publish_instance(child_inst).map_err(|_| ERR_DERIVE_PUBLISH)?;
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
    let target = parent.cnode[instance_slot].ok_or(ERR_HOST_CALL_SLOT_EMPTY)?;

    // Arg-passing convention: parent's φ[9..=10] → child's φ[7..=8].
    // φ[11] holds the ecall op-code on a kernel-mode ecall exit (not
    // a usable arg), and φ[12] is reserved; both default to 0 for
    // the child. The bench guest threads `depth` through φ[9] alone.
    let args = [parent.regs[9], parent.regs[10], 0, 0];

    let mut child = match target {
        CapHashOrRef::Hash(h) => build_frame_from_published(&h, endpoint_idx, args)?,
        CapHashOrRef::Ref(r) => build_frame_from_instance_ref(r, endpoint_idx, args)?,
    };

    // Child inherits the parent's cnode entries that the child's
    // image didn't pre-populate. Lets the bench guest reach
    // `SLOT_IMAGE` without the harness re-installing it per level.
    for (i, slot) in parent.cnode.iter().enumerate() {
        if child.cnode[i].is_none() {
            child.cnode[i] = *slot;
        }
    }
    Ok(child)
}

/// Build a frame from a `Cap::Instance` blob published in the shared
/// talc cache (the top-level invocation path; also used by
/// `host_call` when the cnode slot points at a host-pre-published
/// instance hash). Acquires refcount-pinning handles on both the
/// Instance and its Image.
fn build_frame_from_published(
    instance_hash: &CapHash,
    endpoint_idx: u32,
    args: [u64; 4],
) -> Result<KernelFrame, u32> {
    let instance_handle: CapHandle<TalcAlloc> =
        state_cache::lookup_blob_handle(instance_hash).ok_or(ERR_INSTANCE_NOT_FOUND)?;
    let inst = match &instance_handle.cap {
        Cap::Instance(i) => i,
        _ => return Err(ERR_INSTANCE_KIND),
    };
    let image_hash = inst.image_hash;
    let image_hash_chain = inst.image_hash_chain;
    let inst_regs = inst.regs;

    let image_handle: CapHandle<TalcAlloc> =
        state_cache::lookup_blob_handle(&image_hash).ok_or(ERR_IMAGE_NOT_FOUND)?;
    build_frame_from_image_handle(
        image_handle,
        image_hash,
        image_hash_chain,
        instance_handle,
        endpoint_idx,
        args,
        Some(&inst_regs),
    )
}

/// Build a frame from a `Cap::Instance` resident in `cache.instances`
/// (kernel-derived sub-VM). Acquires refcount-pinning handles on
/// both the Instance and its Image.
fn build_frame_from_instance_ref(
    ref_id: CapRef,
    endpoint_idx: u32,
    args: [u64; 4],
) -> Result<KernelFrame, u32> {
    let instance_handle: CapHandle<TalcAlloc> =
        state_cache::lookup_instance_handle(ref_id).ok_or(ERR_INSTANCE_NOT_FOUND)?;
    let inst = match &instance_handle.cap {
        Cap::Instance(i) => i,
        _ => return Err(ERR_INSTANCE_KIND),
    };
    let image_hash = inst.image_hash;
    let image_hash_chain = inst.image_hash_chain;

    let image_handle: CapHandle<TalcAlloc> =
        state_cache::lookup_blob_handle(&image_hash).ok_or(ERR_IMAGE_NOT_FOUND)?;
    build_frame_from_image_handle(
        image_handle,
        image_hash,
        image_hash_chain,
        instance_handle,
        endpoint_idx,
        args,
        None,
    )
}

/// Core frame builder: takes refcount-pinning handles on Image and
/// Instance plus the resolved identity hashes, seeds regs from
/// endpoint + optional instance overrides, then seeds the per-frame
/// cnode from `image.pinned + initial`.
fn build_frame_from_image_handle(
    image: CapHandle<TalcAlloc>,
    image_hash: CapHash,
    image_hash_chain: CapHash,
    instance: CapHandle<TalcAlloc>,
    endpoint_idx: u32,
    args: [u64; 4],
    inst_regs: Option<&[u64; NUM_REGS]>,
) -> Result<KernelFrame, u32> {
    // Read everything we need from `image` first; the struct
    // construction below moves `image` into the returned `KernelFrame`
    // so any borrows on it must release before that point.
    let (regs, pc, cnode) = {
        let img = image_cap(&image)?;

        let endpoint = endpoint_idx as usize;
        if endpoint >= img.endpoints.len() {
            return Err(ERR_ENDPOINT_OOB);
        }
        let ep = &img.endpoints[endpoint];
        if ep.entry_pc == 0 {
            return Err(ERR_ENDPOINT_UNDEFINED);
        }

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
        (regs, ep.entry_pc as u32, cnode)
    };

    Ok(KernelFrame {
        image,
        image_hash,
        image_hash_chain,
        instance,
        regs,
        pc,
        cnode,
        runtime: None,
    })
}

/// Helper: borrow the inner `Cap::Image` from a handle, or return
/// an error if the entry is the wrong kind.
fn image_cap(
    handle: &CapHandle<TalcAlloc>,
) -> Result<&javm_cap::image_cap::ImageCap<TalcAlloc>, u32> {
    match &handle.cap {
        Cap::Image(i) => Ok(i),
        _ => Err(ERR_IMAGE_KIND),
    }
}

/// Helper: borrow the inner `Cap::Instance` from a handle.
fn instance_cap(
    handle: &CapHandle<TalcAlloc>,
) -> Option<&javm_cap::instance::InstanceCap<TalcAlloc>> {
    match &handle.cap {
        Cap::Instance(i) => Some(i),
        _ => None,
    }
}

/// Construct a fresh `Cap::Instance` for a kernel-derived sub-VM.
/// Inherits the parent's chain via `image_hash_chain`; `regs`, `pc`,
/// `gas_remaining`, `rw_overlays` start empty (the in-kernel
/// recurse-spawn pattern doesn't persist any of these via the
/// instance cap — the frame's own `regs`/`pc` carry per-call state,
/// settled back at HALT in Phase 4).
fn build_transient_instance_cap(image_hash: CapHash, image_hash_chain: CapHash) -> Cap<TalcAlloc> {
    use allocator_api2::vec::Vec as AVec;
    let alloc = state_cache::talc_alloc();
    Cap::Instance(javm_cap::instance::InstanceCap {
        image_hash_chain,
        image_hash,
        // Sub-VMs inherit the parent's cnode operationally via the
        // per-frame `cnode` Vec (set in `dispatch_host_call`); the
        // cap-resident `root_cnode` is a placeholder until Phase 4
        // moves cnode mutation into the cache.
        root_cnode: CapHashOrRef::Hash([0u8; 32]),
        rw_overlays: AVec::new_in(alloc),
        mem_size: 0,
        regs: [0u64; NUM_REGS],
        pc: 0,
        gas_remaining: 0,
    })
}
