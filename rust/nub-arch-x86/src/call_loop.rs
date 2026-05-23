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
//! - **Kernel-private transient instances.** `derive_spawn` does NOT
//!   publish a fresh `Cap::Instance` to the shared talc cache —
//!   `CacheDirectory` has only `MAX_BLOB_SLOTS = 256` blob slots, so
//!   a deep recursion (depth ≥ 256) would exhaust it. Instead, we
//!   keep a kernel-private `BTreeMap<CapHash, TransientInstance>`
//!   keyed by the child's extended `image_hash_chain`. `host_call`
//!   looks up here first, falling back to the shared cache for
//!   `Cap::Instance`s published by the host driver.
//!
//! - **Per-frame cnode is a flat `[Option<CapHash>; 256]`.** Top
//!   frame's cnode is seeded from the running `Cap::Instance`'s
//!   `root_cnode` (looked up in the shared cache); child frames
//!   inherit the parent's cnode entries. The published cnode is
//!   read-only — slot writes (`derive_spawn` → dst) mutate the
//!   per-frame copy.

#![cfg(target_os = "none")]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::UnsafeCell;

use javm_cap::cap::Cap;
use javm_cap::hash::{Blake2b256, Hash};
use javm_cap::{CapHash, NUM_REGS};

use crate::jit_run::{self, ExitInfo, FrameRuntime, MemRegion};
use crate::state_cache;

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
const ERR_HOST_CALL_SLOT_EMPTY: u32 = 40;
const ERR_JIT_FAILED: u32 = 50;
const ERR_DEPTH_LIMIT: u32 = 51;

/// One stack frame on the in-kernel call stack. Owns the per-frame
/// PVM state (regs, pc, cnode) plus copies of the image's code /
/// bitmask / jump-table arrays (those copies are small — the JIT
/// code cache holds the heavy compiled bytes, not us). Top frame is
/// built from a published `Cap::Instance` lookup; child frames are
/// built by [`dispatch_host_call`].
pub struct KernelFrame {
    image_hash: CapHash,
    image_hash_chain: CapHash,
    code: Vec<u8>,
    bitmask: Vec<u8>,
    jump_table: Vec<u32>,
    regs: [u64; NUM_REGS],
    pc: u32,
    mem_size: u32,
    overlays: Vec<(u32, Vec<u8>)>,
    cnode: Vec<Option<CapHash>>,
    /// Per-frame ring-3 resources (PT + mem/ctx/stack buffers). Lazily
    /// built on the first [`run_one_entry`] for this frame and reused
    /// across every subsequent re-entry (after a child HALTs and the
    /// parent resumes). Cuts N PageTable + 3 PageBuf allocations for
    /// a depth-N recursion. Dropped when the frame is popped.
    runtime: Option<FrameRuntime>,
}

/// One transient `Cap::Instance` created by an in-kernel
/// `derive_spawn`. Lives until the corresponding child frame HALTs,
/// then is dropped from the table by [`forget_transient`].
struct TransientInstance {
    image_hash: CapHash,
    image_hash_chain: CapHash,
}

struct TransientTable {
    inner: UnsafeCell<BTreeMap<CapHash, TransientInstance>>,
}

/// SAFETY: single-threaded guest (Hyperlight serialises calls).
unsafe impl Sync for TransientTable {}

static TRANSIENT: TransientTable = TransientTable {
    inner: UnsafeCell::new(BTreeMap::new()),
};

fn transient_get(hash: &CapHash) -> Option<TransientInstance> {
    // SAFETY: single-threaded guest.
    let map = unsafe { &*TRANSIENT.inner.get() };
    map.get(hash).map(|t| TransientInstance {
        image_hash: t.image_hash,
        image_hash_chain: t.image_hash_chain,
    })
}

fn transient_insert(hash: CapHash, t: TransientInstance) {
    // SAFETY: single-threaded guest.
    let map = unsafe { &mut *TRANSIENT.inner.get() };
    map.insert(hash, t);
}

fn forget_transient(hash: &CapHash) {
    // SAFETY: single-threaded guest.
    let map = unsafe { &mut *TRANSIENT.inner.get() };
    map.remove(hash);
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
    let mut transient_owned: Vec<Option<CapHash>> = Vec::with_capacity(8);
    stack.push(top);
    transient_owned.push(None);
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
                if pop_and_reflect(&mut stack, &mut transient_owned, info.regs[7])? {
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
                    OP_REPLY
                        if pop_and_reflect(&mut stack, &mut transient_owned, info.regs[7])? =>
                    {
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
                        let (child, owns) = {
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
                        transient_owned.push(owns);
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
        let mut regions: [(u32, &[u8]); 3] = [(0, &[]), (0, &[]), (0, &[])];
        for (slot, ov) in regions.iter_mut().zip(frame.overlays.iter()).take(3) {
            *slot = (ov.0, ov.1.as_slice());
        }
        let [arg, ro, rw] = regions;

        let rt = unsafe {
            jit_run::build_frame_runtime(
                &frame.image_hash,
                &frame.code,
                &frame.bitmask,
                &frame.jump_table,
                frame.pc,
                frame.mem_size,
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
        .ok_or(ERR_JIT_FAILED)?;
        frame.runtime = Some(rt);
    }

    let rt = frame.runtime.as_mut().expect("just built");
    let info = unsafe { jit_run::enter_frame(rt, gas, frame.pc, frame.regs) };
    Ok(info)
}

/// Pop the top frame; if a parent exists, reflect the popped child's
/// `return_value` into the parent's φ[7]. Returns `true` when the
/// stack has been drained — the RPC caller uses this to know it's
/// time to hand a result back to the host.
fn pop_and_reflect(
    stack: &mut Vec<KernelFrame>,
    transient_owned: &mut Vec<Option<CapHash>>,
    return_value: u64,
) -> Result<bool, u32> {
    let _popped = stack.pop().expect("non-empty");
    let owned = transient_owned.pop().expect("paired with stack");
    if let Some(h) = owned {
        forget_transient(&h);
    }
    if stack.is_empty() {
        return Ok(true);
    }
    let parent = stack.last_mut().unwrap();
    parent.regs[7] = return_value;
    Ok(false)
}

/// `host_derive_spawn(image_slot=φ[7], cnode_slot=φ[8],
/// dst_slot=φ[9])`. V1: ignores `cnode_slot` (no prepared cnode
/// support — the child inherits the parent's cnode at CALL time).
/// Computes `child_chain = blake2b(running.chain, image_hash)`,
/// inserts a transient-instances entry, writes the chain hash to
/// the parent's `dst_slot`.
fn dispatch_derive_spawn(frame: &mut KernelFrame) -> Result<(), u32> {
    let image_slot = (frame.regs[7] & 0xFF) as usize;
    let _cnode_slot = (frame.regs[8] & 0xFF) as usize;
    let dst_slot = (frame.regs[9] & 0xFF) as usize;

    if image_slot >= CNODE_SLOTS || dst_slot >= CNODE_SLOTS {
        return Err(ERR_DERIVE_SLOT_OOB);
    }
    // V1: cnode lookup is best-effort. We can't walk the published
    // `Cap::CNode` from the guest (SparseList's inner BTreeMap lives
    // in the host's Global allocator, so the pointers don't map),
    // so empty slots fall back to the running frame's own image_hash.
    // That matches the recursive-spawn bench's usage exactly — it
    // wants to spawn its own image — and is a reasonable default for
    // any caller that just wants to re-enter its own program with
    // fresh state.
    let image_hash = frame.cnode[image_slot].unwrap_or(frame.image_hash);
    let child_chain = Blake2b256::hash_pair(&frame.image_hash_chain, &image_hash);
    transient_insert(
        child_chain,
        TransientInstance {
            image_hash,
            image_hash_chain: child_chain,
        },
    );
    frame.cnode[dst_slot] = Some(child_chain);
    Ok(())
}

/// `host_call(instance_slot=φ[7], endpoint_idx=φ[8])`. Reads the
/// target hash from the parent's cnode, builds a fresh
/// [`KernelFrame`] for the child. Parent's φ[9..=12] become child's
/// φ[7..=10] (arg-passing convention — used by the recursive-spawn
/// bench to thread the remaining depth count).
fn dispatch_host_call(parent: &KernelFrame) -> Result<(KernelFrame, Option<CapHash>), u32> {
    let instance_slot = (parent.regs[7] & 0xFF) as usize;
    let endpoint_idx = (parent.regs[8] & 0xFF) as u32;
    if instance_slot >= CNODE_SLOTS {
        return Err(ERR_HOST_CALL_SLOT_EMPTY);
    }
    let instance_hash = parent.cnode[instance_slot].ok_or(ERR_HOST_CALL_SLOT_EMPTY)?;

    // Arg-passing convention: parent's φ[9..=10] → child's φ[7..=8].
    // φ[11] holds the ecall op-code on a kernel-mode ecall exit (not
    // a usable arg), and φ[12] is reserved; both default to 0 for
    // the child. The bench guest threads `depth` through φ[9] alone.
    let args = [parent.regs[9], parent.regs[10], 0, 0];

    // Look up the child instance: transient table first (in-kernel
    // derives don't hit the shared cache), then fall back to shared
    // cache for host-pre-published `Cap::Instance`s.
    let (mut child, owns) = if let Some(t) = transient_get(&instance_hash) {
        let frame =
            build_frame_from_image(&t.image_hash, t.image_hash_chain, endpoint_idx, args, None)?;
        (frame, Some(instance_hash))
    } else {
        (
            build_frame_from_published(&instance_hash, endpoint_idx, args)?,
            None,
        )
    };
    // Child inherits the parent's cnode entries that the child's
    // image didn't pre-populate. Lets the bench guest reach
    // `SLOT_IMAGE` without the harness re-installing it per level.
    for (i, slot) in parent.cnode.iter().enumerate() {
        if child.cnode[i].is_none() {
            child.cnode[i] = *slot;
        }
    }
    Ok((child, owns))
}

/// Build a frame from a `Cap::Instance` published in the shared talc
/// cache (the top-level invocation path, plus host_call to host-
/// pre-published Instances).
fn build_frame_from_published(
    instance_hash: &CapHash,
    endpoint_idx: u32,
    args: [u64; 4],
) -> Result<KernelFrame, u32> {
    let inst_cap = state_cache::lookup_cap(instance_hash).ok_or(ERR_INSTANCE_NOT_FOUND)?;
    let inst = match inst_cap {
        Cap::Instance(i) => i,
        _ => return Err(ERR_INSTANCE_KIND),
    };
    let mut frame = build_frame_from_image(
        &inst.image_hash,
        inst.image_hash_chain,
        endpoint_idx,
        args,
        Some(&inst.regs),
    )?;

    // V1 limitation: we deliberately do NOT walk the published
    // `Cap::CNode` from inside the guest sandbox. `CNodeCap.slots`
    // is a `SparseList<…>` whose inner `entries` field is a `Global`-
    // allocated `BTreeMap` — even for `Cap<TalcAlloc>`. The deep-
    // clone path leaves those BTreeMap nodes in host memory, so a
    // guest-side walk would deref host VAs and page-fault. Top-frame
    // cnode seeding still picks up the image's pinned + initial
    // overlay slots (handled in `build_frame_from_image`), and
    // [`dispatch_derive_spawn`] falls back to the parent's
    // image_hash for the recursive-spawn case where no explicit
    // image slot lookup is needed.

    // Override the frame's overlay set with the published Instance's
    // `rw_overlays` so the host driver's `instance_with_overlays`
    // call (which bakes mem-region content directly into the
    // InstanceCap, bypassing image.mappings + cnode resolution) keeps
    // working. The image-mappings path
    // ([`build_frame_from_image`]) only kicks in when the Instance
    // has no overlays of its own — the case for transient sub-VM
    // children created by `derive_spawn`.
    if !inst.rw_overlays.is_empty() {
        frame.overlays.clear();
        for ov in inst.rw_overlays.iter() {
            if !ov.bytes.is_empty() {
                frame
                    .overlays
                    .push((ov.start, ov.bytes.as_slice().to_vec()));
            }
        }
    }
    if inst.mem_size > frame.mem_size {
        frame.mem_size = inst.mem_size;
    }

    Ok(frame)
}

/// Core frame builder shared by published + transient instance
/// paths. Looks up the image (in the shared cache, unconditionally —
/// images are always content-addressed and never transient), copies
/// code/bitmask/jt, seeds regs + cnode from image pinned/initial.
fn build_frame_from_image(
    image_hash: &CapHash,
    image_hash_chain: CapHash,
    endpoint_idx: u32,
    args: [u64; 4],
    inst_regs: Option<&[u64; NUM_REGS]>,
) -> Result<KernelFrame, u32> {
    let img_cap = state_cache::lookup_cap(image_hash).ok_or(ERR_IMAGE_NOT_FOUND)?;
    let img = match img_cap {
        Cap::Image(i) => i,
        _ => return Err(ERR_IMAGE_KIND),
    };

    let endpoint = endpoint_idx as usize;
    if endpoint >= img.endpoints.len() {
        return Err(ERR_ENDPOINT_OOB);
    }
    let ep = &img.endpoints[endpoint];
    if ep.entry_pc == 0 {
        return Err(ERR_ENDPOINT_UNDEFINED);
    }

    let code: Vec<u8> = img.code.as_slice().to_vec();
    let bitmask: Vec<u8> = javm_exec::unpack_bitmask(img.bitmask.as_slice(), code.len());
    let jump_table: Vec<u32> = img.jump_table.as_slice().to_vec();

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

    let mut cnode: Vec<Option<CapHash>> = vec![None; CNODE_SLOTS];
    for e in img.pinned.iter() {
        let s = e.slot.get() as usize;
        if s < CNODE_SLOTS {
            cnode[s] = Some(e.cap_hash);
        }
    }
    for e in img.initial.iter() {
        let s = e.slot.get() as usize;
        if s < CNODE_SLOTS && cnode[s].is_none() {
            cnode[s] = Some(e.cap_hash);
        }
    }

    let mut mem_size: u32 = 0;
    let mut overlays: Vec<(u32, Vec<u8>)> = Vec::new();
    for m in img.mappings.iter() {
        let end = (m.start + m.size) as u32;
        if end > mem_size {
            mem_size = end;
        }
        if m.source_path_len == 0 {
            continue;
        }
        let src_slot = m.source_path[0];
        let target_hash = match cnode.get(src_slot.get() as usize).and_then(|s| s.as_ref()) {
            Some(h) => *h,
            None => continue,
        };
        if let Some(Cap::Data(d)) = state_cache::lookup_cap(&target_hash)
            && let javm_cap::DataContent::Inline(bytes) = &d.content
            && !bytes.is_empty()
        {
            overlays.push((m.start as u32, bytes.as_slice().to_vec()));
        }
    }

    Ok(KernelFrame {
        image_hash: *image_hash,
        image_hash_chain,
        code,
        bitmask,
        jump_table,
        regs,
        pc: ep.entry_pc as u32,
        mem_size,
        overlays,
        cnode,
        runtime: None,
    })
}
