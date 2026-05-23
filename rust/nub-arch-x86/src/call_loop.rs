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
use javm_cap::slot::SlotIdx;
use javm_cap::{CapHash, CapRef, NUM_REGS};
use nub_host_common::cache::TalcAlloc;

use crate::jit_run::{self, DirectMap, ExitInfo, FrameRuntime, MemRegion};
use crate::page_alloc::PageBuf;
use crate::paging;
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
const ERR_MAP_BAD_KIND: u32 = 60;
const ERR_MAP_PAGED_UNSUPPORTED: u32 = 61;

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
    /// Refcount-pinned handles on every `Cap::Data` blob mapped into
    /// this frame's PT, in resolution order. Populated once at frame
    /// build (`build_frame_from_image_handle`); reused on every
    /// `build_runtime` rebuild so eviction never bumps the count
    /// again. Dropped on frame teardown → refcount-decrement → cache
    /// reclaim on the next scratch sweep. Pinning the source caps is
    /// what makes the direct PT mapping safe: as long as a handle
    /// lives, the talc-resident bytes the PTEs point at stay alive.
    mapping_pins: Vec<DataMappingPin>,
    /// CoW-armed guest VA ranges. A subset of `mapping_pins` — the
    /// initial-slot mappings whose pages can be copy-on-write'd on
    /// guest writes. Published to the #PF handler at `enter_frame`
    /// time so it can recognise legitimate write faults and remap.
    cow_ranges: Vec<CowRange>,
    /// CoW-allocated fresh pages, populated by `jit_pf_handler` on
    /// the first write to each page of a CoW range. On frame pop
    /// these get materialised into a fresh `Cap::Data` via the
    /// auto-mint path (Commit 5).
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
/// until [`auto_mint_dirty_pages`] consumes it at frame pop.
pub struct DirtyPage {
    /// Page-aligned guest VA where this page lives in the frame's
    /// PT. The byte offset within the source cap is `guest_va -
    /// cow_range.start` (V1 only supports mapping.source_offset = 0).
    pub guest_va: u32,
    /// Content hash of the original cap whose page we forked.
    pub source_hash: CapHash,
    /// CNode slot the source cap lived in. The auto-mint path
    /// rewrites the parent's slot from `source_hash` → fresh hash.
    pub source_slot: SlotIdx,
    /// 4 KiB page holding the dirtied contents. Page's PA is what
    /// the PTE currently points at; on auto-mint we read these bytes
    /// to build the fresh `Cap::Data`.
    pub page: PageBuf,
}

/// One DataCap pinned into this frame's PT. `start` is the guest VA
/// (4 KiB-aligned), `size` the mapped length (4 KiB-aligned, ≤ the
/// cap's content). `handle` keeps the cap entry alive so the
/// physical pages mapped at `start..start+size` cannot be reclaimed
/// while the frame holds the mapping.
pub struct DataMappingPin {
    pub start: u32,
    pub size: u32,
    pub handle: CapHandle<TalcAlloc>,
}

impl DataMappingPin {
    /// Physical address of the cap's page-aligned inline content,
    /// or `None` if the entry isn't an inline `Cap::Data`.
    fn content_pa(&self) -> Option<u64> {
        let Cap::Data(d) = &self.handle.cap else {
            return None;
        };
        let javm_cap::DataContent::Inline(bytes) = &d.content else {
            return None;
        };
        paging::va_to_pa(bytes.as_ptr() as u64)
    }
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
    // Split-borrow: cow_ranges (read-only slice), dirty_pages
    // (raw *mut for the #PF handler to append to), and runtime
    // (where the JIT actually runs) are all independent fields of
    // KernelFrame. The 2024-edition disjoint borrow check allows
    // them to coexist.
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
fn build_runtime<'a>(frame: &'a KernelFrame) -> Result<FrameRuntime, u32> {
    let img = image_cap(&frame.image)?;

    let mut direct_maps: Vec<DirectMap> = Vec::with_capacity(frame.mapping_pins.len());
    let mut mem_size: u32 = 0;
    for pin in frame.mapping_pins.iter() {
        let end = pin.start.saturating_add(pin.size);
        if end > mem_size {
            mem_size = end;
        }
        let pa = pin.content_pa().ok_or(ERR_MAP_BAD_KIND)?;
        let cap_bytes = match &pin.handle.cap {
            Cap::Data(d) => match &d.content {
                javm_cap::DataContent::Inline(b) => b.len() as u32,
                _ => return Err(ERR_MAP_BAD_KIND),
            },
            _ => return Err(ERR_MAP_BAD_KIND),
        };
        let size = pin.size.min(cap_bytes);
        if size == 0 {
            continue;
        }
        direct_maps.push(DirectMap {
            start: pin.start,
            pa,
            size,
        });
    }

    // Instance rw_overlays: per-instance evolved state, currently
    // allocated via the host's `Global` allocator and so not safely
    // direct-mappable (no page-alignment guarantee). Memcpy through
    // the per-frame mem_buf as before.
    let mut regions: [(u32, &'a [u8]); 3] = [(0, &[]), (0, &[]), (0, &[])];
    let mut n = 0usize;
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

    // Extend mem_size to cover image-declared mappings even when
    // their source slot is empty (frame still expects zeroed memory
    // at the declared range).
    for m in img.mappings.iter() {
        let end = (m.start + m.size) as u32;
        if end > mem_size {
            mem_size = end;
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

    // SAFETY: caller keeps `frame.image` and `frame.mapping_pins`
    // alive for the runtime's lifetime; code/jt/cap bytes are
    // refcount-pinned through those handles.
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
            &direct_maps,
        )
    }
    .ok_or(ERR_JIT_FAILED)
}

/// Pop the top frame; if a parent exists, reflect the popped child's
/// `return_value` into the parent's φ[7]. Before dropping the popped
/// frame, run the auto-mint path on any dirty pages it accumulated
/// (CoW writes during ring-3 execution) and rewrite the matching
/// parent cnode slot to the freshly-published `Cap::Data` hash.
///
/// Returns `true` when the stack has been drained — the RPC caller
/// uses this to know it's time to hand a result back to the host.
/// The dropped frame's `CapHandle`s decrement their refcounts
/// automatically; the per-RPC scratch sweep at end of `run_top`
/// reclaims any orphaned `cache.instances` slots.
fn pop_and_reflect(stack: &mut Vec<KernelFrame>, return_value: u64) -> bool {
    let mut popped = stack.pop().expect("non-empty");
    if !popped.dirty_pages.is_empty() {
        // We don't bubble errors out of auto-mint: a publish failure
        // (e.g., directory full) is a soft fault — drop the dirty
        // pages, leave the parent cnode pointing at the original
        // cap, and continue. The guest still observed its own writes
        // during the call (they went through CoW); the only loss is
        // visibility to the parent.
        let _ = auto_mint_dirty_pages(&mut popped, stack);
    }
    drop(popped);
    if stack.is_empty() {
        return true;
    }
    let parent = stack.last_mut().unwrap();
    parent.regs[7] = return_value;
    false
}

/// Materialise the popped frame's CoW dirty pages as a fresh
/// `Cap::Data` per source cap, publish them to the shared cache,
/// and rewrite the matching slot in the parent's per-frame cnode so
/// the parent sees the modified data on its next entry. Per the
/// approved plan this fires on every frame pop (including HALT /
/// panic exits, per spec §2's status-2 path).
fn auto_mint_dirty_pages(popped: &mut KernelFrame, stack: &mut [KernelFrame]) -> Result<(), u32> {
    use alloc::collections::BTreeMap;

    let dirty = core::mem::take(&mut popped.dirty_pages);
    // Group dirty pages by source cap so each cap mints exactly once
    // even when the guest dirtied multiple of its pages.
    let mut by_source: BTreeMap<CapHash, (SlotIdx, Vec<DirtyPage>)> = BTreeMap::new();
    for dp in dirty {
        let slot = dp.source_slot;
        let hash = dp.source_hash;
        by_source
            .entry(hash)
            .or_insert((slot, Vec::new()))
            .1
            .push(dp);
    }

    for (orig_hash, (source_slot, group)) in by_source {
        let new_cap = mint_with_dirty(orig_hash, &group)?;
        let new_hash = javm_cap::cap_hash(&new_cap);
        state_cache::publish_blob(new_hash, new_cap).map_err(|_| ERR_DERIVE_PUBLISH)?;

        // Rewrite the matching cnode slot on the parent (if any).
        // Only update when the parent still points at the original
        // hash — if the parent's image overrode the slot or the
        // parent already promoted to a ref, leave it alone.
        if let Some(parent) = stack.last_mut() {
            let s = source_slot.get() as usize;
            if let Some(entry @ Some(CapHashOrRef::Hash(_))) = parent.cnode.get_mut(s)
                && matches!(entry, Some(CapHashOrRef::Hash(h)) if *h == orig_hash)
            {
                *entry = Some(CapHashOrRef::Hash(new_hash));
            }
        }
    }
    Ok(())
}

/// Build a fresh `Cap::Data` whose bytes equal the original cap's
/// content patched with every dirty page in `group`. Caller has
/// already grouped by `source_hash` so every entry in `group`
/// refers to the same original cap.
fn mint_with_dirty(orig_hash: CapHash, group: &[DirtyPage]) -> Result<Cap<TalcAlloc>, u32> {
    use javm_cap::DataContent;

    let orig_handle: CapHandle<TalcAlloc> =
        state_cache::lookup_blob_handle(&orig_hash).ok_or(ERR_HOST_CALL_SLOT_EMPTY)?;
    let orig_bytes = match &orig_handle.cap {
        Cap::Data(d) => match &d.content {
            DataContent::Inline(b) => b,
            DataContent::Paged { .. } => return Err(ERR_MAP_PAGED_UNSUPPORTED),
        },
        _ => return Err(ERR_MAP_BAD_KIND),
    };

    // Allocate fresh page-aligned bytes in the shared talc heap.
    let alloc = state_cache::talc_alloc();
    let mut new_bytes = javm_cap::alloc_page_aligned_zeroed(orig_bytes.len(), alloc);
    new_bytes.copy_from_slice(orig_bytes.as_slice());

    // Patch each dirty page. We assume mapping.start equals the
    // cap's byte-0 (V1 doesn't expose a source_offset on
    // MemoryMapping); the offset within the cap is therefore
    // `guest_va - cow_range.start`. Today's `CowRange.start` always
    // matches the mapping.start, so this is `guest_va & mask` for
    // mappings that begin at a page-aligned VA.
    //
    // We recompute the per-page offset from the *original* cap size
    // — if the dirty page is past the cap's end, we skip it (would
    // be writing into mem_buf-only territory, not part of the cap).
    for dp in group {
        // Locate the source mapping by source_slot; mapping.start is
        // the guest VA the cap starts at.
        // Conservatively, we use guest_va modulo the cap size to
        // place the dirty bytes — works for V1 where each cap is
        // mapped exactly once.
        let cap_len = orig_bytes.len();
        let off = (dp.guest_va as usize) % cap_len.max(1);
        if off + crate::paging::PAGE_SIZE > cap_len {
            continue;
        }
        // SAFETY: dp.page owns 4 KiB at dp.page.kva(); new_bytes
        // is at least `off + PAGE_SIZE` long after the bounds check.
        unsafe {
            core::ptr::copy_nonoverlapping(
                dp.page.kva() as *const u8,
                new_bytes.as_mut_ptr().add(off),
                crate::paging::PAGE_SIZE,
            );
        }
    }

    Ok(Cap::Data(javm_cap::DataCap {
        content: DataContent::Inline(new_bytes),
    }))
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

    // Resolve image mappings to refcount-bumping handles on each
    // `Cap::Data` we'll project into the PT. Done once at frame build;
    // every subsequent `build_runtime` rebuild reads PAs off the
    // already-pinned handles instead of re-bumping the cache. Initial
    // slots get armed for CoW alongside; their pages are mapped RO at
    // build time and flipped writable by the #PF handler on first
    // write.
    let (mapping_pins, cow_ranges) = resolve_mapping_pins(&image, &cnode)?;

    Ok(KernelFrame {
        image,
        image_hash,
        image_hash_chain,
        instance,
        regs,
        pc,
        cnode,
        mapping_pins,
        cow_ranges,
        dirty_pages: Vec::new(),
        runtime: None,
    })
}

/// Walk `image.mappings` and pin every Cap::Data backing them. Both
/// **pinned** (immutable RO) and **initial** (RW with CoW) slots get
/// refcount-bumping handles + direct PT projection; the latter also
/// add a `CowRange` so the #PF handler will copy-on-write their
/// pages on the first guest write. Errors out on `Paged` caps; V1
/// only supports `Inline`.
fn resolve_mapping_pins(
    image: &CapHandle<TalcAlloc>,
    cnode: &[Option<CapHashOrRef>],
) -> Result<(Vec<DataMappingPin>, Vec<CowRange>), u32> {
    let img = image_cap(image)?;
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
    let mut pins = Vec::with_capacity(img.mappings.len());
    let mut cow_ranges = Vec::new();
    for m in img.mappings.iter() {
        if m.source_path_len == 0 {
            continue;
        }
        let src_slot_raw = m.source_path[0].get();
        let src_slot = src_slot_raw as usize;
        let is_pinned = src_slot < CNODE_SLOTS && pinned_slot[src_slot];
        let is_initial = src_slot < CNODE_SLOTS && initial_slot[src_slot];
        if !is_pinned && !is_initial {
            continue;
        }
        let target_hash = match cnode.get(src_slot) {
            Some(Some(CapHashOrRef::Hash(h))) => *h,
            _ => continue,
        };
        let handle: CapHandle<TalcAlloc> =
            state_cache::lookup_blob_handle(&target_hash).ok_or(ERR_HOST_CALL_SLOT_EMPTY)?;
        match &handle.cap {
            Cap::Data(d) => match &d.content {
                javm_cap::DataContent::Inline(_) => {}
                javm_cap::DataContent::Paged { .. } => return Err(ERR_MAP_PAGED_UNSUPPORTED),
            },
            _ => return Err(ERR_MAP_BAD_KIND),
        }
        pins.push(DataMappingPin {
            start: m.start as u32,
            size: m.size as u32,
            handle,
        });
        if is_initial {
            cow_ranges.push(CowRange {
                start: m.start as u32,
                end: (m.start + m.size) as u32,
                source_hash: target_hash,
                source_slot: SlotIdx(src_slot_raw),
            });
        }
    }
    Ok((pins, cow_ranges))
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
