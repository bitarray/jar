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
//! - **The frame owns its mem.** Each [`KernelFrame`] holds its
//!   read-write memory as an owned [`DataCap`] (`frame.mem`), cloned
//!   from the running Instance at build. The CoW #PF handler writes
//!   dirtied pages straight into the cap's `overlay`, so the cap is
//!   the source of truth: a runtime rebuilt on resume (after eviction)
//!   sources the overlay page, not the immutable backing, and the
//!   frame's writes survive. The cap is dropped at frame pop (Phase 2
//!   does not yet propagate it upward — see the data-flow section).
//!
//! - **Sub-VM instances are inline `Owned` caps.** `derive_spawn`
//!   builds a fresh `Cap::Instance` and stores it directly in the
//!   parent's cnode slot as [`CapHashOrRef::Owned`] — no cache publish,
//!   no `CapRef`. `host_call` then **moves** that instance out of the
//!   slot (`take_key`, zero copy) into the child frame; at HALT the
//!   frame's final mem/regs/pc fold back into the instance and it moves
//!   back into the parent's slot. The instance has exactly one owner at
//!   every instant (parent slot → child frame → parent slot). A
//!   host-published `Hash` instance is the only `host_call` target that
//!   is *not* consumed (the hash is reinserted; the blob is read-only).
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
//! What this means for [`KernelFrame::mem`]:
//!
//! - The CoW #PF handler ([`crate::jit_run::jit_pf_handler`])
//!   allocates a fresh page on every guest write to a CoW-armed
//!   mapping and inserts it into the running frame's `mem` DataCap
//!   `overlay`. That page is the frame's own working memory — it lets
//!   the frame read its own writes within ring 3, and (unlike the old
//!   throwaway dirty-page `Vec`) survives a runtime rebuild.
//!
//! - On frame pop the cap is **dropped**, not propagated. F1's
//!   modifications to its mem region do not appear in F0's cnode or
//!   memory automatically; F1 must hand them up through an explicit
//!   data-flow channel. Today that channel is `φ[7]` (the return
//!   value reflected by [`pop_and_reflect`]) plus the scratchpad
//!   slot[0] cap moved at CALL/HALT. The running Instance's own `mem`
//!   is not yet moved or persisted (deferred); a cap-shaped result
//!   travels through the scratchpad slot, not `mem`.
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

use alloc::boxed::Box;

use javm_cap::cache::CapHashOrRef;
use javm_cap::cap::Cap;
use javm_cap::cap::instance::InstanceCap;
use javm_cap::hash::{Blake2b256, Hash};
use javm_cap::slot::Key;
use javm_cap::{CNodeCap, CapHash, DataCap, MissingOr, NUM_REGS};
use nub_arch_x86_abi::SCRATCHPAD_HEAD_LEN;

use crate::jit_run::{self, ExitInfo, FrameRuntime};
use crate::page_alloc::PageBuf;
use crate::paging;
use crate::state_cache::CACHE;

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

/// One stack frame on the in-kernel call stack. Holds the running Image's
/// identity hashes, the frame's **owned** `mem` DataCap + PVM register/PC
/// state, its cnode snapshot, and the ring-3 resource cache. The Image cap
/// is resolved from the heap-resident [`CACHE`] on access (blobs never evict
/// mid-RPC); the running Instance's memory is owned outright (`mem`), not
/// re-resolved from the cache.
pub struct KernelFrame {
    /// Content hash of the Image cap this frame runs. Resolved via
    /// `CACHE.lock().get(CapHashOrRef::Hash(image_hash))` at each access.
    image_hash: CapHash,
    /// Image's chain hash. Used by `derive_spawn` to compute the
    /// child's chain. Cached locally to avoid a cap deref per
    /// derive.
    image_hash_chain: CapHash,
    /// Set when this frame was built by moving an `Owned` instance out of a
    /// parent cnode slot (`host_call` of a `derive_spawn`'d sub-VM): the
    /// `(parent slot, parked InstanceCap)`. The instance's `mem` was moved
    /// into [`Self::mem`]; the rest (image, chain, root_cnode, regs, pc, gas)
    /// is parked here. At HALT, [`pop_and_reflect`] folds this frame's final
    /// mem/regs/pc back into the `InstanceCap`, boxes it `Owned`, and moves it
    /// back into the parent's slot — the single-owner round trip. `None` for a
    /// top-level (Hash) frame.
    owned_origin: Option<(Key, InstanceCap)>,
    /// The frame's **owned** read-write memory: a [`DataCap`] cloned from the
    /// running Instance at frame build (Arc-backing bump + empty overlay). The
    /// #PF handler copy-on-writes guest writes straight into its `overlay`
    /// (via `jit_run::OVERLAY_SINK`), so the cap is the source of truth — a
    /// rebuilt runtime (after eviction) sources the overlay page, not the
    /// immutable backing, and writes are never lost. Persists across this
    /// frame's runtime re-builds; dropped at frame pop (Phase 2 does not yet
    /// propagate it to the parent or persist it — see the module doc).
    mem: DataCap,
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

/// Successful loop result — what the host RPC returns to the bench
/// driver. On guest-side panic the loop returns `Err(code)` instead
/// and `nub_invoke_cached` packs the code into `exit_arg`.
pub struct LoopOutcome {
    pub exit_reason: u32,
    pub exit_arg: u32,
    pub return_value: u64,
    pub gas_remaining: i64,
    /// Effective bytes of the running Instance's scratchpad (slot[0]) region
    /// head at top HALT (see [`SCRATCHPAD_HEAD_LEN`]). Read from the top frame's
    /// owned `mem` DataCap (overlay-then-backing); zero on a non-clean exit. The
    /// host surfaces this as the uncompressed run result.
    pub scratchpad_head: [u8; SCRATCHPAD_HEAD_LEN],
}

/// Read the running Instance's scratchpad (slot[0]) region head — the effective
/// bytes of `[DATA_BASE, DATA_BASE + SCRATCHPAD_HEAD_LEN)`, the V1 scratchpad
/// convention (the scratchpad DataCap maps at the data extent's base). The
/// frame owns its `mem` DataCap; `copy_into` reads effective bytes
/// (overlay-then-backing) directly — a guest write to the region CoW'd a fresh
/// overlay page (the post-run bytes), an unwritten region reads the backing
/// (`Empty` → zero). Byte offset 0 of `mem` is guest VA `DATA_BASE`.
fn read_scratchpad_head(frame: &KernelFrame) -> [u8; SCRATCHPAD_HEAD_LEN] {
    let mut out = [0u8; SCRATCHPAD_HEAD_LEN];
    if frame.mem.content_len() as usize >= SCRATCHPAD_HEAD_LEN {
        frame.mem.copy_into(0, &mut out);
    }
    out
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
                // Read the scratchpad head from the top frame BEFORE it is
                // popped (and dropped) — only meaningful at the top-level HALT.
                let head = if stack.len() == 1 {
                    read_scratchpad_head(stack.last().expect("stack non-empty"))
                } else {
                    [0u8; SCRATCHPAD_HEAD_LEN]
                };
                if pop_and_reflect(&mut stack, info.regs[7]) {
                    break LoopOutcome {
                        exit_reason: info.exit_reason,
                        exit_arg: info.exit_arg,
                        return_value: info.regs[7],
                        gas_remaining: gas,
                        scratchpad_head: head,
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
                        scratchpad_head: [0u8; SCRATCHPAD_HEAD_LEN],
                    };
                }
                gas -= ecall_cost;

                let op = if info.exit_reason == EXIT_HOST_CALL {
                    info.exit_arg
                } else {
                    info.regs[11] as u32
                };
                match op {
                    OP_REPLY => {
                        // Read the scratchpad head from the top frame before the
                        // pop (only meaningful at the top-level trampoline HALT).
                        let head = if stack.len() == 1 {
                            read_scratchpad_head(stack.last().expect("stack non-empty"))
                        } else {
                            [0u8; SCRATCHPAD_HEAD_LEN]
                        };
                        if pop_and_reflect(&mut stack, info.regs[7]) {
                            // Preserve the JIT exit shape so the host bench
                            // harness (which asserts `(reason=4, arg=0)` for the
                            // subsoil trampoline halt) doesn't trip.
                            break LoopOutcome {
                                exit_reason: info.exit_reason,
                                exit_arg: info.exit_arg,
                                return_value: info.regs[7],
                                gas_remaining: gas,
                                scratchpad_head: head,
                            };
                        }
                        // Stack still has frames; the parent picks up at the next
                        // iter with the child's φ[7] reflected.
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
                                scratchpad_head: [0u8; SCRATCHPAD_HEAD_LEN],
                            };
                        }
                    }
                    OP_HOST_CALL => {
                        if stack.len() >= MAX_DEPTH {
                            return Err(ERR_DEPTH_LIMIT);
                        }
                        let mut child = {
                            let parent = stack.last_mut().expect("non-empty");
                            dispatch_host_call(parent)?
                        };
                        // Scratchpad: MOVE the caller's slot[0] into the
                        // callee. `take_key` empties the parent (one owner);
                        // the callee's image-default slot[0], if any, is
                        // overwritten by the caller-provided scratchpad.
                        {
                            let parent = stack.last_mut().expect("non-empty");
                            if let Some(cap) =
                                parent.cnode.take_key(&[javm_cap::abi::SCRATCHPAD_SLOT])
                            {
                                child
                                    .cnode
                                    .set_key(&[javm_cap::abi::SCRATCHPAD_SLOT], Some(cap));
                            }
                        }
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
                            scratchpad_head: [0u8; SCRATCHPAD_HEAD_LEN],
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
                    scratchpad_head: [0u8; SCRATCHPAD_HEAD_LEN],
                };
            }
        }
    };

    // Drop the stack BEFORE we hand the outcome back. Each frame owns its
    // `mem` DataCap and any inline `Owned` cnode caps outright, so the drop
    // frees them directly — there are no `cache.instances` entries to reclaim
    // (the recompiler no longer mints `Ref`).
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
    // Split borrow of two disjoint fields: the #PF handler CoWs guest writes
    // into `frame.mem`'s overlay while the JIT runs against `frame.runtime`'s
    // PT. The raw-pointer cast ends the `&mut frame.mem` borrow immediately.
    let overlay_sink: *mut DataCap = &mut frame.mem;
    let rt = frame.runtime.as_mut().expect("just built");
    let info = unsafe { jit_run::enter_frame(rt, gas, pc, regs, overlay_sink) };
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

    // The frame's RW memory is its **owned** dense `DataCap` (`frame.mem`)
    // covering the whole data extent, holding both initial and pinned content
    // at their VAs with page-aligned slabs. Source every data page from it
    // (overlay-then-backing, so a rebuilt runtime picks up prior CoW writes):
    // pinned VA ranges as `PinnedCapRo`, everything else (initial + ephemeral,
    // the latter backed by `Empty` → zero page) as one catch-all
    // `UnpinnedCapCow` range. The slabs are owned by the frame, so their PAs
    // stay valid for the frame's life past this function's return.
    let data_base = javm_cap::layout::DATA_BASE;
    let mem = &frame.mem;
    let extent = mem.content_len() as u32;
    let mem_size = data_base.saturating_add(extent);
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
/// `return_value` into the parent's φ[7], move its scratchpad (slot[0]) back,
/// and — when the child was a moved-in `Owned` sub-VM — fold the child's final
/// mem/regs/pc back into its `InstanceCap` and move it back into the parent's
/// origin slot (the single-owner round trip). Returns `true` when the stack
/// has been drained (the RPC caller hands a result back to the host).
fn pop_and_reflect(stack: &mut Vec<KernelFrame>, return_value: u64) -> bool {
    let mut popped = stack.pop().expect("non-empty");

    // REQUIRED ordering: drop the child's ring-3 runtime (its page table)
    // FIRST, so the cap's overlay pages are unmapped before the cap moves
    // anywhere. Single-threaded Hyperlight + stack discipline then guarantee no
    // live PT references the cap once its own PT is gone; a later host_call of
    // the returned instance builds a fresh PT.
    popped.runtime = None;

    if stack.is_empty() {
        // Top-level HALT: the scratchpad + mem stay on the popped frame; the
        // host return path surfaces slot[0] / `scratchpad_head` as the result.
        // The frame is dropped at scope end (top-level mem persistence deferred).
        return true;
    }

    // Move the callee's scratchpad (slot[0]) back to the caller.
    let scratch = popped.cnode.take_key(&[javm_cap::abi::SCRATCHPAD_SLOT]);

    // If the child was a moved-in `Owned` instance, fold its final state back
    // into the parked `InstanceCap` (mem moved, regs/pc copied) so the parent's
    // slot gets the *updated* instance — sub-VM state persists across calls.
    let owned_back = match popped.owned_origin.take() {
        Some((slot, mut inst)) => {
            inst.regs = popped.regs;
            inst.pc = popped.pc as u64;
            inst.mem = popped.mem; // move the (overlaid) mem back into the cap
            Some((slot, inst))
        }
        None => None,
    };

    let parent = stack.last_mut().unwrap();
    parent.regs[7] = return_value;
    if let Some(cap) = scratch {
        parent
            .cnode
            .set_key(&[javm_cap::abi::SCRATCHPAD_SLOT], Some(cap));
    }
    if let Some((slot, inst)) = owned_back {
        parent.cnode.set_key(
            slot.as_slice(),
            Some(CapHashOrRef::Owned(Box::new(Cap::Instance(inst)))),
        );
    }
    false
}

/// `host_derive_spawn(image_slot=φ[7], cnode_slot=φ[8],
/// dst_slot=φ[9])`. V1: ignores `cnode_slot` (no prepared cnode
/// support — the child inherits the parent's cnode at CALL time).
/// Computes `child_chain = blake2b(running.chain, image_hash)`, builds a
/// fresh `Cap::Instance`, and stores it **inline** as
/// [`CapHashOrRef::Owned`] in the parent's `dst_slot` — no cache publish,
/// no `CapRef`. The instance is single-owner: `host_call` later *moves* it
/// into the child frame and HALT moves it back (zero copy).
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
        Some(CapHashOrRef::Ref(_) | CapHashOrRef::Owned(_)) | None => frame.image_hash,
    };
    let child_chain = Blake2b256::hash_pair(&frame.image_hash_chain, &image_hash);

    let cap = Cap::Instance(InstanceCap {
        image_hash_chain: child_chain,
        image_hash,
        root_cnode: CapHashOrRef::Hash([0u8; 32]),
        mem: DataCap::empty(),
        regs: [0u64; NUM_REGS],
        pc: 0,
        gas_remaining: 0,
    });
    // CNode ops run in ring-0 dispatch (kernel heap live); `set` on the
    // unbounded radix map is infallible here. The child lives inline in the
    // parent's slot as `Owned` — the unique owner until host_call moves it.
    frame
        .cnode
        .set(&dst_slot, Some(CapHashOrRef::Owned(Box::new(cap))))
        .map_err(|_| ERR_DERIVE_SLOT_OOB)?;
    Ok(false)
}

/// `host_call(instance_slot=φ[7], endpoint_idx=φ[8])`. **Moves** the target
/// instance out of the parent's cnode slot (`take_key`) and builds a fresh
/// child [`KernelFrame`]. Parent's φ[9..=10] become child's φ[7..=8]
/// (arg-passing convention — the recursive-spawn bench threads the remaining
/// depth through φ[9]).
///
/// - `Owned` (a `derive_spawn`'d sub-VM): moved into the child frame with
///   zero copy; the parent's slot is left empty and HALT moves the updated
///   instance back ([`KernelFrame::owned_origin`] → [`pop_and_reflect`]).
/// - `Hash` (a host-published instance): NOT consumed — the hash is
///   reinserted and the frame built read-only from the blob.
/// - `Ref`: the recompiler no longer mints `Ref`; a stray one is a bug.
fn dispatch_host_call(parent: &mut KernelFrame) -> Result<KernelFrame, u32> {
    let instance_slot = Key::from((parent.regs[7] & 0xFF) as u8);
    let endpoint_idx = (parent.regs[8] & 0xFF) as u32;
    let args = [parent.regs[9], parent.regs[10], 0, 0];

    // MOVE the target out of the parent cnode (zero-copy for `Owned`).
    let target = parent
        .cnode
        .take_key(instance_slot.as_slice())
        .ok_or(ERR_HOST_CALL_SLOT_EMPTY)?;

    let mut child = match target {
        // Single-owner instance: move it into the child frame; record the
        // origin slot so HALT folds the updated instance back.
        CapHashOrRef::Owned(boxed) => {
            build_frame_from_owned(*boxed, instance_slot.clone(), endpoint_idx, args)?
        }
        // Host-published instance: not consumed by host_call — put the hash
        // back and build read-only from the blob.
        CapHashOrRef::Hash(h) => {
            parent
                .cnode
                .set_key(instance_slot.as_slice(), Some(CapHashOrRef::Hash(h)));
            build_frame_from_published(&h, endpoint_idx, args)?
        }
        CapHashOrRef::Ref(_) => return Err(ERR_INSTANCE_KIND),
    };

    // The child inherits the parent's cnode entries its image didn't
    // pre-populate. Per the data-flow principle every inherited entry is a
    // real copy: `Hash` entries copy the hash directly (cheap). `Owned`
    // entries are **skipped** — they are single-owner and move-only, so
    // copying one would create two owners (same rule as the scratchpad
    // slot[0] below). The moved-out `instance_slot` is already gone from the
    // parent (for `Owned`) so it is naturally not inherited.
    //
    // The scratchpad slot (slot[0]) is EXCLUDED here: it is not inherited by
    // copy but *moved* by the caller (the `OP_HOST_CALL` arm).
    let scratch_phys = CNodeCap::key_of(&[javm_cap::abi::SCRATCHPAD_SLOT]);
    for (phys_key, val) in parent.cnode.slots.iter() {
        if *phys_key == scratch_phys {
            continue;
        }
        if let MissingOr::Materialized(CapHashOrRef::Owned(_)) = val {
            continue;
        }
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
    let (image_hash, image_hash_chain, inst_regs, mem) = match &*arc {
        Cap::Instance(i) => (i.image_hash, i.image_hash_chain, i.regs, i.mem.clone()),
        _ => return Err(ERR_INSTANCE_KIND),
    };
    build_frame_inner(
        image_hash,
        image_hash_chain,
        None,
        endpoint_idx,
        args,
        Some(&inst_regs),
        mem,
    )
}

/// Build a frame by **moving** an `Owned` `Cap::Instance` into it: the
/// instance's `mem` becomes the frame's owned memory, and the rest of the
/// instance (image, chain, root_cnode, regs, pc, gas) is parked in
/// [`KernelFrame::owned_origin`] alongside `origin_slot` so HALT can fold the
/// frame's final state back and return the instance to the parent's slot.
fn build_frame_from_owned(
    cap: Cap,
    origin_slot: Key,
    endpoint_idx: u32,
    args: [u64; 4],
) -> Result<KernelFrame, u32> {
    let Cap::Instance(mut inst) = cap else {
        return Err(ERR_INSTANCE_KIND);
    };
    // Move the instance's mem into the frame; the parked instance keeps an
    // empty mem until HALT folds the frame's (overlaid) mem back.
    let mem = core::mem::replace(&mut inst.mem, DataCap::empty());
    let image_hash = inst.image_hash;
    let image_hash_chain = inst.image_hash_chain;
    let inst_regs = inst.regs;
    build_frame_inner(
        image_hash,
        image_hash_chain,
        Some((origin_slot, inst)),
        endpoint_idx,
        args,
        Some(&inst_regs),
        mem,
    )
}

// `build_frame_from_instance_ref` / `build_frame_from_cap` were removed: the
// recompiler no longer mints `CapHashOrRef::Ref`, so `dispatch_host_call`
// dispatches `Owned`/`Hash` inline (and rejects a stray `Ref`).

/// Core frame builder: reads the image cap to seed regs/pc/cnode +
/// CoW ranges, stores only IDs on the frame (no `CapHandle` pins).
/// `owned_origin` is the parent slot + parked `InstanceCap` for a moved-in
/// `Owned` sub-VM (`None` for a top-level / `Hash` frame).
#[allow(clippy::too_many_arguments)]
fn build_frame_inner(
    image_hash: CapHash,
    image_hash_chain: CapHash,
    owned_origin: Option<(Key, InstanceCap)>,
    endpoint_idx: u32,
    args: [u64; 4],
    inst_regs: Option<&[u64; NUM_REGS]>,
    mem: DataCap,
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
        owned_origin,
        mem,
        regs,
        pc,
        cnode,
        pinned,
        runtime: None,
    })
}
