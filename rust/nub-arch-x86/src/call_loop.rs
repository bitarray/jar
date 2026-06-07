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
//!   the source of truth: a runtime rebuilt after a future reclamation
//!   (host-backed swap) would source the overlay page, not the immutable
//!   backing, so the frame's writes survive. The cap is dropped at frame
//!   pop (Phase 2 does not yet propagate it upward — see the data-flow
//!   section).
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

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cell::UnsafeCell;

use javm_cap::cache::CapHashOrRef;
use javm_cap::cap::Cap;
use javm_cap::cap::image::ImageCap;
use javm_cap::cap::instance::InstanceCap;
use javm_cap::hash::{Blake2b256, Hash};
use javm_cap::slot::Key;
use javm_cap::{CNodeCap, CapHash, DataCap, MissingOr, NUM_REGS};
use nub_arch_x86_abi::SCRATCHPAD_HEAD_LEN;

use crate::cached_cap::{CacheSlot, CachedCap};
use crate::jit_run::{self, ExitInfo, FrameRuntime};
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
/// `host_image_hash_chain(src_slot=φ[7], dst_slot=φ[8])` — read the cap's
/// kernel-attested type identity (an Instance's cumulative `image_hash_chain`,
/// or an Image's content hash) and place a `Cap::Data` of its 32 raw bytes at
/// `dst`. Reclaims the old `HOST_TYPE_OF`/`HOST_SAME_TYPE` ABI slots (20/21):
/// type identity is now read as plain bytes and compared in userspace
/// (memcmp), so there is no separate `Cap::Type` kind or same-type host op.
const OP_IMAGE_HASH_CHAIN: u32 = 20;
const OP_HOST_CALL: u32 = 26;

/// Hard ceiling on the in-kernel call-stack depth. NOTE: with runtime eviction
/// removed, every live frame keeps its ~24 KiB page table resident, so
/// `32768 × 24 KiB ≈ 768 MiB` exceeds the 256 MiB guest heap — a deep recursion
/// exhausts talc inside `build_runtime` and **OOM-panics (a guest-wide abort)
/// at ~9000 deep, before this `MAX_DEPTH` check ever fires.** So this is not a
/// graceful cap; it is a far-above-any-real-workload backstop (no workload
/// approaches even depth 1000). The real synchronous-depth bound is the
/// **cnode nesting depth limit, enforced at move-time** (faults are permanent →
/// reject at construction, not at use), which supersedes this constant once
/// `derive_spawn` becomes a nesting move — see
/// `docs/spec-staging/implementation/call-depth-and-cap-nesting.md`.
const MAX_DEPTH: usize = 32_768;

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
    /// The parent cnode slot to return this instance to, set when the frame was
    /// built by moving an `Owned` sub-VM out of that slot (`host_call` of a
    /// `derive_spawn`'d instance). The instance is fully **decomposed** into
    /// this frame's own fields — `image_hash` / `image_hash_chain` (identity),
    /// [`Self::mem`], [`Self::regs`], [`Self::pc`] — so only the return slot
    /// needs remembering; at HALT [`pop_and_reflect`] reconstructs the
    /// `InstanceCap` from those fields, boxes it `Owned`, and moves it back into
    /// the slot — the single-owner round trip. `None` for a top-level /
    /// host-published (`Hash`) frame (nothing to return).
    owned_origin: Option<Key>,
    /// The frame's **owned** read-write memory: a [`DataCap`] cloned from the
    /// running Instance at frame build (Arc-backing bump + empty overlay). The
    /// #PF handler copy-on-writes guest writes straight into its `overlay`
    /// (via `jit_run::OVERLAY_SINK`), so the cap is the source of truth — a
    /// runtime rebuilt after a future reclamation (host-backed swap) sources the
    /// overlay page, not the immutable backing, so writes are never lost.
    /// Dropped at frame pop (Phase 2 does not yet propagate it to the parent or
    /// persist it — see the module doc).
    mem: DataCap,
    /// Live PVM register file. Written by the JIT on every entry/
    /// exit.
    regs: [u64; NUM_REGS],
    /// Current PVM PC. Same lifecycle as `regs`.
    pc: u32,
    /// Per-frame cnode snapshot: the radix kv-map (`Hasher(Key) ->
    /// CapHashOrRef<Box<CachedCap>>`) seeded from the running `Cap::Instance`'s
    /// image (pinned/initial, as `Hash` entries) and grown by `derive_spawn`
    /// (as inline `Owned(CachedCap)`). No fixed slot count — a normal
    /// `CNodeCap`. The payload is [`CachedCap`] — a cap plus its engine-private
    /// page-table cache — so a resident sub-VM's runtime rides *with* the cap
    /// in its slot (no parent-side side-table). CNode ops run only in the
    /// call-loop dispatch (ring 0 after the JIT context switch), so the
    /// kernel-heap `RadixMap` is live; the JIT-compiled guest code never
    /// touches this directly. The `CachedCap` payload is deliberately
    /// non-wire-serialisable, so this cnode cannot be hashed or shipped.
    cnode: CNodeCap<Box<CachedCap>>,
    /// Slot keys this frame's image declares pinned (read-only), sorted —
    /// the recompiler's mirror of the interpreter's
    /// `InstanceEntry.pinned_slots`. A write to one of these (e.g. a
    /// `derive_spawn` dst) must trap, matching the interpreter's
    /// `OpError::SlotPinned`. Sorted (image pinned slots are emitted sorted),
    /// so membership is a `binary_search`.
    pinned: Vec<Key>,
    /// Per-page category-#3 [`javm_exec::mat::PageState`] (one byte/page) over
    /// the frame's data extent `[DATA_BASE, DATA_BASE + mem.content_len())`,
    /// advancing NotPresent → PresentRo → PresentRw as the #PF handler
    /// materializes pages. This is the category-#3 gas *history* — path
    /// dependent and not reconstructable. It lives on the `KernelFrame` (not the
    /// [`FrameRuntime`]) deliberately: it must outlive any future reclamation of
    /// the runtime (host-backed swap — see
    /// `docs/spec-staging/implementation/call-depth-and-cap-nesting.md`), so that
    /// a frame resumed after its runtime was reclaimed never re-charges
    /// category-#3 for pages it already paid for (which would fork the
    /// never-reclaiming interpreter).
    mat_state: Vec<u8>,
    /// Materialized read-only **units** — sorted set of
    /// [`javm_exec::mat::unit_base`] values (one per `cap ∩ 2 MiB cluster`, for
    /// code and pinned caps). Same gas-history / reclamation-survival rationale
    /// as `mat_state` above.
    ro_units: Vec<u32>,
    /// Per-frame ring-3 resources (the page table). Lazily built on the first
    /// [`run_one_entry`] for this frame and reused across every subsequent
    /// re-entry (parent resume after a child HALT) — so a depth-N recursion
    /// pays N page-table builds, not one per re-entry. It is *not* evicted:
    /// the synchronous call stack is bounded structurally (cnode nesting depth;
    /// see the doc above), so all live page tables stay resident.
    ///
    /// On a child HALT this runtime is **not** dropped if the child was a
    /// resident `Owned` sub-VM — instead [`pop_and_reflect`] re-arms it (clears
    /// W on each CoW'd leaf) and re-attaches it to the returning instance's
    /// [`CachedCap`] cache slot, so the next CALL of that same instance reuses
    /// the whole page table. The cache rides *with* the cap in the parent's
    /// cnode slot — no parent-side side-table — and is freed automatically when
    /// the slot is overwritten (`derive_spawn`) or the frame pops, so peak live
    /// page tables match the no-cache case (one per stack frame, plus the
    /// just-popped child).
    runtime: Option<FrameRuntime>,
}

/// One cap-backed data mapping projected into the guest address space,
/// lazily materialized (category #3). The #PF handler scans this list when a
/// guest access faults inside ring 3; a hit identifies the page's **kind**
/// (pinned read-only vs unpinned copy-on-write), so the handler knows whether a
/// write faults or CoWs. The page's **source PA** is resolved lazily on fault
/// from the frame's `mem` DataCap (`jit_run::mem_source_pa`), so this is just a
/// region/kind map — `O(mappings)`, with no per-page PA arena. Pages NOT
/// covered by any `MatRange` are outside the declared data extent and fault.
#[derive(Clone, Copy, Debug)]
pub struct MatRange {
    pub start: u32,
    pub end: u32,
    /// [`javm_exec::mat::PageKind`] as a `u8`: pinned slots are
    /// `PinnedCapRo` (a write hard-faults), initial slots are
    /// `UnpinnedCapCow` (a write copies-on-write).
    pub kind: u8,
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
                    OP_IMAGE_HASH_CHAIN => {
                        let trapped = {
                            let frame = stack.last_mut().expect("non-empty");
                            dispatch_image_hash_chain(frame)?
                        };
                        if trapped {
                            // Pinned/empty dst or wrong src kind → guest trap.
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
                        // Charge the call-frame materialization — JIT compile
                        // (O(code)) + eager read-only page-in (per declared
                        // 2 MiB unit) + frame-setup base — computed statically
                        // from the callee Image and billed to the CALLER (on
                        // top of the ecall floor above). Check-before-charge,
                        // gated **before** `dispatch_host_call` moves the
                        // instance, so an OOG here leaves the parent slot
                        // untouched and the re-attempt is clean (gas-cost.md
                        // §3). Charged in full on every CALL — the compiled
                        // image + page table are memoized for *work* only,
                        // never a gas discount — so gas is independent of the
                        // node-local compile/PT cache (gas_const::call_frame_cost).
                        let frame_cost = {
                            let parent = stack.last().expect("non-empty");
                            host_call_frame_cost(parent)?
                        };
                        if gas < frame_cost {
                            break LoopOutcome {
                                exit_reason: EXIT_OOG,
                                exit_arg: 0,
                                return_value: info.regs[7],
                                gas_remaining: gas,
                                scratchpad_head: [0u8; SCRATCHPAD_HEAD_LEN],
                            };
                        }
                        gas -= frame_cost;
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
                        // No runtime eviction: every live frame keeps its page
                        // table resident. The call stack is depth-bounded by
                        // `MAX_DEPTH` (interim) / the cnode nesting limit
                        // (target), so the resident page-table set is bounded
                        // structurally rather than by an LRU cap.
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
/// frame builds [`FrameRuntime`] (the page table); subsequent calls
/// (parent resumes after a child HALT) reuse it — the runtime is never
/// evicted, so it is built exactly once per frame. Frame mem + `mat_state`
/// persist across re-entries — the parent's writes and gas history survive
/// the child's execution.
fn run_one_entry(frame: &mut KernelFrame, gas: i64) -> Result<ExitInfo, u32> {
    if frame.runtime.is_none() {
        let rt = build_runtime(frame)?;
        frame.runtime = Some(rt);
    }
    let pc = frame.pc;
    let regs = frame.regs;
    // Split borrow of disjoint fields: while the JIT runs against
    // `frame.runtime`'s PT, the #PF handler CoWs guest writes into `frame.mem`'s
    // overlay and advances `frame.mat_state` / `frame.ro_units` in place. The
    // raw-pointer casts end those `&mut` borrows immediately, so the subsequent
    // `frame.runtime` borrow does not conflict.
    let overlay_sink: *mut DataCap = &mut frame.mem;
    let mat_state_ptr = frame.mat_state.as_mut_ptr();
    let mat_state_len = frame.mat_state.len() as u64;
    let ro_units: *mut Vec<u32> = &mut frame.ro_units;
    let rt = frame.runtime.as_mut().expect("just built");
    let info = unsafe {
        jit_run::enter_frame(
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

    // Pinned mappings → PinnedCapRo ranges (pushed first → precedence). Bounds +
    // kind only; the #PF handler resolves each page's source PA lazily from
    // `frame.mem` (`jit_run::mem_source_pa`).
    for m in img.mappings.iter() {
        if m.path().is_empty() || !img.mapping_is_pinned(m.start as u32) {
            continue;
        }
        let span = (m.size as u32).next_multiple_of(paging::PAGE_SIZE as u32);
        if span == 0 {
            continue;
        }
        mat_ranges.push(MatRange {
            start: m.start as u32,
            end: (m.start as u32).saturating_add(span),
            kind: javm_exec::mat::PageKind::PinnedCapRo.as_u8(),
        });
    }

    // Catch-all RW range over the whole extent (initial + ephemeral).
    if pages > 0 {
        mat_ranges.push(MatRange {
            start: data_base,
            end: mem_size,
            kind: javm_exec::mat::PageKind::UnpinnedCapCow.as_u8(),
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
            mem_size,
            mat_ranges,
        )
    }
    .ok_or(ERR_JIT_FAILED)
}

/// Pop the top frame; if a parent exists, reflect the popped child's
/// `return_value` into the parent's φ[7], move its scratchpad (slot[0]) back,
/// and — when the child was a moved-in `Owned` sub-VM — reconstruct its
/// `InstanceCap` from the frame's final mem/regs/pc (+ carried identity) and
/// move it back into the parent's origin slot (the single-owner round trip).
/// Returns `true` when the stack has been drained (the RPC caller hands a
/// result back to the host).
fn pop_and_reflect(stack: &mut Vec<KernelFrame>, return_value: u64) -> bool {
    let mut popped = stack.pop().expect("non-empty");

    if stack.is_empty() {
        // Top-level HALT: no parent to park the runtime in, so drop it (its
        // page table). The scratchpad + mem stay on the popped frame; the host
        // return path surfaces slot[0] / `scratchpad_head` as the result. The
        // frame is dropped at scope end (top-level mem persistence deferred).
        popped.runtime = None;
        return true;
    }

    // Move the callee's scratchpad (slot[0]) back to the caller.
    let scratch = popped.cnode.take_key(&[javm_cap::abi::SCRATCHPAD_SLOT]);

    // If the child was a moved-in `Owned` instance, reconstruct its
    // `InstanceCap` from this frame's final state so the parent's slot gets the
    // *updated* instance — sub-VM state persists across calls — AND carry its
    // re-armed page table back so the parent can park it for the next CALL. The
    // page table travels **paired** with the cap (their overlay pages stay
    // mapped): no PT references a cap whose PT it doesn't own. A non-`Owned`
    // (host-published `Hash`) child is not resident, so its runtime is dropped
    // (the next CALL rebuilds it from the blob).
    let owned_back = match popped.owned_origin.take() {
        Some(slot) => {
            // Re-arm BEFORE the mem moves into the cap: clear W on every CoW'd
            // leaf so the next CALL re-faults on first write and re-charges its
            // CoW (gas-neutral — the page is reused, only the W bit toggles).
            let runtime = popped.runtime.take();
            if let Some(rt) = &runtime {
                rt.rearm_cow(popped.mem.overlay.keys().copied());
            }
            // Reconstruct from the frame's authoritative running state: identity
            // (`image_hash` / `image_hash_chain`) is carried on the frame, and
            // the final `mem` / `regs` / `pc` are the frame's. `root_cnode` and
            // `gas_remaining` stay spawn-time placeholders — V1 persists neither
            // the running cnode nor residual gas into the cap (the exact values
            // the parked shell used to carry).
            let inst = InstanceCap {
                image_hash_chain: popped.image_hash_chain,
                image_hash: popped.image_hash,
                root_cnode: CapHashOrRef::Hash([0u8; 32]),
                mem: popped.mem, // the (overlaid) mem
                regs: popped.regs,
                pc: popped.pc as u64,
                gas_remaining: 0,
            };
            Some((slot, inst, runtime))
        }
        None => {
            popped.runtime = None;
            None
        }
    };

    let parent = stack.last_mut().unwrap();
    parent.regs[7] = return_value;
    if let Some(cap) = scratch {
        parent
            .cnode
            .set_key(&[javm_cap::abi::SCRATCHPAD_SLOT], Some(cap));
    }
    if let Some((slot, inst, runtime)) = owned_back {
        // Re-attach the (re-armed) page table to the returning instance's
        // `CachedCap` cache slot, so the next `host_call` of this instance
        // reuses it. The cache rides *with* the cap in the parent's cnode slot
        // — no side-table, freed automatically when the slot is overwritten or
        // the parent frame pops.
        let cache = match runtime {
            Some(rt) => CacheSlot::Instance(rt),
            None => CacheSlot::None,
        };
        parent.cnode.set_key(
            slot.as_slice(),
            Some(CapHashOrRef::Owned(Box::new(CachedCap {
                cap: Cap::Instance(inst),
                cache,
            }))),
        );
    }
    false
}

/// Per-`image_hash` cache of the **clean** composed instance-memory backing.
///
/// The composed RW backing for an Image is identical for every sub-VM spawned
/// from it and is never mutated during execution — guest writes CoW into the
/// *per-instance* overlay, never the backing. So we compose it once per
/// `image_hash` (content-addressed ⇒ never stale) and hand each
/// `derive_spawn` a [`DataCap::clone`] — an `Arc`-bump of the shared backing +
/// an empty overlay — instead of re-running the full compose (a `CACHE.get`
/// per mapping + a `place_shared` pass + a fresh slab alloc) every spawn. All
/// spawns sharing one backing direct-map the same read-only physical frames
/// and each CoWs only the pages it writes, so sharing is sound (single
/// mutator: each instance's overlay).
///
/// `UnsafeCell<BTreeMap>` mirrors [`crate::jit_cache`]'s compile cache: the
/// Hyperlight guest is single-threaded, so the `unsafe` is sound and local.
struct MemCache {
    inner: UnsafeCell<BTreeMap<CapHash, DataCap>>,
}
/// SAFETY: single-threaded guest (Hyperlight serialisation).
unsafe impl Sync for MemCache {}
static MEM_CACHE: MemCache = MemCache {
    inner: UnsafeCell::new(BTreeMap::new()),
};

/// Drop every cached clean instance-mem backing. Bench-only (paired with
/// [`crate::jit_cache::evict_all`]) so a "cold" measurement re-composes;
/// correctness never needs it (the cache is content-addressed by `image_hash`).
pub fn evict_mem_cache() {
    // SAFETY: single-threaded guest; no in-flight call when this RPC fires.
    let map = unsafe { &mut *MEM_CACHE.inner.get() };
    map.clear();
}

/// Build a derived sub-VM's initial `mem` DataCap from its Image. The composed
/// backing is memoized per `image_hash` (see [`MemCache`]): on a hit each spawn
/// gets a cheap clone (shared backing `Arc` + empty overlay); on a miss
/// [`compose_instance_mem`] builds it once.
fn build_instance_mem(image_hash: &CapHash, img: &ImageCap) -> DataCap {
    // Fast path: clone the cached clean backing (Arc-bump + empty overlay).
    // SAFETY: single-threaded guest (Hyperlight serialisation); the returned
    // borrow is cloned before any mutation of the map.
    if let Some(clean) = unsafe { (*MEM_CACHE.inner.get()).get(image_hash) } {
        return clean.clone();
    }
    // Miss: compose once (no MEM_CACHE borrow held across the compose), cache,
    // hand out a clone.
    let mem = compose_instance_mem(img);
    // SAFETY: single-threaded guest.
    unsafe {
        (*MEM_CACHE.inner.get()).insert(*image_hash, mem.clone());
    }
    mem
}

/// Compose the clean instance-mem backing from the image's data mappings: a
/// dense backing covering `[DATA_BASE, max(mapping.start + size))`, with each
/// mapping's source `Cap::Data` (resolved from [`CACHE`] via the image's
/// pinned/initial slot `cap_hash`) **Arc-shared** at the mapping's offset.
///
/// Mirrors the *content* of the host's [`javm_cap::image::Image::instance_mem_backing`]
/// (top-level instances) and the interpreter's `dispatch_derive_spawn_cached`
/// fold (`javm/src/ecall.rs`), so a derived child sees its pinned read-only +
/// initial read-write data instead of an empty extent. Unlike the copying
/// `put_page` fold, the source pages are shared by `Arc` (the recompiler maps
/// them by PA, so the child direct-maps the same read-only frames as every
/// sibling and CoWs — into its own overlay — only the pages it writes).
///
/// The recompiler has no prepared cnode (it ignores `cnode_slot`), so a
/// mapping's source resolves to the image's own pinned/initial default
/// (`pinned` first — the same precedence `build_frame_inner` seeds the cnode
/// with).
fn compose_instance_mem(img: &ImageCap) -> DataCap {
    let data_base = javm_cap::layout::DATA_BASE as u64;
    let mem_top = img
        .mappings
        .iter()
        .map(|m| m.start + m.size)
        .max()
        .unwrap_or(data_base);
    let mut mem = DataCap::from_bytes_sized(&[], mem_top.saturating_sub(data_base));
    for m in img.mappings.iter() {
        let Some(src_slot) = m.path().first() else {
            continue;
        };
        let Some(src_hash) = img
            .pinned
            .iter()
            .chain(img.initial.iter())
            .find(|e| e.slot == *src_slot)
            .map(|e| e.cap_hash)
        else {
            continue;
        };
        let Some(src_arc) = CACHE.get(CapHashOrRef::Hash(src_hash)) else {
            continue;
        };
        if let Cap::Data(d) = &*src_arc {
            mem.place_shared(m.start.saturating_sub(data_base), d);
        }
    }
    mem
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
        Some(CapHashOrRef::Owned(_)) | None => frame.image_hash,
    };
    let child_chain = Blake2b256::hash_pair(&frame.image_hash_chain, &image_hash);

    // Build the child's initial memory from its Image (pinned RO + initial RW
    // sources folded at their VAs, source pages Arc-shared) — like the top-
    // level instance's `instance_mem_backing`. Without this the child runs
    // against an empty extent and faults on its own initial-slot writes.
    let child_mem = {
        let img_arc = CACHE
            .get(CapHashOrRef::Hash(image_hash))
            .ok_or(ERR_IMAGE_NOT_FOUND)?;
        match &*img_arc {
            Cap::Image(img) => build_instance_mem(&image_hash, img),
            _ => return Err(ERR_IMAGE_KIND),
        }
    };

    let cap = Cap::Instance(InstanceCap {
        image_hash_chain: child_chain,
        image_hash,
        root_cnode: CapHashOrRef::Hash([0u8; 32]),
        mem: child_mem,
        regs: [0u64; NUM_REGS],
        pc: 0,
        gas_remaining: 0,
    });
    // CNode ops run in ring-0 dispatch (kernel heap live); `set` on the
    // unbounded radix map is infallible here. The child lives inline in the
    // parent's slot as `Owned(CachedCap)` — the unique owner until host_call
    // moves it. Overwriting the slot drops any previous occupant's `CachedCap`
    // (and its parked page table), so a stale cache for that slot is
    // invalidated automatically — no separate side-table to maintain.
    frame
        .cnode
        .set(&dst_slot, Some(CapHashOrRef::Owned(CachedCap::boxed(cap))))
        .map_err(|_| ERR_DERIVE_SLOT_OOB)?;
    Ok(false)
}

/// `host_image_hash_chain(src_slot=φ[7], dst_slot=φ[8])`. Reads the type
/// identity of the cap at `src_slot` — an `Cap::Instance`'s cumulative
/// `image_hash_chain`, or a `Cap::Image`'s content hash (which *is* its
/// identity) — and places a `Cap::Data` holding those 32 raw bytes
/// (page-padded) at `dst_slot`. The result is freely readable/comparable:
/// same-type is a userspace `memcmp` of two such DataCaps; there is no
/// `Cap::Type` kind and no same-type host op (see [`OP_IMAGE_HASH_CHAIN`]).
///
/// Returns `Ok(true)` to TRAP (pinned/empty dst, or a src that is neither an
/// Instance nor an Image), mirroring `dispatch_derive_spawn`'s trap discipline.
fn dispatch_image_hash_chain(frame: &mut KernelFrame) -> Result<bool, u32> {
    // V1 single-byte ABI: φ[7] = src slot, φ[8] = dst slot.
    let src_slot = Key::from((frame.regs[7] & 0xFF) as u8);
    let dst_slot = Key::from((frame.regs[8] & 0xFF) as u8);

    // Writing into a pinned (read-only) slot traps, mirroring the
    // derive_spawn pinned-dst rejection.
    if frame.pinned.binary_search(&dst_slot).is_ok() {
        return Ok(true);
    }

    // Read the source cap's type identity. `peek_key` borrows (no clone, so
    // an Owned instance's parked page-table cache is untouched). Hash targets
    // resolve through the blob cache; an inline Owned instance reads its field
    // directly (no hash needed).
    let chain: CapHash = match frame.cnode.peek_key(src_slot.as_slice()) {
        Some(CapHashOrRef::Hash(h)) => {
            let h = *h;
            let arc = CACHE
                .get(CapHashOrRef::Hash(h))
                .ok_or(ERR_INSTANCE_NOT_FOUND)?;
            match &*arc {
                Cap::Instance(i) => i.image_hash_chain,
                // An Image is content-addressed: its hash IS its identity.
                Cap::Image(_) => h,
                _ => return Ok(true),
            }
        }
        Some(CapHashOrRef::Owned(cc)) => match &cc.cap {
            Cap::Instance(i) => i.image_hash_chain,
            Cap::Image(_) => cc.cap.cap_hash(),
            _ => return Ok(true),
        },
        None => return Ok(true),
    };

    // Mint a Cap::Data of the 32 identity bytes (padded to a page) and place
    // it at dst as an inline Owned cap, settled at termination — same
    // placement convention as derive_spawn's child instance.
    let cap = Cap::data_inline(&chain);
    frame
        .cnode
        .set(&dst_slot, Some(CapHashOrRef::Owned(CachedCap::boxed(cap))))
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
        // Single-owner instance: move it (and its parked page table) into the
        // child frame; record the origin slot so HALT folds the updated
        // instance back.
        CapHashOrRef::Owned(boxed) => {
            let CachedCap { cap, cache } = *boxed;
            let mut child = build_frame_from_owned(cap, instance_slot.clone(), endpoint_idx, args)?;
            // Page-table reuse: if this resident instance carries a parked
            // runtime (re-armed at its last HALT), move it into the child frame
            // instead of rebuilding the page table. The data extent is fixed
            // per image (immutable), so the parked extent must match.
            if let CacheSlot::Instance(rt) = cache {
                debug_assert_eq!(
                    rt.data_extent(),
                    child.mem.content_len(),
                    "parked runtime extent must match the resident instance's mem",
                );
                child.runtime = Some(rt);
            }
            child
        }
        // Host-published instance: not consumed by host_call — put the hash
        // back and build read-only from the blob.
        CapHashOrRef::Hash(h) => {
            parent
                .cnode
                .set_key(instance_slot.as_slice(), Some(CapHashOrRef::Hash(h)));
            build_frame_from_published(&h, endpoint_idx, args)?
        }
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
    // `key_of` is payload-independent (it hashes the logical key); annotate
    // the generic so it resolves, matching the parent frame's cnode payload.
    let scratch_phys = CNodeCap::<Box<CachedCap>>::key_of(&[javm_cap::abi::SCRATCHPAD_SLOT]);
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

/// Category-#3 call-frame cost for materializing the callee `image_hash`,
/// computed **statically** from its Image so both engines agree (see
/// [`javm_exec::gas_const::call_frame_cost`]): the JIT compile (`O(code)`),
/// the eager read-only page-in (one page-in per declared 2 MiB read-only
/// unit — the code region plus every pinned mapping, each clustered per
/// 2 MiB), and the fixed frame-setup base. Charged to the caller at an
/// in-kernel CALL, in full on every CALL (compile/PT memoization is a
/// node-local performance optimization, never a gas discount), so gas is
/// independent of the cache.
fn call_frame_cost_for(image_hash: &CapHash) -> Result<i64, u32> {
    let img_arc = CACHE
        .get(CapHashOrRef::Hash(*image_hash))
        .ok_or(ERR_IMAGE_NOT_FOUND)?;
    let img = match &*img_arc {
        Cap::Image(i) => i,
        _ => return Err(ERR_IMAGE_KIND),
    };
    // Declared read-only 2 MiB units: the code region (one cap) plus each
    // pinned (read-only) mapping, clustered per 2 MiB.
    let cluster = 1u64 << javm_exec::mat::CLUSTER_SHIFT;
    let mut ro_units = (img.code.len() as u64).div_ceil(cluster);
    for m in img.mappings.iter() {
        if img.mapping_is_pinned(m.start as u32) {
            ro_units = ro_units.saturating_add(m.size.div_ceil(cluster));
        }
    }
    let cost = javm_exec::gas_const::call_frame_cost(
        img.code.len().min(u32::MAX as usize) as u32,
        ro_units.min(u32::MAX as u64) as u32,
    );
    Ok(cost.min(i64::MAX as u64) as i64)
}

/// The CALL frame cost for the instance in `parent`'s host_call slot,
/// resolved by **peeking** the slot (no move) so the gas gate can run
/// **before** [`dispatch_host_call`] mutates the parent. This keeps an OOG
/// at a CALL a clean, no-work re-attempt (gas-cost.md §3): the parent slot
/// is untouched, so a top-up `CALL_RESUME` re-runs the CALL from a
/// pristine state. Resolves the callee `image_hash` exactly as
/// `dispatch_host_call` will (same slot, same `Owned`/`Hash` handling), so
/// the cost gated here equals the cost the built child would have.
fn host_call_frame_cost(parent: &KernelFrame) -> Result<i64, u32> {
    let instance_slot = Key::from((parent.regs[7] & 0xFF) as u8);
    let image_hash = match parent.cnode.peek_key(instance_slot.as_slice()) {
        Some(CapHashOrRef::Owned(boxed)) => match &boxed.cap {
            Cap::Instance(i) => i.image_hash,
            _ => return Err(ERR_INSTANCE_KIND),
        },
        Some(CapHashOrRef::Hash(h)) => {
            let arc = CACHE
                .get(CapHashOrRef::Hash(*h))
                .ok_or(ERR_INSTANCE_NOT_FOUND)?;
            match &*arc {
                Cap::Instance(i) => i.image_hash,
                _ => return Err(ERR_INSTANCE_KIND),
            }
        }
        None => return Err(ERR_HOST_CALL_SLOT_EMPTY),
    };
    call_frame_cost_for(&image_hash)
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
/// instance is fully decomposed — its `mem` becomes the frame's owned memory
/// and its identity (`image_hash` / `image_hash_chain`) + `regs` seed the
/// frame. `root_cnode`, `pc`, and `gas_remaining` are not needed at build (the
/// frame starts at the endpoint's entry-pc with a freshly-seeded cnode). Only
/// `origin_slot` is remembered in [`KernelFrame::owned_origin`] so HALT can
/// reconstruct the instance from the frame's final state and return it.
fn build_frame_from_owned(
    cap: Cap,
    origin_slot: Key,
    endpoint_idx: u32,
    args: [u64; 4],
) -> Result<KernelFrame, u32> {
    let Cap::Instance(inst) = cap else {
        return Err(ERR_INSTANCE_KIND);
    };
    let InstanceCap {
        image_hash,
        image_hash_chain,
        regs,
        mem,
        ..
    } = inst;
    build_frame_inner(
        image_hash,
        image_hash_chain,
        Some(origin_slot),
        endpoint_idx,
        args,
        Some(&regs),
        mem,
    )
}

// `build_frame_from_instance_ref` / `build_frame_from_cap` were removed: a
// cnode slot is a `Hash` or an inline `Owned` cap, so `dispatch_host_call`
// dispatches both inline.

/// Core frame builder: reads the image cap to seed regs/pc/cnode +
/// CoW ranges, stores only IDs on the frame (no `CapHandle` pins).
/// `owned_origin` is the parent return slot for a moved-in `Owned` sub-VM
/// (`None` for a top-level / `Hash` frame).
#[allow(clippy::too_many_arguments)]
fn build_frame_inner(
    image_hash: CapHash,
    image_hash_chain: CapHash,
    owned_origin: Option<Key>,
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

    // Category-#3 bookkeeping over the data extent: one `PageState` byte per
    // page (all `NotPresent` initially), and an empty RO-unit set. Sized from
    // the frame's `mem` (`content_len` is a page multiple and never resizes
    // mid-frame — CoW only adds overlay pages), so its length matches the
    // `FrameRuntime`'s `mem_top - data_base` extent. Lives here, on the
    // `KernelFrame`, not the runtime, so it survives any future runtime
    // reclamation (host-backed swap) — see the field doc.
    let mat_state_pages = (mem.content_len() / paging::PAGE_SIZE as u64) as usize;

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
        mat_state: alloc::vec![0u8; mat_state_pages],
        ro_units: Vec::new(),
        runtime: None,
    })
}
