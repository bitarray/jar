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
/// `host_yield(sender_slot=φ[7], …)` — emit the yield_key carried by the
/// YieldSender at `sender_slot`. Pure-cap `kernel:*` syscalls
/// (`kernel:mint_yield` / `kernel:merge_yield_receiver`) are caught by the
/// kernel as the implicit ROOT receiver and handled INLINE — the guest resumes
/// at the next instruction (the "syscalls conceptually push a kernel frame but
/// we don't actually push" model). Everything else — a user key, or a
/// `kernel:*` key not wired inline — is ROUTED: the loop walks the call stack
/// from the emitter toward the root (skipping the emitter instance's own
/// frames) and the nearest ancestor whose per-CALL snapshotted YieldReceiver
/// contains the key catches it (push a ReferenceEntry, suspend the yielder;
/// resumed by [`OP_CALL_RESUME`]). Gas/quota `kernel:*` syscalls (need the meter
/// table) remain a later stage.
const OP_HOST_YIELD: u32 = 16;
const OP_DERIVE_SPAWN: u32 = 18;
/// `host_image_hash_chain(src_slot=φ[7], dst_slot=φ[8])` — read the cap's
/// kernel-attested type identity (an Instance's cumulative `image_hash_chain`,
/// or an Image's content hash) and place a `Cap::Data` of its 32 raw bytes at
/// `dst`. Reclaims the old `HOST_TYPE_OF`/`HOST_SAME_TYPE` ABI slots (20/21):
/// type identity is now read as plain bytes and compared in userspace
/// (memcmp), so there is no separate `Cap::Type` kind or same-type host op.
const OP_IMAGE_HASH_CHAIN: u32 = 20;
const OP_HOST_CALL: u32 = 26;
/// `call_resume()` — resume the Waiting yielder directly below this handler's
/// ReferenceEntry (spec §4 CALL_RESUME). The handler's scratchpad (`slot[0]`)
/// reflects to the yielder as its response; the ReferenceEntry pops; the yielder
/// becomes the running top and continues at its post-yield PC. Faults if the top
/// is not a handler activation (no outstanding yield to resume). New
/// guest-kernel op number — needs no recompiler change (the recompiler surfaces
/// `ecalli imm` → EXIT_HOST_CALL(imm) generically; dispatched here).
const OP_CALL_RESUME: u32 = 27;
/// `drop_paused()` — a yield handler gives up on its Waiting yielder (spec §4
/// DROP_PAUSED): discard the entry directly below this handler's ReferenceEntry
/// (its frame + state) WITHOUT resuming it; the handler keeps running. Faults if
/// the top is not a handler activation. New guest-kernel op number.
const OP_DROP_PAUSED: u32 = 28;

/// φ[8] status the kernel writes into the caller on apply termination (spec §4
/// calling convention): `Ok` on a normal HALT/REPLY return and on a CALL_RESUME
/// response, `YIELDED` when a routed yield hands control to a catcher. A
/// discriminating handler branches on φ[8] to tell a yield from a plain return;
/// a straight-line one ignores it.
const STATUS_OK: u64 = 0;
const STATUS_YIELDED: u64 = 1;

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
/// `host_yield` carried a yield_key the kernel does not (yet) handle as root
/// receiver — a non-`kernel:*` user key (ancestor routing is a later stage) or
/// a `kernel:*` syscall not yet wired (gas/quota/oog).
const ERR_YIELD_UNHANDLED: u32 = 70;
/// A `host_yield` operand slot did not hold the expected kernel-assisted
/// Instance (YieldSender / YieldReceiver).
const ERR_YIELD_BAD_SENDER: u32 = 71;

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

/// What a kernel call-stack entry runs.
enum EntryKind {
    /// A fresh invocation of an Instance — owns the running [`KernelFrame`].
    /// Pushed by CALL; popped (and reflected) by HALT. Boxed so the stack `Vec`
    /// element stays pointer-sized: a [`KernelFrame`] is large (~500 B) and a
    /// `Reference` carries no frame, so an inline variant would bloat every
    /// stack slot. One alloc per CALL is negligible beside the per-frame page
    /// table build.
    Instance(Box<KernelFrame>),
    /// A **yield activation**: re-runs an earlier [`EntryKind::Instance`] (the
    /// one at [`StackEntry::target`]) at its post-CALL continuation, with the
    /// yield payload reflected into its scratchpad. It carries no frame of its
    /// own — running the top of the stack runs the *referent's* frame — so one
    /// Instance shares a single PC/regs/mem across its InstanceEntry and every
    /// ReferenceEntry (spec §3 "same-instance entries share PC"). Pushed by a
    /// routed `host_yield`; popped by `CALL_RESUME`.
    Reference,
}

/// One entry on the in-kernel call stack. The stack drives control transfer:
/// CALL pushes an [`EntryKind::Instance`], a routed `host_yield` pushes an
/// [`EntryKind::Reference`], and HALT / `CALL_RESUME` pop. Exactly one entry —
/// the top — is *Running*; every entry below it is *Waiting* (kernel-internal
/// accounting, not a σ-visible Instance state).
struct StackEntry {
    kind: EntryKind,
    /// Index of the [`EntryKind::Instance`] whose [`KernelFrame`] this entry
    /// runs: its **own** index for an InstanceEntry, the **referent's** index
    /// for a ReferenceEntry. Lower-or-equal to the entry's own index and stable
    /// (entries below the top never move while the top exists).
    target: usize,
    /// Canonical Instance identity for **emitter-exclusion**: an InstanceEntry
    /// gets a fresh id at CALL; a ReferenceEntry copies its referent's id, so
    /// every stack entry of one Instance compares equal. Yield routing skips all
    /// entries whose `instance_id` matches the emitter's (spec §3 "skip ALL
    /// frames belonging to the emitting instance").
    instance_id: u64,
    /// The catch-list this entry offers to the subtree currently below it: a
    /// **snapshot** of its Instance's `yield_receiver_slot` YieldReceiver taken
    /// at this entry's most recent DOWNWARD CALL (a sorted, deduped key set;
    /// empty until/unless this entry has called down). Static for the in-flight
    /// sub-call — a frame cannot shrink its catch-set mid-flight to dodge a
    /// descendant's yield (spec §3 "frozen for the sub-call").
    catch_set: Vec<Key>,
    /// The gas meter that funds this entry's frame — computed ONCE at push time
    /// as `own_meter.or(parent_or_catcher.active)`: the frame's own
    /// `gas_slots[0]` → `Gas{meter_key}` if it declares one, else (loaned) it
    /// inherits its caller's active meter; a handler `ReferenceEntry` inherits the
    /// CATCHER's active meter. `None` = host-budgeted (the top frame and its
    /// loaned descendants). The loop reconciles `gas` to this on each iteration
    /// (see [`reconcile_active`]). Storing it (vs. a stack walk) is unambiguous in
    /// the presence of yields, where the entries between a handler Reference and
    /// its referent are a *suspended* subtree, NOT the running frame's ancestry.
    /// Aliasing falls out: a child naming the same meter as a live ancestor gets
    /// the SAME `active`, so no reconcile/swap — it shares the one balance.
    active: Option<Key>,
}

impl StackEntry {
    /// A fresh InstanceEntry at stack position `index` carrying a new
    /// `instance_id`. `target` is its own index (it runs its own frame); the
    /// catch-set is empty until its first downward CALL; `active` is stamped by
    /// the CALL site (`own_meter.or(parent.active)`).
    fn instance(frame: KernelFrame, index: usize, instance_id: u64) -> Self {
        StackEntry {
            kind: EntryKind::Instance(Box::new(frame)),
            target: index,
            instance_id,
            catch_set: Vec::new(),
            active: None,
        }
    }
}

/// Resolve a frame's own gas meter: read its Image's `gas_slots[0]`, look that
/// slot up in the frame's cnode, and decode the `Gas{meter_key}` handle there.
/// `None` if the Image declares no gas slot, the slot is empty, or it doesn't
/// hold a `Gas` handle (the frame then loans its caller's active meter).
fn resolve_frame_meter(frame: &KernelFrame) -> Option<Key> {
    let img_arc = CACHE.get(CapHashOrRef::Hash(frame.image_hash))?;
    let slot = match &*img_arc {
        Cap::Image(i) => i.gas_slots.first()?.clone(),
        _ => return None,
    };
    javm_cap::gas_meter_key(&read_instance_cap(frame, &slot)?)
}

/// Reconcile the threaded `gas` (the live balance of the running frame's active
/// meter) when the active meter changes between loop iterations: bank the OLD
/// active scope's balance, load the NEW scope's. `meters[k]` is authoritative for
/// every non-active meter; `host_budget` holds the banked host scope (the
/// host-budgeted top + its loaned descendants, active == `None`). Aliasing falls
/// out for free: a descendant naming the same meter has the SAME active meter, so
/// no swap happens and it shares the live balance — no double-spend.
fn reconcile_active(
    old: &Option<Key>,
    new: &Option<Key>,
    gas: &mut i64,
    host_budget: &mut i64,
    meters: &mut BTreeMap<Key, i64>,
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

/// The RPC's ROOT-scope remaining gas — what a break surfaces to the host (which
/// harvests it into the top-level meter). The live `gas` when the root scope is
/// the running frame's active meter, else the root scope's banked balance:
/// `meters[root]` for a metered root, or `host_budget` for a host-budgeted top.
fn root_remaining(
    root: &Option<Key>,
    current: &Option<Key>,
    gas: i64,
    host_budget: i64,
    meters: &BTreeMap<Key, i64>,
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

/// `&mut` to the [`KernelFrame`] the entry at `idx` runs, following a
/// ReferenceEntry to its referent InstanceEntry. The referent is always an
/// `Instance` (a Reference's `target` only ever names an InstanceEntry).
fn frame_at_mut(stack: &mut [StackEntry], idx: usize) -> &mut KernelFrame {
    let target = stack[idx].target;
    match &mut stack[target].kind {
        EntryKind::Instance(f) => f,
        EntryKind::Reference => unreachable!("ReferenceEntry.target must be an InstanceEntry"),
    }
}

/// Shared-borrow companion of [`frame_at_mut`].
fn frame_at(stack: &[StackEntry], idx: usize) -> &KernelFrame {
    let target = stack[idx].target;
    match &stack[target].kind {
        EntryKind::Instance(f) => f,
        EntryKind::Reference => unreachable!("ReferenceEntry.target must be an InstanceEntry"),
    }
}

/// Snapshot a frame's Instance `yield_receiver_slot` YieldReceiver as a sorted,
/// deduped catch-set — the keys it will catch from the subtree of its *next*
/// downward CALL (spec §3 per-CALL snapshot). Empty when the Image declares no
/// receiver slot, the slot is empty, or it doesn't hold a YieldReceiver
/// (catches nothing). Reads only; never mutates.
fn snapshot_catch_set(frame: &KernelFrame) -> Vec<Key> {
    let Some(img_arc) = CACHE.get(CapHashOrRef::Hash(frame.image_hash)) else {
        return Vec::new();
    };
    let slot = match &*img_arc {
        Cap::Image(i) => match &i.yield_receiver_slot {
            Some(s) => s.clone(),
            None => return Vec::new(),
        },
        _ => return Vec::new(),
    };
    match read_instance_cap(frame, &slot) {
        Some(inst) => {
            let mut keys = javm_cap::yield_receiver_keys(&inst).unwrap_or_default();
            keys.sort();
            keys.dedup();
            keys
        }
        None => Vec::new(),
    }
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
    let mut stack: Vec<StackEntry> = Vec::with_capacity(8);
    // Monotonic Instance identity for emitter-exclusion (§3). The top-level
    // invocation is instance 0; every CALL mints the next id.
    let mut next_iid: u64 = 0;
    stack.push(StackEntry::instance(top, 0, next_iid));
    next_iid += 1;
    // GAS MODEL (single reconciliation point). The threaded `gas` always holds
    // the LIVE balance of the running frame's ACTIVE meter — `active_meter(top)`,
    // the frame's stored `active` (its own meter, or its caller/catcher's).
    // `meters[k]` is authoritative for every non-active meter. At the top of each
    // iteration we reconcile: if the top's active meter changed since last
    // iteration, bank the old scope + load the new. Every CALL/HALT/yield/resume/
    // drop changes the top, so this one point catches them all — no per-transition
    // gas bookkeeping. The guest meter table is per-RPC (a block-spanning table is
    // the deferred lazy-load piece).
    let mut meters: BTreeMap<Key, i64> = BTreeMap::new();
    // The TOP frame's own meter (its `gas_slots[0]` → `Gas{root_meter_key}`, if
    // any) is the RPC's ROOT scope: stamp it like any frame and seed the table
    // from the host-supplied budget, so `set_gas_meter` on the root meter (a chain
    // self-harvesting, or a child aliasing the root) goes through the SAME table as
    // sub-meters. A top with NO gas slot is host-budgeted (`root_active == None`,
    // tracked in `host_budget`).
    let root_active = resolve_frame_meter(frame_at(&stack, 0));
    stack[0].active = root_active.clone();
    if let Some(k) = &root_active {
        meters.insert(k.clone(), initial_gas);
    }
    let mut gas = initial_gas;
    let mut host_budget = initial_gas;
    let mut current_active: Option<Key> = root_active.clone();

    let outcome = loop {
        let top_idx = stack.len() - 1;
        // Reconcile the active meter for the (possibly new) top frame.
        let new_active = active_meter(&stack, top_idx);
        reconcile_active(
            &current_active,
            &new_active,
            &mut gas,
            &mut host_budget,
            &mut meters,
        );
        current_active = new_active;
        // Phase 1: run one ring-3 entry on the top entry's frame (an
        // InstanceEntry runs its own frame; a ReferenceEntry runs its
        // referent's — the same Instance, sharing one PC/regs/mem).
        let info = {
            let frame = frame_at_mut(&mut stack, top_idx);
            run_one_entry(frame, gas)?
        };
        gas = info.gas_remaining;
        // Mirror the JIT's post-exit state back into the running frame.
        {
            let frame = frame_at_mut(&mut stack, top_idx);
            frame.regs = info.regs;
            frame.pc = info.pc;
        }

        // Phase 2: classify the exit. Borrow scopes are kept tight so
        // we can mutate `stack` (push/pop) inside each arm.
        match info.exit_reason {
            EXIT_HALT => {
                // Read the scratchpad head from the InstanceEntry that will drain
                // (its `target` reaches stack[0]) BEFORE it is popped — meaningful
                // only at the top-level HALT. `frame_at(top_idx)` resolves the
                // running frame whether the top is an InstanceEntry or a handler
                // ReferenceEntry.
                let head = if stack[top_idx].target == 0 {
                    read_scratchpad_head(frame_at(&stack, top_idx))
                } else {
                    [0u8; SCRATCHPAD_HEAD_LEN]
                };
                // A handler activation (ReferenceEntry) that HALTs without
                // resuming/dropping its yielder triggers the sub-tree-atomic
                // unwind; an ordinary InstanceEntry pops and reflects.
                let drained = if stack[top_idx].target != top_idx {
                    unwind_to_handler(&mut stack, top_idx, info.regs[7])
                } else {
                    pop_and_reflect(&mut stack, info.regs[7])
                };
                if drained {
                    break LoopOutcome {
                        exit_reason: info.exit_reason,
                        exit_arg: info.exit_arg,
                        return_value: info.regs[7],
                        gas_remaining: root_remaining(
                            &root_active,
                            &current_active,
                            gas,
                            host_budget,
                            &meters,
                        ),
                        scratchpad_head: head,
                    };
                }
            }
            EXIT_HOST_CALL | EXIT_ECALL => {
                // ecall block: charge its dynamic cost (check-before-charge)
                // BEFORE doing the work. The cost is the ecall floor PLUS, for an
                // in-kernel CALL (OP_HOST_CALL), the callee's call_frame_cost —
                // and these are charged ATOMICALLY as one `actual` (gas-cost.md
                // §3): a single gate, so an OOG leaves gas UNCHANGED and the
                // re-attempt from the ecall's OWN pc (info.pc is the next
                // instruction; custom-0 is 4 bytes) is clean. Splitting the gate
                // would double-charge the floor across an OOG+resume.
                let is_ecalli = info.exit_reason == EXIT_HOST_CALL;
                let ecall_cost = javm_exec::gas_const::ecall_dynamic_cost(is_ecalli) as i64;
                let op = if info.exit_reason == EXIT_HOST_CALL {
                    info.exit_arg
                } else {
                    info.regs[11] as u32
                };
                // The CALL frame-materialization cost (JIT compile + eager RO
                // page-in + setup base), computed statically from the callee
                // Image and billed to the caller; resolved BEFORE charging so it
                // joins the floor in one atomic gate. Depth-limit is a hard Err,
                // not an OOG.
                let frame_cost = if op == OP_HOST_CALL {
                    if stack.len() >= MAX_DEPTH {
                        return Err(ERR_DEPTH_LIMIT);
                    }
                    let parent = frame_at(&stack, top_idx);
                    host_call_frame_cost(parent)?
                } else {
                    0
                };
                let total_cost = ecall_cost + frame_cost;
                if gas < total_cost {
                    // A metered frame re-attempts THIS ecall after a kernel:oog
                    // topup; unmetered / uncaught → bubble EXIT_OOG.
                    if try_oog_yield(&mut stack, top_idx, info.pc.saturating_sub(4)) {
                        continue;
                    }
                    break LoopOutcome {
                        exit_reason: EXIT_OOG,
                        exit_arg: 0,
                        return_value: info.regs[7],
                        gas_remaining: root_remaining(
                            &root_active,
                            &current_active,
                            gas,
                            host_budget,
                            &meters,
                        ),
                        scratchpad_head: [0u8; SCRATCHPAD_HEAD_LEN],
                    };
                }
                gas -= total_cost;

                match op {
                    OP_REPLY => {
                        // Read the scratchpad head from the InstanceEntry that
                        // will drain before the pop (see EXIT_HALT).
                        let head = if stack[top_idx].target == 0 {
                            read_scratchpad_head(frame_at(&stack, top_idx))
                        } else {
                            [0u8; SCRATCHPAD_HEAD_LEN]
                        };
                        // A handler REPLYing without resuming/dropping → sub-tree
                        // unwind; an ordinary InstanceEntry pops and reflects.
                        let drained = if stack[top_idx].target != top_idx {
                            unwind_to_handler(&mut stack, top_idx, info.regs[7])
                        } else {
                            pop_and_reflect(&mut stack, info.regs[7])
                        };
                        if drained {
                            // Preserve the JIT exit shape so the host bench
                            // harness (which asserts `(reason=4, arg=0)` for the
                            // subsoil trampoline halt) doesn't trip.
                            break LoopOutcome {
                                exit_reason: info.exit_reason,
                                exit_arg: info.exit_arg,
                                return_value: info.regs[7],
                                gas_remaining: root_remaining(
                                    &root_active,
                                    &current_active,
                                    gas,
                                    host_budget,
                                    &meters,
                                ),
                                scratchpad_head: head,
                            };
                        }
                        // Stack still has frames; the parent picks up at the next
                        // iter with the child's φ[7] reflected.
                    }
                    OP_DERIVE_SPAWN => {
                        let trapped = {
                            let frame = frame_at_mut(&mut stack, top_idx);
                            dispatch_derive_spawn(frame)?
                        };
                        if trapped {
                            // Pinned dst → guest trap, mirroring the interpreter.
                            break LoopOutcome {
                                exit_reason: EXIT_TRAP,
                                exit_arg: 0,
                                return_value: info.regs[7],
                                gas_remaining: root_remaining(
                                    &root_active,
                                    &current_active,
                                    gas,
                                    host_budget,
                                    &meters,
                                ),
                                scratchpad_head: [0u8; SCRATCHPAD_HEAD_LEN],
                            };
                        }
                    }
                    OP_IMAGE_HASH_CHAIN => {
                        let trapped = {
                            let frame = frame_at_mut(&mut stack, top_idx);
                            dispatch_image_hash_chain(frame)?
                        };
                        if trapped {
                            // Pinned/empty dst or wrong src kind → guest trap.
                            break LoopOutcome {
                                exit_reason: EXIT_TRAP,
                                exit_arg: 0,
                                return_value: info.regs[7],
                                gas_remaining: root_remaining(
                                    &root_active,
                                    &current_active,
                                    gas,
                                    host_budget,
                                    &meters,
                                ),
                                scratchpad_head: [0u8; SCRATCHPAD_HEAD_LEN],
                            };
                        }
                    }
                    OP_HOST_YIELD => {
                        let outcome = {
                            let frame = frame_at_mut(&mut stack, top_idx);
                            dispatch_host_yield(frame, &mut meters, &mut gas, &current_active)?
                        };
                        match outcome {
                            // A kernel-root pure-cap syscall handled inline; the
                            // guest resumes at the next instruction (the
                            // "conceptually push a kernel frame but don't" path).
                            YieldOutcome::Inline => {}
                            // Bad/empty sender slot or pinned dst → guest trap.
                            YieldOutcome::Trap => {
                                break LoopOutcome {
                                    exit_reason: EXIT_TRAP,
                                    exit_arg: 0,
                                    return_value: info.regs[7],
                                    gas_remaining: root_remaining(
                                        &root_active,
                                        &current_active,
                                        gas,
                                        host_budget,
                                        &meters,
                                    ),
                                    scratchpad_head: [0u8; SCRATCHPAD_HEAD_LEN],
                                };
                            }
                            // Route `key` to an ancestor YieldReceiver (the
                            // payload is a copy of the emitted YieldSender). No
                            // catcher → the emitter faults ("unhandled yield_key").
                            YieldOutcome::Route { key, sender_slot } => {
                                let payload =
                                    read_instance_cap(frame_at(&stack, top_idx), &sender_slot);
                                if !route_yield(&mut stack, top_idx, &key, payload) {
                                    break LoopOutcome {
                                        exit_reason: EXIT_TRAP,
                                        exit_arg: ERR_YIELD_UNHANDLED,
                                        return_value: info.regs[7],
                                        gas_remaining: root_remaining(
                                            &root_active,
                                            &current_active,
                                            gas,
                                            host_budget,
                                            &meters,
                                        ),
                                        scratchpad_head: [0u8; SCRATCHPAD_HEAD_LEN],
                                    };
                                }
                            }
                        }
                    }
                    OP_CALL_RESUME => {
                        // Resume the Waiting yielder directly below this handler
                        // activation. The top MUST be a ReferenceEntry (we are
                        // running as a yield handler); an InstanceEntry top has no
                        // outstanding yield to resume → trap.
                        if stack[top_idx].target == top_idx {
                            break LoopOutcome {
                                exit_reason: EXIT_TRAP,
                                exit_arg: 0,
                                return_value: info.regs[7],
                                gas_remaining: root_remaining(
                                    &root_active,
                                    &current_active,
                                    gas,
                                    host_budget,
                                    &meters,
                                ),
                                scratchpad_head: [0u8; SCRATCHPAD_HEAD_LEN],
                            };
                        }
                        // Reflect the handler's scratchpad slot[0] (its response)
                        // to the yielder, pop the ReferenceEntry, and let the
                        // yielder become the running top (it continues at its
                        // post-yield PC next iteration). Gas is reconciled at the
                        // next loop top: the handler's active meter banks and the
                        // yielder's loads (picking up a kernel:oog topup).
                        let response = {
                            let handler = frame_at_mut(&mut stack, top_idx);
                            handler.cnode.take_key(&[javm_cap::abi::SCRATCHPAD_SLOT])
                        };
                        stack.pop();
                        let yielder_idx = stack.len() - 1;
                        let yielder = frame_at_mut(&mut stack, yielder_idx);
                        if let Some(cap) = response {
                            yielder
                                .cnode
                                .set_key(&[javm_cap::abi::SCRATCHPAD_SLOT], Some(cap));
                        }
                        // Spec §4: a resumed yielder sees φ[8] = Ok (the handler's
                        // response status) — its host_yield "returns" here.
                        yielder.regs[8] = STATUS_OK;
                    }
                    OP_DROP_PAUSED => {
                        // Give up on the Waiting yielder: discard the WHOLE caught
                        // subtree (the yielder + any intermediates a descendant
                        // routed past — same scope as a handler HALT, §10), but
                        // keep the handler running. The top must be a handler
                        // ReferenceEntry — an InstanceEntry top has no outstanding
                        // yield → trap.
                        if stack[top_idx].target == top_idx {
                            break LoopOutcome {
                                exit_reason: EXIT_TRAP,
                                exit_arg: 0,
                                return_value: info.regs[7],
                                gas_remaining: root_remaining(
                                    &root_active,
                                    &current_active,
                                    gas,
                                    host_budget,
                                    &meters,
                                ),
                                scratchpad_head: [0u8; SCRATCHPAD_HEAD_LEN],
                            };
                        }
                        // Truncate everything above the handler's InstanceEntry
                        // (the ReferenceEntry + the discarded subtree); the handler
                        // becomes a plain InstanceEntry again and continues at its
                        // post-drop pc. (Discarded metered frames were banked at
                        // route_yield, so the meter table stays consistent — gas is
                        // STM-exempt: a dropped subtree's spend is NOT refunded.)
                        // Using `target+1` (not `top_idx-1`) keeps subsequent
                        // CALL_RESUME/DROP_PAUSED sound — there is no longer a stale
                        // handler with a wedged intermediate below it.
                        let handler_inst = stack[top_idx].target;
                        stack.truncate(handler_inst + 1);
                    }
                    OP_HOST_CALL => {
                        // The ecall floor + this CALL's frame_cost were charged
                        // atomically at the top of the arm (check-before-charge,
                        // before `dispatch_host_call` moves any instance, so an
                        // OOG left the parent slot pristine). Charged in full on
                        // every CALL — compile/PT memoization is for *work*, never
                        // a gas discount — so gas is independent of the cache.
                        //
                        // Snapshot the caller's catch-set at this downward CALL
                        // (§3): the keys it will catch from the callee's whole
                        // subtree. Captured from the caller's CURRENT
                        // `yield_receiver_slot`, stored on the caller entry, and
                        // frozen for the sub-call — yield routing consults it.
                        let catch_set = {
                            let parent = frame_at(&stack, top_idx);
                            snapshot_catch_set(parent)
                        };
                        let mut child = {
                            let parent = frame_at_mut(&mut stack, top_idx);
                            dispatch_host_call(parent)?
                        };
                        // Scratchpad: MOVE the caller's slot[0] into the
                        // callee. `take_key` empties the parent (one owner);
                        // the callee's image-default slot[0], if any, is
                        // overwritten by the caller-provided scratchpad.
                        {
                            let parent = frame_at_mut(&mut stack, top_idx);
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
                        stack[top_idx].catch_set = catch_set;
                        let child_idx = stack.len();
                        stack.push(StackEntry::instance(child, child_idx, next_iid));
                        next_iid += 1;
                        // Stamp the child's active (funding) meter: its own
                        // `gas_slots[0]` meter, else (loaned) the caller's active
                        // meter. The loop-top reconcile then swaps `gas` only when
                        // the active meter actually changes — a child naming a NEW
                        // meter becomes the active scope (gas := meters[k],
                        // effective-0 if unfunded → OOG-routes on first debit); a
                        // child naming the SAME meter as a live ancestor keeps the
                        // shared scope (no swap, no double-spend).
                        let parent_active = stack[top_idx].active.clone();
                        stack[child_idx].active =
                            resolve_frame_meter(frame_at(&stack, child_idx)).or(parent_active);
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
                            gas_remaining: root_remaining(
                                &root_active,
                                &current_active,
                                gas,
                                host_budget,
                                &meters,
                            ),
                            scratchpad_head: [0u8; SCRATCHPAD_HEAD_LEN],
                        };
                    }
                }
            }
            _ => {
                // PageFault (3), Panic (1), OOG (2), Trap (7), …
                // An in-block OOG (the JIT's per-block gas gate) on a metered
                // frame re-attempts the SAME block after a kernel:oog topup —
                // `info.pc` is that block's bb_start (the gate is a pre-charge:
                // the block was not entered and no gas was charged). Unmetered /
                // uncaught OOG, and every other exit (fault/panic/trap), bubble
                // verbatim.
                if info.exit_reason == EXIT_OOG && try_oog_yield(&mut stack, top_idx, info.pc) {
                    continue;
                }
                break LoopOutcome {
                    exit_reason: info.exit_reason,
                    exit_arg: info.exit_arg,
                    return_value: info.regs[7],
                    gas_remaining: root_remaining(
                        &root_active,
                        &current_active,
                        gas,
                        host_budget,
                        &meters,
                    ),
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

/// Walk the kernel stack for a catcher of `key` (emitter-exclusion: skip every
/// frame whose instance matches the top emitter's) and, if one is found, suspend
/// the emitter and transfer control to the catcher as a yield handler: reflect
/// `payload` (a YieldSender / `Gas` cap copy) into the catcher's scratchpad
/// slot[0], flag φ[8] = YIELDED, and push a ReferenceEntry to the catcher (the
/// yielder stays Waiting below, resumed later by `CALL_RESUME`). Gas is NOT
/// handled here — the loop-top [`reconcile_active`] banks the emitter's active
/// meter and loads the catcher's on the next iteration.
///
/// Returns `true` if routed, `false` if no ancestor catches `key` — the caller
/// decides (fault the emitter for a user key, or bubble EXIT_OOG for kernel:oog).
fn route_yield(
    stack: &mut Vec<StackEntry>,
    top_idx: usize,
    key: &Key,
    payload: Option<InstanceCap>,
) -> bool {
    let emitter_iid = stack[top_idx].instance_id;
    let mut catcher = None;
    for j in (0..top_idx).rev() {
        if stack[j].instance_id == emitter_iid {
            continue;
        }
        if stack[j].catch_set.binary_search(key).is_ok() {
            catcher = Some(j);
            break;
        }
    }
    let Some(j) = catcher else {
        return false;
    };
    let target = stack[j].target;
    let recv_iid = stack[j].instance_id;
    // The handler runs the catcher's frame, so it is funded by the catcher's
    // active meter (NOT the emitter's).
    let recv_active = stack[j].active.clone();
    {
        let catcher_frame = frame_at_mut(stack, j);
        if let Some(inst) = payload {
            catcher_frame.cnode.set_key(
                &[javm_cap::abi::SCRATCHPAD_SLOT],
                Some(CapHashOrRef::Owned(CachedCap::boxed(Cap::Instance(inst)))),
            );
        }
        catcher_frame.regs[8] = STATUS_YIELDED;
    }
    stack.push(StackEntry {
        kind: EntryKind::Reference,
        target,
        instance_id: recv_iid,
        catch_set: Vec::new(),
        active: recv_active,
    });
    true
}

/// The gas meter funding the frame run by the entry at `idx` — the precomputed
/// [`StackEntry::active`] (own meter, or inherited from the caller/catcher at
/// push). O(1), unambiguous under yields.
fn active_meter(stack: &[StackEntry], idx: usize) -> Option<Key> {
    stack[idx].active.clone()
}

/// On gas exhaustion, inject a routed `kernel:oog` yield (payload =
/// `Gas{meter_key}` of the meter funding the depleted pool) so a registered
/// receiver (the chain) can top up the meter and `CALL_RESUME` — the frame then
/// re-runs from `reattempt_pc` (a bb_start: the failing block's start, or the
/// ecall's own pc). The depleted pool belongs to the ACTIVE meter (nearest
/// metered ancestor), which may live below a loaned frame or on a handler
/// ReferenceEntry's referent — not necessarily on the top entry. Returns `true`
/// if routed; `false` if the pool is host-budgeted (no metered frame) or no
/// receiver caught `kernel:oog` (the caller bubbles EXIT_OOG — host-stub root
/// catch).
fn try_oog_yield(stack: &mut Vec<StackEntry>, top_idx: usize, reattempt_pc: u32) -> bool {
    let Some(meter) = active_meter(stack, top_idx) else {
        return false;
    };
    frame_at_mut(stack, top_idx).pc = reattempt_pc;
    let oog_key = Key::from(&javm_cap::yield_cap::YK_OOG[..]);
    let payload = Some(javm_cap::gas_handle(&meter));
    route_yield(stack, top_idx, &oog_key, payload)
}

/// A yield handler (a ReferenceEntry activation) HALTed/REPLYed without resuming
/// or dropping its yielder. Per sub-tree atomicity (spec §10) the handler
/// Instance's HALT commits/discards its WHOLE caught subtree — the abandoned
/// yielder plus any intermediate frames a descendant's yield routed past — and
/// reflects to the handler Instance's own caller. Discards every entry above the
/// handler's InstanceEntry (their frames, banked meters kept), then reflects that
/// InstanceEntry's HALT exactly as a normal pop. Returns `true` when the stack
/// drains.
fn unwind_to_handler(stack: &mut Vec<StackEntry>, top_idx: usize, return_value: u64) -> bool {
    let h_inst = stack[top_idx].target;
    // Drop the handler activation + the abandoned subtree above the handler's
    // own frame; the handler's InstanceEntry becomes the top. Gas is reconciled
    // at the next loop top (the discarded metered frames bank naturally as the
    // active meter changes back to the handler's).
    stack.truncate(h_inst + 1);
    pop_and_reflect(stack, return_value)
}

/// Pop the top frame; if a parent exists, reflect the popped child's
/// `return_value` into the parent's φ[7], move its scratchpad (slot[0]) back,
/// and — when the child was a moved-in `Owned` sub-VM — reconstruct its
/// `InstanceCap` from the frame's final mem/regs/pc (+ carried identity) and
/// move it back into the parent's origin slot (the single-owner round trip).
/// Returns `true` when the stack has been drained (the RPC caller hands a
/// result back to the host). Gas is NOT touched here — the loop-top
/// [`reconcile_active`] banks the popped frame's meter and loads the parent's on
/// the next iteration.
fn pop_and_reflect(stack: &mut Vec<StackEntry>, return_value: u64) -> bool {
    // A HALT/REPLY only pops an InstanceEntry — a ReferenceEntry (handler
    // activation) is removed by CALL_RESUME, and a handler that HALTs without
    // resuming is caught by the EXIT_HALT/OP_REPLY guards before this point.
    let mut popped = match stack.pop().expect("non-empty").kind {
        EntryKind::Instance(boxed) => *boxed,
        EntryKind::Reference => unreachable!("pop_and_reflect on a ReferenceEntry"),
    };

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

    // The parent is the entry directly below; follow a ReferenceEntry to the
    // referent frame so a child of a handler activation reflects into the
    // handler's Instance (which spawned/called it).
    let parent_idx = stack.len() - 1;
    let parent = frame_at_mut(stack, parent_idx);
    parent.regs[7] = return_value;
    // Spec §4: the caller's φ[8] reflects the termination status — Ok for a normal
    // HALT/REPLY return (resetting any stale YIELDED a prior catch left there).
    parent.regs[8] = STATUS_OK;
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

/// Read an owned `InstanceCap` from a frame cnode slot — a `Hash` resolves
/// through the blob cache, an inline `Owned` reads its boxed cap. `None` if the
/// slot is empty or doesn't hold a `Cap::Instance`. Clones, but the
/// kernel-assisted handles this is used for (YieldSender / YieldReceiver) are
/// tiny (a few registers + a small mem).
fn read_instance_cap(frame: &KernelFrame, slot: &Key) -> Option<InstanceCap> {
    match frame.cnode.peek_key(slot.as_slice())? {
        CapHashOrRef::Hash(h) => {
            let arc = CACHE.get(CapHashOrRef::Hash(*h))?;
            match &*arc {
                Cap::Instance(i) => Some(i.clone()),
                _ => None,
            }
        }
        CapHashOrRef::Owned(cc) => match &cc.cap {
            Cap::Instance(i) => Some(i.clone()),
            _ => None,
        },
    }
}

/// Outcome of a `host_yield`, classified by [`dispatch_host_yield`] for the
/// call loop to act on.
enum YieldOutcome {
    /// A `kernel:*` pure-cap syscall the kernel handled inline as the implicit
    /// root receiver (no stack push); the guest resumes at the next instruction.
    Inline,
    /// The operand was malformed (bad/empty sender, pinned dst, wrong cap kind)
    /// → trap the emitter.
    Trap,
    /// Not handled inline → route `key` to an ancestor YieldReceiver. `key` is
    /// the YieldSender's yield_key; `sender_slot` names the YieldSender so the
    /// loop can reflect a copy of it to the catcher as the yield payload.
    Route { key: Key, sender_slot: Key },
}

/// `host_yield(sender_slot=φ[7], …)`. Reads the `YieldSender` at `sender_slot`
/// and classifies the yield: a `kernel:*` pure-cap syscall (mint_yield,
/// merge_yield_receiver, mint_gas, mint_quota) is performed INLINE as the
/// implicit root receiver ([`YieldOutcome::Inline`]); a malformed operand traps
/// ([`YieldOutcome::Trap`]); anything else — a user key, or a `kernel:*` key not
/// handled inline — is routed to an ancestor YieldReceiver by the call loop
/// ([`YieldOutcome::Route`]). `Err(code)` is reserved for an internal cnode
/// failure (loud, not a guest-visible trap).
///
/// V1 single-byte ABI: all slot operands are the low byte of their φ register.
/// `kernel:mint_yield`: φ[8] = new yield_key byte, φ[9] = YieldSender dst,
/// φ[10] = YieldReceiver dst. `kernel:merge_yield_receiver`: φ[8] = receiver A
/// slot, φ[9] = receiver B slot, φ[10] = dst slot. `kernel:mint_gas` /
/// `kernel:mint_quota`: φ[8] = meter_key / quota_key byte, φ[9] = handle dst.
/// `kernel:set_gas_meter`: φ[8] = meter_key byte, φ[9] = value; returns the
/// previous balance in φ[7].
fn dispatch_host_yield(
    frame: &mut KernelFrame,
    meters: &mut BTreeMap<Key, i64>,
    gas: &mut i64,
    active: &Option<Key>,
) -> Result<YieldOutcome, u32> {
    let sender_slot = Key::from((frame.regs[7] & 0xFF) as u8);
    let yield_key = match read_instance_cap(frame, &sender_slot) {
        Some(inst) => match javm_cap::yield_sender_key(&inst) {
            Some(k) => k,
            None => return Ok(YieldOutcome::Trap), // not a YieldSender → trap
        },
        None => return Ok(YieldOutcome::Trap), // empty / non-Instance sender → trap
    };

    // User keys (and any kernel:* key not wired inline below) route to an
    // ancestor YieldReceiver; the loop walks the stack and suspends the emitter.
    if !javm_cap::is_kernel_yield_key(&yield_key) {
        return Ok(YieldOutcome::Route {
            key: yield_key,
            sender_slot,
        });
    }
    let k = yield_key.as_slice();

    if k == javm_cap::yield_cap::YK_MINT_YIELD {
        let new_key = Key::from((frame.regs[8] & 0xFF) as u8);
        let sender_dst = Key::from((frame.regs[9] & 0xFF) as u8);
        let receiver_dst = Key::from((frame.regs[10] & 0xFF) as u8);
        if frame.pinned.binary_search(&sender_dst).is_ok()
            || frame.pinned.binary_search(&receiver_dst).is_ok()
        {
            return Ok(YieldOutcome::Trap);
        }
        let sender = Cap::Instance(javm_cap::yield_sender(&new_key));
        let receiver = Cap::Instance(javm_cap::yield_receiver(&[new_key]));
        frame
            .cnode
            .set(
                &sender_dst,
                Some(CapHashOrRef::Owned(CachedCap::boxed(sender))),
            )
            .map_err(|_| ERR_DERIVE_SLOT_OOB)?;
        frame
            .cnode
            .set(
                &receiver_dst,
                Some(CapHashOrRef::Owned(CachedCap::boxed(receiver))),
            )
            .map_err(|_| ERR_DERIVE_SLOT_OOB)?;
        Ok(YieldOutcome::Inline)
    } else if k == javm_cap::yield_cap::YK_MERGE_YIELD_RECEIVER {
        let a_slot = Key::from((frame.regs[8] & 0xFF) as u8);
        let b_slot = Key::from((frame.regs[9] & 0xFF) as u8);
        let dst = Key::from((frame.regs[10] & 0xFF) as u8);
        if frame.pinned.binary_search(&dst).is_ok() {
            return Ok(YieldOutcome::Trap);
        }
        let a = read_instance_cap(frame, &a_slot).ok_or(ERR_YIELD_BAD_SENDER)?;
        let b = read_instance_cap(frame, &b_slot).ok_or(ERR_YIELD_BAD_SENDER)?;
        let merged = match javm_cap::merge_yield_receivers(&a, &b) {
            Some(m) => m,
            None => return Ok(YieldOutcome::Trap), // operands not both receivers
        };
        frame
            .cnode
            .set(
                &dst,
                Some(CapHashOrRef::Owned(CachedCap::boxed(Cap::Instance(merged)))),
            )
            .map_err(|_| ERR_DERIVE_SLOT_OOB)?;
        Ok(YieldOutcome::Inline)
    } else if k == javm_cap::yield_cap::YK_MINT_GAS {
        // kernel:mint_gas(φ8=meter_key byte, φ9=dst): mint a Gas{meter_key}
        // handle (pure-cap, like mint_yield). The meter mapping it indexes is
        // managed separately (set_gas_meter / the host meter table).
        mint_unit_handle(
            frame,
            javm_cap::gas_handle(&Key::from((frame.regs[8] & 0xFF) as u8)),
        )
    } else if k == javm_cap::yield_cap::YK_MINT_QUOTA {
        // kernel:mint_quota(φ8=quota_key byte, φ9=dst): the storage-quota
        // analogue of mint_gas.
        mint_unit_handle(
            frame,
            javm_cap::quota_handle(&Key::from((frame.regs[8] & 0xFF) as u8)),
        )
    } else if k == javm_cap::yield_cap::YK_SET_GAS_METER {
        // kernel:set_gas_meter(φ8=meter_key byte, φ9=value) -> previous (φ7).
        // Atomically set the meter's balance, returning the previous — the chain's
        // topup/harvest primitive. If `meter_key` is the CURRENTLY ACTIVE meter
        // (e.g. a frame topping up the pool it itself loans from), the live `gas`
        // is authoritative, so set it directly and return its value; otherwise the
        // table entry is authoritative.
        let meter_key = Key::from((frame.regs[8] & 0xFF) as u8);
        let value = frame.regs[9] as i64;
        let previous = if active.as_ref() == Some(&meter_key) {
            let p = *gas;
            *gas = value;
            p
        } else {
            meters.insert(meter_key, value).unwrap_or(0)
        };
        frame.regs[7] = previous as u64;
        Ok(YieldOutcome::Inline)
    } else {
        // A kernel:* key not wired inline (oog / storage_exhausted / …): route it.
        // The kernel root catches kernel:* keys the chain registered in its
        // YieldReceiver (e.g. kernel:oog); an unregistered key finds no catcher
        // and the emitter faults.
        Ok(YieldOutcome::Route {
            key: yield_key,
            sender_slot,
        })
    }
}

/// Place a freshly-minted kernel unit handle (`Gas` / `Quota`) into the dst slot
/// named by φ[9] (V1 single-byte ABI). Traps on a pinned dst. Shared by
/// `kernel:mint_gas` / `kernel:mint_quota`.
fn mint_unit_handle(frame: &mut KernelFrame, handle: InstanceCap) -> Result<YieldOutcome, u32> {
    let dst = Key::from((frame.regs[9] & 0xFF) as u8);
    if frame.pinned.binary_search(&dst).is_ok() {
        return Ok(YieldOutcome::Trap);
    }
    frame
        .cnode
        .set(
            &dst,
            Some(CapHashOrRef::Owned(CachedCap::boxed(Cap::Instance(handle)))),
        )
        .map_err(|_| ERR_DERIVE_SLOT_OOB)?;
    Ok(YieldOutcome::Inline)
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
    let (image_hash, image_hash_chain, mem, root_cnode) = match &*arc {
        Cap::Instance(i) => (
            i.image_hash,
            i.image_hash_chain,
            i.mem.clone(),
            root_cnode_hash(&i.root_cnode),
        ),
        _ => return Err(ERR_INSTANCE_KIND),
    };
    build_frame_inner(
        image_hash,
        image_hash_chain,
        None,
        endpoint_idx,
        args,
        mem,
        root_cnode,
    )
}

/// The root-cnode content hash to seed a frame from, or `None` when there is no
/// persistent cnode to load: an inline `Owned` root cnode (mid-mutation — not a
/// published instance) or the all-zero spawn-time placeholder a `derive_spawn`'d
/// sub-VM carries (see [`dispatch_derive_spawn`] / [`pop_and_reflect`]).
fn root_cnode_hash(root_cnode: &CapHashOrRef) -> Option<CapHash> {
    match root_cnode {
        CapHashOrRef::Hash(h) if *h != [0u8; 32] => Some(*h),
        _ => None,
    }
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
        mem,
        root_cnode,
        ..
    } = inst;
    build_frame_inner(
        image_hash,
        image_hash_chain,
        Some(origin_slot),
        endpoint_idx,
        args,
        mem,
        root_cnode_hash(&root_cnode),
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
    mem: DataCap,
    root_cnode: Option<CapHash>,
) -> Result<KernelFrame, u32> {
    let img_arc = CACHE
        .get(CapHashOrRef::Hash(image_hash))
        .ok_or(ERR_IMAGE_NOT_FOUND)?;
    let img = match &*img_arc {
        Cap::Image(i) => i,
        _ => return Err(ERR_IMAGE_KIND),
    };

    // V1 single-byte ABI: the endpoint selector is the low byte of
    // `endpoint_idx`, looked up as a Key in the sparse endpoint list. An absent
    // key is an undefined endpoint.
    let target = Key::from((endpoint_idx & 0xFF) as u8);
    let ep = img
        .endpoints
        .iter()
        .find(|(k, _)| *k == target)
        .map(|(_, ep)| ep)
        .ok_or(ERR_ENDPOINT_OOB)?;

    // Spec CALL convention (_index.md §4): φ = endpoint.initial_regs, then
    // φ[7..11] = args, all other φ = 0. A CALL is a fresh per-invocation register
    // file — the Instance's SAVED regs do NOT seed it (a sub-VM persists across
    // CALLs via its memory/CoW overlay, not its registers). CALL_RESUME, which
    // does restore saved regs, runs the live Waiting frame in place and never
    // reaches this builder.
    let mut regs = ep.initial_regs;
    for (i, v) in args.iter().enumerate() {
        regs[7 + i] = *v;
    }
    let pc = ep.entry_pc as u32;

    let mut cnode: CNodeCap<Box<CachedCap>> = CNodeCap::new();
    // Seed the persistent state from the instance's root cnode first. This is
    // how arbitrary caps — `Cap::Instance` (YieldSenders, sub-VM handles) that
    // can't be pinned, plus carried-over mutable slots — flow to the guest. A
    // published root cnode holds only `Hash` entries; an inline `Owned` (in
    // principle) deep-clones into the frame's `CachedCap` form. Entries are
    // copied by raw radix key (the cnode is keyed by `Hasher(Key)`, so the
    // logical key isn't recoverable to re-`set`).
    if let Some(rc) = root_cnode {
        let rc_arc = CACHE
            .get(CapHashOrRef::Hash(rc))
            .ok_or(ERR_INSTANCE_NOT_FOUND)?;
        let Cap::CNode(cn) = &*rc_arc else {
            return Err(ERR_INSTANCE_KIND);
        };
        for (k, mo) in cn.slots.iter() {
            if let MissingOr::Materialized(t) = mo {
                let conv = match t {
                    CapHashOrRef::Hash(h) => CapHashOrRef::Hash(*h),
                    CapHashOrRef::Owned(b) => CapHashOrRef::Owned(CachedCap::boxed((**b).clone())),
                };
                cnode.slots.insert(*k, MissingOr::Materialized(conv));
            }
        }
    }
    // Image pinned slots overlay the root-cnode state (image-authoritative:
    // pinned content is swapped as a unit at set_image), then initial slots
    // fill only still-empty slots (bootstrap-only).
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
