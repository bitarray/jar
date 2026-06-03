//! Shared runners for the bench harness (`benches/bench.rs`) and the
//! sub-VM benches (`benches/sub_vm_recurse.rs`,
//! `benches/sub_vm_data_recurse.rs`).
//!
//! The bench measures the full per-invocation lifecycle:
//!   * `Nub::put_cap_with_hash` for each cap the invocation requires
//!     (Data blobs the Image references, the Image itself, the empty
//!     root cnode, the Instance). Each put is a single
//!     `BTreeMap::get + refcount.fetch_add(1)` after warm-up — i.e. a
//!     few tens of nanoseconds per cap.
//!   * `Nub::invoke_cached(instance_hash, endpoint, args, gas)`.
//!
//! - `run_interpreter` — `Nub::new_local()` drives the byte-PVM
//!   interpreter (`javm-exec`) in-process.
//! - `run_recompiler` — a long-lived `Nub::new_hyperlight()` sandbox
//!   (cached in a `OnceLock`) drives the in-kernel JIT path through
//!   the same `invoke_cached` API.
//!
//! `BuiltCaps` holds the pre-built `Cap` graph + its precomputed
//! hashes. Construction happens once per workload at bench warm-up via
//! [`BuiltCaps::for_image`]; the iter loop reuses the resulting handles.
//!
//! Linux x86-64 only — `nub` pulls the Hyperlight host stack
//! unconditionally.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use criterion::{BenchmarkId, Criterion, Throughput};
use javm_cap::NUM_REGS;
use javm_cap::image::{Image, PinnedCap};
use javm_cap::slot::Key;
use javm_cap::{Cap, CapHash};
use nub::{InvocationResult, Nub, SCRATCHPAD_HEAD_LEN};
use std::sync::{Mutex, OnceLock};

/// HostCall(0) — the trampoline halt all bench programs end on
/// (`ecalli 0`). Both backends surface it as `exit_reason=4,
/// exit_arg=0`.
const EXIT_HOSTCALL: u32 = 4;

/// Default initial-gas budget for the bench.
pub const INITIAL_GAS: u64 = 100_000_000_000;

/// Pre-built `Cap` graph for one (image, endpoint) bench cell.
///
/// Built once at warm-up via [`Self::for_image`]; the iter loop puts each
/// cap with its precomputed hash and invokes. The first iter pays the
/// full deep-clone cost (caps move into the Nub's cache allocator);
/// subsequent iters hit the idempotent fast path (refcount bump only).
pub struct BuiltCaps {
    /// Cap::Data blobs for each pinned-slot Data + each initial-slot Data,
    /// paired with their content hashes.
    pub data_caps: Vec<(CapHash, Cap)>,
    /// Cap::Image referencing the data_caps above by hash.
    pub image_cap: Cap,
    pub image_hash: CapHash,
    /// Empty Cap::CNode (V1 has no per-instance slot bindings).
    pub cnode_cap: Cap,
    pub cnode_hash: CapHash,
    /// Cap::Instance with the bench's flat (ro, rw) overlay layout.
    pub instance_cap: Cap,
    pub instance_hash: CapHash,
    pub endpoint_idx: u8,
}

impl BuiltCaps {
    /// Build the full `Cap` graph for `image[endpoint_idx]`. All
    /// hashes are precomputed once here.
    pub fn for_image(image: &Image, endpoint_idx: u8) -> Self {
        let endpoint = image
            .endpoints
            .get(&endpoint_idx)
            .unwrap_or_else(|| panic!("endpoint {endpoint_idx} not declared"));

        // 1. Build a Cap::Data per non-empty pinned/initial slot. Track
        //    each slot's resolved CapHash so the Image can reference them.
        let mut data_caps: Vec<(CapHash, Cap)> = Vec::new();
        let mut pinned_hashes: Vec<(Key, CapHash)> = Vec::new();
        let mut initial_hashes: Vec<(Key, CapHash)> = Vec::new();

        for (slot, pinned) in &image.pinned_slots {
            let (h, cap) = match pinned {
                PinnedCap::Data { content, size } => {
                    let cap = Cap::data_inline_with_size(content, *size);
                    let h = ssz::hash_tree_root(&cap);
                    (h, Some(cap))
                }
                PinnedCap::Image { content_hash } => {
                    // Sub-Image hash assumed already-published; carry it
                    // through to the image_with_slots builder.
                    (*content_hash, None)
                }
            };
            pinned_hashes.push((slot.clone(), h));
            if let Some(c) = cap {
                data_caps.push((h, c));
            }
        }
        for (slot, init) in &image.initial_slots {
            let cap = Cap::data_inline_with_size(&init.content, init.size);
            let h = ssz::hash_tree_root(&cap);
            initial_hashes.push((slot.clone(), h));
            data_caps.push((h, cap));
        }

        // 2. Build the Cap::Image referencing the data caps by hash.
        let image_cap = Cap::image_with_slots(image, &pinned_hashes, &initial_hashes)
            .expect("image_with_slots");
        let image_hash = ssz::hash_tree_root(&image_cap);

        // 3. Empty root CNode (V1: no per-instance slot bindings).
        let cnode_cap = Cap::empty_cnode();
        let cnode_hash = ssz::hash_tree_root(&cnode_cap);

        // 4. Build the Instance with the bench's memory image.
        let mem = image.instance_mem_backing();

        let mut regs = [0u64; NUM_REGS];
        for (&i, &v) in &endpoint.initial_regs {
            if let Some(slot) = regs.get_mut(i as usize) {
                *slot = v;
            }
        }

        let instance_cap =
            Cap::instance_with_mem([0u8; 32], image_hash, cnode_hash, mem, regs, 0, 0);
        let instance_hash = ssz::hash_tree_root(&instance_cap);

        BuiltCaps {
            data_caps,
            image_cap,
            image_hash,
            cnode_cap,
            cnode_hash,
            instance_cap,
            instance_hash,
            endpoint_idx,
        }
    }

    /// Put every cap into `nub`'s cache via `put_cap_with_hash`.
    /// Idempotent re-puts after the first call are refcount bumps only.
    pub fn put_into(&self, nub: &mut Nub) {
        for (h, cap) in &self.data_caps {
            nub.put_cap_with_hash(*h, cap)
                .unwrap_or_else(|e| panic!("put_cap_with_hash data: {e}"));
        }
        nub.put_cap_with_hash(self.image_hash, &self.image_cap)
            .unwrap_or_else(|e| panic!("put_cap_with_hash image: {e}"));
        nub.put_cap_with_hash(self.cnode_hash, &self.cnode_cap)
            .unwrap_or_else(|e| panic!("put_cap_with_hash cnode: {e}"));
        nub.put_cap_with_hash(self.instance_hash, &self.instance_cap)
            .unwrap_or_else(|e| panic!("put_cap_with_hash instance: {e}"));
    }
}

/// RAII guard around the singleton Hyperlight Nub. Derefs to `&mut Nub`.
///
/// The sandbox is **never** torn down and rebuilt — doing so (the former
/// `reset_nub_hyperlight`) re-`mmap`'d the snapshot at the same fixed guest VA
/// while the prior KVM memslot/mapping could still alias it, which trampled
/// host heap (the "went past end of probe sequence" corruption). One long-lived
/// sandbox runs thousands of distinct invocations cleanly, so the guard simply
/// holds the singleton.
pub struct NubGuard {
    inner: std::sync::MutexGuard<'static, Nub>,
}

impl std::ops::Deref for NubGuard {
    type Target = Nub;
    fn deref(&self) -> &Nub {
        &self.inner
    }
}

impl std::ops::DerefMut for NubGuard {
    fn deref_mut(&mut self) -> &mut Nub {
        &mut self.inner
    }
}

/// Bench-side accessor for the long-lived Hyperlight Nub. Returned
/// guard holds the singleton mutex for the duration of one
/// criterion `iter_batched` step (setup + routine).
pub fn nub_hyperlight_lock() -> NubGuard {
    NubGuard {
        inner: nub_hyperlight().lock().expect("nub mutex"),
    }
}

/// Bench helper: drive one invocation through an already-locked Nub.
/// Used inside `iter_batched`'s routine closure so the timed body is
/// just the host-call round-trip + JIT path (no mutex acquire, no
/// cap publish, no eviction).
pub fn invoke(nub: &mut Nub, built: &BuiltCaps) -> (u64, u64) {
    let result = nub
        .invoke_cached(built.instance_hash, built.endpoint_idx, [0; 4], INITIAL_GAS)
        .unwrap_or_else(|e| panic!("invoke_cached: {e}"));
    finish(&result)
}

/// Drive `built[endpoint_idx]` through the PVM2 (RISC-V) interpreter via
/// a fresh `Nub::new_local()` (the Local backend has no per-invocation
/// state, so a fresh Nub each call is fine — and matches the chain's
/// per-event allocation model).
pub fn run_interpreter(built: &BuiltCaps) -> (u64, u64) {
    let mut nub = Nub::new_local();
    built.put_into(&mut nub);
    let result = nub
        .invoke_cached(built.instance_hash, built.endpoint_idx, [0; 4], INITIAL_GAS)
        .unwrap_or_else(|e| panic!("interpreter invoke_cached: {e}"));
    finish(&result)
}

/// Drive `built[endpoint_idx]` through the in-kernel JIT via the long-
/// lived Hyperlight `Nub`. **Warm-cache** path: subsequent calls with
/// the same Image hit the JIT compile cache. Useful for measuring
/// steady-state execute throughput in isolation.
pub fn run_recompiler(built: &BuiltCaps) -> (u64, u64) {
    let mut nub = nub_hyperlight_lock();
    built.put_into(&mut nub);
    let result = nub
        .invoke_cached(built.instance_hash, built.endpoint_idx, [0; 4], INITIAL_GAS)
        .unwrap_or_else(|e| panic!("recompiler invoke_cached: {e}"));
    finish(&result)
}

fn finish(result: &InvocationResult) -> (u64, u64) {
    assert_eq!(
        result.exit_reason, EXIT_HOSTCALL,
        "unexpected exit_reason {} (exit_arg={})",
        result.exit_reason, result.exit_arg,
    );
    assert_eq!(
        result.exit_arg, 0,
        "expected HostCall(0) trampoline halt, got HostCall({})",
        result.exit_arg,
    );
    let gas_used = INITIAL_GAS.saturating_sub(result.gas_remaining);
    (result.return_value, gas_used)
}

/// `exit_reason` reported when a recompiler run aborts the VM — a guest
/// CPU fault delivered as an unhandled IDT vector (e.g. `#DE` from `idiv`
/// on INT_MIN/-1) surfaces as a host `Err(GuestAborted)`, not an
/// [`InvocationResult`]. Distinct from every real PVM2 exit reason (0..=7).
pub const ABORT_SENTINEL: u32 = u32::MAX;

/// Raw invocation outcome for differential testing — the four
/// [`InvocationResult`] fields with **no clean-halt assertion**.
///
/// `run_interpreter`/`run_recompiler` assert a clean `HostCall(0)` halt
/// (via `finish`) and panic otherwise — correct for benches, wrong for a
/// differential harness that must *observe* a divergent exit. These raw
/// variants surface whatever happened, with `exit_reason = ABORT_SENTINEL`
/// for the recompiler's guest-abort path.
///
/// `gas_used` is `INITIAL_GAS - gas_remaining`; on an abort it is 0 (no
/// `InvocationResult` was produced).
///
/// `scratchpad_head` is the running Instance's scratchpad (slot[0]) region head
/// — the lossless, model-conformant result readback that supersedes the former
/// x10 fold. The fuzz differential compares it across engines and against the
/// oracle gold (see `javm_fuzz::replay`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawRun {
    pub exit_reason: u32,
    pub exit_arg: u32,
    pub return_value: u64,
    pub gas_used: u64,
    pub scratchpad_head: [u8; SCRATCHPAD_HEAD_LEN],
}

impl RawRun {
    fn from_result(r: &InvocationResult) -> Self {
        RawRun {
            exit_reason: r.exit_reason,
            exit_arg: r.exit_arg,
            return_value: r.return_value,
            gas_used: INITIAL_GAS.saturating_sub(r.gas_remaining),
            scratchpad_head: r.scratchpad_head,
        }
    }

    fn aborted() -> Self {
        RawRun {
            exit_reason: ABORT_SENTINEL,
            exit_arg: 0,
            return_value: 0,
            gas_used: 0,
            scratchpad_head: [0u8; SCRATCHPAD_HEAD_LEN],
        }
    }
}

/// Interpreter run with no clean-halt assertion (cf. [`run_interpreter`]).
/// The Local backend never aborts the host, so `invoke_cached` returns
/// `Ok` in practice; an `Err` is still mapped to the abort sentinel for
/// symmetry with the recompiler.
pub fn run_interpreter_raw(built: &BuiltCaps) -> RawRun {
    let mut nub = Nub::new_local();
    built.put_into(&mut nub);
    match nub.invoke_cached(built.instance_hash, built.endpoint_idx, [0; 4], INITIAL_GAS) {
        Ok(r) => RawRun::from_result(&r),
        Err(_) => RawRun::aborted(),
    }
}

/// Recompiler run with no clean-halt assertion (cf. [`run_recompiler`]).
///
/// On a guest abort (e.g. `#DE`), `invoke_cached` returns `Err` and the
/// sandbox is poisoned; we report [`ABORT_SENTINEL`] and do **not** rebuild it
/// (rebuilding was the source of the host-heap corruption). A caller that hits
/// an abort should stop — every subsequent invoke on the poisoned sandbox also
/// returns `Err` → `ABORT_SENTINEL`. (For valid PVM2 code no abort occurs, so
/// long differential sweeps run uninterrupted.)
pub fn run_recompiler_raw(built: &BuiltCaps) -> RawRun {
    let mut nub = nub_hyperlight_lock();
    built.put_into(&mut nub);
    match nub.invoke_cached(built.instance_hash, built.endpoint_idx, [0; 4], INITIAL_GAS) {
        Ok(r) => RawRun::from_result(&r),
        Err(_) => RawRun::aborted(),
    }
}

/// The long-lived Hyperlight sandbox, shared across every invocation. Built
/// once and never torn down (see [`NubGuard`] for why a rebuild corrupts).
fn nub_hyperlight() -> &'static Mutex<Nub> {
    static NUB: OnceLock<Mutex<Nub>> = OnceLock::new();
    NUB.get_or_init(|| Mutex::new(Nub::new_hyperlight().expect("Hyperlight sandbox")))
}

// ============================================================================
// Sub-VM recurse benches (shared driver)
// ============================================================================
//
// `benches/sub_vm_recurse.rs` and `benches/sub_vm_data_recurse.rs` differ
// only in which guest blob they ship and their label, so the whole build +
// invoke + criterion driver lives here and each bench file is a one-liner.

/// cnode slot holding the recurse Image (each level inherits it from its
/// parent — see `dispatch_host_call` in `nub-arch-x86::call_loop`).
const SLOT_IMAGE_RECURSE: u32 = 3;

/// Top-of-recursion `Cap::Instance` published for a sub-VM bench.
pub struct SubVmTop {
    pub top_instance: CapHash,
    pub image_hash: CapHash,
}

/// Build + publish (once) the recurse Image, its cnode, and the top
/// Instance into `nub` from the SSZ-encoded Image `blob`. Returns the
/// top instance hash so the bench loop can invoke it directly.
pub fn build_sub_vm_top(nub: &mut Nub, blob: &[u8]) -> SubVmTop {
    use javm_cap::{CNodeCap, CapHashOrRef};
    use ssz::Decode;

    const ENDPOINT_IDX: u8 = 0;

    let image = Image::from_ssz_bytes(blob).expect("decode sub-vm image");

    // The bench guest ships .rodata + a small stack (and, for the data
    // variant, a 64 KiB pinned blob) via its image mappings. Publish a
    // Cap::Data per pinned/initial slot and reference them from the
    // Cap::Image; the in-kernel call_loop reads those bytes from the
    // shared cache when building a child frame's mem image.
    let mut data_caps: Vec<(CapHash, Cap)> = Vec::new();
    let mut pinned_hashes: Vec<(Key, CapHash)> = Vec::new();
    let mut initial_hashes: Vec<(Key, CapHash)> = Vec::new();
    for (slot, pinned) in &image.pinned_slots {
        let (h, maybe_cap) = match pinned {
            PinnedCap::Data { content, size } => {
                let cap = Cap::data_inline_with_size(content, *size);
                let h = ssz::hash_tree_root(&cap);
                (h, Some(cap))
            }
            PinnedCap::Image { content_hash } => (*content_hash, None),
        };
        pinned_hashes.push((slot.clone(), h));
        if let Some(cap) = maybe_cap {
            data_caps.push((h, cap));
        }
    }
    for (slot, init) in &image.initial_slots {
        let cap = Cap::data_inline_with_size(&init.content, init.size);
        let h = ssz::hash_tree_root(&cap);
        initial_hashes.push((slot.clone(), h));
        data_caps.push((h, cap));
    }
    for (h, cap) in &data_caps {
        nub.put_cap_with_hash(*h, cap).expect("put data");
    }
    let image_cap =
        Cap::image_with_slots(&image, &pinned_hashes, &initial_hashes).expect("image_with_slots");
    let image_hash = ssz::hash_tree_root(&image_cap);
    nub.put_cap_with_hash(image_hash, &image_cap)
        .expect("put image");

    let mut cn = CNodeCap::new();
    cn.set(
        &Key::from(SLOT_IMAGE_RECURSE as u8),
        Some(CapHashOrRef::Hash(image_hash)),
    )
    .expect("set image slot");
    let cnode_cap = Cap::CNode(cn);
    let cnode_hash = ssz::hash_tree_root(&cnode_cap);
    nub.put_cap_with_hash(cnode_hash, &cnode_cap)
        .expect("put cnode");

    let endpoint = image.endpoints.get(&ENDPOINT_IDX).expect("endpoint 0");
    let mut regs = [0u64; NUM_REGS];
    for (&i, &v) in &endpoint.initial_regs {
        if let Some(slot) = regs.get_mut(i as usize) {
            *slot = v;
        }
    }

    let mem = image.instance_mem_backing();
    let inst_cap = Cap::instance_with_mem([0u8; 32], image_hash, cnode_hash, mem, regs, 0, 0);
    let inst_hash = ssz::hash_tree_root(&inst_cap);
    nub.put_cap_with_hash(inst_hash, &inst_cap)
        .expect("put instance");

    SubVmTop {
        top_instance: inst_hash,
        image_hash,
    }
}

/// One sub-VM bench iteration: invoke the top instance with `depth` and
/// panic unless it halted cleanly on the trampoline HostCall(0).
pub fn invoke_sub_vm(nub: &mut Nub, top: &SubVmTop, depth: u64) {
    let result = nub
        .invoke_cached(top.top_instance, 0, [depth, 0, 0, 0], INITIAL_GAS)
        .expect("invoke_cached");
    assert!(
        result.exit_reason == EXIT_HOSTCALL && result.exit_arg == 0,
        "sub-VM exited non-cleanly: reason={} arg={} ret={} gas={}",
        result.exit_reason,
        result.exit_arg,
        result.return_value,
        result.gas_remaining,
    );
}

/// First 8 bytes of a `CapHash` as lowercase hex (bench logging).
pub fn hex_short(h: &CapHash) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(16);
    for b in &h[..8] {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Run the full sub-VM recurse criterion bench for `blob`, labelled
/// `label`. Publishes the top instance once (the kernel stays warm: the
/// JIT cache holds the compiled image, the cap cache holds the
/// Image/Top-Instance/CNode), runs a depth-0/1 sanity check, then sweeps
/// depths {10, 100, 1000}.
pub fn run_recurse_bench(c: &mut Criterion, blob: &[u8], label: &str) {
    let top = build_sub_vm_top(&mut nub_hyperlight_lock(), blob);
    eprintln!(
        "[{label}] image_hash={} top_instance={}",
        hex_short(&top.image_hash),
        hex_short(&top.top_instance),
    );

    // depth 0 (single CALL/HALT) + depth 1 sanity before the loop —
    // catches top-frame / direct-mapping setup bugs early.
    {
        let mut nub = nub_hyperlight_lock();
        invoke_sub_vm(&mut nub, &top, 0);
        invoke_sub_vm(&mut nub, &top, 1);
    }
    eprintln!("[{label}] depth 0/1 ok");

    let mut g = c.benchmark_group(label);
    g.sample_size(20);
    for &depth in &[10u64, 100, 1_000] {
        g.throughput(Throughput::Elements(depth));
        g.bench_with_input(BenchmarkId::from_parameter(depth), &depth, |b, &d| {
            b.iter(|| invoke_sub_vm(&mut nub_hyperlight_lock(), &top, d))
        });
    }
    g.finish();
}
