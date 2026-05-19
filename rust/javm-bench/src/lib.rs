//! Shared runners for `benches/pvm_bench.rs`.
//!
//! Both backends route through the cache-based API:
//!   - `Nub::publish_instance(spec)` once per workload (idempotent).
//!   - `Nub::invoke_cached(hash, ep, args, gas)` per iteration.
//!
//! - `run_interpreter` — `Nub::new_local()` drives the byte-PVM
//!   interpreter (`javm-exec`) in-process. Constructed per-call;
//!   `new_local()` is a trivial allocation.
//! - `run_recompiler` — a long-lived `Nub::new_hyperlight()` sandbox
//!   (cached in a `OnceLock`) drives the in-kernel JIT path via the
//!   same `invoke_cached` API. The sandbox boot (~hundreds of ms)
//!   lands on the first `nub_hyperlight()` call; subsequent calls
//!   reuse the cached instance, and the bench harness primes it via
//!   the sanity check before the timed loop.
//!
//! `build_publish_spec` is the shared spec-builder — projects an
//! `Image` + endpoint onto a [`PublishSpec`] once, before the iter
//! loop. The bench publishes once (idempotent) and then the per-iter
//! cost is just `invoke_cached` + a HashMap lookup.
//!
//! Linux x86-64 only — `nub` pulls the Hyperlight host stack
//! unconditionally.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use javm_cap::image::{Image, PinnedCap};
use javm_exec::{REG_COUNT, unpack_bitmask};
use nub::{InvocationResult, Nub, PublishSpec};
use std::sync::{Mutex, OnceLock};

/// HostCall(0) — the trampoline halt all bench programs end on
/// (`ecalli 0`). Both backends surface it as `exit_reason=4,
/// exit_arg=0`.
const EXIT_HOSTCALL: u32 = 4;

/// Default initial-gas budget for the bench. Stored at build time so
/// `finish` can compute `gas_used` from the result's remaining gas.
const INITIAL_GAS: u64 = 100_000_000_000;

/// Build a [`PublishSpec`] from `image`'s endpoint. Builds once per
/// workload — the bench harness reuses the same spec across all
/// criterion iterations, so the per-iter cost stays in `invoke_cached`.
pub fn build_publish_spec(image: &Image, endpoint_idx: u8) -> PublishSpec {
    let bitmask = unpack_bitmask(&image.packed_bitmask, image.code.len());
    let endpoint = image
        .endpoints
        .get(&endpoint_idx)
        .unwrap_or_else(|| panic!("endpoint {endpoint_idx} not declared"));

    // Endpoint invocation = process spawn. `initial_regs` from the
    // Image's endpoint table IS the bootstrap snapshot (typically
    // phi[1] = stack_top); endpoint is encoded by PC, not by a
    // register the kernel writes.
    let mut regs = [0u64; REG_COUNT];
    for (&i, &v) in &endpoint.initial_regs {
        if let Some(slot) = regs.get_mut(i as usize) {
            *slot = v;
        }
    }

    let (mem_size, ro_start, ro_data, rw_start, rw_data) = build_data_layout(image);

    // Dense entry-pc table: place the requested endpoint's PC at
    // index `endpoint_idx`; leave others at 0 (= not defined).
    let mut entry_pcs = [0u64; nub_arch_x86_abi::MAX_ENDPOINTS];
    if (endpoint_idx as usize) < entry_pcs.len() {
        entry_pcs[endpoint_idx as usize] = endpoint.entry_pc;
    }

    // Hash for cache identity: blake2b256 over a few stable fields.
    // The bench doesn't care about the chain semantics — just needs a
    // deterministic 32-byte id distinct per (image, endpoint).
    let instance_hash = hash_image_endpoint(image, endpoint_idx);

    PublishSpec {
        instance_hash,
        code: image.code.clone(),
        bitmask,
        jump_table: image.jump_table.clone(),
        mem_size,
        ro_start,
        ro_data,
        rw_start,
        rw_data,
        arg_start: 0,
        arg_data: Vec::new(),
        entry_pcs,
        initial_regs: regs,
    }
}

fn hash_image_endpoint(image: &Image, endpoint_idx: u8) -> [u8; 32] {
    // Cheap stable hash. blake3 is already a transitive dep via the
    // hyperlight host stack; reuse it.
    let mut hasher = blake3::Hasher::new();
    hasher.update(&image.code);
    hasher.update(&[endpoint_idx]);
    hasher.finalize().as_bytes()[..32]
        .try_into()
        .expect("blake3 32-byte digest")
}

/// Drive `spec` through the byte-PVM interpreter via `Nub::new_local`.
/// Publish is idempotent — the cost on second+ calls is just a
/// HashMap lookup.
pub fn run_interpreter(spec: &PublishSpec) -> (u64, u64) {
    let mut nub = Nub::new_local();
    // Local backend publish moves the spec into a HashMap; we clone
    // to keep the caller's PublishSpec usable across iterations.
    nub.publish_instance(spec.clone())
        .expect("publish_instance (local)");
    let result = nub
        .invoke_cached(spec.instance_hash, 0, [0; 4], INITIAL_GAS)
        .unwrap_or_else(|e| panic!("interpreter invoke_cached: {e}"));
    finish(&result)
}

/// Drive `spec` through the in-kernel JIT via the cached Hyperlight
/// `Nub`. The first call publishes the spec into the cache; subsequent
/// calls are publish-no-op + invoke.
pub fn run_recompiler(spec: &PublishSpec) -> (u64, u64) {
    let mut nub = nub_hyperlight().lock().expect("nub mutex");
    nub.publish_instance(spec.clone())
        .expect("publish_instance (hyperlight)");
    let result = nub
        .invoke_cached(spec.instance_hash, 0, [0; 4], INITIAL_GAS)
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

/// Long-lived Hyperlight sandbox shared across bench iterations.
/// Sandbox construction takes ~hundreds of ms; the bench harness's
/// sanity check pays this cost before the timed loop runs.
fn nub_hyperlight() -> &'static Mutex<Nub> {
    static NUB: OnceLock<Mutex<Nub>> = OnceLock::new();
    NUB.get_or_init(|| Mutex::new(Nub::new_hyperlight().expect("Hyperlight sandbox")))
}

/// Walk the Image's memory mappings + slot contents and project them
/// onto the recompiler's flat `(arg, ro, rw)` shape.
///
/// - `ro`: the unique pinned mapping (typically `.rodata`).
/// - `rw`: the unique non-pinned mapping whose initial slot has
///   non-empty content (typically `.data`).
/// - Stack and heap have empty `content` — they live within `mem_size`
///   as implicit zero-initialised RW pages.
/// - `arg`: empty (no payload delivery).
/// - `mem_size`: `max(mapping.start + mapping.size)` over all mappings.
fn build_data_layout(image: &Image) -> (u32, u32, Vec<u8>, u32, Vec<u8>) {
    let mut mem_size: u32 = 0;
    let mut ro: Option<(u32, Vec<u8>)> = None;
    let mut rw: Option<(u32, Vec<u8>)> = None;

    for mapping in &image.memory_mappings {
        let end = (mapping.start + mapping.size) as u32;
        if end > mem_size {
            mem_size = end;
        }

        let target = mapping.source.target();
        if let Some(PinnedCap::Data { content, .. }) = image.pinned_slots.get(&target) {
            assert!(ro.is_none(), "multiple pinned mappings not supported");
            ro = Some((mapping.start as u32, content.clone()));
        } else if let Some(init) = image.initial_slots.get(&target)
            && !init.content.is_empty()
        {
            assert!(
                rw.is_none(),
                "multiple non-empty initial mappings not supported"
            );
            rw = Some((mapping.start as u32, init.content.clone()));
        }
    }

    let (ro_start, ro_data) = ro.unwrap_or((0, Vec::new()));
    let (rw_start, rw_data) = rw.unwrap_or((0, Vec::new()));

    (mem_size, ro_start, ro_data, rw_start, rw_data)
}
