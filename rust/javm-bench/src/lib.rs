//! Shared runners for `benches/pvm_bench.rs`.
//!
//! Both backends route through the cache-based API:
//!   - `Nub::publish_image` / `publish_cnode` / `publish_instance` once
//!     per workload (idempotent on the content-hash key).
//!   - `Nub::invoke_cached(instance_hash, ep, args, gas)` per iteration.
//!
//! - `run_interpreter` — `Nub::new_local()` drives the byte-PVM
//!   interpreter (`javm-exec`) in-process.
//! - `run_recompiler` — a long-lived `Nub::new_hyperlight()` sandbox
//!   (cached in a `OnceLock`) drives the in-kernel JIT path via the
//!   same `invoke_cached` API.
//!
//! `Published` is the shared post-publish handle — the bench harness
//! publishes once via `publish_local` / `publish_hyperlight`, then
//! reuses the resulting `(instance_hash, endpoint_idx)` pair across
//! iterations so per-iter cost is just `invoke_cached`.
//!
//! Linux x86-64 only — `nub` pulls the Hyperlight host stack
//! unconditionally.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use javm_cap::image::{Image, PinnedCap};
use javm_cap::NUM_REGS;
use nub::{InvocationResult, Nub};
use nub_arch_x86_abi::CapHash;
use std::sync::{Mutex, OnceLock};

/// HostCall(0) — the trampoline halt all bench programs end on
/// (`ecalli 0`). Both backends surface it as `exit_reason=4,
/// exit_arg=0`.
const EXIT_HOSTCALL: u32 = 4;

/// Default initial-gas budget for the bench.
const INITIAL_GAS: u64 = 100_000_000_000;

/// Published handle: enough state for `Nub::invoke_cached` to re-enter.
#[derive(Debug, Clone, Copy)]
pub struct Published {
    pub instance_hash: CapHash,
    pub endpoint_idx: u8,
}

/// Publish `image`'s `endpoint_idx` into `nub`, returning a
/// [`Published`] handle for subsequent `Nub::invoke_cached` calls.
///
/// V1 lays the image's ro/rw bytes into `InstanceCap.rw_overlays`
/// rather than walking the slot-graph at invoke time — the slot
/// machinery is in place but `nub_invoke_cached` reads overlays
/// directly for V1. The Image's `pinned_slots` and `memory_mappings`
/// are still used by `publish_image` to materialise the canonical
/// content hash, but the bench's runtime layout comes from overlays.
pub fn publish(nub: &mut Nub, image: &Image, endpoint_idx: u8) -> Published {
    // Sanity-check the endpoint exists.
    let endpoint = image
        .endpoints
        .get(&endpoint_idx)
        .unwrap_or_else(|| panic!("endpoint {endpoint_idx} not declared"));

    // 1. publish_image — drives all the pinned/initial Data publishes
    //    and yields the Image's content hash.
    let image_h = nub.publish_image(image).expect("publish_image");

    // 2. Empty root CNode (V1 has no per-instance slot bindings).
    let cnode_h = nub.publish_cnode(0, &[]).expect("publish_cnode (empty)");

    // 3. Materialise the bench's flat (ro, rw) layout as
    //    InstanceCap.rw_overlays for the guest to lay flat at invoke.
    let (mem_size, overlays) = build_overlays(image);
    let overlay_slices: Vec<(u32, &[u8])> = overlays
        .iter()
        .map(|(start, bytes)| (*start, bytes.as_slice()))
        .collect();

    // 4. Build the endpoint's initial_regs (dense [u64; NUM_REGS]).
    //    Used by `nub_invoke_cached` as the regs baseline; args
    //    overlay φ[7..=10] on top.
    let mut regs = [0u64; NUM_REGS];
    for (&i, &v) in &endpoint.initial_regs {
        if let Some(slot) = regs.get_mut(i as usize) {
            *slot = v;
        }
    }

    // 5. publish_instance. pc/gas live on InstanceCap but
    //    nub_invoke_cached overrides them from the endpoint table +
    //    packet, so 0/0 is fine here.
    let instance_h = nub
        .publish_instance([0u8; 32], image_h, cnode_h, &overlay_slices, mem_size, regs, 0, 0)
        .expect("publish_instance");

    Published {
        instance_hash: instance_h,
        endpoint_idx,
    }
}

/// Drive `image[endpoint_idx]` through the byte-PVM interpreter via
/// `Nub::new_local`.
pub fn run_interpreter(image: &Image, endpoint_idx: u8) -> (u64, u64) {
    let mut nub = Nub::new_local();
    let p = publish(&mut nub, image, endpoint_idx);
    let result = nub
        .invoke_cached(p.instance_hash, p.endpoint_idx, [0; 4], INITIAL_GAS)
        .unwrap_or_else(|e| panic!("interpreter invoke_cached: {e}"));
    finish(&result)
}

/// Drive `image[endpoint_idx]` through the in-kernel JIT via the
/// cached Hyperlight `Nub`.
pub fn run_recompiler(image: &Image, endpoint_idx: u8) -> (u64, u64) {
    let mut nub = nub_hyperlight().lock().expect("nub mutex");
    let p = publish(&mut nub, image, endpoint_idx);
    let result = nub
        .invoke_cached(p.instance_hash, p.endpoint_idx, [0; 4], INITIAL_GAS)
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
fn nub_hyperlight() -> &'static Mutex<Nub> {
    static NUB: OnceLock<Mutex<Nub>> = OnceLock::new();
    NUB.get_or_init(|| Mutex::new(Nub::new_hyperlight().expect("Hyperlight sandbox")))
}

/// Walk the Image's memory mappings + slot contents and produce
/// `(mem_size, overlays)` for the InstanceCap. Each non-empty
/// content gets an overlay `(start, bytes)`.
///
/// V1 uses the same shape the legacy `PublishSpec` produced: one
/// overlay for the unique pinned mapping (typically `.rodata`), one
/// for the unique non-empty initial mapping (`.data`). Stack/heap
/// are empty inside `mem_size` as zero-init RW pages.
fn build_overlays(image: &Image) -> (u32, Vec<(u32, Vec<u8>)>) {
    let mut mem_size: u32 = 0;
    let mut overlays: Vec<(u32, Vec<u8>)> = Vec::new();

    for mapping in &image.memory_mappings {
        let end = (mapping.start + mapping.size) as u32;
        if end > mem_size {
            mem_size = end;
        }

        let target = mapping.source.target();
        if let Some(PinnedCap::Data { content, .. }) = image.pinned_slots.get(&target) {
            if !content.is_empty() {
                overlays.push((mapping.start as u32, content.clone()));
            }
        } else if let Some(init) = image.initial_slots.get(&target)
            && !init.content.is_empty()
        {
            overlays.push((mapping.start as u32, init.content.clone()));
        }
    }

    (mem_size, overlays)
}
