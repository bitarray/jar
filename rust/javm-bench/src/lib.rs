//! Shared runners for `benches/pvm_bench.rs` and `benches/stark_bench.rs`.
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

#![cfg_attr(not(all(target_os = "linux", target_arch = "x86_64")), allow(unused))]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use javm_cap::NUM_REGS;
use javm_cap::image::{Image, PinnedCap};
use javm_cap::slot::SlotIdx;
use javm_cap::{Cap, CapHash};
use nub::{InvocationResult, Nub};
use std::sync::{Mutex, OnceLock};

/// HostCall(0) — the trampoline halt all bench programs end on
/// (`ecalli 0`). Both backends surface it as `exit_reason=4,
/// exit_arg=0`.
const EXIT_HOSTCALL: u32 = 4;

/// Default initial-gas budget for the bench.
const INITIAL_GAS: u64 = 100_000_000_000;

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
        let mut pinned_hashes: Vec<(SlotIdx, CapHash)> = Vec::new();
        let mut initial_hashes: Vec<(SlotIdx, CapHash)> = Vec::new();

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
            pinned_hashes.push((*slot, h));
            if let Some(c) = cap {
                data_caps.push((h, c));
            }
        }
        for (slot, init) in &image.initial_slots {
            let cap = Cap::data_inline_with_size(&init.content, init.size);
            let h = ssz::hash_tree_root(&cap);
            initial_hashes.push((*slot, h));
            data_caps.push((h, cap));
        }

        // 2. Build the Cap::Image referencing the data caps by hash.
        let image_cap = Cap::image_with_slots(image, &pinned_hashes, &initial_hashes)
            .expect("image_with_slots");
        let image_hash = ssz::hash_tree_root(&image_cap);

        // 3. Empty root CNode (V1: no per-instance slot bindings).
        let cnode_cap = Cap::empty_cnode(0).expect("empty_cnode");
        let cnode_hash = ssz::hash_tree_root(&cnode_cap);

        // 4. Build the Instance with the bench's flat overlay layout.
        let (mem_size, overlays) = build_overlays(image);
        let overlay_slices: Vec<(u32, &[u8])> = overlays
            .iter()
            .map(|(start, bytes)| (*start, bytes.as_slice()))
            .collect();

        let mut regs = [0u64; NUM_REGS];
        for (&i, &v) in &endpoint.initial_regs {
            if let Some(slot) = regs.get_mut(i as usize) {
                *slot = v;
            }
        }

        let instance_cap = Cap::instance_with_overlays(
            [0u8; 32],
            image_hash,
            cnode_hash,
            &overlay_slices,
            mem_size,
            regs,
            0,
            0,
        );
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
    fn put_into(&self, nub: &mut Nub) {
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

/// Drive `built[endpoint_idx]` through the byte-PVM interpreter via a
/// fresh `Nub::new_local()` (the Local backend has no per-invocation
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
/// lived Hyperlight `Nub`.
pub fn run_recompiler(built: &BuiltCaps) -> (u64, u64) {
    let mut nub = nub_hyperlight().lock().expect("nub mutex");
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

/// Long-lived Hyperlight sandbox shared across bench iterations.
fn nub_hyperlight() -> &'static Mutex<Nub> {
    static NUB: OnceLock<Mutex<Nub>> = OnceLock::new();
    NUB.get_or_init(|| Mutex::new(Nub::new_hyperlight().expect("Hyperlight sandbox")))
}

/// Walk the Image's memory mappings + slot contents and produce
/// `(mem_size, overlays)` for the InstanceCap. Each non-empty content
/// becomes one `(start, bytes)` overlay; stack/heap are empty inside
/// `mem_size` as zero-init RW pages.
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
