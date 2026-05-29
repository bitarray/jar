//! Sub-VM recursive-spawn bench for the in-kernel JIT path.
//!
//! Measures how many `Cap::Instance`s the KVM microkernel can
//! derive-and-CALL inside one second. The guest at
//! `components/benches/sub-vm-recurse` reads `depth` from φ[7]; if
//! zero, returns; otherwise `derive_spawn`s a child Instance from the
//! same Image and `host_call`s it with `depth - 1`. The in-kernel
//! CALL/HALT loop ([`nub_arch_x86::call_loop`]) keeps each level in a
//! kernel-private call stack; the JIT code cache
//! ([`nub_arch_x86::jit_cache`]) amortises the compile across all
//! levels.
//!
//! ## What this measures
//!
//! Per recursion level the kernel pays:
//!   1. ~3 µs `derive_spawn` (Blake2b chain extend + transient-table
//!      insert).
//!   2. ~10–15 µs PT setup + ring-3 entry + JIT entry.
//!   3. ~10–15 µs HALT exit + PT teardown + parent restore.
//!
//! On bench warmup the first CALL pays the one-time JIT compile
//! (~500 µs); every subsequent CALL hits the cache. The reported
//! VMs/sec at depth ≥ 100 is the steady-state rate.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use javm_cap::image::{Image, PinnedCap};
use javm_cap::slot::SlotIdx;
use javm_cap::{CNodeCap, Cap, CapHash, CapHashOrRef, NUM_REGS};
use nub::Nub;
use ssz::Decode;
use std::sync::{Mutex, OnceLock};

const BLOB: &[u8] = include_bytes!(env!("SUB_VM_RECURSE_BLOB"));
const SLOT_IMAGE_RECURSE: u8 = 3;
const ENDPOINT_IDX: u8 = 0;
const INITIAL_GAS: u64 = 100_000_000_000;
const EXIT_HOSTCALL: u32 = 4;

/// Result of one `Nub::invoke_cached` against the top recurse
/// instance: just a per-bench sanity check that the invocation
/// completed cleanly.
struct Built {
    top_instance: CapHash,
    image_hash: CapHash,
}

/// Build + publish (once) the recurse Image, its cnode, and the top
/// Instance into the given `Nub`. Returns the top instance hash so
/// the iter loop can invoke it directly.
fn build_and_publish(nub: &mut Nub, depth_seed: u64) -> Built {
    let image = Image::from_ssz_bytes(BLOB).expect("decode recurse image");

    // The bench guest is a real Rust program (subsoil trampoline +
    // tiny ecall sequence) and ships .rodata + a small stack via its
    // image mappings. Publish a Cap::Data per pinned/initial slot
    // and reference them from the Cap::Image — the in-kernel
    // call_loop will read those Cap::Data bytes from the shared
    // cache when building a child frame's mem image.
    let mut data_caps: Vec<(CapHash, Cap)> = Vec::new();
    let mut pinned_hashes: Vec<(SlotIdx, CapHash)> = Vec::new();
    let mut initial_hashes: Vec<(SlotIdx, CapHash)> = Vec::new();
    for (slot, pinned) in &image.pinned_slots {
        let (h, maybe_cap) = match pinned {
            PinnedCap::Data { content, size } => {
                let cap = Cap::data_inline_with_size(content, *size);
                let h = ssz::hash_tree_root(&cap);
                (h, Some(cap))
            }
            PinnedCap::Image { content_hash } => (*content_hash, None),
        };
        pinned_hashes.push((*slot, h));
        if let Some(cap) = maybe_cap {
            data_caps.push((h, cap));
        }
    }
    for (slot, init) in &image.initial_slots {
        let cap = Cap::data_inline_with_size(&init.content, init.size);
        let h = ssz::hash_tree_root(&cap);
        initial_hashes.push((*slot, h));
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

    // Recurse cnode: slot 3 → image_hash. Each level's frame inherits
    // this entry from its parent (see `dispatch_host_call` in
    // `nub-arch-x86::call_loop`).
    let mut cn = CNodeCap::new(8).expect("cnode");
    cn.set(
        SlotIdx(SLOT_IMAGE_RECURSE as u32),
        Some(CapHashOrRef::Hash(image_hash)),
    )
    .expect("set image slot");
    let cnode_cap = Cap::CNode(cn);
    let cnode_hash = ssz::hash_tree_root(&cnode_cap);
    nub.put_cap_with_hash(cnode_hash, &cnode_cap)
        .expect("put cnode");

    // Top instance: image_hash, root_cnode, fresh state, depth_seed
    // is overridden each iter by the caller's `args[0]`.
    let _ = depth_seed; // depth is supplied via invoke_cached args
    let endpoint = image.endpoints.get(&ENDPOINT_IDX).expect("endpoint 0");
    let mut regs = [0u64; NUM_REGS];
    for (&i, &v) in &endpoint.initial_regs {
        if let Some(slot) = regs.get_mut(i as usize) {
            *slot = v;
        }
    }
    // Materialise rw_overlays so the top frame sees the actual
    // .rodata / .data bytes. Same layout used by `javm-bench`'s
    // existing pvm_bench harness — pinned `Data` content and
    // non-empty initial-slot content map onto `(start, bytes)`
    // overlays at the mapping's start.
    let mut mem_size: u32 = 0;
    let mut overlays: Vec<(u32, Vec<u8>)> = Vec::new();
    // Code is RO direct-mapped at CODE_BASE, not a flat-buffer overlay;
    // `memory_mappings` lists data/slot regions only.
    for mapping in &image.memory_mappings {
        let target = mapping.source.target();
        let end = (mapping.start + mapping.size) as u32;
        if end > mem_size {
            mem_size = end;
        }
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
    let overlay_slices: Vec<(u32, &[u8])> =
        overlays.iter().map(|(s, b)| (*s, b.as_slice())).collect();
    let inst_cap = Cap::instance_with_overlays(
        [0u8; 32],
        image_hash,
        cnode_hash,
        &overlay_slices,
        mem_size,
        regs,
        0,
        0,
    );
    let inst_hash = ssz::hash_tree_root(&inst_cap);
    nub.put_cap_with_hash(inst_hash, &inst_cap)
        .expect("put instance");

    Built {
        top_instance: inst_hash,
        image_hash,
    }
}

/// One bench iteration: invoke the top instance with `depth` and
/// validate it halted cleanly.
fn invoke(nub: &mut Nub, top: &Built, depth: u64) {
    let result = nub
        .invoke_cached(
            top.top_instance,
            ENDPOINT_IDX,
            [depth, 0, 0, 0],
            INITIAL_GAS,
        )
        .expect("invoke_cached");
    if !(result.exit_reason == EXIT_HOSTCALL && result.exit_arg == 0) {
        panic!(
            "sub-VM recurse exited non-cleanly: reason={} arg={} ret={} gas={}",
            result.exit_reason, result.exit_arg, result.return_value, result.gas_remaining,
        );
    }
}

/// Long-lived Hyperlight sandbox shared across bench iterations.
fn nub_hyperlight() -> &'static Mutex<Nub> {
    static NUB: OnceLock<Mutex<Nub>> = OnceLock::new();
    NUB.get_or_init(|| Mutex::new(Nub::new_hyperlight().expect("Hyperlight sandbox")))
}

fn sub_vm_recurse(c: &mut Criterion) {
    // Publish once, outside the bench loop. The kernel side stays
    // warm across iters: the JIT cache holds the compiled image; the
    // shared cap cache holds the Image + Top-Instance + CNode at
    // their content hashes.
    let top = {
        let mut nub = nub_hyperlight().lock().expect("nub mutex");
        build_and_publish(&mut nub, 0)
    };
    eprintln!(
        "[sub_vm_recurse] image_hash={} top_instance={}",
        hex_short(&top.image_hash),
        hex_short(&top.top_instance),
    );

    // Sanity: depth=0 (no recursion, single CALL/HALT) must
    // round-trip cleanly. Catches top-frame setup bugs early.
    {
        let mut nub = nub_hyperlight().lock().expect("nub mutex");
        invoke(&mut nub, &top, 0);
        eprintln!("[sub_vm_recurse] depth=0 ok");
        invoke(&mut nub, &top, 1);
        eprintln!("[sub_vm_recurse] depth=1 ok");
    }

    let mut g = c.benchmark_group("sub_vm_recurse");
    g.sample_size(20);
    for &depth in &[10u64, 100, 1_000] {
        g.throughput(Throughput::Elements(depth));
        g.bench_with_input(BenchmarkId::from_parameter(depth), &depth, |b, &d| {
            b.iter(|| {
                let mut nub = nub_hyperlight().lock().expect("nub mutex");
                invoke(&mut nub, &top, d);
            })
        });
    }
    g.finish();
}

fn hex_short(h: &CapHash) -> String {
    let mut s = String::with_capacity(16);
    for b in &h[..8] {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

criterion_group!(benches, sub_vm_recurse);
criterion_main!(benches);
