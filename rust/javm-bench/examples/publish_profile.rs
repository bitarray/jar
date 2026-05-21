//! Fine-grained profile of where publish_image / publish_instance time goes.
//!
//! Breaks each step into its sub-operations (talc alloc + memcpy, cap_hash,
//! BTreeMap lookup) and times each on a hot loop, so we can see where the
//! ~700 µs per publish_image / per publish_instance lands.

use std::time::Instant;

use allocator_api2::alloc::Global;
use allocator_api2::vec::Vec as AVec;
use javm_cap::cap::Cap;
use javm_cap::cap_hash::cap_hash;
use javm_cap::data::{DataCap, DataContent};
use javm_cap::image::Image;
use javm_cap::NUM_REGS;
use nub::Nub;
use ssz::Decode;

fn iter_us(n: u32, dur: std::time::Duration) -> f64 {
    dur.as_secs_f64() * 1e6 / n as f64
}

fn measure<F: FnMut()>(label: &str, n: u32, mut f: F) {
    let t = Instant::now();
    for _ in 0..n {
        f();
    }
    let e = t.elapsed();
    eprintln!("  {label:55}{:>10.3} µs/iter", iter_us(n, e));
}

fn main() {
    let path = std::env::args().nth(1).expect("usage: publish_profile <pvm-blob>");
    let blob = std::fs::read(&path).expect("read");
    let image = Image::from_ssz_bytes(&blob).expect("decode Image");
    eprintln!(
        "image: code={} bitmask={} jump_table={} pinned_slots={} initial_slots={} mappings={}",
        image.code.len(),
        image.packed_bitmask.len(),
        image.jump_table.len(),
        image.pinned_slots.len(),
        image.initial_slots.len(),
        image.memory_mappings.len(),
    );

    let big_payload: Vec<u8> = image
        .initial_slots
        .values()
        .map(|i| i.content.clone())
        .max_by_key(|v| v.len())
        .unwrap_or_default();
    eprintln!("biggest initial-slot payload: {} bytes", big_payload.len());

    let n: u32 = 200;

    eprintln!("\n=== high-level (Nub::publish_*) ===");
    let mut nub = Nub::new_local();
    let _ = nub.publish_image(&image).unwrap();
    let _ = nub.publish_cnode(0, &[]).unwrap();

    measure("Nub::publish_image (idempotent, hot)", n, || {
        let _ = nub.publish_image(&image).unwrap();
    });
    measure("Nub::publish_cnode(empty) (idempotent, hot)", n, || {
        let _ = nub.publish_cnode(0, &[]).unwrap();
    });

    use javm_cap::image::PinnedCap;
    let mut overlays: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut mem_size: u32 = 0;
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
    let overlay_refs: Vec<(u32, &[u8])> =
        overlays.iter().map(|(s, b)| (*s, b.as_slice())).collect();
    let image_h = nub.publish_image(&image).unwrap();
    let cnode_h = nub.publish_cnode(0, &[]).unwrap();
    let regs = [0u64; NUM_REGS];
    measure("Nub::publish_instance (idempotent, hot)", n, || {
        let _ = nub
            .publish_instance([0; 32], image_h, cnode_h, &overlay_refs, mem_size, regs, 0, 0)
            .unwrap();
    });

    eprintln!(
        "\n=== sub-operations on the biggest payload ({} B) ===",
        big_payload.len()
    );
    let bytes = big_payload.as_slice();
    let size_u64 = bytes.len() as u64;

    // (a) Pure SHA-256 throughput on the input slice (theoretical floor).
    use sha2::Digest;
    measure("(a) sha2::Sha256 over input slice (single hash)", n, || {
        let mut h = sha2::Sha256::new();
        h.update(bytes);
        let _ = std::hint::black_box(h.finalize());
    });

    // (b) AVec<u8, Global> alloc + memcpy + drop — host heap baseline.
    measure(
        "(b) AVec<u8, Global> alloc + extend_from_slice + drop",
        n,
        || {
            let mut v: AVec<u8, Global> = AVec::with_capacity_in(bytes.len(), Global);
            v.extend_from_slice(bytes);
            std::hint::black_box(&v);
            drop(v);
        },
    );

    // (c) cap_hash(Cap::Data) — SSZ merkleize over the bytes, with Cap
    //     already built. Isolates the hash work from the alloc/copy.
    let cap_data: Cap<Global> = {
        let mut v: AVec<u8, Global> = AVec::with_capacity_in(bytes.len(), Global);
        v.extend_from_slice(bytes);
        Cap::Data(DataCap {
            size: size_u64,
            content: DataContent::Inline(v),
        })
    };
    measure("(c) cap_hash(Cap::Data) on pre-built Cap", n, || {
        let h = cap_hash(&cap_data);
        std::hint::black_box(h);
    });

    // (d) Full publish_data_inline_with_size hit-path on Global: build
    //     Cap::Data + cap_hash + drop. Compare against the talc-backed (e).
    measure("(d) build Cap::Data(Global) + cap_hash + drop", n, || {
        let mut v: AVec<u8, Global> = AVec::with_capacity_in(bytes.len(), Global);
        v.extend_from_slice(bytes);
        let cap: Cap<Global> = Cap::Data(DataCap {
            size: size_u64,
            content: DataContent::Inline(v),
        });
        let h = cap_hash(&cap);
        std::hint::black_box(h);
        drop(cap);
    });

    // (e) Nub::publish_data on the same bytes — talc-backed, full
    //     publish_data_inline_with_size path (alloc + memcpy + hash +
    //     put_blob lookup + drop). Difference vs (d) ≈ talc cost.
    measure(
        "(e) Nub::publish_data(bytes) [talc-backed; hit path]",
        n,
        || {
            let _ = nub.publish_data(bytes).unwrap();
        },
    );
}
