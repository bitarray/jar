//! Fine-grained profile of where publish_image / publish_instance time goes.
//!
//! Breaks each step into its sub-operations (talc alloc + memcpy, cap_hash,
//! BTreeMap lookup) and times each on a hot loop, so we can see where the
//! ~700 µs per publish_image / per publish_instance lands.
//!
//! Linux x86-64 only — `nub` pulls the Hyperlight host stack
//! unconditionally; on other targets `javm_bench` compiles down to nothing
//! and `main` becomes a no-op so the example still links.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {
    eprintln!(
        "publish_profile is Linux x86-64 only; this build target has no \
         Hyperlight host stack."
    );
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::time::Instant;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use javm_cap::cap::Cap;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use javm_cap::image::Image;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use nub::Nub;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use ssz::Decode;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn iter_us(n: u32, dur: std::time::Duration) -> f64 {
    dur.as_secs_f64() * 1e6 / n as f64
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn measure<F: FnMut()>(label: &str, n: u32, mut f: F) {
    let t = Instant::now();
    for _ in 0..n {
        f();
    }
    let e = t.elapsed();
    eprintln!("  {label:55}{:>10.3} µs/iter", iter_us(n, e));
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: publish_profile <pvm-blob>");
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

    eprintln!("\n=== high-level (Nub::put_cap_with_hash, idempotent) ===");
    let mut nub = Nub::new_local();
    let built = javm_bench::BuiltCaps::for_image(&image, 0);

    // Warm-up: first put pays the deep-clone; subsequent puts are
    // BTreeMap lookup + refcount bump only.
    for (h, cap) in &built.data_caps {
        nub.put_cap_with_hash(*h, cap).unwrap();
    }
    nub.put_cap_with_hash(built.image_hash, &built.image_cap)
        .unwrap();
    nub.put_cap_with_hash(built.cnode_hash, &built.cnode_cap)
        .unwrap();
    nub.put_cap_with_hash(built.instance_hash, &built.instance_cap)
        .unwrap();

    measure("Nub::put_cap_with_hash image (idempotent)", n, || {
        nub.put_cap_with_hash(built.image_hash, &built.image_cap)
            .unwrap();
    });
    measure("Nub::put_cap_with_hash cnode (idempotent)", n, || {
        nub.put_cap_with_hash(built.cnode_hash, &built.cnode_cap)
            .unwrap();
    });
    measure("Nub::put_cap_with_hash instance (idempotent)", n, || {
        nub.put_cap_with_hash(built.instance_hash, &built.instance_cap)
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

    // (b) Vec<u8> alloc + memcpy + drop — host heap baseline.
    measure("(b) Vec<u8> alloc + extend_from_slice + drop", n, || {
        let mut v: Vec<u8> = Vec::with_capacity(bytes.len());
        v.extend_from_slice(bytes);
        std::hint::black_box(&v);
        drop(v);
    });

    // (c) cap_hash(Cap::Data) — SSZ merkleize over the bytes, with Cap
    //     already built. Isolates the hash work from the alloc/copy.
    let cap_data: Cap = Cap::data_inline_with_size(bytes, size_u64);
    measure("(c) cap_hash(Cap::Data) on pre-built Cap", n, || {
        let h = cap_data.cap_hash();
        std::hint::black_box(h);
    });

    // (d) Full data_inline_with_size hit-path on Global: build
    //     Cap::Data + cap_hash + drop. Compare against the talc-backed (e).
    measure("(d) build Cap::Data(Global) + cap_hash + drop", n, || {
        let cap: Cap = Cap::data_inline_with_size(bytes, size_u64);
        let h = cap.cap_hash();
        std::hint::black_box(h);
        drop(cap);
    });

    // (e) Nub::put_cap on a fresh Cap::Data — talc-backed, exercises
    //     the full put_cap path including SSZ cap_hash + (on first
    //     iter) deep-clone into talc; subsequent iters hit the
    //     idempotent fast path. Difference vs (d) ≈ talc + idempotency
    //     short-circuit cost.
    let data_cap_global: Cap = Cap::data_inline(bytes);
    measure("(e) Nub::put_cap(&data_cap) [idempotent re-put]", n, || {
        let _ = nub.put_cap(&data_cap_global).unwrap();
    });
}
