//! Diagnostic: characterise whether the guest heap leaks across
//! repeated `Nub::invoke_spec` calls, fragments, or stays steady.
//!
//! Runs the `prime_sieve` workload N times against a single
//! Hyperlight sandbox, sampling `talc`'s counters every K iters.
//! Prints `(iter, allocated_bytes, allocation_count, fragment_count,
//! available_bytes)`. Run with:
//!
//! ```bash
//! cargo test -p javm-bench --test heap_drift --release -- --nocapture
//! ```
//!
//! Interpretation:
//! - `allocated_bytes` growing monotonically → real leak (Vec / Box
//!   somewhere not getting dropped per iter).
//! - `allocated_bytes` oscillates within a band, `fragment_count`
//!   climbs, `available_bytes` shrinks → fragmentation (talc can't
//!   coalesce despite proper free).
//! - All four steady → no leak; OOM (if it happens) is from something
//!   else (Hyperlight scratch / CoW).
//!
//! This is gated to Linux/x86_64 + a build flag — it's not part of
//! the normal CI loop.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use javm_cap::image::{Image, PinnedCap};
use javm_exec::{REG_COUNT, unpack_bitmask};
use nub::{InvocationSpec, Nub, PvmRegs};
use scale::Decode;

const PRIME_SIEVE_BLOB: &[u8] = include_bytes!(env!("PRIME_SIEVE_BLOB"));
const GAS: u64 = 100_000_000_000;
/// Total iterations.
const N: usize = 2000;
/// Sample interval — print talc counters every `STEP` iters.
const STEP: usize = 100;

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
            assert!(ro.is_none());
            ro = Some((mapping.start as u32, content.clone()));
        } else if let Some(init) = image.initial_slots.get(&target)
            && !init.content.is_empty()
        {
            assert!(rw.is_none());
            rw = Some((mapping.start as u32, init.content.clone()));
        }
    }

    let (ro_start, ro_data) = ro.unwrap_or((0, Vec::new()));
    let (rw_start, rw_data) = rw.unwrap_or((0, Vec::new()));

    (mem_size, ro_start, ro_data, rw_start, rw_data)
}

fn build_spec(image: &Image, ep: u8) -> InvocationSpec {
    let bitmask = unpack_bitmask(&image.packed_bitmask, image.code.len());
    let endpoint = image.endpoints.get(&ep).expect("endpoint declared");
    let mut regs = [0u64; REG_COUNT];
    regs[11] = ep as u64;
    for (&i, &v) in &endpoint.initial_regs {
        if let Some(slot) = regs.get_mut(i as usize) {
            *slot = v;
        }
    }
    let (mem_size, ro_start, ro_data, rw_start, rw_data) = build_data_layout(image);
    InvocationSpec {
        code: image.code.clone(),
        bitmask,
        jump_table: image.jump_table.clone(),
        entry_pc: endpoint.entry_pc as u32,
        initial_gas: GAS,
        initial_regs: PvmRegs::from_array(regs),
        mem_size,
        arg_start: 0,
        arg_data: Vec::new(),
        ro_start,
        ro_data,
        rw_start,
        rw_data,
    }
}

/// Diagnostic isolating the leak from any of *our* per-call work: this
/// drives `Nub::invoke` (which calls the trivial `nub_smoke` guest
/// function — returns 42, no compile, no decode, no Vec<u8> input).
/// If heap_stats grows linearly here too, the leak is in Hyperlight's
/// `#[guest_function]` dispatch wrapper (FunctionCall TryFrom,
/// FlatBufferBuilder, etc.), not anything we wrote.
#[test]
#[ignore]
fn heap_drift_nub_smoke() {
    use nub::{InstanceRef, InvokeOptions};

    let mut nub = Nub::new_hyperlight().expect("sandbox");
    let s0 = nub.heap_stats().expect("baseline heap_stats");
    eprintln!(
        "iter         alloc_B    n_alloc   n_frag   avail_B   Δalloc (nub_smoke / Nub::invoke)"
    );
    eprintln!(
        "{:>5}  {:>12}  {:>8}  {:>7}  {:>9}  {:>9}",
        0, s0.allocated_bytes, s0.allocation_count, s0.fragment_count, s0.available_bytes, 0i64,
    );

    let mut prev = s0;
    for i in 1..=N {
        let _ = nub
            .invoke(InstanceRef::from_hash([0; 32]), 0, &[], InvokeOptions::default())
            .expect("invoke");

        if i % STEP == 0 || i == 1 {
            let s = nub.heap_stats().expect("heap_stats");
            let delta = s.allocated_bytes as i64 - prev.allocated_bytes as i64;
            eprintln!(
                "{:>5}  {:>12}  {:>8}  {:>7}  {:>9}  {:>+9}",
                i,
                s.allocated_bytes,
                s.allocation_count,
                s.fragment_count,
                s.available_bytes,
                delta,
            );
            prev = s;
        }
    }
}

/// Bisect step 1: ship the SCALE-encoded spec bytes into the guest
/// but have the guest immediately drop them. If THIS leaks, the leak
/// is in the input-Vec<u8> Hyperlight plumbing (`try_pop_shared_input`,
/// `FunctionCall::try_from` of FlatBuffers). If not, leak is in the
/// SCALE decode or downstream.
#[test]
#[ignore]
fn heap_drift_passthrough() {
    use scale::Encode;

    let image = Image::decode(PRIME_SIEVE_BLOB).expect("decode prime_sieve Image").0;
    let spec = build_spec(&image, 0);
    let bytes = spec.encode();

    let mut nub = Nub::new_hyperlight().expect("sandbox");
    let s0 = nub.heap_stats().expect("baseline heap_stats");
    eprintln!(
        "iter         alloc_B    n_alloc   n_frag   avail_B   Δalloc (nub_passthrough)"
    );
    eprintln!(
        "{:>5}  {:>12}  {:>8}  {:>7}  {:>9}  {:>9}",
        0, s0.allocated_bytes, s0.allocation_count, s0.fragment_count, s0.available_bytes, 0i64,
    );
    let mut prev = s0;
    for i in 1..=N {
        nub.diag_passthrough(bytes.clone()).expect("passthrough");
        if i % STEP == 0 || i == 1 {
            let s = nub.heap_stats().expect("heap_stats");
            let delta = s.allocated_bytes as i64 - prev.allocated_bytes as i64;
            eprintln!(
                "{:>5}  {:>12}  {:>8}  {:>7}  {:>9}  {:>+9}",
                i, s.allocated_bytes, s.allocation_count, s.fragment_count, s.available_bytes, delta,
            );
            prev = s;
        }
    }
}

/// Bisect step 2: ship the bytes AND SCALE-decode into an
/// `InvocationSpec`, then drop. If this leaks but `passthrough`
/// doesn't, the SCALE decode is the culprit. If neither leaks but
/// `prime_sieve` does, the leak is in `run_pvm_with_mem`.
#[test]
#[ignore]
fn heap_drift_decode_only() {
    use scale::Encode;

    let image = Image::decode(PRIME_SIEVE_BLOB).expect("decode prime_sieve Image").0;
    let spec = build_spec(&image, 0);
    let bytes = spec.encode();

    let mut nub = Nub::new_hyperlight().expect("sandbox");
    let s0 = nub.heap_stats().expect("baseline heap_stats");
    eprintln!(
        "iter         alloc_B    n_alloc   n_frag   avail_B   Δalloc (nub_decode_only)"
    );
    eprintln!(
        "{:>5}  {:>12}  {:>8}  {:>7}  {:>9}  {:>9}",
        0, s0.allocated_bytes, s0.allocation_count, s0.fragment_count, s0.available_bytes, 0i64,
    );
    let mut prev = s0;
    for i in 1..=N {
        nub.diag_decode_only(bytes.clone()).expect("decode_only");
        if i % STEP == 0 || i == 1 {
            let s = nub.heap_stats().expect("heap_stats");
            let delta = s.allocated_bytes as i64 - prev.allocated_bytes as i64;
            eprintln!(
                "{:>5}  {:>12}  {:>8}  {:>7}  {:>9}  {:>+9}",
                i, s.allocated_bytes, s.allocation_count, s.fragment_count, s.available_bytes, delta,
            );
            prev = s;
        }
    }
}

/// Bisect step 3: decode + run `Compiler::new(...).compile(...)` in
/// the guest, drop. No pool, no page-table, no ring 3. Isolates
/// whether the leak is in `javm-recompiler-x86`'s compiler itself.
#[test]
#[ignore]
fn heap_drift_compile_only() {
    use scale::Encode;

    let image = Image::decode(PRIME_SIEVE_BLOB).expect("decode prime_sieve Image").0;
    let spec = build_spec(&image, 0);
    let bytes = spec.encode();

    let mut nub = Nub::new_hyperlight().expect("sandbox");
    let s0 = nub.heap_stats().expect("baseline heap_stats");
    eprintln!(
        "iter         alloc_B    n_alloc   n_frag   avail_B   Δalloc (nub_compile_only)"
    );
    eprintln!(
        "{:>5}  {:>12}  {:>8}  {:>7}  {:>9}  {:>9}",
        0, s0.allocated_bytes, s0.allocation_count, s0.fragment_count, s0.available_bytes, 0i64,
    );
    let mut prev = s0;
    for i in 1..=N {
        nub.diag_compile_only(bytes.clone()).expect("compile_only");
        if i % STEP == 0 || i == 1 {
            let s = nub.heap_stats().expect("heap_stats");
            let delta = s.allocated_bytes as i64 - prev.allocated_bytes as i64;
            eprintln!(
                "{:>5}  {:>12}  {:>8}  {:>7}  {:>9}  {:>+9}",
                i, s.allocated_bytes, s.allocation_count, s.fragment_count, s.available_bytes, delta,
            );
            prev = s;
        }
    }
}

#[test]
#[ignore] // Run explicitly with --ignored to keep CI fast.
fn heap_drift_prime_sieve() {
    let image = Image::decode(PRIME_SIEVE_BLOB).expect("decode prime_sieve Image").0;
    let spec = build_spec(&image, 0);
    let mut nub = Nub::new_hyperlight().expect("sandbox");

    let s0 = nub.heap_stats().expect("baseline heap_stats");
    eprintln!(
        "iter         alloc_B    n_alloc   n_frag   avail_B   Δalloc"
    );
    eprintln!(
        "{:>5}  {:>12}  {:>8}  {:>7}  {:>9}  {:>9}",
        0, s0.allocated_bytes, s0.allocation_count, s0.fragment_count, s0.available_bytes, 0i64,
    );

    let mut prev = s0;
    for i in 1..=N {
        let result = nub.invoke_spec(&spec).expect("invoke_spec");
        assert_eq!(result.exit_reason, 4);
        assert_eq!(result.exit_arg, 0);

        if i % STEP == 0 || i == 1 {
            let s = nub.heap_stats().expect("heap_stats");
            let delta = s.allocated_bytes as i64 - prev.allocated_bytes as i64;
            eprintln!(
                "{:>5}  {:>12}  {:>8}  {:>7}  {:>9}  {:>+9}",
                i,
                s.allocated_bytes,
                s.allocation_count,
                s.fragment_count,
                s.available_bytes,
                delta,
            );
            prev = s;
        }
    }
}
