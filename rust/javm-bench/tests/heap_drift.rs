//! Regression test: the guest heap must not grow across repeated
//! `Nub::invoke_spec` calls. Runs `prime_sieve` 2000 times against a
//! single Hyperlight sandbox, sampling `talc`'s counters every 100
//! iters; asserts that allocated bytes and allocation count are
//! exactly bit-stable from iter 1 onward (iter 0 → 1 is allowed to
//! grow once for one-shot static init).
//!
//! Catches re-introduction of the kind of leak we fixed in commit
//! ad8b227d — there `install_ring3_exit_gate` was `Box::leak`ing 4106
//! B per invocation, exhausting the heap during long bench runs.
//!
//! Requires the `heap-diag` feature. Run with:
//!
//! ```bash
//! cargo test -p javm-bench --test heap_drift --features heap-diag \
//!     --release -- --ignored --nocapture
//! ```

#![cfg(all(target_os = "linux", target_arch = "x86_64", feature = "heap-diag"))]

use javm_cap::image::{Image, PinnedCap};
use javm_exec::{REG_COUNT, unpack_bitmask};
use nub::{InvocationSpec, Nub, PvmRegs};
use scale::Decode;

const PRIME_SIEVE_BLOB: &[u8] = include_bytes!(env!("PRIME_SIEVE_BLOB"));
const GAS: u64 = 100_000_000_000;
const N: usize = 2000;
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

#[test]
#[ignore]
fn heap_drift_prime_sieve() {
    let image = Image::decode(PRIME_SIEVE_BLOB)
        .expect("decode prime_sieve Image")
        .0;
    let spec = build_spec(&image, 0);
    let mut nub = Nub::new_hyperlight().expect("sandbox");

    // Iter 0: baseline.
    let _ = nub.heap_stats().expect("baseline heap_stats");

    // Iter 1: lets any first-call static init (e.g. one-shot IDT
    // install in `install_ring3_exit_gate`) settle.
    let _ = nub.invoke_spec(&spec).expect("invoke_spec");
    let warm = nub.heap_stats().expect("post-warmup heap_stats");
    eprintln!("iter         alloc_B    n_alloc   n_frag   avail_B   Δalloc");
    eprintln!(
        "{:>5}  {:>12}  {:>8}  {:>7}  {:>9}  {:>9}",
        1,
        warm.allocated_bytes,
        warm.allocation_count,
        warm.fragment_count,
        warm.available_bytes,
        0i64,
    );

    // Iters 2..=N: should be exactly bit-stable.
    for i in 2..=N {
        nub.invoke_spec(&spec).expect("invoke_spec");
        if i % STEP == 0 {
            let s = nub.heap_stats().expect("heap_stats");
            let delta = s.allocated_bytes as i64 - warm.allocated_bytes as i64;
            eprintln!(
                "{:>5}  {:>12}  {:>8}  {:>7}  {:>9}  {:>+9}",
                i,
                s.allocated_bytes,
                s.allocation_count,
                s.fragment_count,
                s.available_bytes,
                delta,
            );
            assert_eq!(
                s.allocated_bytes, warm.allocated_bytes,
                "heap drifted at iter {i}: {} bytes vs warm {} bytes",
                s.allocated_bytes, warm.allocated_bytes,
            );
            assert_eq!(
                s.allocation_count, warm.allocation_count,
                "allocation count drifted at iter {i}: {} vs warm {}",
                s.allocation_count, warm.allocation_count,
            );
        }
    }
}
