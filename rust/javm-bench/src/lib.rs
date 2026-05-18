//! Shared runners for `benches/pvm_bench.rs`.
//!
//! Both backends route through `Nub::invoke_spec(&InvocationSpec)`:
//!
//! - `run_interpreter` — `Nub::new_local()` drives the byte-PVM
//!   interpreter (`javm-exec`) in-process. Constructed per-call;
//!   `new_local()` is a trivial allocation.
//! - `run_recompiler` — a long-lived `Nub::new_hyperlight()` sandbox
//!   (cached in a `OnceLock`) drives the in-kernel JIT path via the
//!   same `invoke_spec` API. The sandbox boot (~hundreds of ms) lands
//!   on the first `nub_hyperlight()` call; subsequent calls reuse the
//!   cached instance, and the bench harness primes it via the sanity
//!   check before the timed loop.
//!
//! `build_spec` is the shared spec-builder — projects an `Image` +
//! endpoint onto an `InvocationSpec` once, before the iter loop.
//! Re-running the same spec is free; the per-iteration cost in the
//! bench is the `invoke_spec` call itself.
//!
//! Linux x86-64 only — `nub` pulls the Hyperlight host stack
//! unconditionally.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use javm_cap::image::{Image, PinnedCap};
use javm_exec::{REG_COUNT, unpack_bitmask};
use nub::{InvocationResult, InvocationSpec, Nub, PvmRegs};
use std::sync::{Mutex, OnceLock};

/// HostCall(0) — the trampoline halt all bench programs end on
/// (`ecalli 0`). Both backends surface it as `exit_reason=4,
/// exit_arg=0`.
const EXIT_HOSTCALL: u32 = 4;

/// Build an `InvocationSpec` from `image`'s endpoint. Builds once per
/// workload — the bench harness reuses the same spec across all
/// criterion iterations, so the per-iter cost stays in `invoke_spec`.
pub fn build_spec(image: &Image, endpoint_idx: u8, gas: u64) -> InvocationSpec {
    let bitmask = unpack_bitmask(&image.packed_bitmask, image.code.len());
    let endpoint = image
        .endpoints
        .get(&endpoint_idx)
        .unwrap_or_else(|| panic!("endpoint {endpoint_idx} not declared"));

    let mut regs = [0u64; REG_COUNT];
    regs[11] = endpoint_idx as u64; // calling-convention φ[11]
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
        initial_gas: gas,
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

/// Drive `spec` through the byte-PVM interpreter via
/// `Nub::new_local().invoke_spec(...)`. Returns `(return_value,
/// gas_used)` from the resulting trampoline halt.
pub fn run_interpreter(spec: &InvocationSpec) -> (u64, u64) {
    let mut nub = Nub::new_local();
    let result = nub
        .invoke_spec(spec)
        .unwrap_or_else(|e| panic!("interpreter invoke_spec: {e}"));
    finish(spec, &result)
}

/// Drive `spec` through the in-kernel JIT via the cached Hyperlight
/// `Nub`. Returns `(return_value, gas_used)` from the resulting
/// trampoline halt.
pub fn run_recompiler(spec: &InvocationSpec) -> (u64, u64) {
    let mut nub = nub_hyperlight().lock().expect("nub mutex");
    let result = nub
        .invoke_spec(spec)
        .unwrap_or_else(|e| panic!("recompiler invoke_spec: {e}"));
    finish(spec, &result)
}

fn finish(spec: &InvocationSpec, result: &InvocationResult) -> (u64, u64) {
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
    let gas_used = spec.initial_gas.saturating_sub(result.gas_remaining);
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
