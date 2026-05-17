//! Shared runners for `benches/pvm_bench.rs`.
//!
//! Two backends, both fed the same SCALE-decoded `Image`:
//!
//! - `run_interpreter` — drives the byte-PVM interpreter via
//!   `jar_kernel::Kernel::apply` (one event, empty payload).
//! - `run_recompiler` — Stage E2: ships the `Image` into a long-lived
//!   `nub::Nub` Hyperlight sandbox (cached in a `OnceLock` so
//!   per-iteration cost amortises the sandbox boot), drives the
//!   in-kernel JIT path via `Nub::invoke_spec`. Linux x86-64 only.

use jar_kernel::{Block, Event, EventOutcome, Kernel};
use javm_cap::image::Image;

/// Drive `image`'s `endpoint_idx` through the kernel interpreter
/// with `gas` budget. Returns `(return_value, gas_used)` from the
/// resulting `EventOutcome::Halt`.
pub fn run_interpreter(image: &Image, endpoint_idx: u8, gas: u64) -> (u64, u64) {
    let mut kernel = Kernel::from_genesis(image.clone());
    let outcomes = kernel
        .apply(
            &Block {
                events: vec![Event {
                    endpoint_idx,
                    payload: Vec::new(),
                }],
            },
            gas,
            gas,
        )
        .expect("kernel apply");
    assert_eq!(
        outcomes.len(),
        1,
        "endpoint {endpoint_idx}: expected one outcome"
    );
    match &outcomes[0] {
        EventOutcome::Halt {
            return_value,
            gas_used,
        } => (*return_value, *gas_used),
        other => panic!("endpoint {endpoint_idx}: expected Halt, got {other:?}"),
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use recomp::run_recompiler;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod recomp {
    use super::*;
    use javm_cap::image::PinnedCap;
    use javm_exec::{REG_COUNT, unpack_bitmask};
    use nub::{InvocationSpec, Nub, PvmRegs};
    use std::sync::{Mutex, OnceLock};

    /// Long-lived Hyperlight sandbox shared across bench iterations.
    /// Sandbox construction takes ~hundreds of ms; without caching,
    /// criterion's per-iteration cost would be dominated by it.
    fn nub() -> &'static Mutex<Nub> {
        static NUB: OnceLock<Mutex<Nub>> = OnceLock::new();
        NUB.get_or_init(|| Mutex::new(Nub::new_hyperlight().expect("Hyperlight sandbox")))
    }

    /// Drive `image`'s `endpoint_idx` through `Nub::invoke_spec`
    /// (in-kernel JIT, ring 3) with `gas` budget. Returns
    /// `(return_value, gas_used)` from the resulting `InvocationResult`.
    pub fn run_recompiler(image: &Image, endpoint_idx: u8, gas: u64) -> (u64, u64) {
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

        let spec = InvocationSpec {
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
        };

        let mut handle = nub().lock().expect("nub mutex");
        let result = handle
            .invoke_spec(&spec)
            .unwrap_or_else(|e| panic!("endpoint {endpoint_idx}: invoke_spec failed: {e}"));

        // The endpoint trampoline halts via `ecalli 0` (REPLY/HALT);
        // the in-kernel JIT surfaces this as exit_reason=4 (HostCall)
        // with exit_arg=0.
        assert_eq!(
            result.exit_reason, 4,
            "endpoint {endpoint_idx}: unexpected exit_reason {} (exit_arg={})",
            result.exit_reason, result.exit_arg,
        );
        assert_eq!(
            result.exit_arg, 0,
            "endpoint {endpoint_idx}: expected HostCall(0) trampoline halt, got HostCall({})",
            result.exit_arg,
        );

        let gas_used = gas.saturating_sub(result.gas_remaining);
        (result.return_value, gas_used)
    }

    /// Walk the Image's memory mappings + slot contents and project
    /// them onto the recompiler's flat `(arg, ro, rw)` shape.
    ///
    /// - `ro`: the unique pinned mapping (typically `.rodata`).
    /// - `rw`: the unique non-pinned mapping whose initial slot has
    ///   non-empty content (typically `.data`).
    /// - Stack and heap have empty `content` — they live within
    ///   `mem_size` as implicit zero-initialised RW pages.
    /// - `arg`: empty (no payload delivery).
    /// - `mem_size`: `max(mapping.start + mapping.size)` over all
    ///   mappings.
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
}
