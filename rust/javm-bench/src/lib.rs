//! Shared runners for `benches/pvm_bench.rs`.
//!
//! Two backends, both fed the same SCALE-decoded `Image`:
//!
//! - `run_interpreter` — drives the byte-PVM interpreter via
//!   `jar_kernel::Kernel::apply` (one event, empty payload).
//! - `run_recompiler` — drives the JIT recompiler standalone with
//!   a `DataLayout` projected from the Image's mappings. Linux
//!   x86-64 only.
//!
//! The pattern duplicates
//! `rust/javm-guest-tests/tests/conformance.rs` rather than
//! extracting a shared crate, because the bench and conformance
//! consumers will pull these helpers in different directions
//! (e.g., the bench may eventually reuse one JIT compilation
//! across iterations).

use javm_cap::image::Image;
use jar_kernel::{Block, Event, EventOutcome, Kernel};

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
    use javm_exec::recompiler::{DataLayout, RecompiledPvm};
    use javm_exec::{ExitReason, REG_COUNT, compute_mem_cycles, unpack_bitmask};

    /// Drive `image`'s `endpoint_idx` through a fresh `RecompiledPvm`
    /// (one JIT compile per call) with `gas` budget. Returns
    /// `(return_value, gas_used)` reading `registers[7]` and
    /// `gas - recomp.gas()`.
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

        let layout = build_data_layout(image);
        let total_pages = (layout.mem_size as u64).div_ceil(4096) as u32;
        let mem_cycles = compute_mem_cycles(total_pages);

        let mut recomp = RecompiledPvm::new(
            &image.code,
            bitmask,
            image.jump_table.clone(),
            regs,
            gas,
            Some(layout),
            mem_cycles,
        )
        .unwrap_or_else(|e| panic!("RecompiledPvm::new failed: {e}"));
        recomp.set_pc(endpoint.entry_pc as u32);

        let exit = recomp.run();
        // The endpoint trampoline halts via `ecalli 0` (REPLY/HALT).
        // The recompiler surfaces this as `HostCall(0)`; the
        // interpreter routes the same opcode through `EcallHandler`
        // and we'd see `Halt` after that translation. Accept either.
        assert!(
            matches!(exit, ExitReason::Halt | ExitReason::HostCall(0)),
            "endpoint {endpoint_idx}: unexpected exit {exit:?}",
        );

        let return_value = recomp.registers()[7];
        let gas_used = gas - recomp.gas();
        (return_value, gas_used)
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
    fn build_data_layout(image: &Image) -> DataLayout {
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

        DataLayout {
            mem_size,
            arg_start: 0,
            arg_data: Vec::new(),
            ro_start,
            ro_data,
            rw_start,
            rw_data,
        }
    }
}
