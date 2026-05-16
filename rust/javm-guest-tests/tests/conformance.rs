//! Three-way conformance harness.
//!
//! Each entry in [`javm_guest_tests::SUITE_TABLE`] is driven three
//! ways:
//!
//! 1. **Native** — call the host fn directly.
//! 2. **Interpreter** — load the transpiled Image into a fresh
//!    `jar_kernel::Kernel`, apply a single event targeting the
//!    endpoint, read `EventOutcome::Halt::{return_value, gas_used}`.
//! 3. **Recompiler** — load the Image's `(code, bitmask, jump_table)`
//!    into a standalone `RecompiledPvm` (Linux x86-64 only). Build
//!    its `DataLayout` from `memory_mappings + pinned_slots +
//!    initial_slots`. Seed `regs` and `PC` from the endpoint
//!    definition. Run; read `φ[7]` post-halt and `GAS_BUDGET - gas()`
//!    for the consumed gas.
//!
//! Assertions:
//! - native == interpreter == recompiler return value.
//! - interpreter gas == recompiler gas.

use jar_cap::image::{Image, PinnedCap};
use jar_kernel::{Block, Event, EventOutcome, Kernel};
use scale::Decode;

const BLOB: &[u8] = include_bytes!(env!("GUEST_TESTS_BLOB"));
const GAS_BUDGET: u64 = 10_000_000_000;

fn image() -> Image {
    Image::decode(BLOB)
        .expect("SCALE-decode guest-tests Image")
        .0
}

fn run_interpreter(image: &Image, ep: u8) -> (u64, u64) {
    let mut kernel = Kernel::from_genesis(image.clone());
    let outcomes = kernel
        .apply(
            &Block {
                events: vec![Event {
                    endpoint_idx: ep,
                    payload: Vec::new(),
                }],
            },
            GAS_BUDGET,
            GAS_BUDGET,
        )
        .expect("kernel apply");
    assert_eq!(outcomes.len(), 1, "endpoint {ep}: expected one outcome");
    match &outcomes[0] {
        EventOutcome::Halt {
            return_value,
            gas_used,
        } => (*return_value, *gas_used),
        other => panic!("endpoint {ep}: expected Halt, got {other:?}"),
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod recomp {
    use super::*;
    use javm_exec::recompiler::{DataLayout, RecompiledPvm};
    use javm_exec::{compute_mem_cycles, unpack_bitmask, ExitReason, REG_COUNT};

    pub fn run(image: &Image, ep: u8) -> (u64, u64) {
        let bitmask = unpack_bitmask(&image.packed_bitmask, image.code.len());
        let endpoint = image
            .endpoints
            .get(&ep)
            .unwrap_or_else(|| panic!("endpoint {ep} not declared in Image"));

        let mut regs = [0u64; REG_COUNT];
        regs[11] = ep as u64; // calling-convention φ[11] = endpoint_idx
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
            GAS_BUDGET,
            Some(layout),
            mem_cycles,
        )
        .unwrap_or_else(|e| panic!("RecompiledPvm::new failed: {e}"));
        recomp.set_pc(endpoint.entry_pc as u32);

        let exit = recomp.run();
        // The endpoint trampoline halts via `ecalli 0` (REPLY/HALT).
        // The recompiler surfaces this as `HostCall(0)`; the
        // interpreter routes the same opcode through `EcallHandler`
        // and we see `Halt` after that translation. Accept either.
        assert!(
            matches!(exit, ExitReason::Halt | ExitReason::HostCall(0)),
            "endpoint {ep}: unexpected exit {exit:?}",
        );

        let return_value = recomp.registers()[7];
        let gas_used = GAS_BUDGET - recomp.gas();
        (return_value, gas_used)
    }

    /// Walk the Image's memory mappings + slot contents and project
    /// them onto the recompiler's flat `(arg, ro, rw)` shape.
    ///
    /// - `ro`: the unique pinned mapping (typically `.rodata`).
    /// - `rw`: the unique non-pinned mapping whose initial slot has
    ///   non-empty content (typically `.data`). Stack and heap
    ///   regions have empty `content` — they live within `mem_size`
    ///   as zero-initialised RW pages and don't need an explicit
    ///   `rw_data` entry.
    /// - `arg`: empty (no payload delivery; the suite bakes its
    ///   inputs into the guest).
    /// - `mem_size`: `max(mapping.start + mapping.size)` over all
    ///   mappings — covers stack, ro, rw, and heap.
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
            } else if let Some(init) = image.initial_slots.get(&target) {
                if !init.content.is_empty() {
                    assert!(
                        rw.is_none(),
                        "multiple non-empty initial mappings not supported"
                    );
                    rw = Some((mapping.start as u32, init.content.clone()));
                }
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

fn conform(ep: u8, name: &str, host_fn: fn() -> u64) {
    let image = image();
    let host = host_fn();

    let (interp_value, interp_gas) = run_interpreter(&image, ep);
    assert_eq!(
        host, interp_value,
        "[{name} ep={ep}] host vs interpreter: {host:#018x} vs {interp_value:#018x}",
    );

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let (recomp_value, recomp_gas) = recomp::run(&image, ep);
        assert_eq!(
            host, recomp_value,
            "[{name} ep={ep}] host vs recompiler: {host:#018x} vs {recomp_value:#018x}",
        );
        assert_eq!(
            interp_gas, recomp_gas,
            "[{name} ep={ep}] gas mismatch: interp {interp_gas} vs recomp {recomp_gas}",
        );
    }
}

#[test]
fn every_suite_matches_three_ways() {
    for &(ep, name, host_fn) in javm_guest_tests::SUITE_TABLE {
        conform(ep, name, host_fn);
    }
}
