//! Three-way conformance harness.
//!
//! Each entry in [`javm_guest_tests::SUITE_TABLE`] is driven three
//! ways:
//!
//! 1. **Native** — call the host fn directly.
//! 2. **Interpreter** — load the transpiled Image into a fresh
//!    `jar_kernel::Kernel`, apply a single event targeting the
//!    endpoint, read `EventOutcome::Halt::{return_value, gas_used}`.
//! 3. **Recompiler (in-kernel JIT)** — Stage E1: ship the program
//!    into a `nub::Nub` Hyperlight sandbox via `invoke_spec`. The
//!    guest's `nub_invoke` entry compiles + runs the program at ring
//!    3 with its own page table; the host reads `(return_value,
//!    gas_remaining)` out of the resulting `InvocationResult`.
//!
//! Assertions:
//! - native == interpreter == recompiler return value.
//! - interpreter gas == recompiler gas.

use jar_kernel::{Block, Event, EventOutcome, Kernel};
use javm_cap::image::Image;
use ssz::Decode;

const BLOB: &[u8] = include_bytes!(env!("GUEST_TESTS_BLOB"));
const GAS_BUDGET: u64 = 10_000_000_000;

fn image() -> Image {
    Image::from_ssz_bytes(BLOB).expect("SSZ-decode guest-tests Image")
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
    use javm_cap::NUM_REGS;
    use nub::Nub;
    use std::sync::{Mutex, OnceLock};

    /// One Hyperlight sandbox shared across every test thread. Cargo
    /// runs tests in parallel by default but `Nub::new_hyperlight()`
    /// reserves a fixed host VA range and only one live sandbox per
    /// process can occupy it (see
    /// `nub_host_common::layout::reserve_guest_va_range`). The same
    /// pattern is used by the bench drivers in `javm-bench`. Sandbox
    /// construction also takes ~hundreds of ms; sharing keeps the
    /// conformance run dominated by JIT execution rather than boot.
    fn nub_hyperlight() -> &'static Mutex<Nub> {
        static NUB: OnceLock<Mutex<Nub>> = OnceLock::new();
        NUB.get_or_init(|| Mutex::new(Nub::new_hyperlight().expect("Hyperlight sandbox")))
    }

    pub fn run(image: &Image, ep: u8) -> (u64, u64) {
        let endpoint = image
            .endpoints
            .get(&ep)
            .unwrap_or_else(|| panic!("endpoint {ep} not declared in Image"));

        // Endpoint invocation = process spawn; `initial_regs` is the
        // bootstrap snapshot. Endpoint is encoded by PC, not by a
        // kernel-written selector register.
        let mut regs = [0u64; NUM_REGS];
        for (&i, &v) in &endpoint.initial_regs {
            if let Some(slot) = regs.get_mut(i as usize) {
                *slot = v;
            }
        }

        let mem = image.instance_mem_backing();

        let mut nub = nub_hyperlight().lock().expect("nub mutex");
        // Publish the canonical Image + an empty root CNode + an
        // InstanceCap binding both. Build each as a Cap<Global>;
        // the cache deep-clones into talc on first put and just
        // bumps refcounts on re-puts of identical content.
        use javm_cap::image::PinnedCap;
        use javm_cap::Cap;
        // Publish a Cap::Data per pinned/initial slot and bind the Image to
        // them — matching production (the jar-kernel + bench `BuiltCaps`
        // path) and the interpreter. The Instance's `mem` backing
        // (`instance_mem_backing`) folds these same slot contents in, so both
        // engines materialize byte-identical memory with matching gas tiers.
        let mut pinned_hashes = Vec::new();
        let mut initial_hashes = Vec::new();
        for (slot, pinned) in &image.pinned_slots {
            let h = match pinned {
                PinnedCap::Data { content, size } => {
                    let cap = Cap::data_inline_with_size(content, *size);
                    nub.put_cap(&cap)
                        .unwrap_or_else(|e| panic!("endpoint {ep}: put_cap pinned data: {e}"))
                }
                PinnedCap::Image { content_hash } => *content_hash,
            };
            pinned_hashes.push((*slot, h));
        }
        for (slot, init) in &image.initial_slots {
            let cap = Cap::data_inline_with_size(&init.content, init.size);
            let h = nub
                .put_cap(&cap)
                .unwrap_or_else(|e| panic!("endpoint {ep}: put_cap initial data: {e}"));
            initial_hashes.push((*slot, h));
        }
        let image_cap = Cap::image_with_slots(image, &pinned_hashes, &initial_hashes)
            .unwrap_or_else(|e| panic!("endpoint {ep}: image_with_slots: {e}"));
        let image_h = nub
            .put_cap(&image_cap)
            .unwrap_or_else(|e| panic!("endpoint {ep}: put_cap image: {e}"));
        let cnode_cap = Cap::empty_cnode();
        let cnode_h = nub
            .put_cap(&cnode_cap)
            .unwrap_or_else(|e| panic!("endpoint {ep}: put_cap cnode: {e}"));
        let instance_cap = Cap::instance_with_mem([0u8; 32], image_h, cnode_h, mem, regs, 0, 0);
        let instance_hash = nub
            .put_cap(&instance_cap)
            .unwrap_or_else(|e| panic!("endpoint {ep}: put_cap instance: {e}"));
        let result = nub
            .invoke_cached(instance_hash, ep, [0; 4], GAS_BUDGET)
            .unwrap_or_else(|e| panic!("endpoint {ep}: invoke_cached failed: {e}"));

        // The endpoint trampoline halts via `ecalli 0` (REPLY/HALT).
        // The in-kernel JIT surfaces this as exit_reason=4 (HostCall)
        // with exit_arg=0; report a panic if we got anything else.
        assert_eq!(
            result.exit_reason, 4,
            "endpoint {ep}: unexpected exit_reason {} (exit_arg={})",
            result.exit_reason, result.exit_arg,
        );
        assert_eq!(
            result.exit_arg, 0,
            "endpoint {ep}: expected HostCall(0) trampoline halt, got HostCall({})",
            result.exit_arg,
        );

        let gas_used = GAS_BUDGET.saturating_sub(result.gas_remaining);
        (result.return_value, gas_used)
    }

    // Instance memory comes from `Image::instance_mem_backing()` (javm-cap)
    // — the single source of truth the kernel + bench paths share, so the
    // conformance oracle can't silently diverge from them.
}

fn conform(ep: u8, name: &str, host_fn: fn() -> u64) {
    let image = image();
    let host = host_fn();

    // `_interp_gas` is only consumed by the recomp gas-equality
    // check below, which is cfg'd to Linux x86_64. Underscore prefix
    // silences `unused_variables` on other targets.
    let (interp_value, _interp_gas) = run_interpreter(&image, ep);
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
            _interp_gas, recomp_gas,
            "[{name} ep={ep}] gas mismatch: interp {_interp_gas} vs recomp {recomp_gas}",
        );
    }
}

#[test]
fn every_suite_matches_three_ways() {
    for &(ep, name, host_fn) in javm_guest_tests::SUITE_TABLE {
        conform(ep, name, host_fn);
    }
}
