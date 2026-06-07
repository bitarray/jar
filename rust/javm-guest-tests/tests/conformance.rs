//! Conformance harness: one driver, two backends.
//!
//! Each entry in [`javm_guest_tests::SUITE_TABLE`] is checked three ways:
//!
//! 1. **Native** — call the host fn directly.
//! 2. **Interpreter** — publish the Image + Instance into a local
//!    [`nub::Nub`] (`nub-arch-local`, the PVM2/RISC-V interpreter run
//!    in-process) and `invoke_cached`.
//! 3. **Recompiler** — publish into a Hyperlight-backed [`nub::Nub`] (the
//!    `nub-arch-x86` in-kernel JIT) and `invoke_cached`.
//!
//! Both PVM arms go through the *same* publish + invoke code
//! ([`backend::run`]); the only difference is the substrate, so the
//! conformance oracle cannot silently diverge between the two engines.
//!
//! Assertions:
//! - native == interpreter == recompiler return value.
//! - interpreter gas == recompiler gas — the interp-vs-JIT cross-check
//!   that catches transpiler/codegen divergences.
//!
//! The nub backends need the KVM/Hyperlight host, so the PVM arms are
//! linux-x86_64 only; on other targets only the native fingerprint runs.

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod backend {
    use javm_cap::image::{Image, PinnedCap};
    use javm_cap::{Cap, Key, NUM_REGS};
    use nub::Nub;
    use ssz::Decode;
    use std::sync::{Mutex, OnceLock};

    const BLOB: &[u8] = include_bytes!(env!("GUEST_TESTS_BLOB"));
    const GAS_BUDGET: u64 = 10_000_000_000;

    pub fn image() -> Image {
        Image::from_ssz_bytes(BLOB).expect("SSZ-decode guest-tests Image")
    }

    /// One Hyperlight sandbox shared across every test thread.
    /// `Nub::new_hyperlight()` reserves a fixed host VA range and only one
    /// live sandbox per process can occupy it (see
    /// `nub_host_common::layout::reserve_guest_va_range`); sandbox
    /// construction also costs ~hundreds of ms, so sharing keeps the run
    /// dominated by JIT execution rather than boot. The same pattern is
    /// used by the bench drivers in `javm-bench`.
    fn hyperlight() -> &'static Mutex<Nub> {
        static NUB: OnceLock<Mutex<Nub>> = OnceLock::new();
        NUB.get_or_init(|| Mutex::new(Nub::new_hyperlight().expect("Hyperlight sandbox")))
    }

    /// Interpreter arm: a fresh in-process `LocalArch` Nub per call (cheap —
    /// no sandbox).
    pub fn interp(image: &Image, ep: u8) -> (u64, u64) {
        run(&mut Nub::new_local(), image, ep)
    }

    /// Recompiler arm: the shared Hyperlight sandbox.
    pub fn recomp(image: &Image, ep: u8) -> (u64, u64) {
        run(&mut hyperlight().lock().expect("nub mutex"), image, ep)
    }

    /// Publish the canonical Image + an empty root CNode + an Instance
    /// binding both into `nub`, invoke endpoint `ep`, and return
    /// `(return_value, gas_used)`. Backend-agnostic: the local interpreter
    /// and the x86 JIT run byte-identical inputs through this one path.
    fn run(nub: &mut Nub, image: &Image, ep: u8) -> (u64, u64) {
        let endpoint = image
            .endpoints
            .get(&Key::from(ep))
            .unwrap_or_else(|| panic!("endpoint {ep} not declared in Image"));

        // Endpoint invocation = process spawn; `initial_regs` is the
        // bootstrap snapshot. The endpoint is encoded by PC, not by a
        // kernel-written selector register.
        let mut regs = [0u64; NUM_REGS];
        for (&i, &v) in &endpoint.initial_regs {
            if let Some(slot) = regs.get_mut(i as usize) {
                *slot = v;
            }
        }

        // Instance memory comes from `Image::instance_mem_backing()`
        // (javm-cap) — the single source of truth the kernel + bench paths
        // share, so the conformance oracle can't silently diverge from them.
        let mem = image.instance_mem_backing();

        // Publish a Cap::Data per pinned/initial slot and bind the Image to
        // them — matching production. The Instance's `mem` backing folds
        // these same slot contents in, so both engines materialize
        // byte-identical memory with matching gas tiers.
        let mut pinned_hashes = Vec::new();
        for (slot, pinned) in &image.pinned_slots {
            let h = match pinned {
                PinnedCap::Data { content, size } => {
                    let cap = Cap::data_inline_with_size(content, *size);
                    nub.put_cap(&cap)
                        .unwrap_or_else(|e| panic!("endpoint {ep}: put_cap pinned data: {e}"))
                }
                PinnedCap::Image { content_hash } => *content_hash,
            };
            pinned_hashes.push((slot.clone(), h));
        }
        let mut initial_hashes = Vec::new();
        for (slot, init) in &image.initial_slots {
            let cap = Cap::data_inline_with_size(&init.content, init.size);
            let h = nub
                .put_cap(&cap)
                .unwrap_or_else(|e| panic!("endpoint {ep}: put_cap initial data: {e}"));
            initial_hashes.push((slot.clone(), h));
        }

        let image_cap = Cap::image_with_slots(image, &pinned_hashes, &initial_hashes)
            .unwrap_or_else(|e| panic!("endpoint {ep}: image_with_slots: {e}"));
        let image_h = nub
            .put_cap(&image_cap)
            .unwrap_or_else(|e| panic!("endpoint {ep}: put_cap image: {e}"));
        let cnode_h = nub
            .put_cap(&Cap::empty_cnode())
            .unwrap_or_else(|e| panic!("endpoint {ep}: put_cap cnode: {e}"));
        let instance_cap = Cap::instance_with_mem([0u8; 32], image_h, cnode_h, mem, regs, 0, 0);
        let instance_hash = nub
            .put_cap(&instance_cap)
            .unwrap_or_else(|e| panic!("endpoint {ep}: put_cap instance: {e}"));

        let result = nub
            .invoke_cached(instance_hash, ep, [0; 4], GAS_BUDGET)
            .unwrap_or_else(|e| panic!("endpoint {ep}: invoke_cached failed: {e}"));

        // The endpoint trampoline halts via `ecalli 0` (REPLY/HALT), surfaced
        // by both engines as exit_reason=4 (HostCall) with exit_arg=0.
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
}

fn conform(ep: u8, name: &str, host_fn: fn() -> u64) {
    let host = host_fn();

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let image = backend::image();
        let (interp_value, interp_gas) = backend::interp(&image, ep);
        let (recomp_value, recomp_gas) = backend::recomp(&image, ep);
        assert_eq!(
            host, interp_value,
            "[{name} ep={ep}] host vs interpreter: {host:#018x} vs {interp_value:#018x}",
        );
        assert_eq!(
            host, recomp_value,
            "[{name} ep={ep}] host vs recompiler: {host:#018x} vs {recomp_value:#018x}",
        );
        assert_eq!(
            interp_gas, recomp_gas,
            "[{name} ep={ep}] gas mismatch: interp {interp_gas} vs recomp {recomp_gas}",
        );
    }

    // On non-(linux x86_64) targets the nub backends are unavailable; only
    // the native fingerprint is computed.
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    let _ = (host, ep, name);
}

#[test]
fn every_suite_matches_three_ways() {
    for &(ep, name, host_fn) in javm_guest_tests::SUITE_TABLE {
        conform(ep, name, host_fn);
    }
}
