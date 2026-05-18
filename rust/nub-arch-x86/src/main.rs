//! Nub Arch implementation for Hyperlight: a bare-metal guest binary
//! that runs the PVM in-kernel JIT path on real CPU + MMU.
//!
//! Built with `nub-build` → `cargo build --target=x86_64-unknown-none`.
//! Links against `nub-arch-guestbin` (our forked + trimmed
//! `hyperlight-guest-bin`). Entry point is `entrypoint` (supplied by
//! guestbin), which initialises the heap + GDT + IDT then calls
//! `hyperlight_main`. We don't define `hyperlight_main` ourselves; the
//! weak default in guestbin is fine.
//!
//! Guest functions are registered via `#[guest_function]`, which
//! uses `linkme` to slot them into a static `GuestFunctionRegister`
//! at compile time. The host invokes them by name via Hyperlight's
//! `OUT`-port + shared-memory function-call ABI.
//!
//! On host targets (target_os != "none") this crate compiles to a
//! trivial empty `main` so `cargo build --workspace` succeeds without
//! dragging Hyperlight-guest deps onto host platforms. Only
//! `cargo build --target=x86_64-unknown-none` produces a real guest
//! ELF.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
extern crate alloc;
#[cfg(target_os = "none")]
extern crate hyperlight_guest_bin;

#[cfg(target_os = "none")]
mod bump;
#[cfg(target_os = "none")]
mod jit_run;
#[cfg(target_os = "none")]
mod paging;
#[cfg(target_os = "none")]
mod pool;
#[cfg(target_os = "none")]
mod ring3;
#[cfg(target_os = "none")]
mod segments;

#[cfg(target_os = "none")]
mod guest {
    use alloc::vec::Vec;
    use nub_arch_x86_abi::{InvocationResult, InvocationSpec};
    use scale::{Decode, Encode};

    use hyperlight_guest_bin::guest_function;

    /// Skeleton stand-in for the `Nub::invoke` RPC (the `Arch::invoke`
    /// trait surface, still mid-wiring). The host's
    /// `Nub::new_hyperlight().invoke(...)` calls into this; returns 42
    /// to match `nub_arch_local::LocalArch`'s stubbed return value so
    /// both backends look identical to the test harness. Real
    /// dispatch — driven by `Kernel<HyperlightArch>` in the guest —
    /// lands in a follow-up commit (Stage 3+).
    #[guest_function("nub_smoke")]
    pub fn nub_smoke() -> u64 {
        42
    }

    /// SCALE-decode the host's `InvocationSpec` from `spec_bytes`,
    /// run the embedded PVM program through the in-kernel JIT path
    /// (`jit_run::run_pvm_with_mem`), SCALE-encode an
    /// `InvocationResult` and return it.
    ///
    /// This is the host-facing RPC the `Nub::invoke_spec` driver
    /// calls. The wire types live in `nub-arch-x86-abi`.
    #[guest_function("nub_invoke")]
    pub fn nub_invoke(spec_bytes: Vec<u8>) -> Vec<u8> {
        let spec = match InvocationSpec::decode(&spec_bytes) {
            Ok((s, _consumed)) => s,
            Err(_) => {
                // Malformed input — return an error sentinel.
                return InvocationResult {
                    exit_reason: u32::MAX,
                    exit_arg: 1,
                    return_value: 0,
                    gas_remaining: 0,
                }
                .encode();
            }
        };

        let info = unsafe {
            crate::jit_run::run_pvm_with_mem(
                &spec.code,
                &spec.bitmask,
                &spec.jump_table,
                spec.initial_gas as i64,
                spec.entry_pc,
                spec.initial_regs.into_array(),
                spec.mem_size,
                crate::jit_run::MemRegion {
                    start: spec.arg_start,
                    data: &spec.arg_data,
                },
                crate::jit_run::MemRegion {
                    start: spec.ro_start,
                    data: &spec.ro_data,
                },
                crate::jit_run::MemRegion {
                    start: spec.rw_start,
                    data: &spec.rw_data,
                },
            )
        };

        let result = match info {
            Some(i) => InvocationResult {
                exit_reason: i.exit_reason,
                exit_arg: i.exit_arg,
                return_value: i.reg_a0,
                gas_remaining: i.gas_remaining.max(0) as u64,
            },
            None => InvocationResult {
                exit_reason: u32::MAX,
                exit_arg: 2,
                return_value: 0,
                gas_remaining: 0,
            },
        };

        result.encode()
    }

    /// Diagnostic: report talc's current allocation state as 32 LE
    /// bytes packing `[allocated_bytes, allocation_count,
    /// fragment_count, available_bytes]` (four u64s). Used to detect
    /// per-iter heap leaks — `allocated_bytes` growing monotonically
    /// indicates a real leak; `allocated_bytes` oscillating with
    /// `fragment_count` climbing indicates fragmentation.
    ///
    /// Gated on `heap-diag` because reading the counters requires
    /// talc's `counters` feature, which adds a small per-alloc cost.
    #[cfg(feature = "heap-diag")]
    #[guest_function("nub_heap_stats")]
    pub fn nub_heap_stats() -> Vec<u8> {
        let counters = hyperlight_guest_bin::HEAP_ALLOCATOR
            .lock()
            .counters()
            .clone();
        let mut buf = alloc::vec![0u8; 32];
        buf[0..8].copy_from_slice(&(counters.allocated_bytes as u64).to_le_bytes());
        buf[8..16].copy_from_slice(&(counters.allocation_count as u64).to_le_bytes());
        buf[16..24].copy_from_slice(&(counters.fragment_count as u64).to_le_bytes());
        buf[24..32].copy_from_slice(&(counters.available_bytes as u64).to_le_bytes());
        buf
    }
}

/// Empty `main` so `cargo build --workspace` (host target) succeeds
/// without including any of the bare-metal guest code. The real entry
/// point on `x86_64-unknown-none` is `entrypoint` from the linked
/// guestbin.
#[cfg(not(target_os = "none"))]
fn main() {}
