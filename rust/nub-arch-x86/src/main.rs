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
//! Guest functions are registered via `#[guest_function(fn_id = N)]`
//! from `nub-host-guest-macro`, which slots them into a `linkme`
//! distributed-slice (`GUEST_FUNCTION_TABLE`) at compile time. The
//! host invokes them by `fn_id` via Hyperlight's `OUT`-port +
//! shared-memory function-call ABI, with rkyv-encoded
//! `Request` / `Response` envelopes.
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
mod jit_run;
#[cfg(target_os = "none")]
mod paging;
#[cfg(target_os = "none")]
mod ring3;
#[cfg(target_os = "none")]
mod segments;
#[cfg(target_os = "none")]
mod state_cache;

#[cfg(target_os = "none")]
mod guest {
    use alloc::vec::Vec;
    use hyperlight_guest_bin::guest_function;
    #[cfg(feature = "heap-diag")]
    use nub_arch_x86_abi::FN_ID_NUB_HEAP_STATS;
    use nub_arch_x86_abi::{
        ArchivedInvocationSpec, FN_ID_NUB_INVOKE, FN_ID_NUB_INVOKE_CACHED, FN_ID_NUB_SMOKE,
        InvocationResult, InvokePacket,
    };
    use rkyv::util::AlignedVec;

    /// Skeleton stand-in for the `Nub::invoke` RPC. The host's
    /// `Nub::new_hyperlight().invoke(...)` calls into this; returns 42
    /// to match `nub_arch_local::LocalArch`'s stubbed return value so
    /// both backends look identical to the test harness.
    #[guest_function(fn_id = FN_ID_NUB_SMOKE)]
    pub fn nub_smoke(_input: &[u8]) -> Vec<u8> {
        let v: u64 = 42;
        rkyv::to_bytes::<rkyv::rancor::Error>(&v)
            .expect("rkyv-encode u64")
            .into_vec()
    }

    /// rkyv-decode the host's `InvocationSpec` from `spec_bytes`,
    /// run the embedded PVM program through the in-kernel JIT path
    /// (`jit_run::run_pvm_with_mem`), rkyv-encode an
    /// `InvocationResult` and return it.
    ///
    /// This is the host-facing RPC the `Nub::invoke_spec` driver
    /// calls. The wire types live in `nub-arch-x86-abi`.
    #[guest_function(fn_id = FN_ID_NUB_INVOKE)]
    pub fn nub_invoke(spec_bytes: &[u8]) -> Vec<u8> {
        // rkyv::access wants an aligned buffer; the ring is byte-
        // addressed and the upstream `internal_dispatch_function`
        // already copied request bytes into an AlignedVec — but the
        // *inner* payload slice we get here is a sub-slice of that
        // and may be misaligned. Copy once more.
        let mut aligned = AlignedVec::<16>::with_capacity(spec_bytes.len());
        aligned.extend_from_slice(spec_bytes);

        let spec =
            match rkyv::access::<ArchivedInvocationSpec, rkyv::rancor::Error>(aligned.as_slice()) {
                Ok(s) => s,
                Err(_) => return encode_result_error(1),
            };

        // The JIT's `run_pvm_with_mem` takes `&[u32]` (native). Each
        // archived element is endian-converted via `.to_native()` —
        // bind the resulting Vec to a local so its slice stays live.
        let jump_table: Vec<u32> = spec.jump_table.iter().map(|v| v.to_native()).collect();
        let initial_regs: [u64; 13] = [
            spec.initial_regs.0.to_native(),
            spec.initial_regs.1.to_native(),
            spec.initial_regs.2.to_native(),
            spec.initial_regs.3.to_native(),
            spec.initial_regs.4.to_native(),
            spec.initial_regs.5.to_native(),
            spec.initial_regs.6.to_native(),
            spec.initial_regs.7.to_native(),
            spec.initial_regs.8.to_native(),
            spec.initial_regs.9.to_native(),
            spec.initial_regs.10.to_native(),
            spec.initial_regs.11.to_native(),
            spec.initial_regs.12.to_native(),
        ];

        let info = unsafe {
            crate::jit_run::run_pvm_with_mem(
                spec.code.as_slice(),
                spec.bitmask.as_slice(),
                &jump_table,
                spec.initial_gas.to_native() as i64,
                spec.entry_pc.to_native(),
                initial_regs,
                spec.mem_size.to_native(),
                crate::jit_run::MemRegion {
                    start: spec.arg_start.to_native(),
                    data: spec.arg_data.as_slice(),
                },
                crate::jit_run::MemRegion {
                    start: spec.ro_start.to_native(),
                    data: spec.ro_data.as_slice(),
                },
                crate::jit_run::MemRegion {
                    start: spec.rw_start.to_native(),
                    data: spec.rw_data.as_slice(),
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

        rkyv::to_bytes::<rkyv::rancor::Error>(&result)
            .expect("rkyv-encode InvocationResult")
            .into_vec()
    }

    fn encode_result_error(exit_arg: u32) -> Vec<u8> {
        let result = InvocationResult {
            exit_reason: u32::MAX,
            exit_arg,
            return_value: 0,
            gas_remaining: 0,
        };
        rkyv::to_bytes::<rkyv::rancor::Error>(&result)
            .expect("rkyv-encode InvocationResult error")
            .into_vec()
    }

    /// Cache-based RPC: read an `InvokePacket` from the input bytes,
    /// look up the referenced Cap::Instance in the host-published
    /// state cache, run its bytecode, return an `InvocationResult`.
    ///
    /// V0 path: copies slabs out of the cache into per-call Vec<u8>'s
    /// and calls the existing `run_pvm_with_mem`. A follow-up can map
    /// the cache region as USER and let the JIT reference cache VAs
    /// directly (zero-copy).
    #[guest_function(fn_id = FN_ID_NUB_INVOKE_CACHED)]
    pub fn nub_invoke_cached(packet_bytes: &[u8]) -> Vec<u8> {
        let packet = match InvokePacket::from_bytes(packet_bytes) {
            Some(p) => p,
            None => return encode_result_error(10),
        };
        let slot = match crate::state_cache::lookup(&packet.instance_hash) {
            Some(s) => s,
            None => return encode_result_error(11),
        };

        // V0: copy cache slabs into Vec<u8>'s. SAFETY:
        // state_cache::lookup() returned, so ensure_mapped already
        // succeeded; offsets came from an IndexSlot the host wrote;
        // they're within the cache region.
        let code: Vec<u8> = unsafe {
            crate::state_cache::slab_bytes(slot.code_off, slot.code_len)
        }
        .to_vec();
        let bitmask: Vec<u8> = unsafe {
            crate::state_cache::slab_bytes(slot.bitmask_off, slot.bitmask_len)
        }
        .to_vec();
        // jump_table is laid out as little-endian u32s in the cache;
        // decode into native u32s here.
        let jt_bytes: &[u8] = unsafe {
            crate::state_cache::slab_bytes(slot.jump_table_off, slot.jump_table_entries * 4)
        };
        let jump_table: Vec<u32> = jt_bytes
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        let ro_data: Vec<u8> = unsafe {
            crate::state_cache::slab_bytes(slot.ro_off, slot.ro_len)
        }
        .to_vec();
        let rw_data: Vec<u8> = unsafe {
            crate::state_cache::slab_bytes(slot.rw_off, slot.rw_len)
        }
        .to_vec();
        let arg_data: Vec<u8> = unsafe {
            crate::state_cache::slab_bytes(slot.arg_off, slot.arg_len)
        }
        .to_vec();

        let endpoint = packet.endpoint_idx as usize;
        if endpoint >= slot.entry_pcs.len() {
            return encode_result_error(12);
        }
        let entry_pc = slot.entry_pcs[endpoint];

        // Overlay caller-supplied register args on φ[7..=10].
        let mut initial_regs = slot.initial_regs;
        for (i, v) in packet.args.iter().enumerate() {
            initial_regs[7 + i] = *v;
        }

        let info = unsafe {
            crate::jit_run::run_pvm_with_mem(
                &code,
                &bitmask,
                &jump_table,
                packet.initial_gas as i64,
                entry_pc as u32,
                initial_regs,
                slot.mem_size,
                crate::jit_run::MemRegion {
                    start: slot.arg_start,
                    data: &arg_data,
                },
                crate::jit_run::MemRegion {
                    start: slot.ro_start,
                    data: &ro_data,
                },
                crate::jit_run::MemRegion {
                    start: slot.rw_start,
                    data: &rw_data,
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
                exit_arg: 13,
                return_value: 0,
                gas_remaining: 0,
            },
        };

        rkyv::to_bytes::<rkyv::rancor::Error>(&result)
            .expect("rkyv-encode InvocationResult")
            .into_vec()
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
    #[guest_function(fn_id = FN_ID_NUB_HEAP_STATS)]
    pub fn nub_heap_stats(_input: &[u8]) -> Vec<u8> {
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
