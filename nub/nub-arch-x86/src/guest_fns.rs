//! Generic guest-function bodies + the [`register_guest_kernel!`] table
//! stamp.
//!
//! The production RPC surface is personality-generic: each `nub_*_impl<P>`
//! here is the full body of one guest function, and
//! [`register_guest_kernel!`] stamps the concrete `#[guest_function]`
//! wrappers (the linkme registrations) for one personality. Exactly one
//! invocation per binary — a second collides on the wrapper fn idents, a
//! compile error (the structural half of the one-personality invariant; see
//! `jit_run::install_handlers` for the runtime backstop).

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use nub_arch_x86_abi::{
    InvocationResult, InvokePacket, PARALLEL_INVOKE_SLOT_BYTES, PARALLEL_INVOKE_STATUS_DONE,
    PARALLEL_INVOKE_STATUS_EMPTY, PARALLEL_INVOKE_STATUS_EVICT_JIT_READY,
    PARALLEL_INVOKE_STATUS_READY, PARALLEL_INVOKE_STATUS_RUNNING, PARALLEL_INVOKE_STATUS_STARTING,
    PARALLEL_INVOKE_STATUS_STOP, ParallelInvokeSlot, SCRATCHPAD_HEAD_LEN,
};

use crate::personality::{GuestPersonality, GuestStore};

/// fn_id constants re-exported for [`register_guest_kernel!`] — the macro
/// references them via `$crate::` so an invoking crate does not need a
/// direct dep on the abi crate.
pub mod fn_ids {
    pub use nub_arch_x86_abi::{
        FN_ID_NUB_EVICT_JIT_ALL, FN_ID_NUB_HEAP_STATS, FN_ID_NUB_INVOKE_CACHED,
        FN_ID_NUB_INVOKE_WORKER, FN_ID_NUB_PUT_CAP,
    };
}

fn encode_result_error(exit_arg: u32) -> Vec<u8> {
    let result = InvocationResult {
        exit_reason: u32::MAX,
        exit_arg,
        return_value: 0,
        gas_remaining: 0,
        scratchpad_head: [0u8; SCRATCHPAD_HEAD_LEN],
    };
    rkyv::to_bytes::<rkyv::rancor::Error>(&result)
        .expect("rkyv-encode InvocationResult error")
        .into_vec()
}

fn invocation_result_from_outcome(
    outcome: Result<crate::task::LoopOutcome, u32>,
) -> InvocationResult {
    match outcome {
        Ok(o) => InvocationResult {
            exit_reason: o.exit_reason,
            exit_arg: o.exit_arg,
            return_value: o.return_value,
            gas_remaining: o.gas_remaining.max(0) as u64,
            scratchpad_head: o.scratchpad_head,
        },
        Err(code) => InvocationResult {
            exit_reason: u32::MAX,
            exit_arg: code,
            return_value: 0,
            gas_remaining: 0,
            scratchpad_head: [0u8; SCRATCHPAD_HEAD_LEN],
        },
    }
}

fn parallel_slot_for_lane(lane: usize) -> Option<*mut ParallelInvokeSlot> {
    let handle = unsafe { &*core::ptr::addr_of!(hyperlight_guest_bin::GUEST_HANDLE) };
    let peb = handle.peb()?;
    let output_ptr = unsafe { (*peb).output_stack.ptr as usize };
    let output_size = unsafe { (*peb).output_stack.size as usize };
    let base = output_ptr.checked_add(output_size)?;
    let offset = lane.checked_mul(PARALLEL_INVOKE_SLOT_BYTES)?;
    Some((base + offset) as *mut ParallelInvokeSlot)
}

/// `put_object` failure sentinel — a hash of all `0xFF`. The host errors
/// on exact equality with this value
/// (`nub-host-kvm::MultiUseSandbox::put_object`), which makes
/// `[0xFF; 32]` a RESERVED hash on the wire: every personality's
/// [`GuestStore::put_object`] must guarantee no real object ever hashes
/// to it (stated on that trait method). javm satisfies this
/// cryptographically — an SSZ content root (with its Union mix-in
/// selector) collides with all-ones only with negligible probability.
/// The personality's `u32` error code is diagnostics-only and never
/// crosses the wire — the sentinel is the sole failure channel.
fn error_hash_sentinel() -> Vec<u8> {
    alloc::vec![0xFFu8; 32]
}

/// Cache-based RPC: read an [`InvokePacket`], drive the in-kernel
/// CALL/HALT loop ([`crate::task::run_top`]) — which spins up frames,
/// dispatches the personality's host ops in-sandbox, and tears each frame
/// down on HALT.
///
/// Memory regions live behind the per-invocation page-table for the
/// duration of one JIT entry; the task loop builds them fresh on every
/// push.
pub fn nub_invoke_cached_impl<P: GuestPersonality>(packet_bytes: &[u8]) -> Vec<u8> {
    let packet = match InvokePacket::from_bytes(packet_bytes) {
        Some(p) => p,
        None => return encode_result_error(10),
    };

    // Objects are resolved via the personality's store (javm: the
    // heap-resident `CACHE` — see `crate::state_cache`).
    let outcome = crate::task::run_top::<P>(
        &packet.root_hash,
        packet.endpoint_idx,
        packet.args,
        packet.initial_gas as i64,
    );

    // Defensive post-invoke housekeeping (javm: reclaim any
    // `cache.instances` entries — a no-op in the current call path, kept as
    // a cheap safety net in case a host-published instance ever lands in
    // the tier).
    P::store().sweep();

    let result = invocation_result_from_outcome(outcome);
    rkyv::to_bytes::<rkyv::rancor::Error>(&result)
        .expect("rkyv-encode InvocationResult")
        .into_vec()
}

/// Long-lived lane worker for the parallel invoke slot ABI. This function is
/// started once per vCPU lane by the host and intentionally does not use the
/// legacy rkyv response ring while running.
pub fn nub_invoke_worker_impl<P: GuestPersonality>(payload: &[u8]) -> Vec<u8> {
    if payload.len() != core::mem::size_of::<u32>() {
        return Vec::new();
    }
    let lane =
        u32::from_le_bytes(payload.try_into().expect("lane payload length checked")) as usize;
    let Some(slot) = parallel_slot_for_lane(lane) else {
        return Vec::new();
    };
    let lane = crate::execution_lane::ExecutionLane::new(lane);
    unsafe {
        if (*slot).status.load(Ordering::Acquire) == PARALLEL_INVOKE_STATUS_STARTING {
            (*slot)
                .status
                .store(PARALLEL_INVOKE_STATUS_EMPTY, Ordering::Release);
        }
    }

    loop {
        let status = unsafe { (*slot).status.load(Ordering::Acquire) };
        match status {
            PARALLEL_INVOKE_STATUS_READY => {
                let claimed = unsafe {
                    (*slot).status.compare_exchange(
                        PARALLEL_INVOKE_STATUS_READY,
                        PARALLEL_INVOKE_STATUS_RUNNING,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                };
                if claimed.is_err() {
                    continue;
                }
                let packet = unsafe { core::ptr::addr_of!((*slot).packet).read_volatile() };
                let outcome = crate::task::run_top_on_lane::<P>(
                    lane,
                    &packet.root_hash,
                    packet.endpoint_idx,
                    packet.args,
                    packet.initial_gas as i64,
                );
                P::store().sweep();
                let result = invocation_result_from_outcome(outcome);
                unsafe {
                    core::ptr::addr_of_mut!((*slot).result).write_volatile(result);
                    (*slot)
                        .status
                        .store(PARALLEL_INVOKE_STATUS_DONE, Ordering::Release);
                }
            }
            PARALLEL_INVOKE_STATUS_EVICT_JIT_READY => {
                let claimed = unsafe {
                    (*slot).status.compare_exchange(
                        PARALLEL_INVOKE_STATUS_EVICT_JIT_READY,
                        PARALLEL_INVOKE_STATUS_RUNNING,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                };
                if claimed.is_err() {
                    continue;
                }
                P::store().evict_jit();
                P::store().sweep();
                unsafe {
                    core::ptr::addr_of_mut!((*slot).result).write_volatile(InvocationResult {
                        exit_reason: 0,
                        exit_arg: 0,
                        return_value: 0,
                        gas_remaining: 0,
                        scratchpad_head: [0u8; SCRATCHPAD_HEAD_LEN],
                    });
                    (*slot)
                        .status
                        .store(PARALLEL_INVOKE_STATUS_DONE, Ordering::Release);
                }
            }
            PARALLEL_INVOKE_STATUS_STOP => unsafe {
                (*slot)
                    .status
                    .store(PARALLEL_INVOKE_STATUS_EMPTY, Ordering::Release);
                return Vec::new();
            },
            _ => core::hint::spin_loop(),
        }
    }
}

/// Store publisher: validate + materialise + insert one published object
/// via [`GuestStore::put_object`] (javm: an rkyv-archived `Cap` into the
/// heap-resident directory). On any decode failure returns the all-`0xFF`
/// sentinel hash; the host compares against it and surfaces a typed error.
pub fn nub_put_object_impl<P: GuestPersonality>(payload: &[u8]) -> Vec<u8> {
    match P::store().put_object(payload) {
        Ok(hash) => hash.to_vec(),
        Err(_) => error_hash_sentinel(),
    }
}

/// Bench-only: drop every entry in the JIT compile cache so the next invoke
/// pays a full recompile. Empty payload, empty response. Not meant for
/// production paths — the cache is content-addressed and re-compiling the
/// same Image produces identical native code. This intentionally leaves
/// clean instance-memory memos intact; the cold bench target is "recompile
/// + execute", not "rebuild every runtime memo".
pub fn nub_evict_jit_all_impl<P: GuestPersonality>(_input: &[u8]) -> Vec<u8> {
    P::store().evict_jit();
    Vec::new()
}

/// Diagnostic: report talc's current allocation state as 40 LE
/// bytes packing `[allocation_count, total_allocation_count,
/// allocated_bytes, fragment_count, available_bytes]` (five u64s).
/// Used to detect per-iter heap leaks and per-CALL allocation churn:
/// - `allocation_count` is the *live* count (alloc − free) — a
///   non-zero per-invoke drift is a leak.
/// - `total_allocation_count` is *cumulative* (monotonic) — its
///   per-invoke delta is the allocation churn, which catches transient
///   allocations (e.g. a rebuilt page table) that are freed again
///   before the next snapshot and so leave `allocation_count` flat.
/// - `allocated_bytes` oscillating with `fragment_count` climbing
///   indicates fragmentation.
///
/// Gated on `heap-diag` because reading the counters requires
/// talc's `counters` feature, which adds a small per-alloc cost.
/// Allocator-only — the one non-generic impl.
#[cfg(feature = "heap-diag")]
pub fn nub_heap_stats_impl(_input: &[u8]) -> Vec<u8> {
    let counters = *hyperlight_guest_bin::HEAP_ALLOCATOR.lock().counters();
    let mut buf = alloc::vec![0u8; 40];
    buf[0..8].copy_from_slice(&(counters.allocation_count as u64).to_le_bytes());
    buf[8..16].copy_from_slice(&counters.total_allocation_count.to_le_bytes());
    buf[16..24].copy_from_slice(&(counters.allocated_bytes as u64).to_le_bytes());
    buf[24..32].copy_from_slice(&(counters.fragment_count as u64).to_le_bytes());
    buf[32..40].copy_from_slice(&(counters.available_bytes as u64).to_le_bytes());
    buf
}

/// Stamp the production guest-function table for personality `$p`.
///
/// Emits one `#[guest_function]` wrapper per production fn_id, each
/// forwarding to the generic `nub_*_impl::<$p>` body. The wrapper fn idents
/// are fixed, so a second invocation in one crate is a compile error — the
/// structural guarantee that one binary hosts exactly one personality (the
/// `jit_run` erased-pointer casts rely on it; see
/// `jit_run::install_handlers`).
///
/// Requirements at the invocation site's crate: a direct dep on package
/// `hyperlight-guest-bin` under its real name (both the expanded
/// `hyperlight_guest_bin::…` paths and the `#[guest_function]` macro's
/// `proc_macro_crate` lookup key on the literal package name — no
/// `package =` rename); `extern crate alloc`; a `heap-diag` feature if the
/// heap-stats probe is wanted (the `cfg` resolves against the invoking
/// crate).
#[macro_export]
macro_rules! register_guest_kernel {
    ($p:ty) => {
        #[hyperlight_guest_bin::guest_function(fn_id = $crate::guest_fns::fn_ids::FN_ID_NUB_INVOKE_CACHED)]
        pub fn nub_invoke_cached(input: &[u8]) -> ::alloc::vec::Vec<u8> {
            $crate::guest_fns::nub_invoke_cached_impl::<$p>(input)
        }

        #[hyperlight_guest_bin::guest_function(fn_id = $crate::guest_fns::fn_ids::FN_ID_NUB_INVOKE_WORKER)]
        pub fn nub_invoke_worker(input: &[u8]) -> ::alloc::vec::Vec<u8> {
            $crate::guest_fns::nub_invoke_worker_impl::<$p>(input)
        }

        #[hyperlight_guest_bin::guest_function(fn_id = $crate::guest_fns::fn_ids::FN_ID_NUB_PUT_CAP)]
        pub fn nub_put_cap(input: &[u8]) -> ::alloc::vec::Vec<u8> {
            $crate::guest_fns::nub_put_object_impl::<$p>(input)
        }

        #[hyperlight_guest_bin::guest_function(fn_id = $crate::guest_fns::fn_ids::FN_ID_NUB_EVICT_JIT_ALL)]
        pub fn nub_evict_jit_all(input: &[u8]) -> ::alloc::vec::Vec<u8> {
            $crate::guest_fns::nub_evict_jit_all_impl::<$p>(input)
        }

        #[cfg(feature = "heap-diag")]
        #[hyperlight_guest_bin::guest_function(fn_id = $crate::guest_fns::fn_ids::FN_ID_NUB_HEAP_STATS)]
        pub fn nub_heap_stats(input: &[u8]) -> ::alloc::vec::Vec<u8> {
            $crate::guest_fns::nub_heap_stats_impl(input)
        }
    };
}
