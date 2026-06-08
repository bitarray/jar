//! Production guest function table. Each `#[guest_function]`
//! registers via the `nub-host-guest-macro`'s `linkme` slice;
//! binaries that `extern crate nub_arch_x86` get these RPCs
//! automatically.

use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use hyperlight_guest_bin::guest_function;
use javm_cap::cap::Cap;
#[cfg(feature = "heap-diag")]
use nub_arch_x86_abi::FN_ID_NUB_HEAP_STATS;
use nub_arch_x86_abi::{
    BootInfo, FN_ID_NUB_EVICT_JIT_ALL, FN_ID_NUB_GET_BOOT_INFO, FN_ID_NUB_INVOKE_CACHED,
    FN_ID_NUB_INVOKE_WORKER, FN_ID_NUB_PUT_CAP, InvocationResult, InvokePacket,
    PARALLEL_INVOKE_SLOT_BYTES, PARALLEL_INVOKE_STATUS_DONE, PARALLEL_INVOKE_STATUS_EMPTY,
    PARALLEL_INVOKE_STATUS_READY, PARALLEL_INVOKE_STATUS_RUNNING, PARALLEL_INVOKE_STATUS_STOP,
    ParallelInvokeSlot, SCRATCHPAD_HEAD_LEN,
};

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

/// Cache-based RPC: read an `InvokePacket`, drive the in-kernel
/// CALL/HALT loop ([`crate::call_loop`]) — which spins up frames,
/// dispatches `derive_spawn` + `host_call` in-sandbox, and tears
/// each frame down on HALT.
///
/// Memory regions live behind the per-invocation page-table for the
/// duration of one JIT entry; the call loop builds them fresh on
/// every push.
#[guest_function(fn_id = FN_ID_NUB_INVOKE_CACHED)]
pub fn nub_invoke_cached(packet_bytes: &[u8]) -> Vec<u8> {
    let packet = match InvokePacket::from_bytes(packet_bytes) {
        Some(p) => p,
        None => return encode_result_error(10),
    };

    // Caps are resolved via the heap-resident `CACHE`
    // (`CacheDirectory<FixedState, CachedCap>`) — see `crate::state_cache`.
    let outcome = crate::call_loop::run_top(
        &packet.instance_hash,
        packet.endpoint_idx,
        packet.args,
        packet.initial_gas as i64,
    );

    // Defensive: reclaim any `cache.instances` entries. The recompiler keeps
    // sub-VMs as inline `Owned` caps that drop with their frame (there is no
    // `Ref` cnode-slot variant), so this is a no-op in the current call path —
    // kept as a cheap safety net in case a host-published instance ever lands
    // in the tier. The talc-OOM that originally required it is gone: `Owned`
    // sub-VMs are freed directly at frame pop, not parked in the directory.
    crate::state_cache::CACHE.sweep_instances();

    let result = match outcome {
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
    };

    rkyv::to_bytes::<rkyv::rancor::Error>(&result)
        .expect("rkyv-encode InvocationResult")
        .into_vec()
}

fn invocation_result_from_outcome(
    outcome: Result<crate::call_loop::LoopOutcome, u32>,
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

/// Long-lived lane worker for the parallel invoke slot ABI. This function is
/// started once per vCPU lane by the host and intentionally does not use the
/// legacy rkyv response ring while running.
#[guest_function(fn_id = FN_ID_NUB_INVOKE_WORKER)]
pub fn nub_invoke_worker(payload: &[u8]) -> Vec<u8> {
    if payload.len() != core::mem::size_of::<u32>() {
        return Vec::new();
    }
    let lane =
        u32::from_le_bytes(payload.try_into().expect("lane payload length checked")) as usize;
    let Some(slot) = parallel_slot_for_lane(lane) else {
        return Vec::new();
    };
    let lane = crate::execution_lane::ExecutionLane::new(lane);

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
                let outcome = crate::call_loop::run_top_on_lane(
                    lane,
                    &packet.instance_hash,
                    packet.endpoint_idx,
                    packet.args,
                    packet.initial_gas as i64,
                );
                crate::state_cache::CACHE.sweep_instances();
                let result = invocation_result_from_outcome(outcome);
                unsafe {
                    core::ptr::addr_of_mut!((*slot).result).write_volatile(result);
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

/// Heap-resident cap-directory publisher. Validates the
/// rkyv-archived [`Cap`] payload via [`rkyv::access`] (zero-copy)
/// then materialises an owned `Cap` via [`rkyv::deserialize`] and
/// inserts it into [`crate::state_cache::CACHE`] via
/// [`javm_cap::cache::CacheDirectory::put_cap`].
///
/// On any decode failure we return a sentinel `CapHash` of
/// all-`0xFF`. The host's `MultiUseSandbox::put_cap` helper
/// compares against this sentinel and surfaces a typed error.
#[guest_function(fn_id = FN_ID_NUB_PUT_CAP)]
pub fn nub_put_cap(payload: &[u8]) -> Vec<u8> {
    // Lazy first-call boot-info patch. `init_directory_va` is
    // idempotent + cheap; nicer than wiring a custom
    // `hyperlight_main` for just this one publication.
    crate::state_cache::init_directory_va();

    let mut aligned = rkyv::util::AlignedVec::<16>::with_capacity(payload.len());
    aligned.extend_from_slice(payload);

    let archived =
        match rkyv::access::<rkyv::Archived<Cap>, rkyv::rancor::Error>(aligned.as_slice()) {
            Ok(a) => a,
            Err(_) => return error_hash_sentinel(),
        };
    let cap: Cap = match rkyv::deserialize::<Cap, rkyv::rancor::Error>(archived) {
        Ok(c) => c,
        Err(_) => return error_hash_sentinel(),
    };
    let hash = match crate::state_cache::CACHE.put_cap(&cap) {
        Ok(h) => h,
        Err(_) => return error_hash_sentinel(),
    };
    let mut out: Vec<u8> = Vec::with_capacity(32);
    out.extend_from_slice(&hash);
    out
}

/// Bench-only: drop every entry in the JIT compile cache so the
/// next `nub_invoke_cached` call pays a full recompile. Empty
/// payload, empty response. Not meant for production paths — the
/// cache is content-addressed and re-compiling the same Image
/// produces identical native code.
#[guest_function(fn_id = FN_ID_NUB_EVICT_JIT_ALL)]
pub fn nub_evict_jit_all(_input: &[u8]) -> Vec<u8> {
    crate::jit_cache::evict_all();
    // Drop the per-image clean-mem memo too, so a "cold" bench re-composes the
    // instance backing rather than cloning a warm one.
    crate::call_loop::evict_mem_cache();
    Vec::new()
}

/// Read the current `BootInfo` block out as raw bytes. Used by
/// the host as a fallback when ELF-section lookup fails. Payload
/// is empty.
#[guest_function(fn_id = FN_ID_NUB_GET_BOOT_INFO)]
pub fn nub_get_boot_info(_input: &[u8]) -> Vec<u8> {
    // Patch the VA on first read if it wasn't already published.
    crate::state_cache::init_directory_va();

    // SAFETY: `BOOT_INFO` is `static mut`; we read it after the
    // init hook above ran, and we publish bytes out via a fresh
    // copy. Reads of a freshly-patched `directory_va` field are
    // safe in this single-threaded boot context.
    let info: BootInfo = unsafe {
        let p = &raw const crate::state_cache::BOOT_INFO;
        core::ptr::read(p)
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &info as *const BootInfo as *const u8,
            core::mem::size_of::<BootInfo>(),
        )
    };
    bytes.to_vec()
}

/// `nub_put_cap` failure sentinel — a `CapHash` of all `0xFF`. No
/// real cap hashes to this value (SSZ root + Union mix-in
/// selector mean a content hash collides with all-ones only
/// with negligible probability), so the host can use equality
/// against this constant as a reliable error flag.
fn error_hash_sentinel() -> Vec<u8> {
    alloc::vec![0xFFu8; 32]
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
#[cfg(feature = "heap-diag")]
#[guest_function(fn_id = FN_ID_NUB_HEAP_STATS)]
pub fn nub_heap_stats(_input: &[u8]) -> Vec<u8> {
    let counters = *hyperlight_guest_bin::HEAP_ALLOCATOR.lock().counters();
    let mut buf = alloc::vec![0u8; 40];
    buf[0..8].copy_from_slice(&(counters.allocation_count as u64).to_le_bytes());
    buf[8..16].copy_from_slice(&counters.total_allocation_count.to_le_bytes());
    buf[16..24].copy_from_slice(&(counters.allocated_bytes as u64).to_le_bytes());
    buf[24..32].copy_from_slice(&(counters.fragment_count as u64).to_le_bytes());
    buf[32..40].copy_from_slice(&(counters.available_bytes as u64).to_le_bytes());
    buf
}
