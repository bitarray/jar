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
mod call_loop;
#[cfg(target_os = "none")]
mod jit_cache;
#[cfg(target_os = "none")]
mod jit_run;
#[cfg(target_os = "none")]
mod page_alloc;
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
    use javm_cap::WireCap;
    use javm_cap::cap::Cap;
    #[cfg(feature = "heap-diag")]
    use nub_arch_x86_abi::FN_ID_NUB_HEAP_STATS;
    use nub_arch_x86_abi::{
        BootInfo, FN_ID_NUB_GET_BOOT_INFO, FN_ID_NUB_INVOKE_CACHED, FN_ID_NUB_PUT_CAP,
        FN_ID_NUB_SMOKE, InvocationResult, InvokePacket,
    };

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
        // (`CacheDirectory<FixedState>`) — see `crate::state_cache`.
        let outcome = crate::call_loop::run_top(
            &packet.instance_hash,
            packet.endpoint_idx,
            packet.args,
            packet.initial_gas as i64,
        );

        // GC the transient instance entries that `derive_spawn`
        // created during this RPC. By now `run_top` has dropped the
        // call stack, so every frame's `CapHashOrRef::Ref(CapRef)`
        // clone is gone — the only holder of each transient instance
        // is the directory's own self-ref. `sweep_instances` walks
        // the instances tier and removes entries where
        // `Arc::strong_count(self_ref) == 1`, looping until stable.
        // Without this, the bench's `sub_vm_data_recurse` OOMs the
        // guest's talc heap within seconds.
        crate::state_cache::CACHE.sweep_instances();

        let result = match outcome {
            Ok(o) => InvocationResult {
                exit_reason: o.exit_reason,
                exit_arg: o.exit_arg,
                return_value: o.return_value,
                gas_remaining: o.gas_remaining.max(0) as u64,
            },
            Err(code) => InvocationResult {
                exit_reason: u32::MAX,
                exit_arg: code,
                return_value: 0,
                gas_remaining: 0,
            },
        };

        rkyv::to_bytes::<rkyv::rancor::Error>(&result)
            .expect("rkyv-encode InvocationResult")
            .into_vec()
    }

    /// Heap-resident cap-directory publisher. Decodes the
    /// rkyv-archived [`WireCap`] payload (= `Cap<CapHash>`), lifts
    /// it to the working form via
    /// [`Cap::into_working`](javm_cap::cap::Cap::into_working), and
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

        let wire: WireCap = match rkyv::from_bytes::<WireCap, rkyv::rancor::Error>(&aligned) {
            Ok(w) => w,
            Err(_) => return error_hash_sentinel(),
        };
        let cap: Cap = wire.into_working();
        let hash = match crate::state_cache::CACHE.put_cap(&cap) {
            Ok(h) => h,
            Err(_) => return error_hash_sentinel(),
        };
        let mut out: Vec<u8> = Vec::with_capacity(32);
        out.extend_from_slice(&hash);
        out
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
