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
        FN_ID_NUB_INVOKE_CACHED, FN_ID_NUB_SMOKE, InvocationResult, InvokePacket,
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

    /// Cache-based RPC: read an `InvokePacket`, look up the referenced
    /// `Cap::Instance` in the host-published state cache, walk to its
    /// `Cap::Image`, run the bytecode, return an `InvocationResult`.
    ///
    /// V1 path: copies cache slabs into per-call `Vec<u8>`s and calls
    /// the existing `run_pvm_with_mem`. A follow-up can flip the cache
    /// mapping to USER and let the JIT reference talc VAs directly
    /// (zero-copy).
    #[guest_function(fn_id = FN_ID_NUB_INVOKE_CACHED)]
    pub fn nub_invoke_cached(packet_bytes: &[u8]) -> Vec<u8> {
        use javm_cap::talc::cap::Cap;

        let packet = match InvokePacket::from_bytes(packet_bytes) {
            Some(p) => p,
            None => return encode_result_error(10),
        };
        let inst_cap = match crate::state_cache::lookup_cap(&packet.instance_hash) {
            Some(c) => c,
            None => return encode_result_error(11),
        };
        let inst = match inst_cap {
            Cap::Instance(i) => i,
            _ => return encode_result_error(12), // cap at hash isn't an Instance
        };
        let img_cap = match crate::state_cache::lookup_cap(&inst.image_hash) {
            Some(c) => c,
            None => return encode_result_error(13),
        };
        let img = match img_cap {
            Cap::Image(i) => i,
            _ => return encode_result_error(14), // cap at image_hash isn't an Image
        };

        let endpoint = packet.endpoint_idx as usize;
        if endpoint >= img.endpoints.len() {
            return encode_result_error(15);
        }
        let ep = &img.endpoints[endpoint];
        if ep.entry_pc == 0 {
            return encode_result_error(16); // endpoint not defined
        }

        // Code/bitmask/jt: copy from cache into per-call Vec<u8>s.
        // ImageCap stores the packed bitmask (1 bit per code byte);
        // the JIT path wants the unpacked form (1 byte per code byte).
        // SAFETY: cache mapping is installed (state_cache::lookup_cap
        // succeeded); pointers live inside the cache region.
        let code: Vec<u8> = img.code.as_slice().to_vec();
        let bitmask: Vec<u8> =
            javm_exec::unpack_bitmask(img.bitmask.as_slice(), code.len());
        let jump_table: Vec<u32> = img.jump_table.as_slice().to_vec();

        // Overlay caller-supplied register args on φ[7..=10] on top
        // of the endpoint's initial_regs baseline.
        let mut initial_regs = ep.initial_regs;
        for (i, v) in packet.args.iter().enumerate() {
            initial_regs[7 + i] = *v;
        }

        // Build memory regions from InstanceCap.rw_overlays. V1 puts
        // ro/rw/arg data all in rw_overlays (the spec-level
        // distinction is materialised by the caller). For backwards
        // compat with run_pvm_with_mem, we pack the first three
        // overlays into the (arg, ro, rw) slots; the JIT path treats
        // them uniformly as initial-state byte regions.
        let mut overlays = img.code.as_slice().iter(); // dummy iterator for type
        let _ = &mut overlays;
        let (arg, ro, rw) = pack_overlays(&inst.rw_overlays);

        let info = unsafe {
            crate::jit_run::run_pvm_with_mem(
                &code,
                &bitmask,
                &jump_table,
                packet.initial_gas as i64,
                ep.entry_pc as u32,
                initial_regs,
                inst.mem_size,
                crate::jit_run::MemRegion {
                    start: arg.0,
                    data: &arg.1,
                },
                crate::jit_run::MemRegion {
                    start: ro.0,
                    data: &ro.1,
                },
                crate::jit_run::MemRegion {
                    start: rw.0,
                    data: &rw.1,
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
                exit_arg: 17,
                return_value: 0,
                gas_remaining: 0,
            },
        };

        rkyv::to_bytes::<rkyv::rancor::Error>(&result)
            .expect("rkyv-encode InvocationResult")
            .into_vec()
    }

    /// Materialised mem overlay: `(start, bytes)` pair, ready for
    /// `run_pvm_with_mem` to lay flat into the per-call memory image.
    type Overlay = (u32, Vec<u8>);

    /// Pack up to three `RwOverlay` entries into the (arg, ro, rw)
    /// triple expected by `run_pvm_with_mem`. Missing entries become
    /// `(0, empty)` which `run_pvm_with_mem` treats as "no overlay".
    fn pack_overlays<A: allocator_api2::alloc::Allocator + Clone>(
        overlays: &allocator_api2::vec::Vec<javm_cap::talc::instance::RwOverlay<A>, A>,
    ) -> (Overlay, Overlay, Overlay) {
        let mut packed = [(0u32, Vec::<u8>::new()), (0, Vec::new()), (0, Vec::new())];
        for (i, o) in overlays.iter().take(3).enumerate() {
            packed[i] = (o.start, o.bytes.as_slice().to_vec());
        }
        let [arg, ro, rw] = packed;
        (arg, ro, rw)
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
