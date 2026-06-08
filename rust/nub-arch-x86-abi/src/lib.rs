//! Wire format for the host ↔ guest "run this PVM program" RPC.
//!
//! The host pre-publishes each `Cap` it wants the guest to see via
//! the [`FN_ID_NUB_PUT_CAP`] RPC (rkyv-archived `javm_cap::Cap`
//! payload; see the `state_cache` module in `nub-arch-x86` for the
//! guest-side heap-resident directory it lands in), then ships a
//! fixed-size
//! [`InvokePacket`] referencing the published `Cap::Instance` by
//! hash on every call. The invoke packet is `#[repr(C)]` bytes (no
//! codec); the response is rkyv-archived ([`InvocationResult`]).

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use core::sync::atomic::{AtomicU32, AtomicU64};

/// `fn_id` for the `nub_heap_stats` diagnostic. Payload is empty;
/// response is 32 bytes packing four LE u64s (allocated_bytes,
/// allocation_count, fragment_count, available_bytes).
pub const FN_ID_NUB_HEAP_STATS: u32 = 2;

/// `fn_id` for the cache-based RPC. Payload is a
/// [`InvokePacket`] (host-side `#[repr(C)]` bytes, no rkyv); the
/// guest dereferences cache VAs by `instance_hash` lookup, runs the
/// JIT, and replies with rkyv-archived [`InvocationResult`].
pub const FN_ID_NUB_INVOKE_CACHED: u32 = 3;

/// `fn_id` for the heap-resident cap directory `put_cap` RPC.
///
/// Payload: rkyv-archived `javm_cap::Cap`. Guest validates and
/// materialises via [`rkyv::access`] + [`rkyv::deserialize`], computes
/// the cap's content hash, inserts into the guest-resident `CACHE`
/// (a resident `CacheDirectory<FixedState, CachedCap>` holding
/// `HashMap<CapHash, Arc<CachedCap>>` in talc heap), and replies with the
/// rkyv-archived [`CapHash`] (raw
/// 32 bytes). The host's `MultiUseSandbox::put_cap` propagates a
/// `CapHasRefError` from `javm_cap` if any slot still holds a Ref.
pub const FN_ID_NUB_PUT_CAP: u32 = 4;

/// `fn_id` for the boot-info-read diagnostic RPC. Empty payload; the
/// guest replies with the raw bytes of its [`BootInfo`] struct. The
/// host can also obtain the same data by reading the kernel's
/// `.boot_info` ELF section directly — this RPC exists as a
/// belt-and-braces fallback in case the ELF symbol lookup misses.
pub const FN_ID_NUB_GET_BOOT_INFO: u32 = 5;

/// `fn_id` for the bench-only "evict the entire JIT compile cache"
/// RPC. Empty payload; empty response. Used by `javm-bench` to force
/// each criterion iteration to pay the recompile cost (otherwise the
/// JIT cache turns the loop into pure warm-cache execute, which isn't
/// what we want to measure for PolkaVM-shaped workloads).
pub const FN_ID_NUB_EVICT_JIT_ALL: u32 = 6;
/// `fn_id` for a long-lived per-vCPU invoke worker. Payload is a little-endian
/// `u32` lane index. The function does not use the legacy rkyv response ring;
/// it polls that lane's [`ParallelInvokeSlot`] in scratch memory, runs invokes
/// with `run_top_on_lane`, and writes results back into the same slot.
pub const FN_ID_NUB_INVOKE_WORKER: u32 = 7;

/// Boot-time info published by the guest at a known location (linker
/// section `.boot_info`). The host reads it after the sandbox boots
/// to learn the VA of the guest's cap directory, then dereferences
/// the directory directly from host code (the kernel half is mapped
/// at the same VA via the shallow-PML4-copy mechanism, so a
/// directory-VA pointer is valid both in guest kernel mode and via
/// the host's mmap shadow of the kernel image).
///
/// `magic` is checked first as a sanity guard against reading a
/// stale or wrong-binary boot region. `directory_va` is the address
/// of the guest's resident cap directory.
/// `directory_type_id` lets future protocol upgrades reject a
/// mismatched layout (today: opaque sentinel matching
/// `CacheDirectory<FixedState, CachedCap>` — bumped when any field is added or
/// its type changes).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BootInfo {
    /// `BootInfo::MAGIC` ("JAR_BOOT" in ASCII, little-endian). Host
    /// reader rejects a region whose first 8 bytes don't match.
    pub magic: u64,
    /// VA of the cap directory's inner `HashMap` (NOT the wrapping
    /// `Mutex`). Resolved by `nub-arch-x86` at boot via
    /// `init_directory_va`.
    pub directory_va: u64,
    /// Hash of the directory's type signature. Bumped when the wire
    /// layout of the directory changes. Today: opaque sentinel, the
    /// host just compares for equality.
    pub directory_type_id: u64,
    /// Base of the per-process GUEST_VA reservation. Mirrors the
    /// host-side constant; reproduced here so the host can sanity-
    /// check the guest agrees on the layout.
    pub guest_va_base: u64,
    /// Reserved space for future fields. Zero-initialised; host
    /// readers should not depend on the contents.
    pub _reserved: [u64; 12],
}

impl BootInfo {
    /// Constant numeric guard. The hex digits spell "JAR_BOOT" when
    /// interpreted as ASCII bytes in big-endian order
    /// (`0x4A 0x41 0x52 0x5F 0x42 0x4F 0x4F 0x54`). Stored as the
    /// numeric u64 with that big-endian interpretation — read+compare
    /// is a single u64 load.
    pub const MAGIC: u64 = 0x4A41_525F_424F_4F54;
}

/// 32-byte Cap::Instance identity hash. Matches
/// `javm_cap::CapHash` byte-wise (kept as a local alias here so
/// `nub-arch-x86-abi` stays free of the javm-cap dependency, which
/// pulls in `alloc::collections` etc.).
pub type CapHash = [u8; 32];

/// Fixed-layout invocation packet. Sent as raw `#[repr(C)]` bytes via
/// the existing rkyv `Request` envelope (its `payload` field). The
/// guest reads the bytes directly with `core::ptr::read_unaligned`.
///
/// `instance_hash` keys the cap to invoke (a published `Cap::Instance`).
/// `endpoint_idx` selects the entry within `ImageCap.endpoints`.
/// `args` overlay φ[7..=10] on top of the endpoint's `initial_regs`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvokePacket {
    pub instance_hash: CapHash,
    pub endpoint_idx: u32,
    pub _pad: u32,
    pub args: [u64; 4],
    pub initial_gas: u64,
}

impl InvokePacket {
    /// Size of the packet in bytes — what the host writes to the
    /// `Request.payload` and what the guest reads back.
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Cast the packet to its raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
    }

    /// Parse a packet from raw bytes (length-checked).
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::SIZE {
            return None;
        }
        Some(unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const Self) })
    }
}

/// Bytes of the running Instance's scratchpad (`slot[0]`) region surfaced at the
/// top-level HALT — a fixed-size **head** of the returned DataCap's effective
/// content. The guest writes its result into the scratchpad-mapped memory
/// region during the run (CoW into the cap); at top HALT the engine reads the
/// region's effective bytes back out here, so the host observes the full,
/// uncompressed result without a separate data-flow event.
///
/// V1 surfaces a fixed-size window (enough for the fuzz differential's 13-slot
/// register signature: 13 × 8 = 104 ≤ 128). The full variable-length DataCap
/// return is deferred to the YieldMarker/YieldCatcher kernel design — see
/// `kernel-assisted-instances.md`. Zero-filled when the Instance maps no
/// scratchpad region (every non-fuzz path today).
pub const SCRATCHPAD_HEAD_LEN: usize = 128;

/// Invocation result. Both backends produce this shape on completion;
/// rkyv-archived on the wire from the cached path's response.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct InvocationResult {
    pub exit_reason: u32,
    pub exit_arg: u32,
    pub return_value: u64,
    pub gas_remaining: u64,
    /// Effective bytes of the running Instance's scratchpad (`slot[0]`) region
    /// head at top HALT (see [`SCRATCHPAD_HEAD_LEN`]). Zero when no scratchpad
    /// region is mapped.
    pub scratchpad_head: [u8; SCRATCHPAD_HEAD_LEN],
}

pub const PARALLEL_INVOKE_SLOT_BYTES: usize = 512;

pub const PARALLEL_INVOKE_STATUS_EMPTY: u32 = 0;
pub const PARALLEL_INVOKE_STATUS_READY: u32 = 1;
pub const PARALLEL_INVOKE_STATUS_RUNNING: u32 = 2;
pub const PARALLEL_INVOKE_STATUS_DONE: u32 = 3;
pub const PARALLEL_INVOKE_STATUS_STOP: u32 = 4;
pub const PARALLEL_INVOKE_STATUS_STARTING: u32 = 5;

/// One host<->guest invoke slot. Slots are addressed by lane index at
/// `parallel_slot_base + lane * PARALLEL_INVOKE_SLOT_BYTES`.
///
/// Synchronization protocol:
/// - host writes `job_id` and `packet`, then stores `READY` with release;
/// - guest CASes `READY -> RUNNING`, runs the invoke, writes `result`, then
///   stores `DONE` with release;
/// - host reads `DONE` with acquire, copies `result`, then stores `EMPTY`.
#[repr(C, align(64))]
pub struct ParallelInvokeSlot {
    pub status: AtomicU32,
    pub _pad0: u32,
    pub job_id: AtomicU64,
    pub packet: InvokePacket,
    pub result: InvocationResult,
}

const _: () = assert!(core::mem::size_of::<ParallelInvokeSlot>() <= PARALLEL_INVOKE_SLOT_BYTES);
const _: () = assert!(core::mem::align_of::<ParallelInvokeSlot>() <= 64);
