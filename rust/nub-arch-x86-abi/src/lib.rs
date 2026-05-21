//! Wire format for the host ↔ guest "run this PVM program" RPC.
//!
//! The host pre-publishes a `Cap::Instance`'s state into the shared
//! state cache (`nub_host_common::cache`), then ships a fixed-size
//! [`InvokePacket`] referencing it by hash on every call. No payload
//! codec — the packet is `#[repr(C)]` bytes; only the response is
//! rkyv-archived ([`InvocationResult`]).

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

/// `fn_id` for the `nub_smoke` skeleton RPC (returns `42u64`).
pub const FN_ID_NUB_SMOKE: u32 = 0;

/// `fn_id` for the `nub_heap_stats` diagnostic. Payload is empty;
/// response is 32 bytes packing four LE u64s (allocated_bytes,
/// allocation_count, fragment_count, available_bytes).
pub const FN_ID_NUB_HEAP_STATS: u32 = 2;

/// `fn_id` for the cache-based RPC. Payload is a
/// [`InvokePacket`] (host-side `#[repr(C)]` bytes, no rkyv); the
/// guest dereferences cache VAs by `instance_hash` lookup, runs the
/// JIT, and replies with rkyv-archived [`InvocationResult`].
pub const FN_ID_NUB_INVOKE_CACHED: u32 = 3;

/// Number of guest-function slots reserved in the dispatch table.
/// Must be at least `max(FN_ID_*) + 1`.
pub const GUEST_FN_TABLE_SIZE: usize = 8;

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

/// Invocation result. Both backends produce this shape on completion;
/// rkyv-archived on the wire from the cached path's response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct InvocationResult {
    pub exit_reason: u32,
    pub exit_arg: u32,
    pub return_value: u64,
    pub gas_remaining: u64,
}
