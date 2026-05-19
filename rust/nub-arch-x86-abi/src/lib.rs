//! Wire format for the host ↔ guest "run this PVM program" RPC.
//!
//! The host pre-publishes a `Cap::Instance`'s state into the shared
//! state cache (`nub_host_common::cache`), then ships a fixed-size
//! [`InvokePacket`] referencing it by hash on every call. No payload
//! codec — the packet is `#[repr(C)]` bytes; only the response is
//! rkyv-archived ([`InvocationResult`]).

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;

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

/// Maximum number of endpoints per Image the cache supports. Matches
/// `nub_host_common::cache::MAX_ENDPOINTS`.
pub const MAX_ENDPOINTS: usize = 64;

/// Number of PVM general-purpose registers (φ\[0\]..φ\[12\]).
pub const NUM_REGS: usize = 13;

/// Fixed-layout invocation packet. Sent as raw `#[repr(C)]` bytes via
/// the existing rkyv `Request` envelope (its `payload` field). The
/// guest reads the bytes directly with `core::ptr::read_unaligned`.
///
/// Args 0..=3 overlay the cached `IndexSlot.initial_regs` at
/// φ[7..=10] before entering the bytecode.
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

/// Spec describing how to publish a `Cap::Instance` into the state
/// cache. The host's `Nub::publish_instance` consumes this and lays
/// the contained slabs into the cache region, then registers an
/// `nub_host_common::cache::IndexSlot` keyed by `instance_hash`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishSpec {
    pub instance_hash: CapHash,
    pub code: Vec<u8>,
    /// Packed (bit-per-byte) bitmask of instruction starts. Same
    /// layout as `javm_cap::image::Image.packed_bitmask`.
    pub bitmask: Vec<u8>,
    pub jump_table: Vec<u32>,
    pub mem_size: u32,
    pub ro_start: u32,
    pub ro_data: Vec<u8>,
    pub rw_start: u32,
    pub rw_data: Vec<u8>,
    pub arg_start: u32,
    pub arg_data: Vec<u8>,
    /// Dense table: `entry_pcs[i]` = PC for endpoint i. `0` means
    /// "not defined" — the host writes this when flattening an
    /// `Image.endpoints` BTreeMap into the cache index.
    pub entry_pcs: [u64; MAX_ENDPOINTS],
    /// Baseline regs to seed at endpoint entry. The host can write
    /// the flattened `EndpointDef.initial_regs` here.
    pub initial_regs: [u64; NUM_REGS],
}

impl PublishSpec {
    /// An empty PublishSpec — useful as a starting point for tests.
    pub fn empty() -> Self {
        Self {
            instance_hash: [0; 32],
            code: Vec::new(),
            bitmask: Vec::new(),
            jump_table: Vec::new(),
            mem_size: 0,
            ro_start: 0,
            ro_data: Vec::new(),
            rw_start: 0,
            rw_data: Vec::new(),
            arg_start: 0,
            arg_data: Vec::new(),
            entry_pcs: [0; MAX_ENDPOINTS],
            initial_regs: [0; NUM_REGS],
        }
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
