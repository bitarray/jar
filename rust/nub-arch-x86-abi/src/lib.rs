//! Wire format for the host ↔ guest "run this PVM program" RPC.
//!
//! The host crate (`nub`) encodes an `InvocationSpec` and ships it
//! via the `nub_invoke` guest_function; the guest decodes, runs,
//! encodes an `InvocationResult` and returns it.
//!
//! Codec: rkyv. The host serialises with `rkyv::to_bytes`, the
//! guest reads with `rkyv::access` (zero-copy pointer cast + a
//! bytecheck validation pass).
//!
//! Also exports the compile-time `FN_ID_*` constants that select
//! which guest function the RPC envelope (`nub_host_common::rpc`)
//! routes to.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;

/// `fn_id` for the `nub_smoke` skeleton RPC (returns `42u64`).
pub const FN_ID_NUB_SMOKE: u32 = 0;

/// `fn_id` for the `nub_invoke` RPC — host → guest "run this PVM
/// program" call. Payload is a rkyv-archived `InvocationSpec`;
/// response is a rkyv-archived `InvocationResult`.
pub const FN_ID_NUB_INVOKE: u32 = 1;

/// `fn_id` for the `nub_heap_stats` diagnostic. Payload is empty;
/// response is 32 bytes packing four LE u64s (allocated_bytes,
/// allocation_count, fragment_count, available_bytes).
pub const FN_ID_NUB_HEAP_STATS: u32 = 2;

/// Number of guest-function slots reserved in the dispatch table.
/// Must be at least `max(FN_ID_*) + 1`.
pub const GUEST_FN_TABLE_SIZE: usize = 8;

/// PVM registers per Image — fixed-width 13-element tuple. SCALE
/// doesn't auto-impl `Decode` for `[u64; N]`, so we use a tuple
/// struct (kept for now; once SCALE leaves we can simplify to a
/// real array).
#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct PvmRegs(
    pub u64,
    pub u64,
    pub u64,
    pub u64,
    pub u64,
    pub u64,
    pub u64,
    pub u64,
    pub u64,
    pub u64,
    pub u64,
    pub u64,
    pub u64,
);

impl PvmRegs {
    pub const fn zeros() -> Self {
        Self(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    }

    pub fn from_array(a: [u64; 13]) -> Self {
        Self(
            a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12],
        )
    }

    pub fn into_array(self) -> [u64; 13] {
        let Self(a, b, c, d, e, f, g, h, i, j, k, l, m) = self;
        [a, b, c, d, e, f, g, h, i, j, k, l, m]
    }
}

#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize)]
#[rkyv(derive(Debug))]
pub struct InvocationSpec {
    pub code: Vec<u8>,
    pub bitmask: Vec<u8>,
    pub jump_table: Vec<u32>,
    pub entry_pc: u32,
    pub initial_gas: u64,
    pub initial_regs: PvmRegs,
    /// Total guest-memory size in bytes. Pages in `[0, mem_size)` are
    /// mapped; accesses past this boundary fault.
    pub mem_size: u32,
    /// `arg` region: guest VA + bytes to populate before entry.
    pub arg_start: u32,
    pub arg_data: Vec<u8>,
    /// `ro` region: pinned/read-only mapping. Mapped user-RO so writes
    /// trigger a #PF (exit_reason=3).
    pub ro_start: u32,
    pub ro_data: Vec<u8>,
    /// `rw` region: initialised read-write mapping.
    pub rw_start: u32,
    pub rw_data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct InvocationResult {
    pub exit_reason: u32,
    pub exit_arg: u32,
    pub return_value: u64,
    pub gas_remaining: u64,
}
