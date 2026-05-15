//! Slot numbers and op-codes the v3 chain ABI exposes to chain
//! Instances at genesis. Mirrors the host-call op-codes defined by
//! [`javm::ecall::host_op`] (those are the runtime op-codes the
//! kernel implements). The slot numbers here are the well-known
//! kernel-cap slot indices the kernel populates at chain init.
//!
//! Stage C.1 baseline — values may shift as Stage C.5 (genesis)
//! finalizes the layout.

use jar_cap::SlotIdx;

// ---- BareFrame slot indices (kernel-issued caps at chain init) ----

/// Root `Cap::Instance[Gas{0}]` handle. The chain reads this slot
/// to learn its active gas meter; it's also the entry in the
/// chain Image's `gas_slots[0]`.
pub const BARE_GAS_SLOT: SlotIdx = SlotIdx(7);

/// Root `Cap::Instance[Quota{0}]` handle (symmetric to
/// `BARE_GAS_SLOT`).
pub const BARE_QUOTA_SLOT: SlotIdx = SlotIdx(8);

/// Chain's `Cap::Instance[YieldCatcher]` (its own catcher; per-block
/// reset). The chain Image's `yield_marker_slot` points here.
pub const BARE_YIELD_CATCHER_SLOT: SlotIdx = SlotIdx(9);

/// `Cap::Instance[SetGasMeter]` factory.
pub const BARE_SET_GAS_METER_SLOT: SlotIdx = SlotIdx(10);

/// `Cap::Instance[SetStorageQuota]` factory.
pub const BARE_SET_STORAGE_QUOTA_SLOT: SlotIdx = SlotIdx(11);

/// `Cap::Instance[MintGas]` factory.
pub const BARE_MINT_GAS_SLOT: SlotIdx = SlotIdx(12);

/// `Cap::Instance[MintQuota]` factory.
pub const BARE_MINT_QUOTA_SLOT: SlotIdx = SlotIdx(13);

/// `Cap::Instance[CreateYieldCatcher]` factory.
pub const BARE_CREATE_YIELD_CATCHER_SLOT: SlotIdx = SlotIdx(14);

/// `Cap::Instance[HostOpen]` — read-only entry handle for `host_open`.
pub const BARE_HOST_OPEN_SLOT: SlotIdx = SlotIdx(15);

/// `Cap::Instance[HostSave]` — entry handle for `host_save`.
pub const BARE_HOST_SAVE_SLOT: SlotIdx = SlotIdx(16);
