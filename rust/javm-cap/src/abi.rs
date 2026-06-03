//! Well-known cnode slot keys the v3 chain ABI exposes at genesis.
//! Shared between jar-kernel (which populates the slots at chain init)
//! and consumers like the JAVM transpiler (which emit chain Images
//! referencing them).
//!
//! Under the V1 single-byte ABI a slot is named by a one-byte
//! [`crate::Key`]; these constants are the byte values. Wrap with
//! `Key::from(BARE_*_SLOT)` at the call site — the same `u8 → Key`
//! boundary the ecall handlers use (`Key::from((gpr & 0xFF) as u8)`).

// ---- BareFrame slot keys (kernel-issued caps at chain init) ----

/// Root `Cap::Instance[Gas{0}]` handle. The chain reads this slot
/// to learn its active gas meter.
pub const BARE_GAS_SLOT: u8 = 7;

/// Root `Cap::Instance[Quota{0}]` handle (symmetric to
/// `BARE_GAS_SLOT`).
pub const BARE_QUOTA_SLOT: u8 = 8;

/// Chain's `Cap::Instance[YieldCatcher]` (its own catcher; per-block
/// reset). The chain Image's `yield_marker_slot` points here.
pub const BARE_YIELD_CATCHER_SLOT: u8 = 9;

/// `Cap::Instance[SetGasMeter]` factory.
pub const BARE_SET_GAS_METER_SLOT: u8 = 10;

/// `Cap::Instance[SetStorageQuota]` factory.
pub const BARE_SET_STORAGE_QUOTA_SLOT: u8 = 11;

/// `Cap::Instance[MintGas]` factory.
pub const BARE_MINT_GAS_SLOT: u8 = 12;

/// `Cap::Instance[MintQuota]` factory.
pub const BARE_MINT_QUOTA_SLOT: u8 = 13;

/// `Cap::Instance[CreateYieldCatcher]` factory.
pub const BARE_CREATE_YIELD_CATCHER_SLOT: u8 = 14;

/// `Cap::Instance[HostOpen]` — read-only entry handle for `host_open`.
pub const BARE_HOST_OPEN_SLOT: u8 = 15;

/// `Cap::Instance[HostSave]` — entry handle for `host_save`.
pub const BARE_HOST_SAVE_SLOT: u8 = 16;
