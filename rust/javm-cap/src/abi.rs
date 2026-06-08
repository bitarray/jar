//! Well-known cnode slot keys the v3 chain ABI exposes at genesis.
//! Shared between jar-kernel (which populates the slots at chain init)
//! and consumers like the JAVM transpiler (which emit chain Images
//! referencing them).
//!
//! Under the V1 single-byte ABI a slot is named by a one-byte
//! [`crate::Key`]; these constants are the byte values. Wrap with
//! `Key::from(BARE_*_SLOT)` at the call site — the same `u8 → Key`
//! boundary the ecall handlers use (`Key::from((gpr & 0xFF) as u8)`).

/// The **scratchpad slot**: the single cap-shaped data-flow channel between a
/// caller and callee. Its *contents* may be freely mutated and reset to empty,
/// but the slot itself is "mutably pinned" — `MGMT_MOVE`/`MGMT_SWAP` of this
/// slot trap. On CALL the caller's scratchpad moves to the callee; on HALT/reply
/// the callee's moves back to the caller; so the **running** Instance always
/// holds the scratchpad here, and every other frame's `slot[0]` is empty (one
/// owner — see the data-flow principle). The fuzz / kernel return path hands the
/// top-level Instance's `slot[0]` `Cap::Data` back as the invocation result.
pub const SCRATCHPAD_SLOT: u8 = 0;

// ---- BareFrame slot keys (kernel-issued caps at chain init) ----

/// Root `Cap::Instance[Gas{0}]` handle. The chain reads this slot
/// to learn its active gas meter.
pub const BARE_GAS_SLOT: u8 = 7;

/// Root `Cap::Instance[Quota{0}]` handle (symmetric to
/// `BARE_GAS_SLOT`).
pub const BARE_QUOTA_SLOT: u8 = 8;

/// Slot the chain Image's `yield_receiver_slot` points at, holding the chain's
/// `Cap::Instance[YieldReceiver]` (its catch-set; per-block reset). The kernel
/// reads it when routing a yield.
///
/// The per-syscall factory/marker slots (set_gas_meter, mint_gas,
/// create_yield_catcher, …) that used to follow are gone: a syscall is a
/// `host_yield` of a named `kernel:*` YieldSender from the top-level scratchpad
/// CNode, caught by the kernel as the root YieldReceiver — not a CALL into a
/// factory Instance pinned at a well-known slot.
pub const BARE_YIELD_RECEIVER_SLOT: u8 = 9;

/// `Cap::Instance[HostOpen]` — read-only entry handle for `host_open`.
pub const BARE_HOST_OPEN_SLOT: u8 = 15;

/// `Cap::Instance[HostSave]` — entry handle for `host_save`.
pub const BARE_HOST_SAVE_SLOT: u8 = 16;
