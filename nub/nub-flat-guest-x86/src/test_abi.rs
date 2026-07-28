//! Flat-private FN_ID constants.
//!
//! Band policy: the nub substrate owns fn_id space `[0, 0x100)`
//! (production ids in `nub-arch-x86-abi`, generic probes in
//! `nub_arch_x86::test_abi`); each personality owns `[0x100, ...)`.
//!
//! The flat personality has no private probes yet — the generic
//! substrate ones are enough to exercise it — so this module exists to
//! document the band and give the next probe an obvious home.

/// First id available to this personality.
pub const FN_ID_FLAT_BASE: u32 = 0x100;
