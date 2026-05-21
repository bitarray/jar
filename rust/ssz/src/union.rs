//! Helpers for SSZ Union types (used by `Option<T>` and derived enums).
//!
//! The wire form of a Union is `selector_byte || payload`. The hash form
//! mixes the selector via `mix_in_selector` over the payload root.

use digest::Digest;
use digest::typenum::U32;

use crate::merkle::mix_in_selector;

/// Compute the hash for an `Option<T>`-style Union root. The selector
/// (0 for None, 1 for Some) is mixed in via the standard `mix_in_selector`.
#[inline]
pub fn option_selector_hash<D: Digest<OutputSize = U32>>(
    payload_root: [u8; 32],
    selector: u8,
) -> [u8; 32] {
    mix_in_selector::<D>(payload_root, selector)
}
