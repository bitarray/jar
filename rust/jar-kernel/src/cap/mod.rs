//! Capabilities — variant structs, the `Capability` enum, and shared
//! helpers (pinning rules + attestation dispatch).

pub mod attest;
pub mod capability;
pub mod kernel_cap;
pub mod pinning;

pub use capability::*;
pub use kernel_cap::{KERNEL_CAP_SLOT, KernelCap};
