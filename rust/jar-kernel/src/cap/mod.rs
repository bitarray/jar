//! Capabilities — variant structs, the `RegisteredCap` enum, and shared
//! helpers (pinning rules + attestation dispatch).

pub mod attest;
pub mod kernel_cap;
pub mod pinning;
pub mod registered;

pub use kernel_cap::{KERNEL_CAP_SLOT, KernelCap};
pub use registered::*;
