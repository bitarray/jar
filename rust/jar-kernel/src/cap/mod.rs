//! Capabilities — variant structs, the `RegisteredCap` enum, and shared
//! helpers (pinning rules + attestation dispatch).

pub mod attest;
pub mod pinning;
pub mod protocol;
pub mod registered;

pub use protocol::{Cap, KERNEL_CAP_SLOT};
pub use registered::*;
