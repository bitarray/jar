//! Capabilities — the `RegCap` enum (cap shapes occupying
//! `vault.slots`), the `ProtocolCap` enum (jar-kernel's impl of
//! `javm::ProtocolCap`), and the `Cap` alias (the complete Frame cap
//! type `javm::Cap<ProtocolCap>` — what's actually in a cap-table cell).

pub mod attest;
pub mod protocol;
pub mod regcap;

pub use protocol::{KERNEL_CAP_SLOT, ProtocolCap};
pub use regcap::*;

/// The complete Frame cap type — a cap-table cell holding any of
/// `Empty`, `Code`, `Data`, `FrameRef`, or `Protocol(ProtocolCap)`.
/// Pattern-match on this when inspecting slot contents; reach for
/// `ProtocolCap` only when you've already destructured the `Protocol`
/// arm.
pub type Cap = javm::cap::Cap<ProtocolCap>;
