//! JAR v3 capability system.
//!
//! Foundational layer for the v3 implementation. Defines the five
//! v3 cap kinds (Instance, Image, Data, CNode, Type), the CNode
//! abstraction with a pluggable backend trait, the Image structure
//! and its hash-chain math, and primitives (BMT, hash) used by
//! upstream layers.
//!
//! No execution awareness. No I/O. No kernel concepts. Caps and
//! cnodes here are pure values with deterministic hashing.
//!
//! See `~/docs/minimum-v3/implementation/architecture.md` for the
//! crate's role in the overall layering.

pub mod bmt;
pub mod error;
pub mod hash;
pub mod slot;

pub use bmt::Bmt;
pub use error::{CapError, OpError};
pub use hash::{Blake2b256, Hash};
pub use slot::{SlotIdx, SlotPath};
