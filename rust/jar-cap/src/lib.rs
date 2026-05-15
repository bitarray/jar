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

pub mod abi;
pub mod bmt;
pub mod cap;
pub mod cnode;
pub mod error;
pub mod hash;
pub mod image;
pub mod ops;
pub mod slot;

pub use bmt::Bmt;
pub use cap::{CNodeCap, Cap, CapHash, CapKind, DataCap, ImageCap, InstanceCap, TypeCap};
pub use cnode::{CNodeBackend, CnodeHash, InMemoryCNode, SlotHasher};
pub use error::{CapError, OpError};
pub use hash::{Blake2b256, Hash};
pub use image::{
    EndpointDef, Image, InitialDataCap, MemoryMapping, PinnedCap, chain_extend, chain_genesis,
    image_content_hash,
};
pub use ops::{mgmt_cnode_mint, mgmt_cnode_swap, mgmt_copy, mgmt_drop, mgmt_move};
pub use slot::{SlotIdx, SlotPath};
