#![cfg_attr(not(feature = "std"), no_std)]

//! JAR v3 capability system.
//!
//! Defines the five v3 cap kinds (Instance, Image, Data, CNode, Type),
//! their content-bearing representations, a two-tier cache for
//! identity-keyed mutable state + content-addressed blobs, and the
//! primitives (BMT, hash) used by upstream layers.
//!
//! `Cap<A>` is allocator-parameterised — `A` defaults to `Global` so
//! existing callers get a heap-resident cap. The cache layer
//! instantiates `Cap<TalcAlloc>` to land content in the shared-memory
//! cache region.
//!
//! See `~/jar/website/content/spec/implementation/architecture.md` for
//! the crate's role in the overall layering.

#[macro_use]
extern crate alloc;

pub mod abi;
pub mod cache;
pub mod cap;
pub mod cap_hash;
pub mod cnode;
pub mod data;
pub mod entry;
pub mod error;
pub mod hash;
pub mod image;
pub mod image_cap;
pub mod instance;
pub mod page;
pub mod slot;

#[cfg(test)]
mod cache_tests;
#[cfg(test)]
mod cap_tests;

pub use cache::{Cache, CacheError};
pub use cap::{
    Cap, CapHash, CapHashOrRef, CapKind, CapRef, MAX_ENDPOINTS, MAX_SOURCE_DEPTH, NUM_REGS, TypeCap,
};
pub use cap_hash::cap_hash;
pub use cnode::{CNodeCap, CNodeSlotEntry};
pub use data::{DataCap, DataContent};
pub use entry::CacheEntry;
pub use error::{CapError, OpError};
pub use hash::{Blake2b256, Hash};
pub use image::{
    EndpointDef as ImageEndpointDef, Image, InitialDataCap, MemoryMapping as ImageMemoryMapping,
    PinnedCap, chain_extend, chain_genesis, image_content_hash,
};
pub use image_cap::{
    EndpointDef, ImageCap, ImageConvertError, ImageSlotEntry, MemoryMapping, image_cap_in,
};
pub use instance::{InstanceCap, RwOverlay};
pub use page::{PageBytes, PageRef, PageSlot};
pub use slot::{SlotIdx, SlotPath};
