#![cfg_attr(not(feature = "std"), no_std)]

//! JAR v3 capability system.
//!
//! Defines the five v3 cap kinds (Instance, Image, Data, CNode, Type),
//! their content-bearing representations, a two-tier cache for
//! identity-keyed mutable state + content-addressed blobs, and the
//! primitives (BMT, hash) used by upstream layers.
//!
//! `Cap` and its inner storage use the default `Global` allocator (=
//! std heap on host, talc on guest via `#[global_allocator]`). The
//! cache layer's outer storage (`HashMap` / `Box` parameters) may still
//! be parameterised on a custom allocator for shared-memory layouts.
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

pub use cache::{CacheDirectory, CacheError};
pub use cap::{
    Cap, CapHash, CapHashOrRef, CapKind, CapRef, MAX_ENDPOINTS, MAX_SOURCE_DEPTH, NUM_REGS, TypeCap,
};
pub use cap_hash::cap_hash;
pub use cnode::{CNodeCap, CNodeSlotEntry};
pub use data::{DataCap, DataContent, PAGE_SIZE};
pub use entry::CacheEntry;
pub use error::{CapError, OpError};
pub use hash::{Blake2b256, Hash};
pub use image::{
    EndpointDef as ImageEndpointDef, Image, InitialDataCap, MemoryMapping as ImageMemoryMapping,
    PinnedCap, chain_extend, chain_genesis, image_content_hash,
};
pub use image_cap::{
    EndpointDef, ImageCap, ImageConvertError, ImageSlotEntry, MemoryMapping, image_cap,
};
pub use instance::{InstanceCap, RwOverlay};
pub use page::{PageBytes, PageRef, PageSlot};
pub use slot::{SlotIdx, SlotPath};
