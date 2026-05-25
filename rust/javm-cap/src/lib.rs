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
pub mod error;
pub mod hash;
pub mod image;
pub mod slot;
pub mod wire;

pub use cache::{CacheDirectory, CacheError, CapHashOrRef, CapRef};
pub use cap::cnode::{CNodeCap, CNodeSlotEntry};
pub use cap::data::{DataCap, DataContent, PAGE_SIZE};
pub use cap::image::{
    EndpointDef, ImageCap, ImageConvertError, ImageSlotEntry, MemoryMapping, image_cap,
};
pub use cap::instance::{InstanceCap, RwOverlay};
pub use cap::page::{PageBytes, PageRef, PageSlot};
pub use cap::{Cap, CapHash, CapKind, MAX_ENDPOINTS, MAX_SOURCE_DEPTH, NUM_REGS, TypeCap};
pub use error::{CapError, OpError};
pub use hash::{Blake2b256, Hash};
pub use image::{
    EndpointDef as ImageEndpointDef, Image, InitialDataCap, MemoryMapping as ImageMemoryMapping,
    PinnedCap, chain_extend, chain_genesis, image_content_hash,
};
pub use slot::{SlotIdx, SlotPath};
