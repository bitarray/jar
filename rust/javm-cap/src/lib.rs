#![cfg_attr(not(feature = "std"), no_std)]

//! JAR v3 capability system.
//!
//! Defines the four v3 cap kinds (Instance, Image, Data, CNode),
//! their content-bearing representations, a two-tier cache for
//! identity-keyed mutable state + content-addressed blobs, and the
//! primitives (BMT, hash) used by upstream layers.
//!
//! `Cap` and its inner storage use the default `Global` allocator (=
//! std heap on host, talc on guest via `#[global_allocator]`). The
//! cache layer's outer storage (`HashMap` / `Box` parameters) may still
//! be parameterised on a custom allocator for shared-memory layouts.
//!
//! `Cap` itself is the wire form: it derives
//! `rkyv::Archive`/`Serialize`/`Deserialize` so callers move caps
//! across the host/guest boundary by writing
//! `rkyv::to_bytes(&cap)?` (errors on unsettled `Ref` targets) and
//! `rkyv::access::<rkyv::Archived<Cap>, _>(bytes)?` for zero-copy
//! decode. See [`cache::CapHasRefError`] for the encode-time error.
//!
//! See `~/jar/website/content/spec/implementation/architecture.md` for
//! the crate's role in the overall layering.

extern crate alloc;

pub mod abi;
pub mod cache;
pub mod cap;
pub mod error;
pub mod hash;
pub mod image;
pub mod kernel_image;
pub mod layout;
pub mod slot;
pub mod yield_cap;

pub use cache::{CacheDirectory, CacheError, CapHasRefError, CapHashOrRef, CapRef, ResidentCap};
pub use cap::cnode::CNodeCap;
pub use cap::data::{DataCap, GROUP_SIZE, PAGE_SIZE, PageResolution, PageSlab};
pub use cap::image::{
    EndpointDef, ImageCap, ImageConvertError, ImageSlotEntry, MemoryMapping, image_cap,
};
pub use cap::instance::InstanceCap;
pub use cap::page::{PageBytes, PageRef, PageSlot};
pub use cap::{Cap, CapHash, MAX_SOURCE_DEPTH, NUM_REGS};
pub use error::{CapError, OpError};
pub use hash::{Blake2b256, Hash, Hasher};
pub use image::{
    ArenaPageRef, CodeRef, DataDesc, DataDescError, Image, ImageBuilder, InitialDataCap, PinnedCap,
    chain_extend, chain_genesis, image_content_hash,
};
pub use kernel_image::{ALL_KERNEL_IMAGES, KernelImage, kernel_image_hash, recognize_kernel_image};
pub use slot::{Key, MAX_KEY_LEN, SlotPath, key_from_regs, key_to_regs};
pub use yield_cap::{
    gas_handle, gas_meter_key, is_kernel_yield_key, merge_yield_receivers, quota_handle, quota_key,
    yield_receiver, yield_receiver_keys, yield_sender, yield_sender_key,
};
// `CNodeCap::slots` stores `MissingOr<CapHashOrRef>` values; re-export it so
// cnode-slot walkers (e.g. the recompiler's cnode-inherit loop) don't need a
// direct `ssz` dependency.
pub use ssz::MissingOr;
