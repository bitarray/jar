//! Allocator-parameterised cap types (v2 shape).
//!
//! These define the canonical Cap representation used by the state
//! cache. Each variant's content lives in `Vec<T, A>` /
//! `Box<T, A>` from `allocator_api2`, so the same type serves both
//! heap (`A = Global`) and cache (`A = TalcAlloc`) contexts.
//!
//! This module is structured to eventually replace the top-level
//! [`crate::cap`] and [`crate::cnode`]; for now it lives in parallel
//! while downstream callers (jar-kernel, javm) are migrated.
//!
//! Naming: this is "the talc-friendly cap module," not specifically
//! "talc-only." With `A = Global` the types live on the heap; only
//! `A = TalcAlloc` puts them in the shared cache region.

pub mod cap;
pub mod cnode;
pub mod data;
pub mod entry;
pub mod image;
pub mod instance;
pub mod page;

#[cfg(test)]
mod tests;

pub use cap::{Cap, CapHash, CapHashOrRef, CapKind, CapRef, MAX_ENDPOINTS, MAX_SOURCE_DEPTH, NUM_REGS};
pub use cnode::{CNodeCap, CNodeSlotEntry};
pub use data::{DataCap, DataContent};
pub use entry::CacheEntry;
pub use image::{EndpointDef, ImageCap, ImageSlotEntry, MemoryMapping};
pub use instance::{InstanceCap, RwOverlay};
pub use page::{PageBytes, PageRef, PageSlot};
