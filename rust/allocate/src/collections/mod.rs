//! Allocator-aware collections.
//!
//! Mirrors `alloc::collections` / `std::collections` paths:
//!
//! - [`HashMap`] — SwissTable hash map (wraps `hashbrown::HashMap`
//!   with hashbrown's `nightly` feature on, so its `A` is the real
//!   `core::alloc::Allocator`). Unordered iteration.
//! - [`BTreeMap`] — ordered B-tree map (wraps
//!   `alloc::collections::BTreeMap`). Sorted iteration.

pub mod btreemap;
pub mod hashmap;

#[cfg(test)]
mod btreemap_tests;
#[cfg(test)]
mod hashmap_tests;

pub use btreemap::BTreeMap;
pub use hashmap::HashMap;
