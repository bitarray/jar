//! Allocator-aware collections.
//!
//! Mirrors `alloc::collections` / `std::collections` paths:
//!
//! - [`HashMap`] — SwissTable hash map (wraps `hashbrown::HashMap`
//!   with hashbrown's `nightly` feature on, so its `A` is the real
//!   `core::alloc::Allocator`).
//!
//! `BTreeMap` is not currently provided. Add a newtype here if a
//! consumer needs an ordered allocator-aware map.

pub mod hashmap;

#[cfg(test)]
mod hashmap_tests;

pub use hashmap::HashMap;
