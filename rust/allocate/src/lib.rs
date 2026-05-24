//! Allocator-aware collections + smart pointers over `allocator-api2 0.4`.
//!
//! The Rust ecosystem is mid-transition to the `Allocator` API. On stable
//! `alloc::collections::BTreeMap` is `BTreeMap<K, V>` (no allocator param),
//! `alloc::sync::Arc<T>` is `Arc<T>` (no allocator param), and `hashbrown`
//! provides `HashMap<K, V, S, A>` but pins `allocator-api2 ^0.2.9` which
//! conflicts with `talc 5.x`'s `allocator-api2 ^0.4` requirement.
//!
//! `allocate` exists to fill the gap by:
//!
//! 1. Re-exporting the `allocator-api2 0.4` core types so callers depend
//!    on one place for the `Allocator` trait, `Box<T, A>`, and `Vec<T, A>`.
//! 2. Vendoring `BTreeMap` from `alloc::collections::BTreeMap`,
//!    `HashMap` from `hashbrown`, and `Arc`/`Weak` from `alloc::sync`,
//!    each mechanically patched to work on stable + `allocator-api2 0.4`.
//!
//! Vendored modules are kept as close to upstream as possible — see
//! the per-module `SOURCE.md` files for the upstream commit SHA and
//! the patches applied. Re-syncing with upstream should be a routine
//! 3-way merge, not a rewrite.

#![no_std]

extern crate alloc;

pub use allocator_api2::alloc::{AllocError, Allocator, Global, Layout};
pub use allocator_api2::boxed::Box;
pub use allocator_api2::vec::Vec;
