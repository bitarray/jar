//! Allocator-aware `Box`, `Vec`, `Arc`, `HashMap` and the `TalcAlloc`
//! bridge — wrapped into stable newtypes for the rest of the workspace.
//!
//! ## Why this crate exists
//!
//! Stable Rust gives us 2-parameter `Box<T>` / `Vec<T>` /
//! `BTreeMap<K, V>` / `Arc<T>` (defaulting to the global allocator),
//! but the 3-parameter forms with a custom allocator are nightly. We
//! want allocator-generic types so the shared talc-managed cache
//! region can own everything (caps, refcounts, map storage) instead
//! of half-talc-half-global.
//!
//! No third-party crate fills the gap cleanly on
//! `allocator-api2 0.4`. So we use the `RUSTC_BOOTSTRAP` env-var
//! escape hatch (see Firefox `mach build` for prior art), scoped via
//! workspace `.cargo/config.toml` to just **three** crates:
//! `allocate, talc, hashbrown`. Everything else compiles
//! strictly-stable.
//!
//! ## What's exposed
//!
//! - [`Allocator`]: a stable supertrait wrapper for
//!   `core::alloc::Allocator`. Any `T: core::alloc::Allocator`
//!   auto-implements this. Use as a bound everywhere: `where A:
//!   allocate::Allocator + Clone`.
//! - [`Box`], [`Vec`], [`Arc`], [`Weak`], [`HashMap`]: newtype
//!   wrappers around `alloc::boxed::Box`, `alloc::vec::Vec`,
//!   `alloc::sync::Arc`, `alloc::sync::Weak`, and
//!   `hashbrown::HashMap` respectively. Newtypes (not re-exports) so
//!   downstream stays on stable Rust.
//! - [`TalcAlloc`]: the talc → `Allocator` bridge. Single impl, no
//!   `allocator-api2` involved.
//! - [`CacheTalcLock`], [`Manual`]: re-exports so consumers don't
//!   need a direct talc dep.

#![no_std]
#![feature(allocator_api)]

extern crate alloc;

/// Stable-name supertrait wrapper for `core::alloc::Allocator`.
///
/// Any `T: core::alloc::Allocator` automatically implements this
/// (blanket impl). Use as a bound everywhere in the workspace:
///
/// ```ignore
/// fn foo<A: allocate::Allocator + Clone>(alloc: A) { ... }
/// ```
///
/// The supertrait is `core::alloc::Allocator` (nightly), but writing
/// `where A: allocate::Allocator` is fully stable in downstream
/// crates — only `allocate` itself needs `#![feature(allocator_api)]`
/// to name the supertrait.
pub trait Allocator: core::alloc::Allocator {}
impl<T: core::alloc::Allocator + ?Sized> Allocator for T {}

/// Re-exports of stable companion types.
pub use alloc::alloc::Global;
pub use core::alloc::{AllocError, Layout};

mod arc;
mod box_;
mod hashmap;
mod talc_alloc;
mod vec;

#[cfg(test)]
mod arc_tests;
#[cfg(test)]
mod box_tests;
#[cfg(test)]
mod hashmap_tests;
#[cfg(test)]
mod vec_tests;

pub use arc::{Arc, Weak};
pub use box_::Box;
pub use hashmap::HashMap;
pub use talc_alloc::{CacheTalcLock, Manual, TalcAlloc};
pub use vec::Vec;
