//! Allocator-aware `Box`, `Vec`, `Arc`, `HashMap` and the `TalcAlloc`
//! bridge — re-exported through a single workspace façade.
//!
//! ## Why this crate exists
//!
//! Stable Rust gives us 2-parameter `Box<T>` / `Vec<T>` / `Arc<T>`
//! (defaulting to the global allocator), but the 3-parameter forms
//! with a custom allocator are nightly-only. We want allocator-generic
//! types so the shared talc-managed cache region can own everything
//! (caps, refcounts, map storage) instead of half-talc-half-global.
//!
//! The fix is `allocator-api2 0.2` + `talc 4.x` + `hashbrown 0.17`
//! (with their `allocator` / `allocator-api2` features). All three
//! agree on a single `Allocator` trait —
//! [`allocator_api2::alloc::Allocator`] — and Box / Vec / HashMap are
//! all allocator-aware on stable. The only thing api2 doesn't ship is
//! an `Arc`, so we provide one in [`sync`].
//!
//! Downstream depends on `allocate` only — no api2, talc, hashbrown,
//! or spinning_top entries in any other crate's `Cargo.toml`.
//!
//! ## Module layout
//!
//! Module paths mirror `alloc::` where it makes sense:
//!
//! - [`boxed::Box<T, A>`] — re-export of `allocator_api2::boxed::Box`.
//! - [`vec::Vec<T, A>`] — re-export of `allocator_api2::vec::Vec`.
//! - [`collections::HashMap<K, V, A>`] — type-alias over
//!   `hashbrown::HashMap` with the default hasher.
//! - [`sync::Arc<T, A>`] — own non-intrusive `Arc` (heap-header
//!   refcount, mirrors std `Arc`'s API).
//! - [`talc`] — `TalcAlloc` / `CacheTalcLock` / talc re-exports.
//!
//! Plus, at the crate root:
//!
//! - [`Allocator`], [`Global`], [`AllocError`], [`Layout`] — re-exports
//!   of `allocator_api2::alloc::*`.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub use allocator_api2::alloc::{AllocError, Allocator, Global, Layout};

pub mod boxed {
    //! Re-export of `allocator_api2::boxed::Box`.
    pub use allocator_api2::boxed::Box;
}

pub mod vec {
    //! Re-export of `allocator_api2::vec::Vec`.
    pub use allocator_api2::vec::Vec;
}

pub mod collections;
pub mod sync;
pub mod talc;

#[cfg(test)]
pub mod test_arena;

#[cfg(test)]
mod boxed_tests;
#[cfg(test)]
mod sync_tests;
#[cfg(test)]
mod vec_tests;
