//! Memory primitives for managing a talc-backed shared region.
//!
//! Bundled because they all serve the same purpose — owning values
//! and slabs inside a [`talc::TalcLock`]-managed heap that lives in
//! shared memory:
//!
//! - [`Aarc<T, A>`] — a hand-rolled `Arc<T>` parameterised over any
//!   [`allocator_api2::alloc::Allocator`]. Generic enough to also work
//!   with `Global` (used by `javm-cap`'s local-backend tests).
//! - [`CacheTalcLock`] — concrete type alias for the
//!   `TalcLock<RawSpinlock, Manual>` flavour used by the cache region.
//! - [`TalcAlloc`] — a `Copy` `Allocator` handle pointing at a
//!   [`CacheTalcLock`]. Lets stock `allocator_api2::{vec::Vec,
//!   boxed::Box}` own talc-backed content.
//! - [`TalcBox<T>`], [`TalcSlice`] — hand-rolled smart pointers that
//!   own a value/slab inside talc memory. Drop frees the slab back
//!   through the underlying [`CacheTalcLock`].

#![no_std]

extern crate alloc;

pub mod aarc;
pub mod talc_alloc;
pub mod talc_box;

#[cfg(test)]
mod aarc_tests;
#[cfg(test)]
mod talc_alloc_tests;

pub use aarc::{Aarc, AarcRefCounted, TalcArc, TalcRefCounted};
pub use talc_alloc::TalcAlloc;
pub use talc_box::{CacheTalcLock, TalcBox, TalcSlice};
