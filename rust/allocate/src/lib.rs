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
//! workspace `.cargo/config.toml` to just the named crates
//! (`allocate, talc, hashbrown, foldhash`). Everything else compiles
//! strictly-stable.
//!
//! ## Module layout
//!
//! Module paths mirror `alloc` / `std`:
//!
//! - [`boxed::Box<T, A>`] — newtype around `alloc::boxed::Box`.
//! - [`vec::Vec<T, A>`] — newtype around `alloc::vec::Vec`.
//! - [`sync::{Arc, Weak}<T, A>`] — newtype around `alloc::sync::Arc` /
//!   `alloc::sync::Weak`.
//! - [`collections::HashMap<K, V, A>`] — newtype around
//!   `hashbrown::HashMap` (with hashbrown's `nightly` feature).
//! - [`talc::{TalcAlloc, CacheTalcLock, Manual}`] — the talc →
//!   `Allocator` bridge and supporting re-exports.
//!
//! Plus the trait and helpers at the crate root:
//!
//! - [`Allocator`]: stable supertrait wrapper for
//!   `core::alloc::Allocator`.
//! - [`Global`], [`AllocError`], [`Layout`].
//! - [`allocate`], [`allocate_zeroed`], [`deallocate`]: free-function
//!   wrappers for the unstable `Allocator` trait methods so callers
//!   don't need `#![feature(allocator_api)]` to invoke them.

#![no_std]
#![feature(allocator_api)]

extern crate alloc;

pub mod boxed;
pub mod collections;
pub mod sync;
pub mod talc;
pub mod vec;

#[cfg(test)]
mod boxed_tests;
#[cfg(test)]
mod sync_tests;
#[cfg(test)]
mod vec_tests;

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

/// `Layout` is stable since Rust 1.28; safe to re-export.
pub use core::alloc::Layout;

/// Stable wrapper for the unit-like global allocator handle.
///
/// Implements `core::alloc::Allocator` by delegating to the stable
/// low-level `alloc::alloc::{alloc, dealloc}` API, so naming the
/// type from downstream stays on stable Rust.
#[derive(Copy, Clone, Debug, Default)]
pub struct Global;

/// Stable wrapper for allocation-failure marker.
///
/// Newtype around `core::alloc::AllocError` (unstable to name) so
/// downstream callers can write `allocate::AllocError` without
/// `#![feature(allocator_api)]`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AllocError;

impl core::fmt::Display for AllocError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("memory allocation failed")
    }
}

// SAFETY: delegates to `alloc::alloc::Global`, which is the canonical
// global allocator and trivially satisfies the `Allocator` contract.
// Forwarding ensures we pick up any future optimizations in
// `Global::grow` / `Global::shrink` / `Global::allocate_zeroed` for
// free.
unsafe impl core::alloc::Allocator for Global {
    #[inline]
    fn allocate(
        &self,
        layout: Layout,
    ) -> Result<core::ptr::NonNull<[u8]>, core::alloc::AllocError> {
        alloc::alloc::Global.allocate(layout)
    }
    #[inline]
    fn allocate_zeroed(
        &self,
        layout: Layout,
    ) -> Result<core::ptr::NonNull<[u8]>, core::alloc::AllocError> {
        alloc::alloc::Global.allocate_zeroed(layout)
    }
    #[inline]
    unsafe fn deallocate(&self, ptr: core::ptr::NonNull<u8>, layout: Layout) {
        unsafe { alloc::alloc::Global.deallocate(ptr, layout) }
    }
    #[inline]
    unsafe fn grow(
        &self,
        ptr: core::ptr::NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
    ) -> Result<core::ptr::NonNull<[u8]>, core::alloc::AllocError> {
        unsafe { alloc::alloc::Global.grow(ptr, old_layout, new_layout) }
    }
    #[inline]
    unsafe fn grow_zeroed(
        &self,
        ptr: core::ptr::NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
    ) -> Result<core::ptr::NonNull<[u8]>, core::alloc::AllocError> {
        unsafe { alloc::alloc::Global.grow_zeroed(ptr, old_layout, new_layout) }
    }
    #[inline]
    unsafe fn shrink(
        &self,
        ptr: core::ptr::NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
    ) -> Result<core::ptr::NonNull<[u8]>, core::alloc::AllocError> {
        unsafe { alloc::alloc::Global.shrink(ptr, old_layout, new_layout) }
    }
}

// Stable-name helpers for unstable `Allocator` trait methods.
// Downstream calls `allocate::allocate(&alloc, layout)` /
// `allocate::allocate_zeroed(...)` instead of `alloc.allocate(...)`
// to stay on stable Rust without `#![feature(allocator_api)]`.

/// Allocate `layout`'s worth of memory from `alloc`. Stable-name
/// wrapper for `<A as core::alloc::Allocator>::allocate`.
#[inline]
pub fn allocate<A: Allocator + ?Sized>(
    alloc: &A,
    layout: Layout,
) -> Result<core::ptr::NonNull<[u8]>, AllocError> {
    <A as core::alloc::Allocator>::allocate(alloc, layout).map_err(|_| AllocError)
}

/// Allocate `layout`'s worth of zero-initialised memory from `alloc`.
/// Stable-name wrapper for `<A as core::alloc::Allocator>::allocate_zeroed`.
#[inline]
pub fn allocate_zeroed<A: Allocator + ?Sized>(
    alloc: &A,
    layout: Layout,
) -> Result<core::ptr::NonNull<[u8]>, AllocError> {
    <A as core::alloc::Allocator>::allocate_zeroed(alloc, layout).map_err(|_| AllocError)
}

/// Stable-name wrapper for `<A as core::alloc::Allocator>::deallocate`.
///
/// # Safety
///
/// `ptr` must come from a previous `allocate` / `allocate_zeroed`
/// call on the *same* allocator, and `layout` must match.
#[inline]
pub unsafe fn deallocate<A: Allocator + ?Sized>(
    alloc: &A,
    ptr: core::ptr::NonNull<u8>,
    layout: Layout,
) {
    unsafe { <A as core::alloc::Allocator>::deallocate(alloc, ptr, layout) }
}
