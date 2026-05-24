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

// SAFETY: Global delegates to the global alloc/dealloc functions
// (stable), which match the Allocator contract.
unsafe impl core::alloc::Allocator for Global {
    fn allocate(
        &self,
        layout: Layout,
    ) -> Result<core::ptr::NonNull<[u8]>, core::alloc::AllocError> {
        if layout.size() == 0 {
            // Zero-sized: return a dangling-but-aligned non-null slice
            // pointer (matches std::alloc::Global behaviour).
            return Ok(core::ptr::NonNull::slice_from_raw_parts(
                unsafe { core::ptr::NonNull::new_unchecked(layout.align() as *mut u8) },
                0,
            ));
        }
        let ptr = unsafe { alloc::alloc::alloc(layout) };
        if ptr.is_null() {
            Err(core::alloc::AllocError)
        } else {
            Ok(core::ptr::NonNull::slice_from_raw_parts(
                unsafe { core::ptr::NonNull::new_unchecked(ptr) },
                layout.size(),
            ))
        }
    }
    unsafe fn deallocate(&self, ptr: core::ptr::NonNull<u8>, layout: Layout) {
        if layout.size() != 0 {
            unsafe { alloc::alloc::dealloc(ptr.as_ptr(), layout) };
        }
    }
}

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
