//! The **flat** personality: nub's reference `Personality` /
//! `GuestPersonality` pair.
//!
//! nub is personality-generic, and until now the only personality was
//! JAVM — 2,700 lines of capability semantics, which makes it a poor
//! answer to "what does a personality actually have to provide?". Flat
//! is that answer: one program, one frame, no capability graph, no
//! sub-VM calls, no yields. A program is published by content hash and
//! invoked by content hash, and that is the whole object model.
//!
//! It exists for two reasons:
//!
//! 1. **It is the executable documentation.** The README's "Building a
//!    personality" section used to point at another repository.
//! 2. **It makes nub's own JIT measurable.** Executing recompiled code
//!    needs the ring-0 substrate in `nub-arch-x86`, which needs a
//!    `GuestPersonality`. Without one, nub could measure how fast it
//!    *compiles* and never how fast the result *runs*.
//!
//! # Layout
//!
//! - [`hash`] — content addressing. `no_std`, shared by both halves.
//! - the host half ([`Flat`], [`FlatLocal`]) — behind the `std` feature,
//!   which the guest build turns off.
//! - the guest half — `nub-flat-guest-x86`, which links this crate with
//!   `default-features = false` for [`hash`].

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod hash;

#[cfg(feature = "std")]
mod local;

#[cfg(feature = "std")]
pub use local::FlatLocal;

/// The flat personality.
///
/// Carries no state: everything it needs is in [`FlatLocal`] (host) or
/// the guest's static store.
#[cfg(feature = "std")]
#[derive(Debug, Clone, Copy, Default)]
pub struct Flat;

#[cfg(feature = "std")]
impl nub::Personality for Flat {
    const NAME: &'static str = "flat";
    type Local = FlatLocal;
}
