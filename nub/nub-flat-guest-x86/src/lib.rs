//! The flat guest personality: nub's reference `GuestPersonality`,
//! plugged into the generic guest kernel (`nub-arch-x86`).
//!
//! This is the half that runs inside the KVM sandbox in ring 0, owns
//! the per-frame page table, and drives the x86-64 JIT. It is what
//! makes nub's recompiler *executable* rather than merely
//! *emittable* — without a `GuestPersonality` there is nobody to build
//! a frame for the compiled code to run in.
//!
//! Four pieces, which is the whole obligation:
//!
//! | module | trait | what it decides |
//! |---|---|---|
//! | [`store`] | `GuestStore` | how a published object is decoded and named |
//! | [`mem`] | `FrameMem` | where a data page comes from, and how CoW works |
//! | [`frame`] | `ExecFrame` | the address-space layout handed to the JIT |
//! | [`personality`] | `GuestPersonality` | root frame, gas policy, exit meaning |
//!
//! Host-visible surface: only [`test_abi`]; everything else is
//! `cfg(target_os = "none")`.

#![cfg_attr(target_os = "none", no_std)]

#[cfg(target_os = "none")]
extern crate alloc; // register_guest_kernel! requirement
#[cfg(target_os = "none")]
extern crate hyperlight_guest_bin; // panic handler + allocator + macro paths

#[cfg(target_os = "none")]
pub mod frame;
#[cfg(target_os = "none")]
pub mod mem;
#[cfg(target_os = "none")]
pub mod personality;
#[cfg(target_os = "none")]
pub mod store;

/// Production guest-function table (linkme contributions).
#[cfg(target_os = "none")]
pub mod guest_prod;

/// Flat-private test fn_ids (band >= 0x100). Always compiled — the host
/// side needs the constants.
pub mod test_abi;
