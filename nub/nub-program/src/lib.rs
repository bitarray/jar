//! The PVM2 program blob: what a linked guest program *is*, with no
//! reference to any kernel personality.
//!
//! A [`ProgramBlob`] is raw PVM2 bytecode plus the geometry and initial
//! contents of its four data regions (stack, ro, rw, heap) and its
//! exported [`Endpoint`]s. That is exactly what an execution engine
//! needs to build an address space and start running, and nothing more.
//!
//! [`abi`] holds the PVM2 address-space constants ([`abi::CODE_BASE`],
//! [`abi::DATA_BASE`]) that both producers and consumers of a blob must
//! agree on. They live here because this is the crate every PVM2
//! producer and consumer can depend on.
//!
//! A capability-based personality layers *on top*: JAVM's cap `Image`
//! wraps a blob's regions in cnode slots, adds content hashing and an
//! SSZ encoding, and keeps the same geometry. Nothing in this crate
//! knows that exists.
//!
//! `#![no_std]` with `alloc`, zero dependencies — the guest-side kernel
//! links this too.

#![no_std]

extern crate alloc;

pub mod abi;
mod blob;
mod codec;

pub use blob::{Endpoint, InvalidProgram, ProgramBlob, Region, RegionKind, Regions};
pub use codec::{DecodeError, MAGIC, VERSION};
