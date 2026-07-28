//! build.rs helpers for cross-compiling nub guest crates.
//!
//! Two unrelated guest worlds live here, because both are nub's
//! cross-compile recipes and neither belongs to a personality:
//!
//! - [`pvm2`] — the **PVM2 guest**: RV64EMC programs that run *inside*
//!   the engine (interpreter or JIT). Custom target JSON, linked by
//!   `nub-linker` into a `nub_program::ProgramBlob`.
//! - [`arch_x86`] — the **bare-metal x86-64 guest kernel**: the ring-0
//!   substrate that *hosts* the engine inside a KVM/Hyperlight sandbox.
//!   Stable `x86_64-unknown-none` target, no `-Zbuild-std`.
//!
//! [`build`] is re-exported at the root for the x86 guest, which is the
//! older and more frequently called of the two.

pub mod arch_x86;
pub mod pvm2;

pub use arch_x86::build;
