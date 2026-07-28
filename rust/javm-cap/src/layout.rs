//! PVM2 guest virtual-address-space layout (ABI constants).
//!
//! These are re-exports of [`nub_program::abi`], which owns them: they
//! are PVM2 ISA/ABI facts, not capability facts, and every producer and
//! consumer of a PVM2 program must agree on them whether or not a
//! capability system is involved.
//!
//! They remain re-exported here because `javm_cap::layout::DATA_BASE`
//! is the spelling used across the JAVM runtimes, and because an Image
//! is laid out against exactly these constants:
//!
//! ```text
//!   [0,         CODE_BASE)  unmapped — NULL guard (catch PC=0 / null deref)
//!   [CODE_BASE, DATA_BASE)  CODE     — RO, ≤ MAX_CODE_SIZE bytes
//!   [DATA_BASE, 4 GiB)      DATA     — stack / ro / rw / heap, RO|RW
//! ```
//!
//! Code placement is a fixed protocol constant rather than an
//! Image-supplied mapping entry: an untrusted Image must not get to
//! choose where its code lands.

pub use nub_program::abi::{CODE_BASE, DATA_BASE, MAX_CODE_SIZE};
