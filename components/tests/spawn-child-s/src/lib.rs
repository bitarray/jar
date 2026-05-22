//! Sub-VM child guest. CALLed by the parent (Image M) with an
//! input `Cap::Data` in `slot[0]`. Reads the bytes, computes their
//! wrapping byte-sum, publishes the result as a single-byte
//! `Cap::Data` back into `slot[0]`, and HALTs. The kernel's
//! HALT-reflect path moves the child's `slot[0]` back into the
//! parent's `slot[0]`.

#![cfg_attr(target_os = "none", no_std)]

use subsoil as _;
