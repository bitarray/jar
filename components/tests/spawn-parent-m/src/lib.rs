//! Sub-VM parent guest. Set up by the test harness with:
//!
//! - slot 3: `Hash(image_s)` — content-addressed `Cap::Image` for S.
//! - slot 5: `Hash(input_data)` — input `Cap::Data` for the call.
//!
//! M mints a fresh prepared CNode, copies the input DataCap into
//! its own `slot[0]` (the CALL scratchpad), derives a child Instance
//! from Image S + the prepared CNode, and CALLs the child. When the
//! child halts, the kernel reflects the child's `slot[0]` (a fresh
//! result DataCap) back into M's `slot[0]`. M reads that DataCap and
//! returns the resulting byte.

#![cfg_attr(target_os = "none", no_std)]

use subsoil as _;
