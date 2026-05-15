//! JAR v3 integration crate.
//!
//! Composes the foundational cap system (`jar-cap`) and the pure
//! execution engine (`javm-exec`) into a call-stack-aware VM driver
//! that implements the v3 kernel ABI.
//!
//! This crate is what `jar-kernel-v3` will call into for every CALL,
//! CALL_RESUME, host call, and yield routing. See
//! `~/docs/minimum-v3/implementation/architecture.md` (Layer 3 —
//! `javm`) for the design.
//!
//! The crate is built up in sub-stages 3.3 through 3.12; modules
//! are declared here as they land. The skeleton has only the empty
//! shell; consumers should treat the API as unstable until Stage 3
//! completes.
