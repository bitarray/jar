//! Common types shared between the nub host (`nub-host-kvm`) and the
//! in-sandbox guest (`nub-arch-guestbin`).
//!
//! Forked + stripped from upstream `hyperlight-common 0.15.0`
//! (Apache-2.0). Everything related to FlatBuffers (the
//! `flatbuffer_wrappers/` module, the generated `flatbuffers/` code,
//! and the `func/` param-tuple polymorphism that fed those types)
//! is gone — those layers are replaced by rkyv-archived RPC
//! envelopes defined in [`rpc`].
//!
//! What remains:
//! - [`outb`] — OUT-port action constants the host↔guest handshake uses.
//! - [`vmem`] — virtual-memory + page-table helpers used by guest paging.
//! - [`mem`] — layout / PEB constants.
//! - [`layout`] — sandbox memory-layout constants.
//! - [`log_level`] — guest log filter.
//! - [`version_note`] — ELF version-note check for guest binaries.
//! - [`rpc`] — `Request` / `Response` envelope types for the
//!   rkyv-based RPC.
//! - [`cache`] (new) — fixed-VA shared state-cache types
//!   ([`cache::TalcBox`], [`cache::TalcSlice`], [`cache::CacheDirectory`])
//!   plus layout constants used by both host and guest.

#![cfg_attr(not(any(test, debug_assertions)), warn(clippy::panic))]
#![cfg_attr(not(any(test, debug_assertions)), warn(clippy::expect_used))]
#![cfg_attr(not(any(test, debug_assertions)), warn(clippy::unwrap_used))]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod cache;
pub mod layout;
pub mod log_level;
pub mod mem;
pub mod outb;
pub mod rpc;
pub mod version_note;
pub mod vmem;
