//! Compile-time guest-function registration.
//!
//! Each guest function is a `fn(&[u8]) -> Vec<u8>` that decodes the
//! caller's archived request payload, runs the user code, and
//! returns the encoded response payload. The `#[guest_function(fn_id
//! = N)]` proc-macro emits a `linkme` distributed-slice entry into
//! [`GUEST_FUNCTION_TABLE`] under the chosen integer id, and the
//! dispatcher in [`super::call`] does the lookup at call time.
//!
//! No more name strings, no more parameter polymorphism — every
//! guest function has the same byte-slice-in / byte-vec-out shape.
//! Typed encode/decode lives inside the user function body (today
//! that means rkyv archives of `nub-arch-x86-abi` types).

use alloc::vec::Vec;

/// One row of the guest-function dispatch table.
#[derive(Clone, Copy)]
pub struct GuestFnEntry {
    /// Compile-time-assigned identifier for this function. The
    /// dispatcher matches the caller's `Request.fn_id` against this.
    pub fn_id: u32,
    /// Implementation: receives the request payload bytes and
    /// returns the response payload bytes.
    pub dispatcher: fn(&[u8]) -> Vec<u8>,
}

/// Compile-time-populated guest-function table. The
/// `#[guest_function(fn_id = N)]` macro emits one entry into this
/// slice; the dispatcher in [`super::call::internal_dispatch_function`]
/// iterates it to find the matching `fn_id`.
#[linkme::distributed_slice]
pub static GUEST_FUNCTION_TABLE: [GuestFnEntry];
