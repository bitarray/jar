//! Wire envelope for the host ↔ guest RPC.
//!
//! Both directions (host → guest function call, guest → host
//! callback) use the same `Request` / `Response` shapes. The
//! payload is opaque bytes — each `fn_id` defines its own inner
//! codec (today: rkyv-archived domain types like
//! `nub_arch_x86_abi::{InvocationSpec, InvocationResult}`).
//!
//! ## Wire layout
//!
//! Serializing a [`Request`] or [`Response`] with `rkyv::to_bytes`
//! produces an `AlignedVec<u8>` that contains:
//!
//! 1. An archived `Request`/`Response` whose `payload` field is an
//!    `ArchivedVec<u8>` (the bytes laid out inline).
//! 2. The rkyv root pointer trailer (a relative offset + length).
//!
//! Readers run `rkyv::access::<ArchivedRequest, _>(&bytes)` (with
//! bytecheck) and pull `archived.payload.as_ref() -> &[u8]` to
//! reach the inner payload — zero allocation, single pointer cast
//! plus the cheap bytecheck pass.
//!
//! Direction is encoded by which shared-memory ring the bytes live
//! in (host's input vs output ring), not by the type.

use alloc::string::String;
use alloc::vec::Vec;

/// Host → guest function call OR guest → host callback. The
/// `payload` is opaque to the envelope: the fn_id selects what
/// inner codec applies.
#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize)]
#[rkyv(derive(Debug))]
pub struct Request {
    /// Compile-time-assigned identifier for the target function.
    /// Receiver matches on this to route to the right handler.
    pub fn_id: u32,
    /// Opaque payload bytes — the fn-specific codec lives inside.
    pub payload: Vec<u8>,
}

/// Reply to a [`Request`]. `status == 0` means OK; non-zero is a
/// receiver-defined error code with the human-readable detail in
/// `error_msg` (mostly for debugging).
///
/// On OK, `payload` holds the function's archived return value.
/// On error, `payload` is typically empty but the field is kept
/// for symmetry / future use.
#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize)]
#[rkyv(derive(Debug))]
pub struct Response {
    /// 0 = ok; non-zero = error (handler-specific code).
    pub status: u32,
    /// Human-readable error detail on non-zero status.
    pub error_msg: Option<String>,
    /// Archived return-value bytes on success; empty on error.
    pub payload: Vec<u8>,
}

impl Response {
    /// Construct a success response with the given archived payload.
    pub fn ok(payload: Vec<u8>) -> Self {
        Self {
            status: 0,
            error_msg: None,
            payload,
        }
    }

    /// Construct an error response. `status` must be non-zero.
    pub fn err(status: u32, msg: impl Into<String>) -> Self {
        debug_assert!(status != 0, "Response::err with status=0 is OK, not error");
        Self {
            status,
            error_msg: Some(msg.into()),
            payload: Vec::new(),
        }
    }
}
