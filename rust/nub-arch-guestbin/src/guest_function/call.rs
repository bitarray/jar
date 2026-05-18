//! Host → guest dispatch: decode rkyv-archived [`Request`], match
//! `fn_id` against [`GUEST_FUNCTION_TABLE`], call the dispatcher,
//! encode the [`Response`] and push it onto the shared output ring.
//!
//! Both envelope types live in [`nub_host_common::rpc`]. The
//! payload bytes inside `Request` are forwarded uninterpreted into
//! the guest function — that function decides its own inner codec
//! (today: rkyv archives of types in `nub-arch-x86-abi`).
//!
//! ## Alignment
//!
//! `rkyv::access` requires its input slice to be aligned to the
//! archived root's alignment (16 by default for our types). The
//! shared input ring is byte-addressed and offers no alignment
//! guarantee, so we copy the popped bytes into an [`AlignedVec`]
//! before calling `access`. The copy cost is dwarfed by the SCALE +
//! 4-FB-allocation cost it replaces.

use alloc::vec::Vec;
use nub_host_common::rpc::{ArchivedRequest, Response};
use rkyv::util::AlignedVec;

use crate::GUEST_HANDLE;
use crate::guest_function::register::GUEST_FUNCTION_TABLE;
use crate::ring::pop_shared_input_raw;

/// Error code used in [`Response::status`] when the request's
/// `fn_id` doesn't match any registered guest function. Non-zero by
/// convention; zero is the success indicator.
pub const STATUS_FN_NOT_FOUND: u32 = 1;

/// Error code used when the request envelope itself failed bytecheck.
pub const STATUS_BAD_REQUEST: u32 = 2;

/// Look up a dispatcher in the table by `fn_id`.
fn lookup(fn_id: u32) -> Option<fn(&[u8]) -> Vec<u8>> {
    GUEST_FUNCTION_TABLE
        .iter()
        .find(|e| e.fn_id == fn_id)
        .map(|e| e.dispatcher)
}

/// Build the rkyv-encoded response bytes for a given outcome.
fn encode_response(resp: Response) -> Vec<u8> {
    rkyv::to_bytes::<rkyv::rancor::Error>(&resp)
        .expect("rkyv-serialize Response (infallible for these shapes)")
        .into_vec()
}

/// Entrypoint invoked from the guestbin's HLT-return path after the
/// host has pushed the request bytes onto the input ring. Pops the
/// bytes, decodes, dispatches, pushes the response.
pub(crate) fn internal_dispatch_function() {
    let handle = unsafe { GUEST_HANDLE };

    let raw = pop_shared_input_raw(&handle).expect("pop request bytes from input ring");

    // rkyv archives need aligned input. Copy into AlignedVec.
    let mut aligned = AlignedVec::<16>::with_capacity(raw.len());
    aligned.extend_from_slice(&raw);

    let resp_bytes = match rkyv::access::<ArchivedRequest, rkyv::rancor::Error>(&aligned) {
        Ok(req) => {
            let fn_id = req.fn_id.to_native();
            match lookup(fn_id) {
                Some(dispatcher) => {
                    let payload = req.payload.as_slice();
                    let out = dispatcher(payload);
                    encode_response(Response::ok(out))
                }
                None => encode_response(Response::err(STATUS_FN_NOT_FOUND, "fn_id not registered")),
            }
        }
        Err(e) => encode_response(Response::err(
            STATUS_BAD_REQUEST,
            alloc::format!("rkyv access Request: {e}"),
        )),
    };

    handle
        .push_shared_output_data(&resp_bytes)
        .expect("push response bytes to output ring");
}
