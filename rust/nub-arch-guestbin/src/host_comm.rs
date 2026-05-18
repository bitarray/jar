//! Guest → host RPC (host-callback channel).
//!
//! Same wire shape as host → guest dispatch: a rkyv-archived
//! [`nub_host_common::rpc::Request`] envelope identifying the
//! target function by `fn_id`, then a rkyv-archived
//! [`nub_host_common::rpc::Response`] coming back. Direction is
//! encoded by which ring the bytes live in (we push to the output
//! ring, host pops; host pushes to the input ring, we pop).
//!
//! The host wakes up on the `OutBAction::CallFunction` outb port
//! and dispatches by `fn_id` (see
//! `nub_host_kvm::sandbox::host_funcs::FunctionRegistry`).

use alloc::format;
use alloc::vec::Vec;

use anyhow::{Result, anyhow};
use nub_host_common::outb::OutBAction;
use nub_host_common::rpc::{ArchivedResponse, Request, Response};
use rkyv::util::AlignedVec;

use crate::GUEST_HANDLE;
use crate::ring::pop_shared_input_raw;

/// 32-bit OUT instruction wrapper. Forked from upstream
/// `hyperlight_guest::arch::amd64::exit::out32` (`pub(crate)` there,
/// so we keep our own copy).
#[inline(always)]
unsafe fn out32(port: u16, val: u32) {
    unsafe {
        core::arch::asm!(
            "out dx, eax",
            in("dx") port,
            in("eax") val,
            options(preserves_flags, nomem, nostack),
        );
    }
}

/// Issue a host callback: serialise a `Request { fn_id, payload }`,
/// push it onto the output ring, trip the `CallFunction` outb port
/// (causing a VMEXIT to the host), and read the host's `Response`
/// from the input ring on return.
///
/// Returns the response payload bytes on success. Non-zero status
/// codes from the host surface as `Err`, with the optional
/// `error_msg` carried along when present.
pub fn call_host_raw(fn_id: u32, payload: &[u8]) -> Result<Vec<u8>> {
    let handle = unsafe { GUEST_HANDLE };

    let req = Request {
        fn_id,
        payload: payload.to_vec(),
    };
    let req_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&req)
        .map_err(|e| anyhow!("rkyv-serialize Request: {e}"))?;

    handle
        .push_shared_output_data(req_bytes.as_slice())
        .map_err(|e| anyhow!("push_shared_output_data: {e:?}"))?;

    unsafe {
        out32(OutBAction::CallFunction as u16, 0);
    }

    let raw = pop_shared_input_raw(&handle)
        .map_err(|e| anyhow!("pop_shared_input_raw: {e:?}"))?;

    let mut aligned = AlignedVec::<16>::with_capacity(raw.len());
    aligned.extend_from_slice(&raw);

    let resp = rkyv::access::<ArchivedResponse, rkyv::rancor::Error>(&aligned)
        .map_err(|e| anyhow!("rkyv-access Response: {e}"))?;

    let status = resp.status.to_native();
    if status != 0 {
        let detail = match resp.error_msg.as_ref() {
            Some(msg) => format!("host call fn_id={fn_id} failed (status={status}): {}", msg.as_str()),
            None => format!("host call fn_id={fn_id} failed (status={status})"),
        };
        return Err(anyhow!(detail));
    }

    Ok(resp.payload.as_slice().to_vec())
}

/// Cast a `Response` into raw bytes (allocation helper for callers
/// that want to build their own error responses).
pub fn encode_response(resp: &Response) -> Result<Vec<u8>> {
    let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(resp)
        .map_err(|e| anyhow!("rkyv-serialize Response: {e}"))?;
    Ok(bytes.into_vec())
}
