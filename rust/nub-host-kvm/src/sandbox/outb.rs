/*
Copyright 2025  The Hyperlight Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

use std::sync::{Arc, Mutex};

use hyperlight_common::flatbuffer_wrappers::guest_log_data::GuestLogData;
use log::{Level, Record};
use nub_host_common::outb::{Exception, OutBAction};
use nub_host_common::rpc::{ArchivedRequest, Response};
use rkyv::util::AlignedVec;
use tracing::{Span, instrument};
use tracing_log::format_trace;

use super::host_funcs::FunctionRegistry;
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::shared_mem::HostSharedMemory;

/// Errors that can occur when handling an outb operation from the guest.
#[derive(Debug, thiserror::Error)]
pub enum HandleOutbError {
    #[error("Guest aborted: error code {code}, message: {message}")]
    GuestAborted {
        /// The error code from the guest
        code: u8,
        /// The error message from the guest
        message: String,
    },
    #[error("Invalid outb port: {0}")]
    InvalidPort(String),
    #[error("Failed to read guest log data: {0}")]
    ReadLogData(String),
    #[error("Trace formatting error: {0}")]
    TraceFormat(String),
    #[error("Failed to read host function call: {0}")]
    ReadHostFunctionCall(String),
    #[error("Failed to acquire lock at {0}:{1} - {2}")]
    LockFailed(&'static str, u32, String),
    #[error("Failed to write host function response: {0}")]
    WriteHostFunctionResponse(String),
    #[error("Invalid character for debug print: {0}")]
    InvalidDebugPrintChar(u32),
}

#[instrument(err(Debug), skip_all, parent = Span::current(), level="Trace")]
pub(super) fn outb_log(
    mgr: &mut SandboxMemoryManager<HostSharedMemory>,
) -> Result<(), HandleOutbError> {
    // This code will create either a logging record or a tracing record for the GuestLogData depending on if the host has set up a tracing subscriber.
    // In theory as we have enabled the log feature in the Cargo.toml for tracing this should happen
    // automatically (based on if there is tracing subscriber present) but only works if the event created using macros. (see https://github.com/tokio-rs/tracing/blob/master/tracing/src/macros.rs#L2421 )
    // The reason that we don't want to use the tracing macros is that we want to be able to explicitly
    // set the file and line number for the log record which is not possible with macros.
    // This is because the file and line number come from the  guest not the call site.

    let log_data: GuestLogData = mgr
        .read_guest_log_data()
        .map_err(|e| HandleOutbError::ReadLogData(e.to_string()))?;

    let record_level: Level = (&log_data.level).into();

    // Work out if we need to log or trace
    // this API is marked as follows but it is the easiest way to work out if we should trace or log

    // Private API for internal use by tracing's macros.
    //
    // This function is *not* considered part of `tracing`'s public API, and has no
    // stability guarantees. If you use it, and it breaks or disappears entirely,
    // don't say we didn't warn you.

    let should_trace = tracing_core::dispatcher::has_been_set();
    let source_file = Some(log_data.source_file.as_str());
    let line = Some(log_data.line);
    let source = Some(log_data.source.as_str());

    // See https://github.com/rust-lang/rust/issues/42253 for the reason this has to be done this way

    if should_trace {
        // Create a tracing event for the GuestLogData
        // Ideally we would create tracing metadata based on the Guest Log Data
        // but tracing derives the metadata at compile time
        // see https://github.com/tokio-rs/tracing/issues/2419
        // so we leave it up to the subscriber to figure out that there are logging fields present with this data
        format_trace(
            &Record::builder()
                .args(format_args!("{}", log_data.message))
                .level(record_level)
                .target("hyperlight_guest")
                .file(source_file)
                .line(line)
                .module_path(source)
                .build(),
        )
        .map_err(|e| HandleOutbError::TraceFormat(e.to_string()))?;
    } else {
        // Create a log record for the GuestLogData
        log::logger().log(
            &Record::builder()
                .args(format_args!("{}", log_data.message))
                .level(record_level)
                .target("hyperlight_guest")
                .file(Some(&log_data.source_file))
                .line(Some(log_data.line))
                .module_path(Some(&log_data.source))
                .build(),
        );
    }

    Ok(())
}

const ABORT_TERMINATOR: u8 = 0xFF;
const MAX_ABORT_BUFFER_LEN: usize = 1024;

fn outb_abort(
    mem_mgr: &mut SandboxMemoryManager<HostSharedMemory>,
    data: u32,
) -> Result<(), HandleOutbError> {
    let buffer = mem_mgr.get_abort_buffer_mut();

    let bytes = data.to_le_bytes(); // [len, b1, b2, b3]
    let len = bytes[0].min(3);

    for &b in &bytes[1..=len as usize] {
        if b == ABORT_TERMINATOR {
            let guest_error_code = *buffer.first().unwrap_or(&0);

            let result = {
                let message = if let Some(&maybe_exception_code) = buffer.get(1) {
                    match Exception::try_from(maybe_exception_code) {
                        Ok(exception) => {
                            let extra_msg = String::from_utf8_lossy(&buffer[2..]);
                            format!("Exception: {:?} | {}", exception, extra_msg)
                        }
                        Err(_) => String::from_utf8_lossy(&buffer[1..]).into(),
                    }
                } else {
                    String::new()
                };

                Err(HandleOutbError::GuestAborted {
                    code: guest_error_code,
                    message,
                })
            };

            buffer.clear();
            return result;
        }

        if buffer.len() >= MAX_ABORT_BUFFER_LEN {
            buffer.clear();
            return Err(HandleOutbError::GuestAborted {
                code: 0,
                message: "Guest abort buffer overflowed".into(),
            });
        }

        buffer.push(b);
    }
    Ok(())
}

/// Handles OutB operations from the guest.
#[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
pub(crate) fn handle_outb(
    mem_mgr: &mut SandboxMemoryManager<HostSharedMemory>,
    host_funcs: &Arc<Mutex<FunctionRegistry>>,
    port: u16,
    data: u32,
) -> Result<(), HandleOutbError> {
    match port
        .try_into()
        .map_err(|e: anyhow::Error| HandleOutbError::InvalidPort(e.to_string()))?
    {
        OutBAction::Log => outb_log(mem_mgr),
        OutBAction::CallFunction => {
            let req_bytes = mem_mgr
                .read_host_function_call_raw()
                .map_err(|e| HandleOutbError::ReadHostFunctionCall(e.to_string()))?;

            let mut aligned = AlignedVec::<16>::with_capacity(req_bytes.len());
            aligned.extend_from_slice(&req_bytes);

            let response =
                match rkyv::access::<ArchivedRequest, rkyv::rancor::Error>(aligned.as_slice()) {
                    Ok(req) => {
                        let fn_id = req.fn_id.to_native();
                        let payload = req.payload.as_slice();
                        let res = host_funcs
                            .try_lock()
                            .map_err(|e| {
                                HandleOutbError::LockFailed(file!(), line!(), e.to_string())
                            })?
                            .call_host_function(fn_id, payload);

                        match res {
                            Ok(bytes) => Response::ok(bytes),
                            Err(e) => Response::err(1, format!("host fn_id={fn_id}: {e}")),
                        }
                    }
                    Err(e) => Response::err(2, format!("rkyv-access Request: {e}")),
                };

            let resp_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&response).map_err(|e| {
                HandleOutbError::WriteHostFunctionResponse(format!("rkyv-serialize: {e}"))
            })?;

            mem_mgr
                .write_host_function_response_raw(resp_bytes.as_slice())
                .map_err(|e| HandleOutbError::WriteHostFunctionResponse(e.to_string()))?;

            Ok(())
        }
        OutBAction::Abort => outb_abort(mem_mgr, data),
        OutBAction::DebugPrint => {
            let ch: char = match char::from_u32(data) {
                Some(c) => c,
                None => {
                    return Err(HandleOutbError::InvalidDebugPrintChar(data));
                }
            };

            eprint!("{}", ch);
            Ok(())
        }
    }
}
