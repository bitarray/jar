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

//! Fn-id-indexed registry of host callbacks the guest can invoke
//! via the `OutBAction::CallFunction` outb port. Each entry is a
//! `FnMut(&[u8]) -> Result<Vec<u8>>` — receives the raw payload
//! bytes from a `nub_host_common::rpc::Request`, produces the raw
//! response payload bytes that the host wraps in a `Response`.
//!
//! No more name strings, no more parameter-tuple polymorphism. If
//! a future caller wants typed `Fn(Spec) -> Result` registration,
//! a sugar attribute (`#[host_function(fn_id = N)]`) in
//! `nub-host-guest-macro` can wrap the encode/decode at compile
//! time.

use tracing::{Span, instrument};

use crate::HyperlightError::HostFunctionNotFound;
use crate::Result;

/// Boxed host function. Takes a payload byte slice (the inner
/// `Request.payload`), returns response payload bytes.
pub type HostFn = Box<dyn FnMut(&[u8]) -> Result<Vec<u8>> + Send>;

/// Maximum number of registered host functions. Sized so the
/// fixed-size array fits in a single cache line of pointer-sized
/// slots while leaving room for a handful of future callbacks.
pub const HOST_FN_TABLE_SIZE: usize = 64;

/// Fn-id-indexed registry. Slots default to `None`; registering at
/// index `i` puts a callback there. Dispatching at index `i`
/// returns `HostFunctionNotFound` if the slot is empty.
pub struct FunctionRegistry {
    functions: [Option<HostFn>; HOST_FN_TABLE_SIZE],
}

impl Default for FunctionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl FunctionRegistry {
    pub const fn new() -> Self {
        // `[None; N]` requires `Copy`; `Option<HostFn>` isn't.
        // Build the array element-by-element.
        Self {
            functions: [const { None }; HOST_FN_TABLE_SIZE],
        }
    }

    /// Register `func` under `fn_id`. Overwrites any prior entry.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub(crate) fn register_host_function(&mut self, fn_id: u32, func: HostFn) -> Result<()> {
        let idx = fn_id as usize;
        if idx >= HOST_FN_TABLE_SIZE {
            return Err(crate::new_error!(
                "register_host_function: fn_id={} exceeds HOST_FN_TABLE_SIZE={}",
                fn_id,
                HOST_FN_TABLE_SIZE
            ));
        }
        self.functions[idx] = Some(func);
        Ok(())
    }

    /// Dispatch a guest→host call to the registered handler. Returns
    /// `HostFunctionNotFound` if no handler is registered for
    /// `fn_id`. The handler's `Err` is propagated as-is.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub(crate) fn call_host_function(&mut self, fn_id: u32, payload: &[u8]) -> Result<Vec<u8>> {
        let idx = fn_id as usize;
        let entry = self
            .functions
            .get_mut(idx)
            .and_then(|slot| slot.as_mut())
            .ok_or_else(|| HostFunctionNotFound(format!("fn_id={fn_id}")))?;
        crate::metrics::maybe_time_and_emit_host_call(&format!("fn_id={fn_id}"), || entry(payload))
    }
}

