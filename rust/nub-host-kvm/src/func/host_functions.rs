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

//! Host-function registration API.
//!
//! Replaces the upstream parameter-tuple polymorphic machinery
//! (`ParameterTuple`/`SupportedReturnType`/`HostFunction<Output, Args>`)
//! with a single byte-slice signature. Each host function takes the
//! raw `Request.payload` bytes from the guest and returns the
//! response payload bytes. Typed encode/decode (if anything) is the
//! caller's job — same shape as `#[guest_function]` on the guest
//! side.

use crate::Result;
use crate::new_error;
use crate::sandbox::UninitializedSandbox;
use crate::sandbox::host_funcs::HostFn;

/// A sandbox on which host functions can be registered.
pub trait Registerable {
    /// Register `func` to be invoked by the guest under the given
    /// `fn_id`. Overwrites any prior entry for that id.
    fn register_host_function(&mut self, fn_id: u32, func: HostFn) -> Result<()>;
}

impl Registerable for UninitializedSandbox {
    fn register_host_function(&mut self, fn_id: u32, func: HostFn) -> Result<()> {
        let mut hfs = self
            .host_funcs
            .try_lock()
            .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?;
        hfs.register_host_function(fn_id, func)
    }
}

/// Allow registering host functions on an already-evolved
/// [`crate::MultiUseSandbox`].
///
/// The primary entry point for host-function registration is the
/// `UninitializedSandbox` impl above — that's the lifecycle phase
/// where the guest hasn't yet been allowed to issue host calls.
/// There are, however, cases where a `MultiUseSandbox` is obtained
/// without traversing the `Uninitialized → evolve()` path:
///
/// - Sandboxes loaded from a persisted snapshot.
/// - Any future API that yields a `MultiUseSandbox` directly.
///
/// In those cases the caller never had a chance to call
/// `register_host_function` on an `UninitializedSandbox`, so we
/// expose the same trait implementation here for late registration.
/// The guest's dispatcher resolves by `fn_id` at call time, so
/// inserting into the registry after `evolve()` is semantically safe
/// as long as the first host-function invocation happens after
/// registration completes.
impl Registerable for crate::MultiUseSandbox {
    fn register_host_function(&mut self, fn_id: u32, func: HostFn) -> Result<()> {
        let mut hfs = self
            .host_funcs
            .try_lock()
            .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?;
        hfs.register_host_function(fn_id, func)
    }
}

pub(crate) fn register_host_function(
    sandbox: &mut UninitializedSandbox,
    fn_id: u32,
    func: HostFn,
) -> Result<()> {
    sandbox
        .host_funcs
        .try_lock()
        .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?
        .register_host_function(fn_id, func)?;
    Ok(())
}
