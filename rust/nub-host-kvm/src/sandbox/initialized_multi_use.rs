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

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use flatbuffers::FlatBufferBuilder;
use hyperlight_common::flatbuffer_wrappers::function_call::{FunctionCall, FunctionCallType};
use hyperlight_common::flatbuffer_wrappers::function_types::{
    ParameterValue, ReturnType, ReturnValue,
};
use hyperlight_common::flatbuffer_wrappers::util::estimate_flatbuffer_capacity;
use tracing::{Span, instrument};

use super::Callable;
use super::host_funcs::FunctionRegistry;
use crate::HyperlightError;
use crate::func::{ParameterTuple, SupportedReturnType};
use crate::hypervisor::InterruptHandle;
use crate::hypervisor::hyperlight_vm::HyperlightVm;
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::shared_mem::HostSharedMemory;
use crate::metrics::{
    METRIC_GUEST_ERROR, METRIC_GUEST_ERROR_LABEL_CODE, maybe_time_and_emit_guest_call,
};
use crate::Result;

/// A fully initialized sandbox that can execute guest functions multiple times.
///
/// Guest functions can be called repeatedly while maintaining state between calls.
///
/// Post-Stage-F: the upstream `snapshot()` / `restore()` / `map_file_cow()`
/// rollback machinery is gone along with the CoW PT marking that backed it.
/// If a guest call fails for any reason, drop the sandbox and build a new
/// one — that's the only recovery path now (and the one `nub` already used).
pub struct MultiUseSandbox {
    /// Unique identifier for this sandbox instance
    id: u64,
    pub(crate) host_funcs: Arc<Mutex<FunctionRegistry>>,
    pub(crate) mem_mgr: SandboxMemoryManager<HostSharedMemory>,
    vm: HyperlightVm,
    #[cfg(gdb)]
    dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
}

impl MultiUseSandbox {
    /// Move an `UninitializedSandbox` into a new `MultiUseSandbox` instance.
    ///
    /// This function is not equivalent to doing an `evolve` from uninitialized
    /// to initialized, and is purposely not exposed publicly outside the crate
    /// (as a `From` implementation would be)
    #[instrument(skip_all, parent = Span::current(), level = "Trace")]
    pub(super) fn from_uninit(
        host_funcs: Arc<Mutex<FunctionRegistry>>,
        mgr: SandboxMemoryManager<HostSharedMemory>,
        vm: HyperlightVm,
        #[cfg(gdb)] dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
    ) -> MultiUseSandbox {
        Self {
            id: super::snapshot::SANDBOX_CONFIGURATION_COUNTER.fetch_add(1, Ordering::Relaxed),
            host_funcs,
            mem_mgr: mgr,
            vm,
            #[cfg(gdb)]
            dbg_mem_access_fn,
        }
    }

    /// Returns this sandbox's unique id.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Calls a guest function by name with the specified arguments.
    ///
    /// Changes made to the sandbox during execution are persisted.
    /// On failure the sandbox should be dropped and rebuilt.
    #[instrument(err(Debug), skip(self, args), parent = Span::current())]
    pub fn call<Output: SupportedReturnType>(
        &mut self,
        func_name: &str,
        args: impl ParameterTuple,
    ) -> Result<Output> {
        maybe_time_and_emit_guest_call(func_name, || {
            let ret = self.call_guest_function_by_name_no_reset(
                func_name,
                Output::TYPE,
                args.into_value(),
            );
            // Use the ? operator to allow converting any hyperlight_common::func::Error
            // returned by from_value into a HyperlightError
            let ret = Output::from_value(ret?)?;
            Ok(ret)
        })
    }

    /// Calls a guest function with type-erased parameters and return values.
    ///
    /// This function is used for fuzz testing parameter and return type handling.
    #[cfg(feature = "fuzzing")]
    #[instrument(err(Debug), skip(self, args), parent = Span::current())]
    pub fn call_type_erased_guest_function_by_name(
        &mut self,
        func_name: &str,
        ret_type: ReturnType,
        args: Vec<ParameterValue>,
    ) -> Result<ReturnValue> {
        maybe_time_and_emit_guest_call(func_name, || {
            self.call_guest_function_by_name_no_reset(func_name, ret_type, args)
        })
    }

    fn call_guest_function_by_name_no_reset(
        &mut self,
        function_name: &str,
        return_type: ReturnType,
        args: Vec<ParameterValue>,
    ) -> Result<ReturnValue> {
        // ===== KILL() TIMING POINT 1 =====
        // Clear any stale cancellation from a previous guest function call or if kill() was called too early.
        // Any kill() that completed (even partially) BEFORE this line has NO effect on this call.
        self.vm.clear_cancel();

        let res = (|| {
            let estimated_capacity = estimate_flatbuffer_capacity(function_name, &args);

            let fc = FunctionCall::new(
                function_name.to_string(),
                Some(args),
                FunctionCallType::Guest,
                return_type,
            );

            let mut builder = FlatBufferBuilder::with_capacity(estimated_capacity);
            let buffer = fc.encode(&mut builder);

            self.mem_mgr.write_guest_function_call(buffer)?;

            let dispatch_res = self.vm.dispatch_call_from_host(
                &mut self.mem_mgr,
                &self.host_funcs,
                #[cfg(gdb)]
                self.dbg_mem_access_fn.clone(),
            );

            // Convert dispatch errors to HyperlightErrors. Upstream tracked
            // whether the error should "poison" the sandbox — we don't poison
            // anymore (no snapshot/restore to recover from), so just discard
            // the poison bit.
            if let Err(e) = dispatch_res {
                let (error, _should_poison) = e.promote();
                return Err(error);
            }

            let guest_result = self.mem_mgr.get_guest_function_call_result()?.into_inner();

            match guest_result {
                Ok(val) => Ok(val),
                Err(guest_error) => {
                    metrics::counter!(
                        METRIC_GUEST_ERROR,
                        METRIC_GUEST_ERROR_LABEL_CODE => (guest_error.code as u64).to_string()
                    )
                    .increment(1);

                    Err(HyperlightError::GuestError(
                        guest_error.code,
                        guest_error.message,
                    ))
                }
            }
        })();

        // Clear partial abort bytes so they don't leak across calls.
        self.mem_mgr.abort_buffer.clear();

        // In the happy path we do not need to clear io-buffers from the host because:
        // - the serialized guest function call is zeroed out by the guest during deserialization, see call to `try_pop_shared_input_data_into::<FunctionCall>()`
        // - the serialized guest function result is zeroed out by us (the host) during deserialization, see `get_guest_function_call_result`
        // - any serialized host function call are zeroed out by us (the host) during deserialization, see `get_host_function_call`
        // - any serialized host function result is zeroed out by the guest during deserialization, see `get_host_return_value`
        if res.is_err() {
            self.mem_mgr.clear_io_buffers();
        }

        // Note: clear_call_active() is automatically called when _guard is dropped here

        res
    }

    /// Returns a handle for interrupting guest execution.
    pub fn interrupt_handle(&self) -> Arc<dyn InterruptHandle> {
        self.vm.interrupt_handle()
    }

    /// Generate a crash dump of the current state of the VM underlying this sandbox.
    #[cfg(crashdump)]
    #[instrument(err(Debug), skip_all, parent = Span::current())]
    pub fn generate_crashdump(&mut self) -> Result<()> {
        crate::hypervisor::crashdump::generate_crashdump(&self.vm, &mut self.mem_mgr, None)
    }

    /// Generate a crash dump of the current state of the VM, writing to `dir`.
    #[cfg(crashdump)]
    #[instrument(err(Debug), skip_all, parent = Span::current())]
    pub fn generate_crashdump_to_dir(&mut self, dir: impl Into<String>) -> Result<()> {
        crate::hypervisor::crashdump::generate_crashdump(
            &self.vm,
            &mut self.mem_mgr,
            Some(dir.into()),
        )
    }
}

impl Callable for MultiUseSandbox {
    fn call<Output: SupportedReturnType>(
        &mut self,
        func_name: &str,
        args: impl ParameterTuple,
    ) -> Result<Output> {
        self.call(func_name, args)
    }
}

impl std::fmt::Debug for MultiUseSandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiUseSandbox").finish()
    }
}
