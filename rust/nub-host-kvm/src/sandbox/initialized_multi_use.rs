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

use javm_cap::cap::Cap;
use javm_cap::wire::WireCap;
use nub_arch_x86_abi::{CapHash as AbiCapHash, FN_ID_NUB_PUT_CAP};
use nub_host_common::rpc::{ArchivedResponse, Request};
use rkyv::util::AlignedVec;
use tracing::{Span, instrument};

use super::host_funcs::FunctionRegistry;
use crate::HyperlightError;
use crate::Result;
use crate::hypervisor::InterruptHandle;
use crate::hypervisor::hyperlight_vm::HyperlightVm;
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::shared_mem::HostSharedMemory;
use crate::metrics::{
    METRIC_GUEST_ERROR, METRIC_GUEST_ERROR_LABEL_CODE, maybe_time_and_emit_guest_call,
};
use nub_host_common::cache::Cache;

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
    /// Host-side state cache. The KVM memory slot installed during
    /// evolve points into `cache`'s mmap'd region; `cache` MUST drop
    /// AFTER `vm` (Rust drops fields in declaration order).
    vm: HyperlightVm,
    pub(crate) cache: Cache,
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
        cache: Cache,
        #[cfg(gdb)] dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
    ) -> MultiUseSandbox {
        Self {
            id: super::snapshot::SANDBOX_CONFIGURATION_COUNTER.fetch_add(1, Ordering::Relaxed),
            host_funcs,
            mem_mgr: mgr,
            vm,
            cache,
            #[cfg(gdb)]
            dbg_mem_access_fn,
        }
    }

    /// Accessor for the host-side state cache. Used by `Nub` to
    /// publish/pin/unpin Cap::Instance state before/after `call_raw`.
    pub fn cache(&mut self) -> &mut Cache {
        &mut self.cache
    }

    /// Returns this sandbox's unique id.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Call a guest function by `fn_id` with a raw byte payload.
    /// Returns the response payload bytes on success.
    ///
    /// Wire format: the host serialises a
    /// [`nub_host_common::rpc::Request`] (rkyv) carrying `fn_id` and
    /// `payload`, ships it via the input data ring, the guest decodes
    /// + dispatches + writes a `Response` to the output ring, and we
    /// read + check `status` before returning the inner payload.
    ///
    /// Changes made to the sandbox during execution are persisted.
    /// On failure the sandbox should be dropped and rebuilt.
    #[instrument(err(Debug), skip(self, payload), parent = Span::current())]
    pub fn call_raw(&mut self, fn_id: u32, payload: &[u8]) -> Result<Vec<u8>> {
        maybe_time_and_emit_guest_call("call_raw", || {
            self.call_guest_function_by_id(fn_id, payload)
        })
    }

    fn call_guest_function_by_id(&mut self, fn_id: u32, payload: &[u8]) -> Result<Vec<u8>> {
        // ===== KILL() TIMING POINT 1 =====
        // Clear any stale cancellation from a previous guest function call or if kill() was called too early.
        // Any kill() that completed (even partially) BEFORE this line has NO effect on this call.
        self.vm.clear_cancel();

        let res = (|| {
            let req = Request {
                fn_id,
                payload: payload.to_vec(),
            };
            let req_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&req)
                .map_err(|e| crate::new_error!("rkyv-serialize Request: {e}"))?;

            self.mem_mgr
                .write_guest_function_call_raw(req_bytes.as_slice())?;

            let dispatch_res = self.vm.dispatch_call_from_host(
                &mut self.mem_mgr,
                &self.host_funcs,
                #[cfg(gdb)]
                self.dbg_mem_access_fn.clone(),
            );

            if let Err(e) = dispatch_res {
                let (error, _should_poison) = e.promote();
                return Err(error);
            }

            let raw_resp = self.mem_mgr.read_guest_function_call_result_raw()?;

            let mut aligned = AlignedVec::<16>::with_capacity(raw_resp.len());
            aligned.extend_from_slice(&raw_resp);

            let resp = rkyv::access::<ArchivedResponse, rkyv::rancor::Error>(aligned.as_slice())
                .map_err(|e| crate::new_error!("rkyv-access Response: {e}"))?;

            let status = resp.status.to_native();
            if status != 0 {
                let msg = resp
                    .error_msg
                    .as_ref()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_else(|| format!("guest fn_id={fn_id} returned status {status}"));
                metrics::counter!(
                    METRIC_GUEST_ERROR,
                    METRIC_GUEST_ERROR_LABEL_CODE => status.to_string()
                )
                .increment(1);
                return Err(HyperlightError::GuestError(
                    hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode::GuestError,
                    msg,
                ));
            }

            Ok(resp.payload.as_slice().to_vec())
        })();

        // Clear partial abort bytes so they don't leak across calls.
        self.mem_mgr.abort_buffer.clear();

        if res.is_err() {
            self.mem_mgr.clear_io_buffers();
        }

        res
    }

    /// Publish a [`Cap`] into the guest's heap-resident cap
    /// directory via the [`FN_ID_NUB_PUT_CAP`] RPC.
    ///
    /// Encodes `cap` as a [`WireCap`] (see `javm-cap`'s `wire`
    /// module), ships it via [`Self::call_raw`], and reads back the
    /// guest-computed `CapHash`. On the guest side, the cap is
    /// inserted into the
    /// `nub_arch_x86::state_cache::DIRECTORY` map, keyed by hash.
    ///
    /// Caps that can't be represented on the wire (e.g.
    /// `DataContent::Paged`, `CNode` with `Ref`-typed slots, etc.)
    /// fail at the wire conversion step with a typed error.
    /// Encode/decode failures are surfaced as
    /// `HyperlightError::Error`. A sentinel response (all-`0xFF`
    /// hash) from the guest is also turned into an error.
    pub fn put_cap(&mut self, cap: &Cap) -> Result<AbiCapHash> {
        let wire = WireCap::from_cap(cap)
            .map_err(|e| crate::new_error!("put_cap: wire conversion failed: {e}"))?;
        let cap_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&wire)
            .map_err(|e| crate::new_error!("put_cap: rkyv encode WireCap: {e}"))?;
        let resp = self.call_raw(FN_ID_NUB_PUT_CAP, cap_bytes.as_slice())?;
        if resp.len() != 32 {
            return Err(crate::new_error!(
                "put_cap: expected 32-byte hash response, got {}",
                resp.len()
            ));
        }
        let mut hash: AbiCapHash = [0u8; 32];
        hash.copy_from_slice(&resp);
        // Guest's `nub_put_cap` returns `0xFF * 32` on decode/conv
        // failure. Surface as a typed error so callers don't observe
        // a fake hash.
        if hash == [0xFFu8; 32] {
            return Err(crate::new_error!(
                "put_cap: guest reported decode/conversion failure (sentinel response)"
            ));
        }
        Ok(hash)
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

impl std::fmt::Debug for MultiUseSandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiUseSandbox").finish()
    }
}
