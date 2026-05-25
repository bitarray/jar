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
use nub_arch_x86_abi::{
    BootInfo, CapHash as AbiCapHash, FN_ID_NUB_GET_BOOT_INFO, FN_ID_NUB_PUT_CAP,
};
use nub_host_common::rpc::{ArchivedResponse, Request};
use rkyv::util::AlignedVec;
use tracing::{Span, instrument};

use super::host_funcs::FunctionRegistry;
use crate::HyperlightError;
use crate::Result;
use crate::guest_cache_reader::GuestCacheReader;
use crate::hypervisor::InterruptHandle;
use crate::hypervisor::hyperlight_vm::HyperlightVm;
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::shared_mem::HostSharedMemory;
use crate::metrics::{
    METRIC_GUEST_ERROR, METRIC_GUEST_ERROR_LABEL_CODE, maybe_time_and_emit_guest_call,
};

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
    /// Lazily-initialised host-side view of the guest's heap-resident
    /// `CacheDirectory`. Built on the first `put_cap_with_hash` call
    /// (triggers `nub_get_boot_info` once to read the directory VA),
    /// then reused. Lets the host short-circuit idempotent re-puts
    /// without a roundtrip + merkle walk through the guest.
    guest_cache_reader: Option<GuestCacheReader>,
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
            guest_cache_reader: None,
            #[cfg(gdb)]
            dbg_mem_access_fn,
        }
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
    /// Converts `cap` to wire form via
    /// [`Cap::try_into_wire`](javm_cap::Cap::try_into_wire), rkyv-
    /// encodes the resulting [`javm_cap::WireCap`], ships it via
    /// [`Self::call_raw`], and reads back the guest-computed
    /// `CapHash`. On the guest side, the cap is inserted into the
    /// `nub_arch_x86::state_cache::DIRECTORY` map, keyed by hash.
    ///
    /// Caps whose graph still holds a `CapHashOrRef::Ref` target
    /// (cache-local lifetime handles with no resolution on the
    /// receive side) fail at the wire conversion step with a typed
    /// error. Encode/decode failures are surfaced as
    /// `HyperlightError::Error`. A sentinel response (all-`0xFF`
    /// hash) from the guest is also turned into an error.
    pub fn put_cap(&mut self, cap: &Cap) -> Result<AbiCapHash> {
        let wire = cap
            .clone()
            .try_into_wire()
            .map_err(|e| crate::new_error!("put_cap: wire conversion failed: {e}"))?;
        let cap_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&wire)
            .map_err(|e| crate::new_error!("put_cap: rkyv encode Cap<CapHash>: {e}"))?;
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

    /// Pre-hashed put: idempotent fast path that short-circuits the
    /// full [`Self::put_cap`] RPC when the guest's directory already
    /// holds `hash`.
    ///
    /// Behaviour:
    ///
    /// - If `GuestCacheReader::contains(hash)` returns `true`,
    ///   return immediately — the guest already has the cap and we
    ///   skip rkyv encode + VMEXIT + guest decode + merkle walk +
    ///   directory insert. This is the hot path for bench loops that
    ///   re-publish the same cap graph every iteration.
    /// - Otherwise, ship `put_cap(cap)`, then debug-assert the
    ///   returned hash matches `hash`.
    ///
    /// The reader is built lazily on first call (one `nub_get_boot_info`
    /// RPC to read `BootInfo.directory_va`, then a single struct
    /// construction); subsequent calls hit the cached reader.
    pub fn put_cap_with_hash(&mut self, hash: AbiCapHash, cap: &Cap) -> Result<()> {
        let exists = self.ensure_guest_cache_reader()?.contains(&hash);
        if exists {
            return Ok(());
        }
        let got = self.put_cap(cap)?;
        debug_assert_eq!(
            got, hash,
            "put_cap_with_hash: guest-computed hash differs from claimed hash"
        );
        Ok(())
    }

    /// Lazily build the `GuestCacheReader`. Issues one
    /// `nub_get_boot_info` RPC to read `BootInfo.directory_va`, then
    /// constructs the reader; subsequent calls return the cached
    /// reader without a roundtrip.
    fn ensure_guest_cache_reader(&mut self) -> Result<&GuestCacheReader> {
        if self.guest_cache_reader.is_none() {
            let raw = self.call_raw(FN_ID_NUB_GET_BOOT_INFO, &[])?;
            let expected = core::mem::size_of::<BootInfo>();
            if raw.len() != expected {
                return Err(crate::new_error!(
                    "nub_get_boot_info: expected {} bytes, got {}",
                    expected,
                    raw.len()
                ));
            }
            // SAFETY: `BootInfo` is `#[repr(C)]` POD; the guest packs
            // exactly `size_of::<BootInfo>()` bytes via
            // `core::ptr::read` over its `static mut BOOT_INFO`. The
            // host's matching layout comes from the same
            // `nub-arch-x86-abi` crate.
            let info: BootInfo =
                unsafe { core::ptr::read_unaligned(raw.as_ptr() as *const BootInfo) };
            // SAFETY: `info.directory_va` was published by the guest
            // after `init_directory_va`; the host has the guest's
            // kernel image mmap'd at the same VA via the
            // `install_snapshot_mapping` fixed-VA shadow, so the
            // pointer is valid in the host's address space.
            let reader = unsafe { GuestCacheReader::new(&info) }
                .map_err(|e| crate::new_error!("guest_cache_reader: {e}"))?;
            self.guest_cache_reader = Some(reader);
        }
        Ok(self.guest_cache_reader.as_ref().expect("set above"))
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
