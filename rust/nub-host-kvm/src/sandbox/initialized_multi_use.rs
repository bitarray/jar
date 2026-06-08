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
use nub_arch_x86_abi::{CapHash as AbiCapHash, FN_ID_NUB_PUT_CAP};
use nub_host_common::rpc::{ArchivedResponse, Request};
use rkyv::util::AlignedVec;
use std::collections::HashSet;
use tracing::{Span, instrument};

use super::host_funcs::FunctionRegistry;
use crate::HyperlightError;
use crate::Result;
use crate::hypervisor::InterruptHandle;
use crate::hypervisor::hyperlight_vm::HyperlightVm;
use crate::hypervisor::virtual_machine::VcpuLane;
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
    pub(crate) mem_mgr: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
    vm: Arc<HyperlightVm>,
    /// Host-side record of every blob hash this sandbox has successfully
    /// published, so `put_cap_with_hash` can short-circuit an idempotent
    /// re-put without a roundtrip + merkle walk through the guest.
    ///
    /// This *replaces* an earlier design that directly dereferenced the
    /// guest's heap-resident `CacheDirectory` hashbrown table from the host
    /// (the deleted `GuestCacheReader`). That was unsound: the guest is built
    /// for `x86_64-unknown-none` (no SSE2 → hashbrown's generic **8-byte**
    /// `Group`) while the host has SSE2 (**16-byte** `Group`). The host's
    /// probe read 8 control bytes *past* the guest's control array, so once
    /// the table grew beyond one group an absent-key lookup could walk off the
    /// end ("went past end of probe sequence") or, worse, silently match the
    /// wrong entry. A hashbrown table simply cannot be shared by direct memory
    /// access across two binaries with different SIMD `Group` widths.
    ///
    /// The host set is correct because the blobs tier is **monotonic**: a cap
    /// is keyed by content hash and `CacheDirectory::put_cap` only ever
    /// `entry().or_insert()`s — blobs are never evicted (only the *instances*
    /// tier is swept). A miss falls through to the idempotent `put_cap` RPC,
    /// so even blobs the guest published on its own (e.g. via `derive_spawn`)
    /// are handled correctly — just without the short-circuit.
    published_blobs: Mutex<HashSet<AbiCapHash>>,
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
    ) -> MultiUseSandbox {
        Self {
            id: super::snapshot::SANDBOX_CONFIGURATION_COUNTER.fetch_add(1, Ordering::Relaxed),
            host_funcs,
            mem_mgr: Arc::new(Mutex::new(mgr)),
            vm: Arc::new(vm),
            published_blobs: Mutex::new(HashSet::new()),
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
    pub fn call_raw(&self, fn_id: u32, payload: &[u8]) -> Result<Vec<u8>> {
        maybe_time_and_emit_guest_call("call_raw", || {
            self.call_guest_function_by_id_on(VcpuLane::PRIMARY, fn_id, payload)
        })
    }

    /// Serialized control-plane call on a selected vCPU lane. This still uses
    /// the legacy shared input/output rings and therefore must not be used as
    /// the concurrent invoke mechanism; it exists to validate and bootstrap
    /// non-primary lanes before the shared job queue lands.
    #[instrument(err(Debug), skip(self, payload), parent = Span::current())]
    pub fn call_raw_on_vcpu(
        &self,
        vcpu_index: usize,
        fn_id: u32,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let lane = VcpuLane::new(vcpu_index);
        maybe_time_and_emit_guest_call("call_raw_on_vcpu", || {
            self.call_guest_function_by_id_on(lane, fn_id, payload)
        })
    }

    fn call_guest_function_by_id_on(
        &self,
        lane: VcpuLane,
        fn_id: u32,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
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

            let mut mem_mgr = self
                .mem_mgr
                .lock()
                .map_err(|_| crate::new_error!("sandbox memory manager mutex poisoned"))?;

            mem_mgr.write_guest_function_call_raw(req_bytes.as_slice())?;

            let dispatch_res = if lane == VcpuLane::PRIMARY {
                self.vm
                    .dispatch_call_from_host(&mut mem_mgr, &self.host_funcs)
            } else {
                self.vm
                    .dispatch_call_from_host_on(lane, &mut mem_mgr, &self.host_funcs)
            };

            if let Err(e) = dispatch_res {
                let (error, _should_poison) = e.promote();
                return Err(error);
            }

            let raw_resp = mem_mgr.read_guest_function_call_result_raw()?;

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
        let mut mem_mgr = self
            .mem_mgr
            .lock()
            .map_err(|_| crate::new_error!("sandbox memory manager mutex poisoned"))?;
        mem_mgr.abort_buffer.clear();

        if res.is_err() {
            mem_mgr.clear_io_buffers();
        }

        res
    }

    /// Publish a [`Cap`] into the guest's heap-resident cap
    /// directory via the [`FN_ID_NUB_PUT_CAP`] RPC.
    ///
    /// rkyv-encodes `cap` directly via [`rkyv::to_bytes`]; the
    /// resulting bytes are shipped via [`Self::call_raw`] and the
    /// guest-computed `CapHash` is read back. On the guest side, the
    /// cap is inserted into the `nub_arch_x86::state_cache::DIRECTORY`
    /// map, keyed by hash.
    ///
    /// Caps whose graph still holds a `CapHashOrRef::Ref` target
    /// (cache-local lifetime handles with no resolution on the
    /// receive side) fail at rkyv-encode with a typed
    /// [`CapHasRefError`](javm_cap::CapHasRefError) wrapped in the
    /// rancor error chain. Other encode/decode failures are surfaced
    /// as `HyperlightError::Error`. A sentinel response (all-`0xFF`
    /// hash) from the guest is also turned into an error.
    pub fn put_cap(&self, cap: &Cap) -> Result<AbiCapHash> {
        let cap_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(cap)
            .map_err(|e| crate::new_error!("put_cap: rkyv encode (or Ref present): {e}"))?;
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
    /// full [`Self::put_cap`] RPC when this sandbox has already
    /// published `hash`.
    ///
    /// Behaviour:
    ///
    /// - If `hash` is in the host-side `published_blobs` set,
    ///   return immediately — we already shipped this cap and the blobs
    ///   tier never evicts, so the guest still holds it. We skip the
    ///   rkyv encode + VMEXIT + guest decode + merkle walk + directory
    ///   insert. This is the hot path for bench loops that re-publish
    ///   the same cap graph every iteration.
    /// - Otherwise, ship `put_cap(cap)`, debug-assert the returned hash
    ///   matches `hash`, and record it.
    ///
    /// We deliberately do **not** check the guest's directory directly:
    /// the guest's `CacheDirectory` is a hashbrown table built with a
    /// different SIMD `Group` width than the host's hashbrown (see
    /// `published_blobs`), so a host-side deref of it is unsound.
    pub fn put_cap_with_hash(&self, hash: AbiCapHash, cap: &Cap) -> Result<()> {
        {
            let published_blobs = self
                .published_blobs
                .lock()
                .map_err(|_| crate::new_error!("published blob set mutex poisoned"))?;
            if published_blobs.contains(&hash) {
                return Ok(());
            }
        }

        let got = self.put_cap(cap)?;
        debug_assert_eq!(
            got, hash,
            "put_cap_with_hash: guest-computed hash differs from claimed hash"
        );

        self.published_blobs
            .lock()
            .map_err(|_| crate::new_error!("published blob set mutex poisoned"))?
            .insert(hash);
        Ok(())
    }

    /// Returns a handle for interrupting guest execution.
    pub fn interrupt_handle(&self) -> Arc<dyn InterruptHandle> {
        self.vm.interrupt_handle()
    }
}

impl std::fmt::Debug for MultiUseSandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiUseSandbox").finish()
    }
}
