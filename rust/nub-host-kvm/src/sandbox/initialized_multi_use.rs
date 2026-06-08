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

use std::sync::atomic::{Ordering, fence};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use javm_cap::cap::Cap;
use nub_arch_x86_abi::{
    CapHash as AbiCapHash, FN_ID_NUB_INVOKE_WORKER, FN_ID_NUB_PUT_CAP, InvocationResult,
    InvokePacket, PARALLEL_INVOKE_STATUS_DONE, PARALLEL_INVOKE_STATUS_EMPTY,
    PARALLEL_INVOKE_STATUS_READY, PARALLEL_INVOKE_STATUS_RUNNING, PARALLEL_INVOKE_STATUS_STARTING,
    PARALLEL_INVOKE_STATUS_STOP,
};
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
    control_lock: Mutex<()>,
    invoke_workers: Mutex<Option<Arc<ParallelInvokeWorkers>>>,
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
            control_lock: Mutex::new(()),
            invoke_workers: Mutex::new(None),
            published_blobs: Mutex::new(HashSet::new()),
        }
    }

    /// Returns this sandbox's unique id.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Fixed vCPU pool size configured for this sandbox.
    pub fn vcpu_count(&self) -> Result<usize> {
        let mem_mgr = self
            .mem_mgr
            .lock()
            .map_err(|_| crate::new_error!("sandbox memory manager mutex poisoned"))?;
        Ok(mem_mgr.layout.get_vcpu_count())
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
            self.stop_invoke_workers()?;
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
            self.stop_invoke_workers()?;
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
        let _control = self
            .control_lock
            .lock()
            .map_err(|_| crate::new_error!("sandbox control mutex poisoned"))?;

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

    /// Submit an invoke packet through the per-lane parallel worker slots.
    ///
    /// Workers are started lazily and remain hot for subsequent invoke calls.
    /// The legacy raw RPC channel remains the serialized control plane.
    pub fn invoke_cached_parallel(
        &self,
        job_id: u64,
        packet: &InvokePacket,
    ) -> Result<InvocationResult> {
        let workers = self.ensure_invoke_workers()?;
        let lane = workers.acquire_lane()?;
        let lane_idx = lane.index();
        let deadline = Instant::now() + Duration::from_secs(30);

        {
            let mem_mgr = self
                .mem_mgr
                .lock()
                .map_err(|_| crate::new_error!("sandbox memory manager mutex poisoned"))?;
            let status = mem_mgr.read_parallel_invoke_status(lane_idx)?;
            if status != PARALLEL_INVOKE_STATUS_EMPTY {
                return Err(crate::new_error!(
                    "parallel invoke lane {} was not empty before submit (status={})",
                    lane_idx,
                    status
                ));
            }
            mem_mgr.write_parallel_invoke_job_id(lane_idx, job_id)?;
            mem_mgr.write_parallel_invoke_packet(lane_idx, packet)?;
            fence(Ordering::Release);
            mem_mgr.write_parallel_invoke_status(lane_idx, PARALLEL_INVOKE_STATUS_READY)?;
        }

        loop {
            let done = {
                let mem_mgr = self
                    .mem_mgr
                    .lock()
                    .map_err(|_| crate::new_error!("sandbox memory manager mutex poisoned"))?;
                match mem_mgr.read_parallel_invoke_status(lane_idx)? {
                    PARALLEL_INVOKE_STATUS_DONE => {
                        fence(Ordering::Acquire);
                        let result = mem_mgr.read_parallel_invoke_result(lane_idx)?;
                        mem_mgr
                            .write_parallel_invoke_status(lane_idx, PARALLEL_INVOKE_STATUS_EMPTY)?;
                        Some(result)
                    }
                    PARALLEL_INVOKE_STATUS_READY | PARALLEL_INVOKE_STATUS_RUNNING => None,
                    other => {
                        return Err(crate::new_error!(
                            "parallel invoke lane {} entered unexpected status {}",
                            lane_idx,
                            other
                        ));
                    }
                }
            };
            if let Some(result) = done {
                return Ok(result);
            }
            if let Some(worker_result) = workers.take_finished_result(lane_idx) {
                let detail = match worker_result {
                    Ok(()) => "clean worker exit".to_string(),
                    Err(e) => e,
                };
                return Err(crate::new_error!(
                    "parallel invoke worker lane {} exited while job {} was pending: {}",
                    lane_idx,
                    job_id,
                    detail
                ));
            }
            if Instant::now() >= deadline {
                let status = self
                    .mem_mgr
                    .lock()
                    .map_err(|_| crate::new_error!("sandbox memory manager mutex poisoned"))?
                    .read_parallel_invoke_status(lane_idx)?;
                return Err(crate::new_error!(
                    "parallel invoke lane {} timed out waiting for job {} (status={})",
                    lane_idx,
                    job_id,
                    status
                ));
            }
            thread::yield_now();
        }
    }

    fn ensure_invoke_workers(&self) -> Result<Arc<ParallelInvokeWorkers>> {
        let mut guard = self
            .invoke_workers
            .lock()
            .map_err(|_| crate::new_error!("parallel invoke worker mutex poisoned"))?;
        if let Some(workers) = guard.as_ref().cloned() {
            return Ok(workers);
        }

        let vcpu_count = self.vcpu_count()?;
        let mut handles = Vec::with_capacity(vcpu_count);
        for lane in 0..vcpu_count {
            handles.push(self.start_invoke_worker_lane(lane)?);
        }
        let workers = Arc::new(ParallelInvokeWorkers::new(vcpu_count, handles));
        *guard = Some(workers.clone());
        Ok(workers)
    }

    fn stop_invoke_workers(&self) -> Result<()> {
        let workers = {
            let mut guard = self
                .invoke_workers
                .lock()
                .map_err(|_| crate::new_error!("parallel invoke worker mutex poisoned"))?;
            let Some(workers) = guard.take() else {
                return Ok(());
            };
            workers
        };

        workers.mark_stopping_and_wait_idle()?;
        for lane in 0..workers.lane_count() {
            {
                let mem_mgr = self
                    .mem_mgr
                    .lock()
                    .map_err(|_| crate::new_error!("sandbox memory manager mutex poisoned"))?;
                mem_mgr.write_parallel_invoke_status(lane, PARALLEL_INVOKE_STATUS_STOP)?;
            }
            workers
                .join_lane(lane, Duration::from_secs(5))?
                .map_err(|e| crate::new_error!("parallel invoke worker lane {lane}: {e}"))?;
        }

        Ok(())
    }

    fn start_invoke_worker_lane(&self, lane: usize) -> Result<InvokeWorkerHandle> {
        let _control = self
            .control_lock
            .lock()
            .map_err(|_| crate::new_error!("sandbox control mutex poisoned"))?;

        {
            let mut mem_mgr = self
                .mem_mgr
                .lock()
                .map_err(|_| crate::new_error!("sandbox memory manager mutex poisoned"))?;
            mem_mgr.write_parallel_invoke_status(lane, PARALLEL_INVOKE_STATUS_STARTING)?;
            let req = Request {
                fn_id: FN_ID_NUB_INVOKE_WORKER,
                payload: (lane as u32).to_le_bytes().to_vec(),
            };
            let req_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&req)
                .map_err(|e| crate::new_error!("rkyv-serialize worker Request: {e}"))?;
            mem_mgr.write_guest_function_call_raw(req_bytes.as_slice())?;
        }

        let vm = self.vm.clone();
        let mem_mgr = self.mem_mgr.clone();
        let host_funcs = self.host_funcs.clone();
        let handle = thread::Builder::new()
            .name(format!("nub-vcpu-worker-{lane}"))
            .spawn(move || {
                let lane = VcpuLane::new(lane);
                vm.dispatch_call_from_host_on_shared(lane, &mem_mgr, &host_funcs)
                    .map_err(|e| format!("dispatch worker lane {}: {e}", lane.index()))?;
                let mut mem_mgr = mem_mgr
                    .lock()
                    .map_err(|_| "sandbox memory manager mutex poisoned".to_string())?;
                let _ = mem_mgr
                    .read_guest_function_call_result_raw()
                    .map_err(|e| format!("read worker shutdown response: {e}"))?;
                Ok(())
            })
            .map_err(|e| crate::new_error!("spawn invoke worker lane {lane}: {e}"))?;

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let status = {
                let mem_mgr = self
                    .mem_mgr
                    .lock()
                    .map_err(|_| crate::new_error!("sandbox memory manager mutex poisoned"))?;
                mem_mgr.read_parallel_invoke_status(lane)?
            };
            if status == PARALLEL_INVOKE_STATUS_EMPTY {
                return Ok(handle);
            }
            if handle.is_finished() {
                let worker_result = handle
                    .join()
                    .map_err(|_| crate::new_error!("invoke worker lane {lane} panicked"))?;
                return Err(crate::new_error!(
                    "invoke worker lane {} exited during startup: {}",
                    lane,
                    worker_result
                        .err()
                        .unwrap_or_else(|| "clean exit before startup handshake".to_string())
                ));
            }
            if Instant::now() >= deadline {
                return Err(crate::new_error!(
                    "invoke worker lane {} timed out during startup (status={})",
                    lane,
                    status
                ));
            }
            thread::yield_now();
        }
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

type InvokeWorkerResult = std::result::Result<(), String>;
type InvokeWorkerHandle = JoinHandle<InvokeWorkerResult>;

struct ParallelInvokeWorkers {
    lane_count: usize,
    state: Mutex<ParallelInvokeWorkerState>,
    ready: Condvar,
    handles: Mutex<Vec<Option<InvokeWorkerHandle>>>,
}

struct ParallelInvokeWorkerState {
    available: Vec<usize>,
    stopping: bool,
}

struct LaneLease {
    lane: usize,
    workers: Arc<ParallelInvokeWorkers>,
}

impl ParallelInvokeWorkers {
    fn new(lane_count: usize, handles: Vec<InvokeWorkerHandle>) -> Self {
        Self {
            lane_count,
            state: Mutex::new(ParallelInvokeWorkerState {
                available: (0..lane_count).rev().collect(),
                stopping: false,
            }),
            ready: Condvar::new(),
            handles: Mutex::new(handles.into_iter().map(Some).collect()),
        }
    }

    fn lane_count(&self) -> usize {
        self.lane_count
    }

    fn acquire_lane(self: &Arc<Self>) -> Result<LaneLease> {
        let mut state = self.state.lock().expect("parallel worker mutex poisoned");
        loop {
            if state.stopping {
                return Err(crate::new_error!(
                    "parallel invoke workers are stopping for a control-plane call"
                ));
            }
            if let Some(lane) = state.available.pop() {
                return Ok(LaneLease {
                    lane,
                    workers: self.clone(),
                });
            }
            state = self
                .ready
                .wait(state)
                .expect("parallel worker mutex poisoned");
        }
    }

    fn release_lane(&self, lane: usize) {
        let mut state = self.state.lock().expect("parallel worker mutex poisoned");
        state.available.push(lane);
        self.ready.notify_all();
    }

    fn mark_stopping_and_wait_idle(&self) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| crate::new_error!("parallel worker mutex poisoned"))?;
        state.stopping = true;
        while state.available.len() != self.lane_count {
            state = self
                .ready
                .wait(state)
                .map_err(|_| crate::new_error!("parallel worker mutex poisoned"))?;
        }
        Ok(())
    }

    fn take_finished_result(&self, lane: usize) -> Option<InvokeWorkerResult> {
        let mut handles = self.handles.lock().expect("parallel worker mutex poisoned");
        let handle = handles.get_mut(lane)?.take_if(|h| h.is_finished())?;
        Some(match handle.join() {
            Ok(result) => result,
            Err(_) => Err("worker thread panicked".to_string()),
        })
    }

    fn join_lane(&self, lane: usize, timeout: Duration) -> Result<InvokeWorkerResult> {
        let deadline = Instant::now() + timeout;
        loop {
            {
                let handles = self
                    .handles
                    .lock()
                    .map_err(|_| crate::new_error!("parallel worker mutex poisoned"))?;
                let Some(Some(handle)) = handles.get(lane) else {
                    return Ok(Ok(()));
                };
                if handle.is_finished() {
                    break;
                }
            }
            if Instant::now() >= deadline {
                return Err(crate::new_error!(
                    "parallel invoke worker lane {} timed out during stop",
                    lane
                ));
            }
            thread::yield_now();
        }

        let handle = self
            .handles
            .lock()
            .map_err(|_| crate::new_error!("parallel worker mutex poisoned"))?
            .get_mut(lane)
            .and_then(Option::take)
            .ok_or_else(|| crate::new_error!("parallel invoke worker lane {} missing", lane))?;
        Ok(match handle.join() {
            Ok(result) => result,
            Err(_) => Err("worker thread panicked".to_string()),
        })
    }
}

impl LaneLease {
    fn index(&self) -> usize {
        self.lane
    }
}

impl Drop for LaneLease {
    fn drop(&mut self) {
        self.workers.release_lane(self.lane);
    }
}

impl std::fmt::Debug for MultiUseSandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiUseSandbox").finish()
    }
}
