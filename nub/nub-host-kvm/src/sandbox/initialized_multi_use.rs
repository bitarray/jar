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

use nub_arch_x86_abi::{
    CapHash as AbiCapHash, FN_ID_NUB_INVOKE_WORKER, FN_ID_NUB_PUT_CAP, InvocationResult,
    InvokePacket, PARALLEL_INVOKE_STATUS_DONE, PARALLEL_INVOKE_STATUS_EMPTY,
    PARALLEL_INVOKE_STATUS_EVICT_JIT_READY, PARALLEL_INVOKE_STATUS_READY,
    PARALLEL_INVOKE_STATUS_RUNNING, PARALLEL_INVOKE_STATUS_STARTING, PARALLEL_INVOKE_STATUS_STOP,
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
    /// published, so `put_object_with_hash` can short-circuit an idempotent
    /// re-put without a roundtrip + hash walk through the guest.
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
    /// The host set is sound only under a **personality obligation**:
    /// publication is permanent — the guest store must retain every object
    /// it has accepted for the sandbox's lifetime, never evicting under
    /// capacity or memory pressure (stated on
    /// `nub::personality::LocalKernel::put_object`; a pressure-evicting
    /// store MUST NOT be driven through this cache). javm satisfies it
    /// structurally: caps are keyed by content hash and
    /// `CacheDirectory::put_cap` only ever `entry().or_insert()`s — blobs
    /// are never evicted (only the *instances* tier is swept). A miss
    /// falls through to the idempotent `put_cap` RPC, so even blobs the
    /// guest published on its own (e.g. via `derive_spawn`) are handled
    /// correctly — just without the short-circuit.
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
            let mut workers = self
                .invoke_workers
                .lock()
                .map_err(|_| crate::new_error!("parallel invoke worker mutex poisoned"))?;
            self.stop_invoke_workers_locked(&mut workers)?;
            let _control = self
                .control_lock
                .lock()
                .map_err(|_| crate::new_error!("sandbox control mutex poisoned"))?;
            self.call_guest_function_by_id_on_locked(VcpuLane::PRIMARY, fn_id, payload)
        })
    }

    /// Serialized control-plane call on a selected vCPU lane. This still uses
    /// the legacy shared input/output rings and therefore must not be used as
    /// the concurrent invoke mechanism; it exists to validate and bootstrap
    /// non-primary lanes. Concurrent invokes use the per-lane worker slots.
    #[instrument(err(Debug), skip(self, payload), parent = Span::current())]
    pub fn call_raw_on_vcpu(
        &self,
        vcpu_index: usize,
        fn_id: u32,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let lane = VcpuLane::new(vcpu_index);
        maybe_time_and_emit_guest_call("call_raw_on_vcpu", || {
            let mut workers = self
                .invoke_workers
                .lock()
                .map_err(|_| crate::new_error!("parallel invoke worker mutex poisoned"))?;
            self.stop_invoke_workers_locked(&mut workers)?;
            let _control = self
                .control_lock
                .lock()
                .map_err(|_| crate::new_error!("sandbox control mutex poisoned"))?;
            self.call_guest_function_by_id_on_locked(lane, fn_id, payload)
        })
    }

    fn call_guest_function_by_id_on_locked(
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

    /// Submit an invoke packet through the per-lane parallel worker slots.
    ///
    /// Workers are started lazily and remain hot for subsequent invoke calls.
    /// The legacy raw RPC channel remains the serialized control plane.
    /// User job waits deliberately have no host-side timeout; without a
    /// cancellation API, the lane must stay reserved until the guest reports
    /// completion or the worker exits.
    pub fn invoke_cached_parallel(
        &self,
        job_id: u64,
        packet: &InvokePacket,
    ) -> Result<InvocationResult> {
        let (workers, lane) = loop {
            let workers = self.ensure_invoke_workers()?;
            if let Some(lane) = workers.try_acquire_lane()? {
                break (workers, lane);
            }
            if let Some(lane_idx) = workers.reserve_unstarted_lane()? {
                match self.start_invoke_worker_lane(lane_idx) {
                    Ok(handle) => workers.install_started_lane(lane_idx, handle)?,
                    Err(e) => {
                        workers.release_start_reservation(lane_idx)?;
                        return Err(e);
                    }
                }
                continue;
            }
            if let Some(lane) = workers.acquire_lane()? {
                break (workers, lane);
            }
        };
        let lane_idx = lane.index();

        let slot = {
            let mem_mgr = self
                .mem_mgr
                .lock()
                .map_err(|_| crate::new_error!("sandbox memory manager mutex poisoned"))?;
            mem_mgr.parallel_invoke_slot_host_ptr(lane_idx)?
        };

        // SAFETY: `lane` is a live `LaneLease`, so this host thread has
        // exclusive host ownership of the slot until the function returns. The
        // guest worker communicates through the ABI atomics in the same slot.
        unsafe {
            let status = (*slot).status.load(Ordering::Acquire);
            if status != PARALLEL_INVOKE_STATUS_EMPTY {
                return Err(crate::new_error!(
                    "parallel invoke lane {} was not empty before submit (status={})",
                    lane_idx,
                    status
                ));
            }
            (*slot).job_id.store(job_id, Ordering::Relaxed);
            core::ptr::addr_of_mut!((*slot).packet).write_volatile(*packet);
            fence(Ordering::Release);
            (*slot)
                .status
                .store(PARALLEL_INVOKE_STATUS_READY, Ordering::Release);
        }

        loop {
            let done = unsafe {
                match (*slot).status.load(Ordering::Acquire) {
                    PARALLEL_INVOKE_STATUS_DONE => {
                        fence(Ordering::Acquire);
                        let result = core::ptr::addr_of!((*slot).result).read_volatile();
                        (*slot)
                            .status
                            .store(PARALLEL_INVOKE_STATUS_EMPTY, Ordering::Release);
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
            thread::yield_now();
        }
    }

    /// Bench-only: evict guest JIT caches while keeping the hot invoke worker
    /// pool alive. The legacy raw RPC path stops workers before entering the
    /// shared control ring; cold benchmarks call this every iteration, so using
    /// the worker slot protocol avoids measuring worker teardown/startup.
    ///
    /// All lanes are reserved first. That preserves the eviction invariant: no
    /// frame runtime can be live while image arenas and templates are dropped.
    pub fn evict_jit_all_parallel(&self) -> Result<()> {
        maybe_time_and_emit_guest_call("evict_jit_all_parallel", || {
            let workers = self.ensure_invoke_workers()?;
            let lanes = workers.acquire_all_lanes()?;
            let Some(control_lane) = lanes.first().map(LaneLease::index) else {
                return Ok(());
            };

            let slot = {
                let mem_mgr = self
                    .mem_mgr
                    .lock()
                    .map_err(|_| crate::new_error!("sandbox memory manager mutex poisoned"))?;
                mem_mgr.parallel_invoke_slot_host_ptr(control_lane)?
            };

            // SAFETY: `lanes` contains a live lease for every started lane, so
            // no host invoke can use `control_lane` while this control command
            // is in flight. The guest worker observes the ABI atomic status.
            unsafe {
                let status = (*slot).status.load(Ordering::Acquire);
                if status != PARALLEL_INVOKE_STATUS_EMPTY {
                    return Err(crate::new_error!(
                        "parallel control lane {} was not empty before evict (status={})",
                        control_lane,
                        status
                    ));
                }
                (*slot).job_id.store(0, Ordering::Relaxed);
                fence(Ordering::Release);
                (*slot)
                    .status
                    .store(PARALLEL_INVOKE_STATUS_EVICT_JIT_READY, Ordering::Release);
            }

            loop {
                let done = unsafe {
                    match (*slot).status.load(Ordering::Acquire) {
                        PARALLEL_INVOKE_STATUS_DONE => {
                            fence(Ordering::Acquire);
                            (*slot)
                                .status
                                .store(PARALLEL_INVOKE_STATUS_EMPTY, Ordering::Release);
                            true
                        }
                        PARALLEL_INVOKE_STATUS_EVICT_JIT_READY | PARALLEL_INVOKE_STATUS_RUNNING => {
                            false
                        }
                        other => {
                            return Err(crate::new_error!(
                                "parallel control lane {} entered unexpected status {}",
                                control_lane,
                                other
                            ));
                        }
                    }
                };
                if done {
                    return Ok(());
                }
                if let Some(worker_result) = workers.take_finished_result(control_lane) {
                    let detail = match worker_result {
                        Ok(()) => "clean worker exit".to_string(),
                        Err(e) => e,
                    };
                    return Err(crate::new_error!(
                        "parallel invoke worker lane {} exited during evict_jit_all: {}",
                        control_lane,
                        detail
                    ));
                }
                thread::yield_now();
            }
        })
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
        let first_handle = self.start_invoke_worker_lane(0)?;
        let workers = Arc::new(ParallelInvokeWorkers::new(vcpu_count, 0, first_handle));
        *guard = Some(workers.clone());
        Ok(workers)
    }

    fn stop_invoke_workers_locked(
        &self,
        guard: &mut Option<Arc<ParallelInvokeWorkers>>,
    ) -> Result<()> {
        let Some(workers) = guard.as_ref().cloned() else {
            return Ok(());
        };

        let started_lanes = workers.mark_stopping_and_wait_idle()?;
        for lane in started_lanes {
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

        *guard = None;
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

    /// Publish a serialized state object into the guest's
    /// heap-resident object store via the [`FN_ID_NUB_PUT_CAP`] RPC.
    ///
    /// `bytes` is the personality-encoded object (JAVM: an
    /// rkyv-encoded `Cap`), shipped opaquely via [`Self::call_raw`];
    /// the guest-computed content hash is read back. The guest-side
    /// personality decodes, validates, hashes, and inserts the object
    /// into its store.
    ///
    /// Encode/decode failures are surfaced as
    /// `HyperlightError::Error`. A sentinel response (all-`0xFF`
    /// hash) from the guest is also turned into an error.
    pub fn put_object(&self, bytes: &[u8]) -> Result<AbiCapHash> {
        let resp = self.call_raw(FN_ID_NUB_PUT_CAP, bytes)?;
        if resp.len() != 32 {
            return Err(crate::new_error!(
                "put_object: expected 32-byte hash response, got {}",
                resp.len()
            ));
        }
        let mut hash: AbiCapHash = [0u8; 32];
        hash.copy_from_slice(&resp);
        // The guest's put handler returns `0xFF * 32` on decode/conv
        // failure. Surface as a typed error so callers don't observe
        // a fake hash.
        if hash == [0xFFu8; 32] {
            return Err(crate::new_error!(
                "put_object: guest reported decode/conversion failure (sentinel response)"
            ));
        }
        Ok(hash)
    }

    /// Pre-hashed put: idempotent fast path that short-circuits the
    /// full [`Self::put_object`] RPC when this sandbox has already
    /// published `hash`.
    ///
    /// Behaviour:
    ///
    /// - If `hash` is in the host-side `published_blobs` set,
    ///   return immediately — we already shipped this object and
    ///   publication is permanent (the personality obligation on
    ///   `published_blobs`), so the guest still holds it. The
    ///   `serialize` closure is never called: no encode, no VMEXIT, no
    ///   guest decode + hash walk + store insert. This is the hot path
    ///   for bench loops that re-publish the same object graph every
    ///   iteration.
    /// - Otherwise, call `serialize()` (personality encode; JAVM: rkyv
    ///   of `Cap`, which fails on unresolved `CapHashOrRef::Ref`
    ///   handles), ship `put_object`, debug-assert the returned hash
    ///   matches `hash`, and record it.
    ///
    /// We deliberately do **not** check the guest's store directly:
    /// the guest's directory is a hashbrown table built with a
    /// different SIMD `Group` width than the host's hashbrown (see
    /// `published_blobs`), so a host-side deref of it is unsound.
    pub fn put_object_with_hash(
        &self,
        hash: AbiCapHash,
        serialize: impl FnOnce() -> std::result::Result<Vec<u8>, String>,
    ) -> Result<()> {
        {
            let published_blobs = self
                .published_blobs
                .lock()
                .map_err(|_| crate::new_error!("published blob set mutex poisoned"))?;
            if published_blobs.contains(&hash) {
                return Ok(());
            }
        }

        let bytes =
            serialize().map_err(|e| crate::new_error!("put_object_with_hash: encode: {e}"))?;
        let got = self.put_object(&bytes)?;
        debug_assert_eq!(
            got, hash,
            "put_object_with_hash: guest-computed hash differs from claimed hash"
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
    started: Vec<bool>,
    stopping: bool,
}

struct LaneLease {
    lane: usize,
    workers: Arc<ParallelInvokeWorkers>,
}

impl ParallelInvokeWorkers {
    fn new(lane_count: usize, first_lane: usize, first_handle: InvokeWorkerHandle) -> Self {
        let mut handles = Vec::with_capacity(lane_count);
        handles.resize_with(lane_count, || None);
        handles[first_lane] = Some(first_handle);
        let mut started = vec![false; lane_count];
        started[first_lane] = true;
        Self {
            lane_count,
            state: Mutex::new(ParallelInvokeWorkerState {
                available: vec![first_lane],
                started,
                stopping: false,
            }),
            ready: Condvar::new(),
            handles: Mutex::new(handles),
        }
    }

    fn try_acquire_lane(self: &Arc<Self>) -> Result<Option<LaneLease>> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| crate::new_error!("parallel worker mutex poisoned"))?;
        if state.stopping {
            return Ok(None);
        }
        Ok(state.available.pop().map(|lane| LaneLease {
            lane,
            workers: self.clone(),
        }))
    }

    fn acquire_lane(self: &Arc<Self>) -> Result<Option<LaneLease>> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| crate::new_error!("parallel worker mutex poisoned"))?;
        loop {
            if state.stopping {
                return Ok(None);
            }
            if let Some(lane) = state.available.pop() {
                return Ok(Some(LaneLease {
                    lane,
                    workers: self.clone(),
                }));
            }
            state = self
                .ready
                .wait(state)
                .map_err(|_| crate::new_error!("parallel worker mutex poisoned"))?;
        }
    }

    fn reserve_unstarted_lane(&self) -> Result<Option<usize>> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| crate::new_error!("parallel worker mutex poisoned"))?;
        if state.stopping {
            return Ok(None);
        }
        for lane in 0..self.lane_count {
            if !state.started[lane] {
                state.started[lane] = true;
                return Ok(Some(lane));
            }
        }
        Ok(None)
    }

    fn install_started_lane(&self, lane: usize, handle: InvokeWorkerHandle) -> Result<()> {
        {
            let mut handles = self
                .handles
                .lock()
                .map_err(|_| crate::new_error!("parallel worker mutex poisoned"))?;
            if lane >= handles.len() || handles[lane].is_some() {
                return Err(crate::new_error!(
                    "parallel invoke worker lane {} already has a handle",
                    lane
                ));
            }
            handles[lane] = Some(handle);
        }
        self.release_lane(lane);
        Ok(())
    }

    fn release_start_reservation(&self, lane: usize) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| crate::new_error!("parallel worker mutex poisoned"))?;
        if lane < state.started.len() {
            state.started[lane] = false;
        }
        self.ready.notify_all();
        Ok(())
    }

    fn acquire_all_lanes(self: &Arc<Self>) -> Result<Vec<LaneLease>> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| crate::new_error!("parallel worker mutex poisoned"))?;
        loop {
            if state.stopping {
                return Err(crate::new_error!("parallel invoke workers are stopping"));
            }
            let started_count = state.started.iter().filter(|&&started| started).count();
            if state.available.len() == started_count {
                return Ok(state
                    .available
                    .drain(..)
                    .map(|lane| LaneLease {
                        lane,
                        workers: self.clone(),
                    })
                    .collect());
            }
            state = self
                .ready
                .wait(state)
                .map_err(|_| crate::new_error!("parallel worker mutex poisoned"))?;
        }
    }

    fn release_lane(&self, lane: usize) {
        let mut state = self.state.lock().expect("parallel worker mutex poisoned");
        state.available.push(lane);
        self.ready.notify_all();
    }

    fn mark_stopping_and_wait_idle(&self) -> Result<Vec<usize>> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| crate::new_error!("parallel worker mutex poisoned"))?;
        state.stopping = true;
        self.ready.notify_all();
        let started_count = state.started.iter().filter(|&&started| started).count();
        while state.available.len() != started_count {
            state = self
                .ready
                .wait(state)
                .map_err(|_| crate::new_error!("parallel worker mutex poisoned"))?;
        }
        Ok(state
            .started
            .iter()
            .enumerate()
            .filter_map(|(lane, &started)| started.then_some(lane))
            .collect())
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
        let handle = self
            .handles
            .lock()
            .map_err(|_| crate::new_error!("parallel worker mutex poisoned"))?
            .get_mut(lane)
            .and_then(Option::take);
        let Some(handle) = handle else {
            return Ok(Ok(()));
        };
        join_invoke_worker_handle(lane, handle, timeout)
    }
}

fn join_invoke_worker_handle(
    lane: usize,
    handle: InvokeWorkerHandle,
    timeout: Duration,
) -> Result<InvokeWorkerResult> {
    let deadline = Instant::now() + timeout;
    while !handle.is_finished() {
        if Instant::now() >= deadline {
            return Err(crate::new_error!(
                "parallel invoke worker lane {} timed out during stop",
                lane
            ));
        }
        thread::yield_now();
    }

    Ok(match handle.join() {
        Ok(result) => result,
        Err(_) => Err("worker thread panicked".to_string()),
    })
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
