//! Nub: the JAR v3 microkernel substrate — uniform caller-facing handle.
//!
//! The [`Nub`] handle hides the choice of substrate behind a single
//! publish/invoke surface, generic over a kernel [`Personality`] `P`
//! (the pluggable semantics layer: what published objects mean, how
//! invocations resolve a root object). Two backends:
//!
//! - **Local**: the personality's in-process kernel
//!   ([`Personality::Local`], a [`LocalKernel`] impl). Used for
//!   tests, deterministic replay, and any host that doesn't need real
//!   ring-0 isolation.
//! - **Hyperlight**: ships invocations as RPCs into a bare-metal
//!   guest binary (the personality's guest crate over the generic
//!   `nub-arch-x86` kernel lib) running inside a Hyperlight sandbox.
//!   The wire protocol is personality-agnostic: opaque bytes +
//!   32-byte [`ObjHash`] keys.
//!
//! Nub itself owns no guest blob and no singleton policy — a
//! personality entrypoint crate (e.g. `rust/javm` for JAVM) builds
//! its guest blob, defines the typed publish surface, and constructs
//! handles via [`Nub::new_local`] / [`Nub::create_hyperlight`].

pub mod personality;
#[cfg(feature = "test-support")]
pub mod test_support;

use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};

use anyhow::Result;
use nub_host_kvm::sandbox::{
    GuestBinary, MultiUseSandbox, SandboxConfiguration, UninitializedSandbox,
};

#[cfg(feature = "heap-diag")]
use nub_arch_x86_abi::FN_ID_NUB_HEAP_STATS;
use nub_arch_x86_abi::InvokePacket;
pub use nub_arch_x86_abi::{CapHash as AbiCapHash, InvocationResult, SCRATCHPAD_HEAD_LEN};
pub use nub_kernel::{CapHash, InstanceRef, InvokeOptions, InvokeOutcome, ObjHash};
pub use personality::{LocalKernel, Personality};

pub const MAX_HYPERLIGHT_VCPUS: usize = nub_arch_x86_abi::MAX_EXECUTION_LANES;

/// Snapshot of the guest's talc allocation state. Returned by
/// [`Nub::heap_stats`].
#[cfg(feature = "heap-diag")]
#[derive(Debug, Clone, Copy)]
pub struct HeapStats {
    /// Live allocation count (incremented on alloc, decremented on
    /// free) — a non-zero per-invoke drift here is a leak.
    pub allocation_count: u64,
    /// Cumulative allocations ever performed (monotonic, never
    /// decremented) — its per-invoke delta is the allocation *churn*,
    /// the right yardstick for "this CALL allocated nothing but a
    /// `KernelFrame`" even when the transient allocations are freed
    /// again before the next snapshot.
    pub total_allocation_count: u64,
    pub allocated_bytes: u64,
    pub fragment_count: u64,
    pub available_bytes: u64,
}

/// Uniform handle to the nub microkernel substrate, generic over the
/// kernel personality.
pub struct Nub<P: Personality> {
    inner: Arc<NubInner<P>>,
}

// Hand-written: `#[derive(Clone)]` would wrongly bound `P: Clone`.
impl<P: Personality> Clone for Nub<P> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

struct NubInner<P: Personality> {
    backend: Mutex<Backend<P>>,
    next_job_id: AtomicU64,
    invoke_executor: Arc<InvokeExecutor<P>>,
    invoke_worker_count: usize,
}

/// Options used when constructing a Hyperlight-backed Nub.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NubOptions {
    /// Fixed vCPU pool size for the backing sandbox. Multi-vCPU Hyperlight
    /// sandboxes keep one hot worker per lane and route top-level invokes
    /// through those workers.
    pub vcpu_count: usize,
}

impl NubOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_vcpu_count(mut self, vcpu_count: usize) -> Self {
        self.vcpu_count = vcpu_count.max(1);
        self
    }

    fn validate(&self) -> Result<()> {
        if self.vcpu_count == 0 {
            return Err(anyhow::anyhow!("NubOptions.vcpu_count must be at least 1"));
        }
        if self.vcpu_count > MAX_HYPERLIGHT_VCPUS {
            return Err(anyhow::anyhow!(
                "NubOptions.vcpu_count={} exceeds guest lane capacity {}",
                self.vcpu_count,
                MAX_HYPERLIGHT_VCPUS
            ));
        }
        Ok(())
    }
}

impl Default for NubOptions {
    fn default() -> Self {
        let default = thread::available_parallelism()
            .map(NonZeroUsize::get)
            .unwrap_or(1)
            .clamp(1, 8);
        let vcpu_count = std::env::var("JAR_NUB_VCPUS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(default);
        Self { vcpu_count }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvokeRequest {
    pub root: AbiCapHash,
    pub endpoint_idx: u8,
    pub args: [u64; 4],
    pub initial_gas: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InvokeJobId(pub u64);

pub struct InvokeJob {
    id: InvokeJobId,
    state: Arc<InvokeJobState>,
}

struct InvokeJobState {
    result: Mutex<Option<Result<InvocationResult, String>>>,
    ready: Condvar,
}

struct QueuedInvoke<P: Personality> {
    nub: Nub<P>,
    id: InvokeJobId,
    request: InvokeRequest,
    state: Arc<InvokeJobState>,
}

struct InvokeExecutor<P: Personality> {
    state: Mutex<InvokeExecutorState<P>>,
    ready: Condvar,
    handles: Mutex<Vec<JoinHandle<()>>>,
}

struct InvokeExecutorState<P: Personality> {
    queue: VecDeque<QueuedInvoke<P>>,
    stopping: bool,
}

impl InvokeJob {
    pub fn id(&self) -> InvokeJobId {
        self.id
    }

    pub fn try_wait(&self) -> Option<Result<InvocationResult>> {
        let guard = self
            .state
            .result
            .lock()
            .expect("InvokeJob result mutex poisoned");
        guard.as_ref().map(|r| match r {
            Ok(v) => Ok(*v),
            Err(e) => Err(anyhow::anyhow!(e.clone())),
        })
    }

    pub fn wait(self) -> Result<InvocationResult> {
        let mut guard = self
            .state
            .result
            .lock()
            .expect("InvokeJob result mutex poisoned");
        while guard.is_none() {
            guard = self
                .state
                .ready
                .wait(guard)
                .expect("InvokeJob result mutex poisoned");
        }
        match guard.take().expect("checked is_some") {
            Ok(v) => Ok(v),
            Err(e) => Err(anyhow::anyhow!(e)),
        }
    }
}

impl InvokeJobState {
    fn new() -> Self {
        Self {
            result: Mutex::new(None),
            ready: Condvar::new(),
        }
    }

    fn complete(&self, result: Result<InvocationResult, String>) {
        let mut guard = self.result.lock().expect("InvokeJob result mutex poisoned");
        *guard = Some(result);
        self.ready.notify_all();
    }
}

impl<P: Personality> InvokeExecutor<P> {
    fn new() -> Self {
        Self {
            state: Mutex::new(InvokeExecutorState {
                queue: VecDeque::new(),
                stopping: false,
            }),
            ready: Condvar::new(),
            handles: Mutex::new(Vec::new()),
        }
    }

    fn ensure_started(self: &Arc<Self>, worker_count: usize) -> Result<()> {
        let mut handles = self
            .handles
            .lock()
            .expect("InvokeExecutor handles mutex poisoned");
        if !handles.is_empty() {
            return Ok(());
        }

        for worker in 0..worker_count.max(1) {
            let executor = self.clone();
            let handle = thread::Builder::new()
                .name(format!("nub-invoke-worker-{worker}"))
                .spawn(move || executor.worker_loop())
                .map_err(|e| anyhow::anyhow!("submit_invoke: spawn worker: {e}"))?;
            handles.push(handle);
        }
        Ok(())
    }

    fn enqueue(&self, job: QueuedInvoke<P>) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .expect("InvokeExecutor state mutex poisoned");
        if state.stopping {
            return Err(anyhow::anyhow!(
                "submit_invoke: Nub invoke executor is stopping"
            ));
        }
        state.queue.push_back(job);
        self.ready.notify_one();
        Ok(())
    }

    fn worker_loop(self: Arc<Self>) {
        while let Some(job) = self.next_job() {
            let id = job.id.0;
            let nub = job.nub;
            let request = job.request;
            let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
                nub.invoke_request_blocking(request, id)
            }))
            .map_err(|_| "invoke worker panicked".to_string())
            .and_then(|r| r.map_err(|e| format!("{e:#}")));
            job.state.complete(result);
        }
    }

    fn next_job(&self) -> Option<QueuedInvoke<P>> {
        let mut state = self
            .state
            .lock()
            .expect("InvokeExecutor state mutex poisoned");
        loop {
            if let Some(job) = state.queue.pop_front() {
                return Some(job);
            }
            if state.stopping {
                return None;
            }
            state = self
                .ready
                .wait(state)
                .expect("InvokeExecutor state mutex poisoned");
        }
    }

    fn stop_and_join(&self) {
        {
            let mut state = self
                .state
                .lock()
                .expect("InvokeExecutor state mutex poisoned");
            state.stopping = true;
            self.ready.notify_all();
        }

        let current = thread::current().id();
        let handles = {
            let mut handles = self
                .handles
                .lock()
                .expect("InvokeExecutor handles mutex poisoned");
            core::mem::take(&mut *handles)
        };
        for handle in handles {
            if handle.thread().id() == current {
                continue;
            }
            let _ = handle.join();
        }
    }
}

impl<P: Personality> Drop for NubInner<P> {
    fn drop(&mut self) {
        self.invoke_executor.stop_and_join();
    }
}

enum Backend<P: Personality> {
    /// In-process backend: the personality's [`LocalKernel`] (object
    /// store + interpreter wiring). Source of truth for objects
    /// published via [`Nub::put_object`] and resolved by
    /// [`Nub::invoke_cached`].
    Local(P::Local),
    /// Hyperlight backend: the object store lives guest-side in the
    /// personality's guest binary; the host writes via the
    /// `FN_ID_NUB_PUT_CAP` RPC and tracks published blob hashes
    /// host-side to short-circuit idempotent re-puts (it does *not*
    /// dereference the guest's hashbrown — see
    /// `MultiUseSandbox::published_blobs` for why that is unsound).
    Hyperlight(Arc<HyperlightDriver>),
}

/// Host-side RPC stub for the Hyperlight backend. The real kernel
/// lives guest-side; this wrapper just ships invocations into the
/// sandbox.
struct HyperlightDriver {
    sandbox: MultiUseSandbox,
    state_root_cache: CapHash,
}

impl<P: Personality> Nub<P> {
    /// Construct a Nub backed by the personality's in-process kernel.
    pub fn new_local() -> Self {
        let invoke_worker_count = thread::available_parallelism()
            .map(NonZeroUsize::get)
            .unwrap_or(2)
            .clamp(2, 8);
        Self {
            inner: Arc::new(NubInner {
                backend: Mutex::new(Backend::Local(P::Local::default())),
                next_job_id: AtomicU64::new(1),
                invoke_executor: Arc::new(InvokeExecutor::new()),
                invoke_worker_count,
            }),
        }
    }

    /// Create a Hyperlight-backed Nub from a guest ELF on disk.
    ///
    /// **At most one per process.** The KVM substrate supports a
    /// single live Hyperlight sandbox per process: the guest-VA
    /// window is one process-wide fixed reservation, and every
    /// sandbox `MAP_FIXED`-overlays its kernel-shadow at the same VA
    /// inside it. A second construction — concurrent or sequential
    /// (the guard is never released, even after dropping the first
    /// sandbox) — fails loudly with
    /// `nub_host_kvm::HyperlightError::SandboxAlreadyCreated` instead
    /// of silently corrupting the live sandbox's guest memory.
    /// Personality entrypoint crates own the blob paths and typically
    /// wrap this constructor in a process-wide singleton (e.g.
    /// `javm::Nub::hyperlight`), which reuses the one sandbox across
    /// callers.
    pub fn create_hyperlight(path: &str, options: NubOptions) -> Result<Self> {
        options.validate()?;
        let mut cfg = SandboxConfiguration::default();
        cfg.set_vcpu_count(options.vcpu_count);
        cfg.set_scratch_size(512 * 1024 * 1024);
        cfg.set_input_data_size(16 * 1024 * 1024);
        cfg.set_output_data_size(16 * 1024 * 1024);
        cfg.set_heap_size(256 * 1024 * 1024);
        let uninit = UninitializedSandbox::new(GuestBinary::FilePath(path.to_string()), Some(cfg))
            .map_err(|e| anyhow::anyhow!("create_hyperlight[{}]: {path}: {e}", P::NAME))?;
        let sandbox = uninit
            .evolve()
            .map_err(|e| anyhow::anyhow!("create_hyperlight[{}]: evolve: {e}", P::NAME))?;
        Ok(Self {
            inner: Arc::new(NubInner {
                backend: Mutex::new(Backend::Hyperlight(Arc::new(HyperlightDriver {
                    sandbox,
                    state_root_cache: [0; 32],
                }))),
                next_job_id: AtomicU64::new(1),
                invoke_executor: Arc::new(InvokeExecutor::new()),
                invoke_worker_count: options.vcpu_count.max(1),
            }),
        })
    }

    /// Current state root.
    pub fn state_root(&self) -> CapHash {
        let backend = self
            .inner
            .backend
            .lock()
            .expect("Nub backend mutex poisoned");
        match &*backend {
            Backend::Local(local) => local.state_root(),
            Backend::Hyperlight(h) => h.state_root_cache,
        }
    }

    /// Bench-only: clear the guest's JIT compile cache so the next
    /// `invoke_cached` pays a full recompile. No-op on the Local
    /// backend (which uses the interpreter and has no JIT cache).
    pub fn evict_jit_all(&self) -> Result<()> {
        let mut backend = self
            .inner
            .backend
            .lock()
            .expect("Nub backend mutex poisoned");
        match &mut *backend {
            Backend::Local(_) => Ok(()),
            Backend::Hyperlight(h) => {
                h.sandbox.evict_jit_all_parallel()?;
                Ok(())
            }
        }
    }

    /// Diagnostic: read the guest's talc allocation counters.
    /// Hyperlight backend only. Requires the `heap-diag` feature.
    #[cfg(feature = "heap-diag")]
    pub fn heap_stats(&self) -> Result<HeapStats> {
        let mut backend = self
            .inner
            .backend
            .lock()
            .expect("Nub backend mutex poisoned");
        match &mut *backend {
            Backend::Local(_) => Err(anyhow::anyhow!(
                "heap_stats: Local backend has no guest heap"
            )),
            Backend::Hyperlight(h) => {
                let raw: Vec<u8> = h.sandbox.call_raw(FN_ID_NUB_HEAP_STATS, &[])?;
                if raw.len() != 40 {
                    return Err(anyhow::anyhow!(
                        "heap_stats: expected 40 bytes, got {}",
                        raw.len()
                    ));
                }
                let parse = |off: usize| u64::from_le_bytes(raw[off..off + 8].try_into().unwrap());
                Ok(HeapStats {
                    allocation_count: parse(0),
                    total_allocation_count: parse(8),
                    allocated_bytes: parse(16),
                    fragment_count: parse(24),
                    available_bytes: parse(32),
                })
            }
        }
    }

    // --- Generic publish surface (personality-encoded bytes) ---

    /// Put a personality-encoded object into the active store. The
    /// personality decodes, validates, and content-hashes the bytes;
    /// the returned [`ObjHash`] is the content-addressed key.
    pub fn put_object(&self, bytes: &[u8]) -> Result<ObjHash> {
        let mut backend = self
            .inner
            .backend
            .lock()
            .expect("Nub backend mutex poisoned");
        match &mut *backend {
            Backend::Local(local) => local.put_object(bytes),
            Backend::Hyperlight(h) => h
                .sandbox
                .put_object(bytes)
                .map_err(|e| anyhow::anyhow!("put_object: {e}")),
        }
    }

    /// Pre-hashed variant. The caller already knows the content hash;
    /// on the hot idempotent path this skips encode + hash entirely.
    ///
    /// Hyperlight backend: short-circuits on a host-side set of blob
    /// hashes this sandbox has already published — on a hit, `bytes`
    /// is never called: no encode, no RPC roundtrip, no guest-side
    /// merkle walk (see
    /// `nub-host-kvm::MultiUseSandbox::put_object_with_hash`).
    pub fn put_object_with_hash(
        &self,
        hash: ObjHash,
        bytes: impl FnOnce() -> std::result::Result<Vec<u8>, String>,
    ) -> Result<()> {
        let mut backend = self
            .inner
            .backend
            .lock()
            .expect("Nub backend mutex poisoned");
        match &mut *backend {
            Backend::Local(local) => {
                let bytes =
                    bytes().map_err(|e| anyhow::anyhow!("put_object_with_hash: encode: {e}"))?;
                local.put_object_with_hash(hash, &bytes)
            }
            Backend::Hyperlight(h) => h
                .sandbox
                .put_object_with_hash(hash, bytes)
                .map_err(|e| anyhow::anyhow!("put_object_with_hash: {e}")),
        }
    }

    /// Typed escape hatch: run `f` against the personality's
    /// [`LocalKernel`] under the backend lock. Returns `None` on the
    /// Hyperlight backend. Personality entrypoint crates use this to
    /// keep their typed publish paths encode-free on Local.
    pub fn with_local<R>(&self, f: impl FnOnce(&mut P::Local) -> R) -> Option<R> {
        let mut backend = self
            .inner
            .backend
            .lock()
            .expect("Nub backend mutex poisoned");
        match &mut *backend {
            Backend::Local(local) => Some(f(local)),
            Backend::Hyperlight(_) => None,
        }
    }

    /// Submit an invocation and return a job handle. Jobs are queued
    /// onto a fixed Nub-owned host executor; Hyperlight execution then
    /// runs on the sandbox's fixed vCPU worker lanes.
    pub fn submit_invoke(&self, request: InvokeRequest) -> Result<InvokeJob> {
        let id = InvokeJobId(self.inner.next_job_id.fetch_add(1, Ordering::Relaxed));
        let state = Arc::new(InvokeJobState::new());
        self.inner
            .invoke_executor
            .ensure_started(self.inner.invoke_worker_count)?;
        self.inner.invoke_executor.enqueue(QueuedInvoke {
            nub: self.clone(),
            id,
            request,
            state: state.clone(),
        })?;
        Ok(InvokeJob { id, state })
    }

    /// Invoke the object graph rooted at a previously-published
    /// `root` hash. V0 args are 4 u64s overlaid per the personality's
    /// register ABI.
    pub fn invoke_cached(
        &self,
        root: ObjHash,
        endpoint_idx: u8,
        args: [u64; 4],
        initial_gas: u64,
    ) -> Result<InvocationResult> {
        // The blocking API can go straight to the KVM lane pool: each caller
        // blocks on its own lane lease. `submit_invoke` keeps the host-side job
        // queue for callers that explicitly want an async handle.
        let id = self.inner.next_job_id.fetch_add(1, Ordering::Relaxed);
        self.invoke_request_blocking(
            InvokeRequest {
                root,
                endpoint_idx,
                args,
                initial_gas,
            },
            id,
        )
    }

    fn invoke_request_blocking(
        &self,
        request: InvokeRequest,
        job_id: u64,
    ) -> Result<InvocationResult> {
        self.invoke_cached_raw(
            job_id,
            request.root,
            request.endpoint_idx,
            request.args,
            request.initial_gas,
        )
    }

    /// The backend dispatch for [`Self::invoke_cached`].
    fn invoke_cached_raw(
        &self,
        job_id: u64,
        root: ObjHash,
        endpoint_idx: u8,
        args: [u64; 4],
        initial_gas: u64,
    ) -> Result<InvocationResult> {
        let hyperlight = {
            let mut backend = self
                .inner
                .backend
                .lock()
                .expect("Nub backend mutex poisoned");
            match &mut *backend {
                // NOTE: the Local kernel runs the invocation under the
                // backend lock, so concurrent Local invokes serialize.
                // Local is the test/replay backend; all its callers
                // assert results, not concurrency.
                Backend::Local(local) => {
                    return local.invoke(root, endpoint_idx as u32, args, initial_gas);
                }
                Backend::Hyperlight(h) => h.clone(),
            }
        };

        // No host-side pin/unpin — the object is owned by the guest's
        // heap-resident store; there's nothing for the host to lock against
        // (the guest doesn't evict). Hyperlight invokes always go through the
        // fixed per-lane worker pool; serialized `call_raw` remains only for the
        // control plane and stops idle workers before using the legacy RPC ring.
        let packet = InvokePacket {
            root_hash: root,
            endpoint_idx: endpoint_idx as u32,
            _pad: 0,
            args,
            initial_gas,
        };

        hyperlight
            .sandbox
            .invoke_cached_parallel(job_id, &packet)
            .map_err(|e| anyhow::anyhow!("invoke_cached_parallel: {e}"))
    }
}
