//! Nub: the JAR v3 microkernel — uniform caller-facing handle.
//!
//! The [`Nub`] handle is the API callers (chain runtime, tests, RPC,
//! `jar-apply`) link against. It hides the choice of substrate behind
//! a single invoke surface, dispatching to one of two backends:
//!
//! - **Local**: runs the PVM2 (RISC-V) interpreter directly in-process via
//!   `nub_arch_local::run_instance`. Used for tests, deterministic
//!   replay, and any host that doesn't need real ring-0 isolation.
//! - **Hyperlight**: ships the invocation as an RPC into a
//!   `nub-arch-x86` guest binary running inside a Hyperlight
//!   sandbox. The actual `Kernel<HyperlightArch>` lives guest-side;
//!   the host holds only the sandbox + a state cache.
//!
//! Both backends share the same typed publish/invoke surface — the
//! caller publishes a `Cap::Image` (and optionally a `Cap::CNode`),
//! publishes a `Cap::Instance` referencing them, and then invokes by
//! the resulting instance hash.

#[cfg(feature = "test-support")]
pub mod test_support;

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::num::NonZeroUsize;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};

use anyhow::Result;
use javm_cap::{
    CacheDirectory, CapHashOrRef, KernelImage, Key, cap::Cap, key_from_regs, recognize_kernel_image,
};
use nub_arch_local::LocalArch;
use nub_host_kvm::sandbox::{
    GuestBinary, MultiUseSandbox, SandboxConfiguration, UninitializedSandbox,
};
use nub_kernel::Kernel;

#[cfg(feature = "heap-diag")]
use nub_arch_x86_abi::FN_ID_NUB_HEAP_STATS;
pub use nub_arch_x86_abi::{CapHash as AbiCapHash, InvocationResult, SCRATCHPAD_HEAD_LEN};
use nub_arch_x86_abi::{FN_ID_NUB_EVICT_JIT_ALL, InvokePacket};
pub use nub_kernel::{CapHash, InstanceRef, InvokeOptions, InvokeOutcome};

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

/// Path to the cross-compiled Hyperlight guest blob. Set by
/// `build.rs` via [`nub_build::build`].
const NUB_ARCH_X86_BLOB_PATH: &str = env!("NUB_ARCH_X86_BLOB");

#[derive(Clone, Copy)]
pub(crate) struct HyperlightBlob {
    pub(crate) label: &'static str,
    pub(crate) path: &'static str,
}

struct HyperlightSingleton {
    blob: HyperlightBlob,
    options: NubOptions,
    nub: Nub,
}

static HYPERLIGHT_NUB: Mutex<Option<HyperlightSingleton>> = Mutex::new(None);

/// Compatibility alias for older tests/benches that named the returned
/// Hyperlight singleton borrow. `Nub` is now a cloneable handle; synchronization
/// lives inside the handle instead of in an outer mutex guard.
pub type HyperlightNubGuard = Nub;

/// Uniform handle to the nub microkernel.
#[derive(Clone)]
pub struct Nub {
    inner: Arc<NubInner>,
}

struct NubInner {
    backend: Mutex<Backend>,
    /// The kernel-maintained gas meter mapping (`meter_key -> remaining gas`).
    /// The interim "static meter mapping" of the kernel-assisted GasMeter
    /// design — a later spec change moves it behind a YieldCatcher. At top-level
    /// invoke the host resolves the running Instance's primary usable gas slot
    /// (first non-empty valid `Gas{meter_key}`), seeds the run from this map
    /// when non-zero, and writes the remaining primary balance back here.
    meters: Mutex<HashMap<Key, u64>>,
    /// The kernel-maintained storage quota mapping (`quota_key -> remaining`).
    /// Symmetric to [`Self::meters`]; quota *charging* is not yet wired (V1),
    /// so this is seeded/observed but not yet debited per dirty page.
    quotas: Mutex<HashMap<Key, u64>>,
    /// Host-side guard for top-level invokes that seed from the same kernel gas
    /// meter. The first parallel milestone rejects concurrent reuse instead of
    /// racing two writers on one balance.
    in_flight_meters: Mutex<BTreeSet<Key>>,
    next_job_id: AtomicU64,
    invoke_executor: Arc<InvokeExecutor>,
    invoke_worker_count: usize,
}

struct MeterReservation {
    inner: Arc<NubInner>,
    key: Key,
}

impl MeterReservation {
    fn reserve(inner: Arc<NubInner>, key: Key) -> Result<Self> {
        {
            let mut in_flight = match inner.in_flight_meters.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            if !in_flight.insert(key.clone()) {
                return Err(anyhow::anyhow!(
                    "invoke_cached: gas meter is already in flight"
                ));
            }
        }
        Ok(Self { inner, key })
    }
}

impl Drop for MeterReservation {
    fn drop(&mut self) {
        let mut in_flight = match self.inner.in_flight_meters.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        in_flight.remove(&self.key);
    }
}

/// Options used when constructing the process-wide Hyperlight Nub singleton.
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
    pub instance_hash: AbiCapHash,
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

struct QueuedInvoke {
    nub: Nub,
    id: InvokeJobId,
    request: InvokeRequest,
    state: Arc<InvokeJobState>,
}

struct InvokeExecutor {
    state: Mutex<InvokeExecutorState>,
    ready: Condvar,
    handles: Mutex<Vec<JoinHandle<()>>>,
}

struct InvokeExecutorState {
    queue: VecDeque<QueuedInvoke>,
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

impl InvokeExecutor {
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

    fn enqueue(&self, job: QueuedInvoke) -> Result<()> {
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

    fn next_job(&self) -> Option<QueuedInvoke> {
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

impl Drop for NubInner {
    fn drop(&mut self) {
        self.invoke_executor.stop_and_join();
    }
}

enum Backend {
    /// In-process backend: the PVM2 (RISC-V) interpreter plus its own
    /// cap directory. `cache` is the source of truth for caps published
    /// via `Nub::put_cap*` and resolved by `Nub::invoke_cached`.
    Local {
        kernel: Kernel<LocalArch>,
        cache: CacheDirectory,
    },
    /// Hyperlight backend: the cap directory lives guest-side as a
    /// `static CacheDirectory<FixedState>` in `nub-arch-x86`; the host
    /// writes via the `FN_ID_NUB_PUT_CAP` RPC and tracks published blob
    /// hashes host-side to short-circuit idempotent re-puts (it does
    /// *not* dereference the guest's hashbrown — see
    /// `MultiUseSandbox::published_blobs` for why that is unsound).
    Hyperlight(Arc<HyperlightDriver>),
}

enum InvokeBackendTarget {
    Local {
        inst: Box<javm_cap::InstanceCap>,
        img: Box<javm_cap::ImageCap>,
    },
    Hyperlight(Arc<HyperlightDriver>),
}

/// Host-side RPC stub for the Hyperlight backend. The real kernel
/// lives guest-side; this wrapper just ships invocations into the
/// sandbox.
struct HyperlightDriver {
    sandbox: MultiUseSandbox,
    state_root_cache: CapHash,
    /// Host-side mirror of the published cap graph, used **only** to resolve an
    /// Instance's primary usable gas slot → `Gas{meter_key}` handle host-side (the
    /// authoritative cap directory lives guest-side). This is the host's own
    /// `CacheDirectory` — not a deref of the guest's hashbrown (which is
    /// unsound across the SIMD-width boundary; see `MultiUseSandbox`).
    host_cache: Mutex<CacheDirectory>,
}

impl Nub {
    /// Construct a Nub backed by the in-process [`LocalArch`].
    pub fn new_local() -> Self {
        let invoke_worker_count = thread::available_parallelism()
            .map(NonZeroUsize::get)
            .unwrap_or(2)
            .clamp(2, 8);
        Self {
            inner: Arc::new(NubInner {
                backend: Mutex::new(Backend::Local {
                    kernel: Kernel::new(LocalArch::new()),
                    cache: CacheDirectory::new(),
                }),
                meters: Mutex::new(HashMap::new()),
                quotas: Mutex::new(HashMap::new()),
                in_flight_meters: Mutex::new(BTreeSet::new()),
                next_job_id: AtomicU64::new(1),
                invoke_executor: Arc::new(InvokeExecutor::new()),
                invoke_worker_count,
            }),
        }
    }

    /// Borrow the process-wide Hyperlight-backed Nub loaded from the
    /// `nub-arch-x86` guest blob.
    pub fn hyperlight() -> Result<HyperlightNubGuard> {
        Self::hyperlight_with_options(NubOptions::default())
    }

    pub fn hyperlight_with_options(options: NubOptions) -> Result<HyperlightNubGuard> {
        Self::hyperlight_with_blob(
            HyperlightBlob {
                label: "production",
                path: NUB_ARCH_X86_BLOB_PATH,
            },
            options,
        )
    }

    pub(crate) fn hyperlight_with_blob(blob: HyperlightBlob, options: NubOptions) -> Result<Nub> {
        options.validate()?;
        let mut guard = HYPERLIGHT_NUB
            .lock()
            .map_err(|_| anyhow::anyhow!("Hyperlight Nub singleton mutex poisoned"))?;
        match guard.as_ref() {
            Some(existing) if existing.blob.path == blob.path && existing.options == options => {}
            Some(existing) if existing.blob.path == blob.path => {
                return Err(anyhow::anyhow!(
                    "Hyperlight Nub singleton already initialized with {} vCPU(s); \
                     cannot reconfigure it to {} vCPU(s)",
                    existing.options.vcpu_count,
                    options.vcpu_count,
                ));
            }
            Some(existing) => {
                return Err(anyhow::anyhow!(
                    "Hyperlight Nub singleton already initialized with {} guest ({:?}); \
                     cannot switch to {} guest ({:?})",
                    existing.blob.label,
                    existing.blob.path,
                    blob.label,
                    blob.path,
                ));
            }
            None => {
                let nub = Self::create_hyperlight_with_blob_path(blob.path, options)?;
                *guard = Some(HyperlightSingleton { blob, options, nub });
            }
        }
        Ok(guard
            .as_ref()
            .expect("Hyperlight Nub singleton initialized")
            .nub
            .clone())
    }

    /// Create the backing sandbox for the process-wide Hyperlight singleton
    /// from an arbitrary guest ELF on disk.
    ///
    /// This is intentionally private: high-level callers must go through the
    /// process singleton returned by [`Self::hyperlight`].
    fn create_hyperlight_with_blob_path(path: &str, options: NubOptions) -> Result<Self> {
        let mut cfg = SandboxConfiguration::default();
        cfg.set_vcpu_count(options.vcpu_count);
        cfg.set_scratch_size(512 * 1024 * 1024);
        cfg.set_input_data_size(16 * 1024 * 1024);
        cfg.set_output_data_size(16 * 1024 * 1024);
        cfg.set_heap_size(256 * 1024 * 1024);
        let uninit = UninitializedSandbox::new(GuestBinary::FilePath(path.to_string()), Some(cfg))?;
        let sandbox = uninit.evolve()?;
        Ok(Self {
            inner: Arc::new(NubInner {
                backend: Mutex::new(Backend::Hyperlight(Arc::new(HyperlightDriver {
                    sandbox,
                    state_root_cache: [0; 32],
                    host_cache: Mutex::new(CacheDirectory::new()),
                }))),
                meters: Mutex::new(HashMap::new()),
                quotas: Mutex::new(HashMap::new()),
                in_flight_meters: Mutex::new(BTreeSet::new()),
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
            Backend::Local { kernel, .. } => kernel.state_root(),
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
            Backend::Local { .. } => Ok(()),
            Backend::Hyperlight(h) => {
                let _ = h.sandbox.call_raw(FN_ID_NUB_EVICT_JIT_ALL, &[])?;
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
            Backend::Local { .. } => Err(anyhow::anyhow!(
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

    // --- New publish surface (caller-built `Cap`) ---

    /// Put a caller-built `Cap` into the active cache. Computes
    /// the cap's content hash and either clones the cap on first put or
    /// bumps refcount on idempotent re-put. Returns the cap's content hash.
    pub fn put_cap(&self, cap: &javm_cap::Cap) -> Result<AbiCapHash> {
        let mut backend = self
            .inner
            .backend
            .lock()
            .expect("Nub backend mutex poisoned");
        match &mut *backend {
            Backend::Local { cache, .. } => cache
                .put_cap(cap)
                .map_err(|e| anyhow::anyhow!("put_cap (local): {e}")),
            Backend::Hyperlight(h) => {
                // Mirror into the host-side cache so `invoke_cached` can resolve
                // gas_slots → meter_key host-side (best-effort; the guest cache
                // is authoritative for execution).
                let _ = h
                    .host_cache
                    .lock()
                    .expect("Hyperlight host cache mutex poisoned")
                    .put_cap(cap);
                h.sandbox
                    .put_cap(cap)
                    .map_err(|e| anyhow::anyhow!("put_cap: {e}"))
            }
        }
    }

    /// Pre-hashed variant. Caller computed `ssz::hash_tree_root(cap)`
    /// at warmup and passes it explicitly; on the hot idempotent
    /// path this lets both backends skip the SSZ merkleize entirely.
    /// Debug-asserts the claimed hash matches the cap; release trusts
    /// the caller.
    ///
    /// Hyperlight backend: short-circuits on a host-side set of blob
    /// hashes this sandbox has already published. On a hit, no RPC
    /// roundtrip and no guest-side merkle walk — the typical bench /
    /// replay workload re-publishes the same cap graph every iteration
    /// and pays only one host-side `HashSet::contains`. (The host does
    /// not read the guest's `CacheDirectory` directly: it is a hashbrown
    /// table built with a different SIMD `Group` width than the host's,
    /// so a cross-binary deref is unsound — see
    /// `nub-host-kvm::MultiUseSandbox::published_blobs`.)
    pub fn put_cap_with_hash(&self, hash: AbiCapHash, cap: &javm_cap::Cap) -> Result<()> {
        let mut backend = self
            .inner
            .backend
            .lock()
            .expect("Nub backend mutex poisoned");
        match &mut *backend {
            Backend::Local { cache, .. } => cache
                .put_cap_with_hash(hash, cap)
                .map_err(|e| anyhow::anyhow!("put_cap_with_hash (local): {e}")),
            Backend::Hyperlight(h) => {
                let _ = h
                    .host_cache
                    .lock()
                    .expect("Hyperlight host cache mutex poisoned")
                    .put_cap_with_hash(hash, cap);
                h.sandbox
                    .put_cap_with_hash(hash, cap)
                    .map_err(|e| anyhow::anyhow!("put_cap_with_hash: {e}"))
            }
        }
    }

    // --- Kernel gas/quota meter mapping (`SetGasMeter` / `SetStorageQuota`) ---

    /// Set the kernel gas meter `meter_key` to `value`; returns the previous
    /// value (0 if absent). The chain-side topup / harvest primitive.
    pub fn set_meter(&self, meter_key: Key, value: u64) -> u64 {
        self.inner
            .meters
            .lock()
            .expect("Nub meter mutex poisoned")
            .insert(meter_key, value)
            .unwrap_or(0)
    }

    /// Read the kernel gas meter `meter_key` (0 if absent).
    pub fn get_meter(&self, meter_key: &Key) -> u64 {
        self.inner
            .meters
            .lock()
            .expect("Nub meter mutex poisoned")
            .get(meter_key)
            .copied()
            .unwrap_or(0)
    }

    /// Set the kernel storage quota `quota_key`; returns the previous value.
    pub fn set_quota(&self, quota_key: Key, value: u64) -> u64 {
        self.inner
            .quotas
            .lock()
            .expect("Nub quota mutex poisoned")
            .insert(quota_key, value)
            .unwrap_or(0)
    }

    /// Read the kernel storage quota `quota_key` (0 if absent).
    pub fn get_quota(&self, quota_key: &Key) -> u64 {
        self.inner
            .quotas
            .lock()
            .expect("Nub quota mutex poisoned")
            .get(quota_key)
            .copied()
            .unwrap_or(0)
    }

    /// Resolve the running Instance's primary usable gas `meter_key` from its
    /// Image gas slots, via the appropriate host-side cache (the Local cache, or
    /// the Hyperlight host mirror). Empty slots are skipped. This host-side path
    /// is only for budget seeding; guest-side execution still performs the strict
    /// invalid-slot checks.
    fn resolve_gas_meter_key(&self, instance_hash: AbiCapHash) -> Option<Key> {
        let backend = self
            .inner
            .backend
            .lock()
            .expect("Nub backend mutex poisoned");
        let cache = match &*backend {
            Backend::Local { cache, .. } => cache,
            Backend::Hyperlight(h) => {
                let cache = h
                    .host_cache
                    .lock()
                    .expect("Hyperlight host cache mutex poisoned");
                return resolve_meter_key_from(&cache, instance_hash);
            }
        };
        resolve_meter_key_from(cache, instance_hash)
    }

    /// Submit an invocation to the singleton Nub and return a job handle. Jobs
    /// are queued onto a fixed Nub-owned host executor; Hyperlight execution then
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

    /// Invoke a previously-published `Cap::Instance` by hash. V0 args
    /// are 4 u64s laid into φ[7..=10] on top of the published
    /// endpoint's `initial_regs` baseline.
    ///
    /// Meter-driven gas: if the Instance's primary usable gas slot names a `Gas`
    /// handle whose `meter_key` has a non-zero entry in the kernel meter mapping,
    /// the run is seeded from that meter and the remaining gas is written back at
    /// exit. Otherwise the call-supplied `initial_gas` is used (and the meter is
    /// left untouched), preserving the bare-budget path.
    pub fn invoke_cached(
        &self,
        instance_hash: AbiCapHash,
        endpoint_idx: u8,
        args: [u64; 4],
        initial_gas: u64,
    ) -> Result<InvocationResult> {
        self.submit_invoke(InvokeRequest {
            instance_hash,
            endpoint_idx,
            args,
            initial_gas,
        })?
        .wait()
    }

    fn invoke_request_blocking(
        &self,
        request: InvokeRequest,
        job_id: u64,
    ) -> Result<InvocationResult> {
        let meter_key = self.resolve_gas_meter_key(request.instance_hash);
        let meter_balance = meter_key.as_ref().map(|k| self.get_meter(k)).unwrap_or(0);
        let (budget, used_meter) = match &meter_key {
            Some(_) if meter_balance > 0 => (meter_balance, true),
            _ => (request.initial_gas, false),
        };

        let _meter_reservation = if used_meter {
            meter_key
                .clone()
                .map(|k| MeterReservation::reserve(self.inner.clone(), k))
                .transpose()?
        } else {
            None
        };

        let result = self.invoke_cached_raw(
            job_id,
            request.instance_hash,
            request.endpoint_idx,
            request.args,
            budget,
        );
        let result = result?;
        if used_meter && let Some(k) = meter_key {
            self.inner
                .meters
                .lock()
                .expect("Nub meter mutex poisoned")
                .insert(k, result.gas_remaining);
        }
        Ok(result)
    }

    /// The backend dispatch for [`Self::invoke_cached`], with the gas budget
    /// already resolved (meter-seeded or call-supplied).
    fn invoke_cached_raw(
        &self,
        job_id: u64,
        instance_hash: AbiCapHash,
        endpoint_idx: u8,
        args: [u64; 4],
        initial_gas: u64,
    ) -> Result<InvocationResult> {
        let target = {
            let mut backend = self
                .inner
                .backend
                .lock()
                .expect("Nub backend mutex poisoned");
            match &mut *backend {
                Backend::Local { cache, .. } => {
                    // Resolve the instance + image from the in-process
                    // cache and drive the PVM2 (RISC-V) interpreter.
                    let instance_cap = cache
                        .get(CapHashOrRef::Hash(instance_hash))
                        .ok_or_else(|| anyhow::anyhow!("invoke_cached: instance not published"))?;
                    let inst = match &*instance_cap {
                        Cap::Instance(i) => i.clone(),
                        _ => {
                            return Err(anyhow::anyhow!(
                                "invoke_cached: cap at hash is not an Instance"
                            ));
                        }
                    };
                    let image_cap = cache
                        .get(CapHashOrRef::Hash(inst.image_hash))
                        .ok_or_else(|| anyhow::anyhow!("invoke_cached: image not in cache"))?;
                    let img = match &*image_cap {
                        Cap::Image(i) => i.clone(),
                        _ => {
                            return Err(anyhow::anyhow!(
                                "invoke_cached: cap at image_hash is not an Image"
                            ));
                        }
                    };
                    InvokeBackendTarget::Local {
                        inst: Box::new(inst),
                        img: Box::new(img),
                    }
                }
                Backend::Hyperlight(h) => InvokeBackendTarget::Hyperlight(h.clone()),
            }
        };

        let hyperlight = match target {
            InvokeBackendTarget::Local { inst, img } => {
                return Ok(nub_arch_local::run_instance(
                    &inst,
                    &img,
                    endpoint_idx,
                    args,
                    initial_gas,
                ));
            }
            InvokeBackendTarget::Hyperlight(h) => h,
        };

        // No host-side pin/unpin — the cap is owned by the guest's
        // heap-resident DIRECTORY; there's nothing for the host to lock against
        // (the guest doesn't evict). Hyperlight invokes always go through the
        // fixed per-lane worker pool; serialized `call_raw` remains only for the
        // control plane and stops idle workers before using the legacy RPC ring.
        let packet = InvokePacket {
            instance_hash,
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

/// Walk `instance_hash → image.gas_slots[*] → cnode slot → Gas{meter_key}` in
/// `cache`, returning the first valid non-empty `meter_key`. `None` if the
/// Image declares no usable gas slot. This helper is intentionally soft: the
/// guest-side kernel loop performs the strict invalid-slot hard faults.
fn resolve_meter_key_from(cache: &CacheDirectory, instance_hash: AbiCapHash) -> Option<Key> {
    let inst_cap = cache.get(CapHashOrRef::Hash(instance_hash))?;
    let Cap::Instance(inst) = &*inst_cap else {
        return None;
    };
    let img_cap = cache.get(CapHashOrRef::Hash(inst.image_hash))?;
    let Cap::Image(img) = &*img_cap else {
        return None;
    };
    let cnode_cap = cache.get(inst.root_cnode.clone())?;
    let Cap::CNode(cnode) = &*cnode_cap else {
        return None;
    };
    for slot in &img.gas_slots {
        let Some(gas_ref) = cnode.get(slot) else {
            continue;
        };
        let gas_cap = cache.get(gas_ref)?;
        let Cap::Instance(g) = &*gas_cap else {
            return None;
        };
        if recognize_kernel_image(g.image_hash_chain) != Some(KernelImage::Gas) {
            return None;
        }
        return Some(key_from_regs(g.regs[0], g.regs[1]));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meter_reservation_rejects_duplicate_and_releases_on_drop() {
        let nub = Nub::new_local();
        let key = Key::from(&[0xCA, 0xFE][..]);

        let first =
            MeterReservation::reserve(nub.inner.clone(), key.clone()).expect("first reservation");
        assert!(
            MeterReservation::reserve(nub.inner.clone(), key.clone()).is_err(),
            "a duplicate in-flight meter reservation must be rejected"
        );

        drop(first);
        let second = MeterReservation::reserve(nub.inner.clone(), key)
            .expect("reservation should be released on drop");
        drop(second);
    }

    #[test]
    fn meter_reservation_drop_tolerates_poisoned_mutex() {
        let nub = Nub::new_local();
        let key = Key::from(&[0xBA, 0xAD][..]);
        let reservation =
            MeterReservation::reserve(nub.inner.clone(), key.clone()).expect("reservation");

        let inner = nub.inner.clone();
        let _ = std::panic::catch_unwind(move || {
            let _guard = inner
                .in_flight_meters
                .lock()
                .expect("lock before intentional panic");
            panic!("poison meter reservation mutex");
        });

        drop(reservation);
        let second = MeterReservation::reserve(nub.inner.clone(), key)
            .expect("drop should release even after poison");
        drop(second);
    }
}
