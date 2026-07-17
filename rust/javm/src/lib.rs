//! JAVM engine entrypoint: the javm-cap kernel personality on the nub
//! substrate.
//!
//! [`Nub`] is THE handle callers (chain runtime, tests, benches, RPC,
//! `jar-apply`) use to invoke JAVM. It wraps the generic
//! [`nub::Nub`] substrate handle and layers the JAVM-typed surface on
//! top: publish caller-built [`javm_cap::Cap`]s ([`Nub::put_cap`] /
//! [`Nub::put_cap_with_hash`]) and invoke published `Cap::Instance`s
//! by content hash ([`Nub::invoke_cached`]).
//!
//! Two backends, one surface:
//!
//! - [`Nub::local`] — the in-process PVM2 (RISC-V) interpreter
//!   ([`JavmLocal`], the JAVM [`nub::LocalKernel`]). Used for tests,
//!   deterministic replay, and any host that doesn't need real ring-0
//!   isolation.
//! - [`Nub::hyperlight`] — the process-wide Hyperlight singleton
//!   running the `javm-guest-x86` guest blob (in-kernel JIT). This
//!   crate owns the blob (built by `build.rs`) and the singleton
//!   policy; the sandbox mechanics live in the generic substrate
//!   ([`nub::Nub::create_hyperlight`]).

mod local;
#[cfg(feature = "test-support")]
mod test_support;

use std::sync::Mutex;

use anyhow::Result;

pub use local::JavmLocal;
#[cfg(feature = "heap-diag")]
pub use nub::HeapStats;
pub use nub::{
    AbiCapHash, CapHash, InvocationResult, InvokeJob, InvokeJobId, InvokeRequest,
    MAX_HYPERLIGHT_VCPUS, NubOptions, ObjHash, SCRATCHPAD_HEAD_LEN,
};

/// The JAVM kernel personality: javm-cap object semantics (rkyv-coded
/// `Cap`s, SSZ content hashing) with [`JavmLocal`] as the in-process
/// kernel.
pub struct Javm;

impl nub::Personality for Javm {
    const NAME: &'static str = "javm";
    type Local = local::JavmLocal;
}

/// Path to the cross-compiled Hyperlight guest blob. Set by
/// `build.rs` via `nub_build::build`.
const JAVM_GUEST_X86_BLOB_PATH: &str = env!("JAVM_GUEST_X86_BLOB");

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

/// Compatibility alias for tests/benches that name the returned
/// Hyperlight singleton borrow. [`Nub`] is a cloneable handle;
/// synchronization lives inside the handle.
pub type HyperlightNubGuard = Nub;

/// Uniform handle to the JAVM engine — a newtype over the generic
/// [`nub::Nub`] substrate handle with the JAVM-typed publish surface.
#[derive(Clone)]
pub struct Nub {
    inner: nub::Nub<Javm>,
}

impl Nub {
    /// Construct a Nub backed by the in-process interpreter
    /// ([`JavmLocal`]).
    pub fn local() -> Self {
        Self {
            inner: nub::Nub::new_local(),
        }
    }

    /// Borrow the process-wide Hyperlight-backed Nub loaded from the
    /// `javm-guest-x86` production guest blob.
    pub fn hyperlight() -> Result<HyperlightNubGuard> {
        Self::hyperlight_with_options(NubOptions::default())
    }

    pub fn hyperlight_with_options(options: NubOptions) -> Result<HyperlightNubGuard> {
        Self::hyperlight_with_blob(
            HyperlightBlob {
                label: "production",
                path: JAVM_GUEST_X86_BLOB_PATH,
            },
            options,
        )
    }

    pub(crate) fn hyperlight_with_blob(blob: HyperlightBlob, options: NubOptions) -> Result<Nub> {
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
                let nub = Nub {
                    inner: nub::Nub::create_hyperlight(blob.path, options)?,
                };
                *guard = Some(HyperlightSingleton { blob, options, nub });
            }
        }
        Ok(guard
            .as_ref()
            .expect("Hyperlight Nub singleton initialized")
            .nub
            .clone())
    }

    // --- Typed publish surface (caller-built `Cap`) ---

    /// Put a caller-built [`javm_cap::Cap`] into the active cache.
    /// Computes the cap's content hash and either clones the cap on
    /// first put or bumps refcount on idempotent re-put. Returns the
    /// cap's content hash.
    pub fn put_cap(&self, cap: &javm_cap::Cap) -> Result<AbiCapHash> {
        // Local: typed, encode-free.
        if let Some(r) = self.inner.with_local(|l| l.put_cap(cap)) {
            return r;
        }
        // Hyperlight: serialize once, ship opaque bytes. Encoding
        // fails on unresolved `CapHashOrRef::Ref` handles.
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(cap)
            .map_err(|e| anyhow::anyhow!("put_cap: rkyv encode (or Ref present): {e}"))?;
        self.inner
            .put_object(bytes.as_slice())
            .map_err(|e| anyhow::anyhow!("put_cap: {e}"))
    }

    /// Pre-hashed variant. Caller computed `ssz::hash_tree_root(cap)`
    /// at warmup and passes it explicitly; on the hot idempotent path
    /// this lets both backends skip the SSZ merkleize entirely.
    /// Debug-asserts the claimed hash matches the cap; release trusts
    /// the caller.
    ///
    /// Hyperlight backend: short-circuits on a host-side set of blob
    /// hashes this sandbox has already published — the typical bench /
    /// replay workload re-publishes the same cap graph every iteration
    /// and pays only one host-side `HashSet::contains`, with the rkyv
    /// encode never running (see `nub::Nub::put_object_with_hash`).
    pub fn put_cap_with_hash(&self, hash: AbiCapHash, cap: &javm_cap::Cap) -> Result<()> {
        if let Some(r) = self.inner.with_local(|l| l.put_cap_with_hash(hash, cap)) {
            return r;
        }
        // Lazy encode: never runs on the host-side published_blobs hit.
        self.inner.put_object_with_hash(hash, || {
            rkyv::to_bytes::<rkyv::rancor::Error>(cap)
                .map(|b| b.to_vec())
                .map_err(|e| format!("rkyv encode (or Ref present): {e}"))
        })
    }

    // --- Invoke surface (forwards to the substrate handle) ---

    /// Invoke a previously-published `Cap::Instance` by hash. V0 args
    /// are 4 u64s laid into φ[7..=10] on top of the published
    /// endpoint's `initial_regs` baseline.
    pub fn invoke_cached(
        &self,
        root: AbiCapHash,
        endpoint_idx: u8,
        args: [u64; 4],
        initial_gas: u64,
    ) -> Result<InvocationResult> {
        self.inner
            .invoke_cached(root, endpoint_idx, args, initial_gas)
    }

    /// Submit an invocation and return an async job handle.
    pub fn submit_invoke(&self, request: InvokeRequest) -> Result<InvokeJob> {
        self.inner.submit_invoke(request)
    }

    /// Bench-only: clear the guest's JIT compile cache so the next
    /// `invoke_cached` pays a full recompile. No-op on the Local
    /// backend.
    pub fn evict_jit_all(&self) -> Result<()> {
        self.inner.evict_jit_all()
    }

    /// Current state root.
    pub fn state_root(&self) -> CapHash {
        self.inner.state_root()
    }

    /// Diagnostic: read the guest's talc allocation counters.
    /// Hyperlight backend only. Requires the `heap-diag` feature.
    #[cfg(feature = "heap-diag")]
    pub fn heap_stats(&self) -> Result<HeapStats> {
        self.inner.heap_stats()
    }
}
