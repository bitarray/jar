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
//! - [`Nub::local`] — the in-process PVM2 (RISC-V) interpreter. Used
//!   for tests, deterministic replay, and any host that doesn't need
//!   real ring-0 isolation.
//! - [`Nub::hyperlight`] — the process-wide Hyperlight singleton
//!   running the `javm-guest-x86` guest blob (in-kernel JIT).

#[cfg(feature = "test-support")]
mod test_support;

use anyhow::Result;

#[cfg(feature = "heap-diag")]
pub use nub::HeapStats;
pub use nub::{
    AbiCapHash, CapHash, InvocationResult, InvokeJob, InvokeJobId, InvokeRequest,
    MAX_HYPERLIGHT_VCPUS, NubOptions, ObjHash, SCRATCHPAD_HEAD_LEN,
};

/// Compatibility alias for tests/benches that name the returned
/// Hyperlight singleton borrow. [`Nub`] is a cloneable handle;
/// synchronization lives inside the handle.
pub type HyperlightNubGuard = Nub;

/// Uniform handle to the JAVM engine — a newtype over the generic
/// [`nub::Nub`] substrate handle with the JAVM-typed publish surface.
#[derive(Clone)]
pub struct Nub {
    inner: nub::Nub,
}

impl Nub {
    /// Construct a Nub backed by the in-process interpreter.
    pub fn local() -> Self {
        Self {
            inner: nub::Nub::new_local(),
        }
    }

    /// Borrow the process-wide Hyperlight-backed Nub loaded from the
    /// `javm-guest-x86` production guest blob.
    pub fn hyperlight() -> Result<HyperlightNubGuard> {
        Ok(Self {
            inner: nub::Nub::hyperlight()?,
        })
    }

    pub fn hyperlight_with_options(options: NubOptions) -> Result<HyperlightNubGuard> {
        Ok(Self {
            inner: nub::Nub::hyperlight_with_options(options)?,
        })
    }

    // --- Typed publish surface (caller-built `Cap`) ---

    /// Put a caller-built [`javm_cap::Cap`] into the active cache.
    /// Computes the cap's content hash and either clones the cap on
    /// first put or bumps refcount on idempotent re-put. Returns the
    /// cap's content hash.
    pub fn put_cap(&self, cap: &javm_cap::Cap) -> Result<AbiCapHash> {
        self.inner.put_cap(cap)
    }

    /// Pre-hashed variant. Caller computed `ssz::hash_tree_root(cap)`
    /// at warmup and passes it explicitly; on the hot idempotent path
    /// this lets both backends skip the SSZ merkleize entirely.
    pub fn put_cap_with_hash(&self, hash: AbiCapHash, cap: &javm_cap::Cap) -> Result<()> {
        self.inner.put_cap_with_hash(hash, cap)
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
