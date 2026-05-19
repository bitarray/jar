//! Nub: the JAR v3 microkernel — uniform caller-facing handle.
//!
//! The [`Nub`] handle is the API callers (chain runtime, tests, RPC,
//! `jar-apply`) link against. It hides the choice of substrate behind
//! a single invoke surface, dispatching to one of two backends:
//!
//! - **Local**: runs `Kernel<nub_arch_local::LocalArch>` directly
//!   in-process. Used for tests, deterministic replay, and any host
//!   that doesn't need real ring-0 isolation.
//!
//! - **Hyperlight**: ships the invocation as an RPC into a
//!   `nub-arch-x86` guest binary running inside a Hyperlight
//!   sandbox. The actual `Kernel<HyperlightArch>` lives guest-side;
//!   the host holds only the sandbox + an `InstanceRef` table.
//!
//! Both backends share the [`nub_kernel::Arch`] trait surface
//! ([`invoke`](Nub::invoke) + [`state_root`](Nub::state_root)). The
//! current skeleton implementation returns a fixed value (42) from
//! either backend, just to exercise the wiring.

use anyhow::Result;
use nub_arch_local::LocalArch;
use nub_host_kvm::sandbox::{
    GuestBinary, MultiUseSandbox, SandboxConfiguration, UninitializedSandbox,
};
use nub_kernel::Kernel;

use nub_arch_x86_abi::{
    ArchivedInvocationResult, FN_ID_NUB_INVOKE, FN_ID_NUB_INVOKE_CACHED, FN_ID_NUB_SMOKE,
    InvokePacket,
};
#[cfg(feature = "heap-diag")]
use nub_arch_x86_abi::FN_ID_NUB_HEAP_STATS;
pub use nub_arch_x86_abi::{InvocationResult, InvocationSpec, PublishSpec, PvmRegs};
pub use nub_kernel::{CapHash, InstanceRef, InvokeOptions, InvokeOutcome};
// Re-export `CapHash` from the abi for callers that don't want to
// depend on nub-kernel just for the alias.
pub use nub_arch_x86_abi::CapHash as AbiCapHash;

use rkyv::primitive::ArchivedU64;
use rkyv::util::AlignedVec;

/// Snapshot of the guest's talc allocation state. Returned by
/// [`Nub::heap_stats`].
#[cfg(feature = "heap-diag")]
#[derive(Debug, Clone, Copy)]
pub struct HeapStats {
    /// Sum of live allocations' layout sizes.
    pub allocated_bytes: u64,
    /// Count of live allocations.
    pub allocation_count: u64,
    /// Number of free-list holes between allocations (fragmentation indicator).
    pub fragment_count: u64,
    /// Bytes available for new allocations (heap total − allocated − talc metadata).
    pub available_bytes: u64,
}

/// Path to the cross-compiled Hyperlight guest blob. Set by
/// `build.rs` via [`nub_build::build`].
const NUB_ARCH_X86_BLOB_PATH: &str = env!("NUB_ARCH_X86_BLOB");

/// Uniform handle to the nub microkernel.
pub struct Nub {
    backend: Backend,
    /// In-process PublishSpec store for the Local backend's
    /// `invoke_cached` path. Always present (even on Hyperlight
    /// backend) so tests can construct a Nub and not care which
    /// backend uses the store. On Hyperlight the store is unused —
    /// the cache region in `sandbox.cache()` is the source of truth.
    local_store: std::collections::HashMap<AbiCapHash, PublishSpec>,
}

enum Backend {
    Local(Kernel<LocalArch>),
    Hyperlight(Box<HyperlightDriver>),
}

/// Host-side RPC stub for the Hyperlight backend. The real kernel
/// lives guest-side; this wrapper just ships invocations into the
/// sandbox.
struct HyperlightDriver {
    sandbox: MultiUseSandbox,
    state_root_cache: CapHash,
}

impl Nub {
    /// Construct a Nub backed by the in-process [`LocalArch`].
    pub fn new_local() -> Self {
        Self {
            backend: Backend::Local(Kernel::new(LocalArch::new())),
            local_store: std::collections::HashMap::new(),
        }
    }

    /// Construct a Nub backed by a fresh Hyperlight sandbox loaded
    /// from the `nub-arch-x86` guest blob.
    pub fn new_hyperlight() -> Result<Self> {
        // Scratch budget covers the per-process pool inside the guest
        // (`nub-arch-x86::pool`): mem + perms + bb + jt + jit +
        // arena + a few page-sized side buffers. Sized to ~144 MiB so
        // the largest bench programs fit with comfortable headroom.
        //
        // Input / output buffers: the host SCALE-encodes an
        // `InvocationSpec` (containing the program's full code +
        // bitmask + jump table + initial data regions) and ships it
        // via Hyperlight's input-data ring. Default 16 KiB is
        // exhausted by guest-tests' multi-endpoint Image.
        let mut cfg = SandboxConfiguration::default();
        // Sized post-Stage-F: forked host (nub-host-kvm) + forked
        // guest-bin still mark writable pages CoW so the host's
        // snapshot machinery has somewhere to roll back from. The
        // leak that motivated the fork is bounded by the heap size —
        // every heap page CoW-resolves once into a fresh scratch
        // frame, then the working set asymptotes. With a 64 MiB heap
        // the worst-case CoW consumption is ~64 MiB; plus the
        // per-process pool (~94 MiB; see `nub-arch-x86::pool`),
        // plus a small stack-growth allowance, comfortably fits in
        // 192 MiB scratch. Without the bench-era 1 GiB heap, the
        // criterion default sample sizes no longer blow the budget.
        cfg.set_scratch_size(512 * 1024 * 1024);
        cfg.set_input_data_size(16 * 1024 * 1024);
        cfg.set_output_data_size(16 * 1024 * 1024);
        cfg.set_heap_size(256 * 1024 * 1024);
        let uninit = UninitializedSandbox::new(
            GuestBinary::FilePath(NUB_ARCH_X86_BLOB_PATH.to_string()),
            Some(cfg),
        )?;
        let sandbox = uninit.evolve()?;
        Ok(Self {
            backend: Backend::Hyperlight(Box::new(HyperlightDriver {
                sandbox,
                state_root_cache: [0; 32],
            })),
            local_store: std::collections::HashMap::new(),
        })
    }

    /// Invoke `endpoint` on `target` with `args`.
    pub fn invoke(
        &mut self,
        target: InstanceRef,
        endpoint: u16,
        args: &[u8],
        opts: InvokeOptions,
    ) -> Result<InvokeOutcome> {
        match &mut self.backend {
            Backend::Local(k) => Ok(k
                .invoke(target, endpoint, args, opts)
                .expect("LocalArch::Error is uninhabited")),
            Backend::Hyperlight(h) => h.invoke(target, endpoint, args, opts),
        }
    }

    /// Current state root.
    pub fn state_root(&self) -> CapHash {
        match &self.backend {
            Backend::Local(k) => k.state_root(),
            Backend::Hyperlight(h) => h.state_root_cache,
        }
    }

    /// Diagnostic: read the guest's talc allocation counters
    /// (allocated_bytes, allocation_count, fragment_count,
    /// available_bytes). Hyperlight backend only. Requires the
    /// `heap-diag` feature.
    #[cfg(feature = "heap-diag")]
    pub fn heap_stats(&mut self) -> Result<HeapStats> {
        match &mut self.backend {
            Backend::Local(_) => Err(anyhow::anyhow!(
                "heap_stats: Local backend has no guest heap"
            )),
            Backend::Hyperlight(h) => {
                let raw: Vec<u8> = h.sandbox.call_raw(FN_ID_NUB_HEAP_STATS, &[])?;
                if raw.len() != 32 {
                    return Err(anyhow::anyhow!(
                        "heap_stats: expected 32 bytes, got {}",
                        raw.len()
                    ));
                }
                let parse = |off: usize| u64::from_le_bytes(raw[off..off + 8].try_into().unwrap());
                Ok(HeapStats {
                    allocated_bytes: parse(0),
                    allocation_count: parse(8),
                    fragment_count: parse(16),
                    available_bytes: parse(24),
                })
            }
        }
    }

    /// Publish a Cap::Instance into the state cache so subsequent
    /// `invoke_cached(hash, …)` calls can find it.
    ///
    /// The Local backend keeps an in-process `HashMap<CapHash,
    /// PublishSpec>`; the Hyperlight backend lays the spec into
    /// the shared cache region (`nub-host-kvm::cache`).
    pub fn publish_instance(&mut self, spec: PublishSpec) -> Result<()> {
        match &mut self.backend {
            Backend::Local(_) => {
                self.local_store
                    .insert(spec.instance_hash, spec);
                Ok(())
            }
            Backend::Hyperlight(h) => h
                .sandbox
                .cache()
                .publish(spec)
                .map_err(|e| anyhow::anyhow!("cache publish: {e}")),
        }
    }

    /// Invoke a previously-published Cap::Instance by hash. V0 args
    /// are 4 u64s laid into φ[7..=10] on top of the published
    /// `initial_regs` baseline.
    pub fn invoke_cached(
        &mut self,
        instance_hash: AbiCapHash,
        endpoint_idx: u8,
        args: [u64; 4],
        initial_gas: u64,
    ) -> Result<InvocationResult> {
        match &mut self.backend {
            Backend::Local(_) => {
                let spec = self
                    .local_store
                    .get(&instance_hash)
                    .ok_or_else(|| anyhow::anyhow!("invoke_cached: hash not published"))?
                    .clone();
                Ok(nub_arch_local::run_published(
                    &spec,
                    endpoint_idx,
                    args,
                    initial_gas,
                ))
            }
            Backend::Hyperlight(h) => {
                h.sandbox
                    .cache()
                    .pin(instance_hash)
                    .map_err(|e| anyhow::anyhow!("cache pin: {e}"))?;
                let packet = InvokePacket {
                    instance_hash,
                    endpoint_idx: endpoint_idx as u32,
                    _pad: 0,
                    args,
                    initial_gas,
                };
                let result_bytes = h
                    .sandbox
                    .call_raw(FN_ID_NUB_INVOKE_CACHED, packet.as_bytes());
                h.sandbox.cache().unpin(instance_hash);
                let result_bytes = result_bytes?;

                let mut aligned = AlignedVec::<16>::with_capacity(result_bytes.len());
                aligned.extend_from_slice(&result_bytes);
                let archived = rkyv::access::<ArchivedInvocationResult, rkyv::rancor::Error>(
                    aligned.as_slice(),
                )
                .map_err(|e| anyhow::anyhow!("rkyv-access InvocationResult: {e}"))?;
                Ok(InvocationResult {
                    exit_reason: archived.exit_reason.to_native(),
                    exit_arg: archived.exit_arg.to_native(),
                    return_value: archived.return_value.to_native(),
                    gas_remaining: archived.gas_remaining.to_native(),
                })
            }
        }
    }

    /// Direct-spec invocation path. Ships a pre-built `InvocationSpec`
    /// straight into the backend, bypassing the (still-skeletal)
    /// `Arch::invoke` trait. The Hyperlight backend rkyv-encodes the
    /// spec and ships it via `MultiUseSandbox::call_raw`; the local
    /// backend runs the byte-PVM interpreter in-process via
    /// `nub_arch_local::run_invocation_spec`.
    pub fn invoke_spec(&mut self, spec: &InvocationSpec) -> Result<InvocationResult> {
        match &mut self.backend {
            Backend::Local(_) => Ok(nub_arch_local::run_invocation_spec(spec)),
            Backend::Hyperlight(h) => {
                let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(spec)
                    .map_err(|e| anyhow::anyhow!("rkyv-serialize InvocationSpec: {e}"))?;
                let result_bytes = h.sandbox.call_raw(FN_ID_NUB_INVOKE, bytes.as_slice())?;

                let mut aligned = AlignedVec::<16>::with_capacity(result_bytes.len());
                aligned.extend_from_slice(&result_bytes);
                let archived =
                    rkyv::access::<ArchivedInvocationResult, rkyv::rancor::Error>(aligned.as_slice())
                        .map_err(|e| anyhow::anyhow!("rkyv-access InvocationResult: {e}"))?;
                Ok(InvocationResult {
                    exit_reason: archived.exit_reason.to_native(),
                    exit_arg: archived.exit_arg.to_native(),
                    return_value: archived.return_value.to_native(),
                    gas_remaining: archived.gas_remaining.to_native(),
                })
            }
        }
    }
}

impl HyperlightDriver {
    fn invoke(
        &mut self,
        _target: InstanceRef,
        _endpoint: u16,
        _args: &[u8],
        _opts: InvokeOptions,
    ) -> Result<InvokeOutcome> {
        // Skeleton: ship a fixed RPC into the guest. The guest's
        // `nub_smoke` returns 42, matching `LocalArch`'s stub. Real
        // dispatch (target / endpoint / args wired through) lands
        // alongside the guest-side `Kernel<HyperlightArch>`.
        let result_bytes = self.sandbox.call_raw(FN_ID_NUB_SMOKE, &[])?;
        let mut aligned = AlignedVec::<16>::with_capacity(result_bytes.len());
        aligned.extend_from_slice(&result_bytes);
        let archived = rkyv::access::<ArchivedU64, rkyv::rancor::Error>(aligned.as_slice())
            .map_err(|e| anyhow::anyhow!("rkyv-access u64 from nub_smoke: {e}"))?;
        Ok(InvokeOutcome {
            return_value: archived.to_native(),
            gas_used: 0,
        })
    }
}
