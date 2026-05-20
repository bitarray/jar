//! Nub: the JAR v3 microkernel — uniform caller-facing handle.
//!
//! The [`Nub`] handle is the API callers (chain runtime, tests, RPC,
//! `jar-apply`) link against. It hides the choice of substrate behind
//! a single invoke surface, dispatching to one of two backends:
//!
//! - **Local**: runs the byte-PVM interpreter directly in-process via
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

use allocator_api2::alloc::Global;
use anyhow::Result;
use javm_cap::slot::SlotIdx;
use javm_cap::talc::{
    Cache as TypedCache, CapHashOrRef, NUM_REGS,
    cap::Cap,
};
use nub_arch_local::LocalArch;
use nub_host_kvm::sandbox::{
    GuestBinary, MultiUseSandbox, SandboxConfiguration, UninitializedSandbox,
};
use nub_kernel::Kernel;

#[cfg(feature = "heap-diag")]
use nub_arch_x86_abi::FN_ID_NUB_HEAP_STATS;
use nub_arch_x86_abi::{
    ArchivedInvocationResult, FN_ID_NUB_INVOKE_CACHED, FN_ID_NUB_SMOKE, InvokePacket,
};
pub use nub_arch_x86_abi::{CapHash as AbiCapHash, InvocationResult};
pub use nub_kernel::{CapHash, InstanceRef, InvokeOptions, InvokeOutcome};

use rkyv::primitive::ArchivedU64;
use rkyv::util::AlignedVec;

/// Snapshot of the guest's talc allocation state. Returned by
/// [`Nub::heap_stats`].
#[cfg(feature = "heap-diag")]
#[derive(Debug, Clone, Copy)]
pub struct HeapStats {
    pub allocated_bytes: u64,
    pub allocation_count: u64,
    pub fragment_count: u64,
    pub available_bytes: u64,
}

/// Path to the cross-compiled Hyperlight guest blob. Set by
/// `build.rs` via [`nub_build::build`].
const NUB_ARCH_X86_BLOB_PATH: &str = env!("NUB_ARCH_X86_BLOB");

/// Uniform handle to the nub microkernel.
pub struct Nub {
    backend: Backend,
    /// In-process typed cache, used by the Local backend to back its
    /// publish_*/invoke_cached path. Always present (even on the
    /// Hyperlight backend) so tests can construct a Nub and not care
    /// which backend they hit. On Hyperlight the local cache is unused
    /// at runtime — the shared-memory cache in `sandbox.cache()` is
    /// the source of truth.
    local_cache: TypedCache<Global>,
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
            local_cache: TypedCache::new_in(Global),
        }
    }

    /// Construct a Nub backed by a fresh Hyperlight sandbox loaded
    /// from the `nub-arch-x86` guest blob.
    pub fn new_hyperlight() -> Result<Self> {
        let mut cfg = SandboxConfiguration::default();
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
            local_cache: TypedCache::new_in(Global),
        })
    }

    /// Invoke `endpoint` on `target` with `args`. Kernel-style entry
    /// point — currently a skeleton returning 42 from both backends.
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

    /// Diagnostic: read the guest's talc allocation counters.
    /// Hyperlight backend only. Requires the `heap-diag` feature.
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

    // --- Typed publish surface ---

    /// Publish an inline `Cap::Data` blob from a byte buffer. Returns
    /// the data cap's hash. Idempotent: re-publishing identical bytes
    /// returns the same hash.
    pub fn publish_data(&mut self, bytes: &[u8]) -> Result<AbiCapHash> {
        match &mut self.backend {
            Backend::Local(_) => self
                .local_cache
                .publish_data_inline(bytes)
                .map_err(|e| anyhow::anyhow!("publish_data (local): {e}")),
            Backend::Hyperlight(h) => h
                .sandbox
                .cache()
                .publish_data_inline(bytes)
                .map_err(|e| anyhow::anyhow!("publish_data: {e}")),
        }
    }

    /// Publish a SCALE-encoded [`javm_cap::image::Image`] end-to-end.
    /// Walks the image's pinned/initial slots, publishes each as a
    /// `Cap::Data`, then publishes the `Cap::Image`. Returns the
    /// image's content hash.
    pub fn publish_image(&mut self, img: &javm_cap::image::Image) -> Result<AbiCapHash> {
        match &mut self.backend {
            Backend::Local(_) => self
                .local_cache
                .publish_image(img)
                .map_err(|e| anyhow::anyhow!("publish_image (local): {e}")),
            Backend::Hyperlight(h) => h
                .sandbox
                .cache()
                .publish_image(img)
                .map_err(|e| anyhow::anyhow!("publish_image: {e}")),
        }
    }

    /// Publish a `Cap::CNode` whose slots reference existing caps.
    /// Each `target` must already be published.
    pub fn publish_cnode(
        &mut self,
        size_log: u8,
        entries: &[(SlotIdx, CapHashOrRef)],
    ) -> Result<AbiCapHash> {
        match &mut self.backend {
            Backend::Local(_) => self
                .local_cache
                .publish_cnode(size_log, entries)
                .map_err(|e| anyhow::anyhow!("publish_cnode (local): {e}")),
            Backend::Hyperlight(h) => h
                .sandbox
                .cache()
                .publish_cnode(size_log, entries)
                .map_err(|e| anyhow::anyhow!("publish_cnode: {e}")),
        }
    }

    /// Publish a `Cap::Instance` blob binding an `image_hash` +
    /// `root_cnode` + initial state. Returns the instance cap's hash.
    #[allow(clippy::too_many_arguments)]
    pub fn publish_instance(
        &mut self,
        image_hash_chain: AbiCapHash,
        image_hash: AbiCapHash,
        root_cnode: AbiCapHash,
        rw_overlays: &[(u32, &[u8])],
        mem_size: u32,
        regs: [u64; NUM_REGS],
        pc: u64,
        gas_remaining: u64,
    ) -> Result<AbiCapHash> {
        match &mut self.backend {
            Backend::Local(_) => self
                .local_cache
                .publish_instance_blob(
                    image_hash_chain,
                    image_hash,
                    root_cnode,
                    rw_overlays,
                    mem_size,
                    regs,
                    pc,
                    gas_remaining,
                )
                .map_err(|e| anyhow::anyhow!("publish_instance (local): {e}")),
            Backend::Hyperlight(h) => h
                .sandbox
                .cache()
                .publish_instance_blob(
                    image_hash_chain,
                    image_hash,
                    root_cnode,
                    rw_overlays,
                    mem_size,
                    regs,
                    pc,
                    gas_remaining,
                )
                .map_err(|e| anyhow::anyhow!("publish_instance: {e}")),
        }
    }

    /// Invoke a previously-published `Cap::Instance` by hash. V0 args
    /// are 4 u64s laid into φ[7..=10] on top of the published
    /// endpoint's `initial_regs` baseline.
    pub fn invoke_cached(
        &mut self,
        instance_hash: AbiCapHash,
        endpoint_idx: u8,
        args: [u64; 4],
        initial_gas: u64,
    ) -> Result<InvocationResult> {
        match &mut self.backend {
            Backend::Local(_) => {
                // Resolve the instance + image from the in-process
                // cache and drive the byte-PVM interpreter.
                let instance_cap = self
                    .local_cache
                    .get(CapHashOrRef::Hash(instance_hash))
                    .ok_or_else(|| anyhow::anyhow!("invoke_cached: instance not published"))?;
                let inst = match instance_cap {
                    Cap::Instance(i) => i,
                    _ => {
                        return Err(anyhow::anyhow!(
                            "invoke_cached: cap at hash is not an Instance"
                        ));
                    }
                };
                let image_cap = self
                    .local_cache
                    .get(CapHashOrRef::Hash(inst.image_hash))
                    .ok_or_else(|| anyhow::anyhow!("invoke_cached: image not in cache"))?;
                let img = match image_cap {
                    Cap::Image(i) => i,
                    _ => {
                        return Err(anyhow::anyhow!(
                            "invoke_cached: cap at image_hash is not an Image"
                        ));
                    }
                };
                Ok(nub_arch_local::run_instance(
                    inst,
                    img,
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
        // `nub_smoke` returns 42, matching `LocalArch`'s stub.
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
