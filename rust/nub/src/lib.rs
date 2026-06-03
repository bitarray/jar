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

use std::collections::HashMap;

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
use nub_arch_x86_abi::{
    ArchivedInvocationResult, FN_ID_NUB_EVICT_JIT_ALL, FN_ID_NUB_INVOKE_CACHED, InvokePacket,
};
pub use nub_arch_x86_abi::{CapHash as AbiCapHash, InvocationResult};
pub use nub_kernel::{CapHash, InstanceRef, InvokeOptions, InvokeOutcome};

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
    /// The kernel-maintained gas meter mapping (`meter_key -> remaining gas`).
    /// The interim "static meter mapping" of the kernel-assisted GasMeter
    /// design — a later spec change moves it behind a YieldCatcher. At frame
    /// entry the kernel resolves the running Instance's `gas_slots[0]` →
    /// `Gas{meter_key}` handle → `meter_key`, seeds the run from this map (a
    /// missing/zero entry falls back to the call-supplied budget), and writes
    /// the remaining gas back here at frame exit.
    meters: HashMap<Key, u64>,
    /// The kernel-maintained storage quota mapping (`quota_key -> remaining`).
    /// Symmetric to [`Self::meters`]; quota *charging* is not yet wired (V1),
    /// so this is seeded/observed but not yet debited per dirty page.
    quotas: HashMap<Key, u64>,
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
    Hyperlight(Box<HyperlightDriver>),
}

/// Host-side RPC stub for the Hyperlight backend. The real kernel
/// lives guest-side; this wrapper just ships invocations into the
/// sandbox.
struct HyperlightDriver {
    sandbox: MultiUseSandbox,
    state_root_cache: CapHash,
    /// Host-side mirror of the published cap graph, used **only** to resolve an
    /// Instance's `gas_slots[0]` → `Gas{meter_key}` handle host-side (the
    /// authoritative cap directory lives guest-side). This is the host's own
    /// `CacheDirectory` — not a deref of the guest's hashbrown (which is
    /// unsound across the SIMD-width boundary; see `MultiUseSandbox`).
    host_cache: CacheDirectory,
}

impl Nub {
    /// Construct a Nub backed by the in-process [`LocalArch`].
    pub fn new_local() -> Self {
        Self {
            backend: Backend::Local {
                kernel: Kernel::new(LocalArch::new()),
                cache: CacheDirectory::new(),
            },
            meters: HashMap::new(),
            quotas: HashMap::new(),
        }
    }

    /// Construct a Nub backed by a fresh Hyperlight sandbox loaded
    /// from the `nub-arch-x86` guest blob.
    pub fn new_hyperlight() -> Result<Self> {
        Self::new_hyperlight_with_blob_path(NUB_ARCH_X86_BLOB_PATH)
    }

    /// Construct a Nub backed by a fresh Hyperlight sandbox loaded
    /// from an arbitrary guest ELF on disk. Used by `test_support`
    /// to swap in the test/bench binaries; production callers should
    /// use [`Self::new_hyperlight`].
    pub(crate) fn new_hyperlight_with_blob_path(path: &str) -> Result<Self> {
        let mut cfg = SandboxConfiguration::default();
        cfg.set_scratch_size(512 * 1024 * 1024);
        cfg.set_input_data_size(16 * 1024 * 1024);
        cfg.set_output_data_size(16 * 1024 * 1024);
        cfg.set_heap_size(256 * 1024 * 1024);
        let uninit = UninitializedSandbox::new(GuestBinary::FilePath(path.to_string()), Some(cfg))?;
        let sandbox = uninit.evolve()?;
        Ok(Self {
            backend: Backend::Hyperlight(Box::new(HyperlightDriver {
                sandbox,
                state_root_cache: [0; 32],
                host_cache: CacheDirectory::new(),
            })),
            meters: HashMap::new(),
            quotas: HashMap::new(),
        })
    }

    /// Current state root.
    pub fn state_root(&self) -> CapHash {
        match &self.backend {
            Backend::Local { kernel, .. } => kernel.state_root(),
            Backend::Hyperlight(h) => h.state_root_cache,
        }
    }

    /// Bench-only: clear the guest's JIT compile cache so the next
    /// `invoke_cached` pays a full recompile. No-op on the Local
    /// backend (which uses the interpreter and has no JIT cache).
    pub fn evict_jit_all(&mut self) -> Result<()> {
        match &mut self.backend {
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
    pub fn heap_stats(&mut self) -> Result<HeapStats> {
        match &mut self.backend {
            Backend::Local { .. } => Err(anyhow::anyhow!(
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

    // --- New publish surface (caller-built `Cap`) ---

    /// Put a caller-built `Cap` into the active cache. Computes
    /// the cap's content hash and either clones the cap on first put or
    /// bumps refcount on idempotent re-put. Returns the cap's content hash.
    pub fn put_cap(&mut self, cap: &javm_cap::Cap) -> Result<AbiCapHash> {
        match &mut self.backend {
            Backend::Local { cache, .. } => cache
                .put_cap(cap)
                .map_err(|e| anyhow::anyhow!("put_cap (local): {e}")),
            Backend::Hyperlight(h) => {
                // Mirror into the host-side cache so `invoke_cached` can resolve
                // gas_slots → meter_key host-side (best-effort; the guest cache
                // is authoritative for execution).
                let _ = h.host_cache.put_cap(cap);
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
    pub fn put_cap_with_hash(&mut self, hash: AbiCapHash, cap: &javm_cap::Cap) -> Result<()> {
        match &mut self.backend {
            Backend::Local { cache, .. } => cache
                .put_cap_with_hash(hash, cap)
                .map_err(|e| anyhow::anyhow!("put_cap_with_hash (local): {e}")),
            Backend::Hyperlight(h) => {
                let _ = h.host_cache.put_cap_with_hash(hash, cap);
                h.sandbox
                    .put_cap_with_hash(hash, cap)
                    .map_err(|e| anyhow::anyhow!("put_cap_with_hash: {e}"))
            }
        }
    }

    // --- Kernel gas/quota meter mapping (`SetGasMeter` / `SetStorageQuota`) ---

    /// Set the kernel gas meter `meter_key` to `value`; returns the previous
    /// value (0 if absent). The chain-side topup / harvest primitive.
    pub fn set_meter(&mut self, meter_key: Key, value: u64) -> u64 {
        self.meters.insert(meter_key, value).unwrap_or(0)
    }

    /// Read the kernel gas meter `meter_key` (0 if absent).
    pub fn get_meter(&self, meter_key: &Key) -> u64 {
        self.meters.get(meter_key).copied().unwrap_or(0)
    }

    /// Set the kernel storage quota `quota_key`; returns the previous value.
    pub fn set_quota(&mut self, quota_key: Key, value: u64) -> u64 {
        self.quotas.insert(quota_key, value).unwrap_or(0)
    }

    /// Read the kernel storage quota `quota_key` (0 if absent).
    pub fn get_quota(&self, quota_key: &Key) -> u64 {
        self.quotas.get(quota_key).copied().unwrap_or(0)
    }

    /// Resolve the running Instance's active gas `meter_key` from its Image's
    /// `gas_slots[0]` → `Gas{meter_key}` handle, via the appropriate host-side
    /// cache (the Local cache, or the Hyperlight host mirror). `None` if the
    /// Image declares no gas slot, the slot is empty, or the cap there is not a
    /// kernel `Gas` handle.
    fn resolve_gas_meter_key(&self, instance_hash: AbiCapHash) -> Option<Key> {
        let cache = match &self.backend {
            Backend::Local { cache, .. } => cache,
            Backend::Hyperlight(h) => &h.host_cache,
        };
        resolve_meter_key_from(cache, instance_hash)
    }

    /// Invoke a previously-published `Cap::Instance` by hash. V0 args
    /// are 4 u64s laid into φ[7..=10] on top of the published
    /// endpoint's `initial_regs` baseline.
    ///
    /// Meter-driven gas: if the Instance's `gas_slots[0]` names a `Gas` handle
    /// whose `meter_key` has a non-zero entry in the kernel meter mapping, the
    /// run is seeded from that meter and the remaining gas is written back at
    /// exit. Otherwise the call-supplied `initial_gas` is used (and the meter is
    /// left untouched), preserving the bare-budget path.
    pub fn invoke_cached(
        &mut self,
        instance_hash: AbiCapHash,
        endpoint_idx: u8,
        args: [u64; 4],
        initial_gas: u64,
    ) -> Result<InvocationResult> {
        let meter_key = self.resolve_gas_meter_key(instance_hash);
        let (budget, used_meter) = match &meter_key {
            Some(k) if self.get_meter(k) > 0 => (self.get_meter(k), true),
            _ => (initial_gas, false),
        };
        let result = self.invoke_cached_raw(instance_hash, endpoint_idx, args, budget)?;
        if used_meter && let Some(k) = meter_key {
            self.meters.insert(k, result.gas_remaining);
        }
        Ok(result)
    }

    /// The backend dispatch for [`Self::invoke_cached`], with the gas budget
    /// already resolved (meter-seeded or call-supplied).
    fn invoke_cached_raw(
        &mut self,
        instance_hash: AbiCapHash,
        endpoint_idx: u8,
        args: [u64; 4],
        initial_gas: u64,
    ) -> Result<InvocationResult> {
        match &mut self.backend {
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
                Ok(nub_arch_local::run_instance(
                    &inst,
                    &img,
                    endpoint_idx,
                    args,
                    initial_gas,
                ))
            }
            Backend::Hyperlight(h) => {
                // No host-side pin/unpin — the cap is owned by the
                // guest's heap-resident DIRECTORY; there's nothing for
                // the host to lock against (the guest doesn't evict).
                let packet = InvokePacket {
                    instance_hash,
                    endpoint_idx: endpoint_idx as u32,
                    _pad: 0,
                    args,
                    initial_gas,
                };
                let result_bytes = h
                    .sandbox
                    .call_raw(FN_ID_NUB_INVOKE_CACHED, packet.as_bytes())?;

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
                    // `[u8; N]` archives byte-identically (u8 has no endianness).
                    scratchpad_head: archived.scratchpad_head,
                })
            }
        }
    }
}

/// Walk `instance_hash → image.gas_slots[0] → cnode slot → Gas{meter_key}` in
/// `cache`, returning the `meter_key`. `None` if any hop is missing or the slot
/// does not hold a kernel `Gas` handle. The cnode resolution uses the
/// Instance's `root_cnode` (a content hash for a settled top-level instance).
fn resolve_meter_key_from(cache: &CacheDirectory, instance_hash: AbiCapHash) -> Option<Key> {
    let inst_cap = cache.get(CapHashOrRef::Hash(instance_hash))?;
    let Cap::Instance(inst) = &*inst_cap else {
        return None;
    };
    let img_cap = cache.get(CapHashOrRef::Hash(inst.image_hash))?;
    let Cap::Image(img) = &*img_cap else {
        return None;
    };
    let slot = img.gas_slots.first()?;
    let cnode_cap = cache.get(inst.root_cnode.clone())?;
    let Cap::CNode(cnode) = &*cnode_cap else {
        return None;
    };
    let gas_ref = cnode.get(slot)?;
    let gas_cap = cache.get(gas_ref)?;
    let Cap::Instance(g) = &*gas_cap else {
        return None;
    };
    if recognize_kernel_image(g.image_hash_chain) != Some(KernelImage::Gas) {
        return None;
    }
    Some(key_from_regs(g.regs[0], g.regs[1]))
}
