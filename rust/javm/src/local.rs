//! [`JavmLocal`] — the JAVM in-process kernel: the [`nub::LocalKernel`]
//! impl driven by the [`Nub`](crate::Nub) Local backend.
//!
//! Holds the host-side [`CacheDirectory`] (source of truth for caps
//! published via [`Nub::put_cap`](crate::Nub::put_cap)) and lowers
//! invocations onto the PVM2 (RISC-V) interpreter via
//! `nub_arch_local`.

use anyhow::Result;
use javm_cap::cap::Cap;
use javm_cap::cap::image::ImageCap;
use javm_cap::cap::instance::InstanceCap;
use javm_cap::{CacheDirectory, CapHashOrRef};
use nub::{CapHash, InvocationResult, LocalKernel, ObjHash};
use nub_arch_local::{ExitingEcallHandler, ProgramSpec, RoOverlay, run_program};
use nub_exec::Regs;

/// The JAVM Local-backend kernel: cap directory + interpreter wiring.
pub struct JavmLocal {
    cache: CacheDirectory,
    /// Stub parity with the historical `Kernel<LocalArch>` state root
    /// (all zeroes until block-apply lands).
    state_root: CapHash,
}

impl Default for JavmLocal {
    fn default() -> Self {
        Self {
            cache: CacheDirectory::new(),
            state_root: [0; 32],
        }
    }
}

impl JavmLocal {
    /// Typed, encode-free publish — the fast path behind
    /// [`Nub::put_cap`](crate::Nub::put_cap) via `nub::Nub::with_local`.
    pub fn put_cap(&mut self, cap: &Cap) -> Result<CapHash> {
        self.cache
            .put_cap(cap)
            .map_err(|e| anyhow::anyhow!("put_cap (local): {e}"))
    }

    /// Typed pre-hashed publish. See
    /// [`Nub::put_cap_with_hash`](crate::Nub::put_cap_with_hash).
    pub fn put_cap_with_hash(&mut self, hash: CapHash, cap: &Cap) -> Result<()> {
        self.cache
            .put_cap_with_hash(hash, cap)
            .map_err(|e| anyhow::anyhow!("put_cap_with_hash (local): {e}"))
    }

    /// Decode a personality-encoded (rkyv-archived) `Cap` payload —
    /// the host-side mirror of the guest's `put_object` decode
    /// (`javm-guest-x86/src/state_cache.rs`).
    fn decode(bytes: &[u8]) -> Result<Cap> {
        let mut aligned = rkyv::util::AlignedVec::<16>::with_capacity(bytes.len());
        aligned.extend_from_slice(bytes);
        let archived = rkyv::access::<rkyv::Archived<Cap>, rkyv::rancor::Error>(aligned.as_slice())
            .map_err(|e| anyhow::anyhow!("rkyv access: {e}"))?;
        rkyv::deserialize::<Cap, rkyv::rancor::Error>(archived)
            .map_err(|e| anyhow::anyhow!("rkyv deserialize: {e}"))
    }
}

impl LocalKernel for JavmLocal {
    fn put_object(&mut self, bytes: &[u8]) -> Result<ObjHash> {
        let cap = Self::decode(bytes).map_err(|e| anyhow::anyhow!("put_object: {e}"))?;
        self.cache
            .put_cap(&cap)
            .map_err(|e| anyhow::anyhow!("put_object: {e}"))
    }

    fn put_object_with_hash(&mut self, hash: ObjHash, bytes: &[u8]) -> Result<()> {
        let cap = Self::decode(bytes).map_err(|e| anyhow::anyhow!("put_object_with_hash: {e}"))?;
        self.cache
            .put_cap_with_hash(hash, &cap)
            .map_err(|e| anyhow::anyhow!("put_object_with_hash: {e}"))
    }

    fn invoke(
        &mut self,
        root: ObjHash,
        endpoint: u32,
        args: [u64; 4],
        initial_gas: u64,
    ) -> Result<InvocationResult> {
        // Resolve the instance + image from the in-process cache and
        // drive the PVM2 (RISC-V) interpreter.
        let instance_cap = self
            .cache
            .get(CapHashOrRef::Hash(root))
            .ok_or_else(|| anyhow::anyhow!("invoke_cached: instance not published"))?;
        let inst = match &*instance_cap {
            Cap::Instance(i) => i.clone(),
            _ => {
                return Err(anyhow::anyhow!(
                    "invoke_cached: cap at hash is not an Instance"
                ));
            }
        };
        let image_cap = self
            .cache
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

        // V1 single-byte ABI: the endpoint selector is a single-byte
        // Key into the sparse endpoint list (matching the guest's
        // `build_frame_inner`).
        Ok(run_instance(
            &inst,
            &img,
            (endpoint & 0xFF) as u8,
            args,
            initial_gas,
        ))
    }

    fn state_root(&self) -> ObjHash {
        self.state_root
    }
}

/// Run an Instance through the PVM2 (RISC-V) interpreter by lowering
/// the JAVM cap layout into a [`ProgramSpec`].
///
/// Endpoint dispatch: `endpoint_idx` selects
/// `image.endpoints[endpoint_idx]`; the endpoint's `entry_pc` is used
/// as the start PC. Caller-supplied `args` overlay φ[7..=10] on top
/// of the endpoint's `initial_regs`. Memory is seeded from the
/// Instance's `mem` DataCap (the whole RW extent), with pinned mappings
/// re-laid read-only.
fn run_instance(
    instance: &InstanceCap,
    image: &ImageCap,
    endpoint_idx: u8,
    args: [u64; 4],
    initial_gas: u64,
) -> InvocationResult {
    let data_base = javm_cap::layout::DATA_BASE;
    let data_extent = instance.mem.content_len();
    let mut mem_image = vec![0u8; data_extent as usize];
    if data_extent > 0 {
        // Seed the whole extent from the Instance's memory image (the immutable
        // backing — both initial and pinned content). No cache lookup needed.
        instance.mem.copy_into(0, &mut mem_image);
    }
    // Pinned mappings become read-only re-lays (same bytes, from the
    // seeded image) so a guest store faults, matching the recompiler's
    // PinnedCapRo direct map.
    let mut ro_overlays = Vec::new();
    for m in image.mappings.iter() {
        if m.path().is_empty() || !image.mapping_is_pinned(m.start as u32) {
            continue;
        }
        let off = (m.start.saturating_sub(data_base as u64)) as usize;
        let len = (m.size as usize).min(mem_image.len().saturating_sub(off));
        if len > 0 {
            ro_overlays.push(RoOverlay {
                start: m.start as u32,
                image_off: off,
                len,
            });
        }
    }

    // V1 single-byte ABI: the endpoint selector is a single-byte Key into the
    // sparse endpoint list.
    let target = javm_cap::Key::from(endpoint_idx);
    let (_, endpoint) = image
        .endpoints
        .iter()
        .find(|(k, _)| *k == target)
        .expect("endpoint key not defined");

    let mut regs = Regs::new();
    regs.pc = endpoint.entry_pc;
    // Endpoint baseline first, then layer the InstanceCap's persisted
    // regs on top (publish_instance writes them; subsequent invokes
    // observe them). Args overlay φ[7..=10] last.
    // Persisted file is the 13 host-mapped slots; x3/x4 (slots 13/14) start
    // at 0 (Regs::new zeros them), matching the recompiler.
    regs.gpr[..javm_cap::NUM_REGS].copy_from_slice(&endpoint.initial_regs);
    for (i, v) in instance.regs.iter().enumerate() {
        if *v != 0 {
            regs.gpr[i] = *v;
        }
    }
    for (i, v) in args.iter().enumerate() {
        regs.gpr[7 + i] = *v;
    }

    // The executable code region, mapped RO at the fixed CODE_BASE
    // (PC = CODE_BASE + byte_offset).
    let (code_base, code_bytes) = image
        .code_mapping()
        .expect("image has no executable code mapping");

    let spec = ProgramSpec {
        code_base,
        code: code_bytes,
        data_base,
        mem_image: &mem_image,
        ro_overlays: &ro_overlays,
        declared_mem_size: instance.mem_size(),
        regs,
    };
    let mut handler = ExitingEcallHandler;
    run_program(&spec, &mut handler, initial_gas)
}
