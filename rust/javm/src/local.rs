//! [`JavmLocal`] — the JAVM in-process kernel: the [`nub::LocalKernel`]
//! impl driven by the [`Nub`](crate::Nub) Local backend.
//!
//! Holds the host-side [`CacheDirectory`] (source of truth for caps
//! published via [`Nub::put_cap`](crate::Nub::put_cap)) and lowers
//! invocations onto the PVM2 (RISC-V) interpreter via
//! `nub_arch_local`.

use anyhow::Result;
use javm_cap::cap::Cap;
use javm_cap::{CacheDirectory, CapHashOrRef};
use nub::{CapHash, InvocationResult, LocalKernel, ObjHash};

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
        // Key into the sparse endpoint list.
        Ok(nub_arch_local::run_instance(
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
