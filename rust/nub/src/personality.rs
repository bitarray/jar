//! Host-side kernel-personality abstraction.
//!
//! A *personality* is the pluggable kernel semantics layer that runs on
//! top of the nub substrate: it defines what published state objects
//! mean (decoding, validation, content hashing), how invocations
//! resolve a root object, and what the guest-side kernel does on
//! ecalls. JAVM's capability system is one personality; nub itself
//! stays personality-agnostic and moves opaque bytes + 32-byte
//! [`ObjHash`] keys.
//!
//! This module holds the *host-side* half of the abstraction — what
//! the [`Nub`](crate::Nub) handle needs from a personality. The
//! guest-side half (`GuestPersonality` — ecall dispatch, state store,
//! gas sourcing) lives in `nub-arch-x86`, where the execution-lane and
//! frame-runtime types it references are defined.

use anyhow::Result;
use nub_arch_x86_abi::InvocationResult;
use nub_kernel::ObjHash;

/// A kernel personality, from the host's point of view.
///
/// The Hyperlight backend needs nothing beyond the guest blob itself
/// (the wire protocol is already hash + opaque bytes), so the trait
/// only carries what the in-process backend requires plus a label for
/// diagnostics.
pub trait Personality: Send + Sync + 'static {
    /// Short personality name for diagnostics and blob labels.
    const NAME: &'static str;

    /// The in-process (Local backend) kernel implementation.
    type Local: LocalKernel + Default + Send + 'static;
}

/// In-process kernel: the personality's object store + interpreter
/// wiring, driven directly by the [`Nub`](crate::Nub) Local backend.
///
/// One impl per personality. Replaces the historical hard-wired
/// `Backend::Local { Kernel<LocalArch>, CacheDirectory }` pair.
pub trait LocalKernel {
    /// Decode + validate + content-hash `bytes` and insert the object
    /// into the store. Returns the personality-computed content hash.
    /// Idempotent re-puts follow the personality's own semantics
    /// (JAVM: refcount bump).
    fn put_object(&mut self, bytes: &[u8]) -> Result<ObjHash>;

    /// Pre-hashed variant of [`put_object`](Self::put_object): the
    /// caller already knows the content hash, letting the impl skip
    /// hashing on idempotent re-puts. Implementations may
    /// debug-assert the claimed hash.
    fn put_object_with_hash(&mut self, hash: ObjHash, bytes: &[u8]) -> Result<()>;

    /// Invoke `endpoint` on the object graph rooted at `root`,
    /// overlaying `args` per the personality's register ABI, bounded
    /// by `initial_gas`.
    fn invoke(
        &mut self,
        root: ObjHash,
        endpoint: u32,
        args: [u64; 4],
        initial_gas: u64,
    ) -> Result<InvocationResult>;

    /// Content-addressed root of the current state (the personality
    /// defines what "root" means; JAVM: hash of the invoking
    /// `Cap::Instance` after the most recent invocation).
    fn state_root(&self) -> ObjHash;
}
