//! Shared types for the JAR minimum kernel.
//!
//! Mirrors the spec at `~/docs/minimum/`. Every map is `BTreeMap` so iteration
//! order is canonical (the spec's determinism contract requires this).

#![forbid(unsafe_code)]

pub(crate) use std::collections::BTreeMap;

mod block;
mod cap;
mod runtime;
mod slot;
mod state;
mod trace;

pub use block::*;
pub use cap::*;
pub use runtime::*;
pub use slot::*;
pub use state::*;
pub use trace::*;

/// 32-byte hash. Used for state roots, blob hashes, and code hashes. The
/// chain commits to a single hash function (blake2b-256) at the protocol
/// level — this width is a kernel constant, not a configurable.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub const ZERO: Hash = Hash([0u8; 32]);

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for Hash {
    fn from(b: [u8; 32]) -> Self {
        Hash(b)
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Block hash alias. Same shape as `Hash`; computed by
/// `jar_kernel::crypto::block_hash` over a canonical block encoding.
pub type BlockHash = Hash;

/// Globally unique vault identifier (allocated monotonically by the kernel).
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
pub struct VaultId(pub u64);

/// Globally unique capability-id (allocated monotonically by the kernel).
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
pub struct CapId(pub u64);

/// Globally unique CNode identifier (allocated monotonically by the kernel).
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
pub struct CNodeId(pub u64);

/// Identifier of a signing key. Variable-width bytes — Ed25519 pubkeys are
/// 32 bytes, BLS pubkeys are 48; the kernel stores the bytes opaquely and
/// passes them through to `Hardware::sign` / `holds_key` and to
/// `jar_kernel::crypto::verify`.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
pub struct KeyId(pub Vec<u8>);

impl KeyId {
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        KeyId(bytes.into())
    }
}

impl AsRef<[u8]> for KeyId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Block-time slot. Strictly monotone increasing block-by-block.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
pub struct Slot(pub u64);

/// Cryptographic signature. Variable-width bytes — Ed25519 is 64, BLS is 96;
/// kernel stores them opaquely and passes them through to
/// `jar_kernel::crypto::verify` / `Hardware::sign`.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct Signature(pub Vec<u8>);

impl Signature {
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Signature(bytes.into())
    }

    /// True iff this is the zero-length sentinel — the placeholder that
    /// proposer-mode `attest()` writes for a Sealing entry before the
    /// kernel back-fills the real signature post-execution.
    pub fn is_reserved(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Top-level kernel error type. Concrete cases are generated as the kernel grows.
#[derive(thiserror::Error, Clone, Debug, Eq, PartialEq)]
pub enum KernelError {
    #[error("capability lookup miss for {0:?}")]
    CapNotFound(CapId),
    #[error("vault not found: {0:?}")]
    VaultNotFound(VaultId),
    #[error("cnode not found: {0:?}")]
    CNodeNotFound(CNodeId),
    #[error("cnode slot {slot} of {cnode:?} is empty")]
    CNodeSlotEmpty { cnode: CNodeId, slot: u8 },
    #[error("pinning violation: {0}")]
    Pinning(String),
    #[error("read-only context rejected mutating host call: {0}")]
    ReadOnly(&'static str),
    #[error("vault quota exceeded: {what}")]
    QuotaExceeded { what: &'static str },
    #[error("trace divergence: {0}")]
    TraceDivergence(String),
    #[error("invocation gas exhausted")]
    OutOfGas,
    #[error("invocation faulted: {0}")]
    Fault(String),
    #[error("structural backstop failed: {0}")]
    StructuralBackstop(String),
    #[error("unimplemented host call: {0}")]
    Unimplemented(&'static str),
    #[error("internal error: {0}")]
    Internal(String),
}

pub type KResult<T> = Result<T, KernelError>;

/// Convenience: a sorted byte-key map (used for vault storage and similar).
pub type ByteMap = BTreeMap<Vec<u8>, Vec<u8>>;
