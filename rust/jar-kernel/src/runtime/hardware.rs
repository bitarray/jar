//! Hardware abstraction.
//!
//! The kernel takes `&H: Hardware` so it can:
//! - hash blobs (`hash`) — used for state-root and attestation blob digests
//! - verify signatures (`verify`) — verifier-mode AttestationCap
//! - decide proposer-vs-verifier per AttestationCap (`holds_key`)
//! - sign blobs in producer mode (`sign`)
//! - emit Dispatch / BroadcastLite commands to the network (`emit`)
//!
//! `Hardware: Crypto` — the trait inherits the type-only `Crypto` suite that
//! names `Hash` / `Signature` / `KeyId`. Kernel code reads `H::Hash` etc.
//! instead of any concrete type.
//!
//! σ is **not** owned by Hardware — passed alongside as `&State<H>` /
//! `State<H>`. Off-chain aggregation slots live in `NodeOffchain<H>`, also
//! outside.
//!
//! There is no blanket `Hardware for Arc<H>` impl. Sharing a `Kernel<H>`
//! across tasks is done by wrapping the kernel itself in `Arc<Kernel<H>>`,
//! not the inner hardware. (A blanket on `Arc<H>` is technically problematic
//! because `Command<Arc<H>>` and `Command<H>` are distinct Rust types even
//! though their associated types coincide.)

use jar_types::{Command, Crypto};

#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum HwError {
    #[error("hardware does not hold the requested key")]
    KeyAbsent,
    #[error("hardware sign failed: {0}")]
    SignFailure(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TracingEvent {
    InvocationFault { reason: String },
    BlockPanic { reason: String },
}

pub trait Hardware: Crypto {
    /// Hash a blob (used for state-root and attestation blob digests).
    fn hash(&self, blob: &[u8]) -> Self::Hash;

    /// Verify a signature. Verifier-mode AttestationCap path.
    fn verify(&self, key: Self::KeyId, msg: &[u8], sig: &Self::Signature) -> bool;

    /// Whether this node holds the secret half of `key`. Decides
    /// proposer-vs-verifier per AttestationCap.
    fn holds_key(&self, key: Self::KeyId) -> bool;

    /// Sign `blob` with the secret half of `key`. Producer-mode AttestationCap.
    fn sign(&self, key: Self::KeyId, blob: &[u8]) -> Result<Self::Signature, HwError>;

    fn emit(&self, cmd: Command<Self>);

    fn tracing_event(&self, ev: TracingEvent) {
        // Default: drop. Tests / production override.
        let _ = ev;
    }
}
