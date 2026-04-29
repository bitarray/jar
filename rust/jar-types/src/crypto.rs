//! Crypto suite: type-only trait that names the curve + hash function.
//!
//! Every parametrized type in `jar-types` (`State<C>`, `Block<C>`, `Body<C>`,
//! `Event<C>`, `AttestationEntry<C>`, etc.) carries a `C: Crypto` parameter
//! whose associated `Hash` / `Signature` / `KeyId` types fix the curve and
//! hash function. The kernel and downstream crates write `H::Hash` (where
//! `H: Hardware: Crypto`) instead of any concrete type.
//!
//! The concrete suite for the v1 chain (Ed25519 + Blake2b-256) is supplied
//! by `jar-crypto::Ed25519Blake`.

use core::fmt::Debug;
use core::hash::Hash;

/// Marker trait selecting a crypto suite at the type level. Implementors are
/// usually unit structs (e.g. `Ed25519Blake`) that carry no runtime state.
///
/// Bound choices:
/// - `Hash` is `Copy` (32 bytes is cheap) and `Ord + Hash` to be a `BTreeMap`
///   key. `Default` so structs holding it can derive `Default`. `AsRef<[u8]>`
///   so canonical encoders can write its bytes.
/// - `Signature` is only `Clone` (64+ bytes); no `Ord`/`Hash` because we
///   don't key collections by signature.
/// - `KeyId` mirrors `Hash`'s bounds (often the same width and used the
///   same way).
pub trait Crypto: Send + Sync + Sized + 'static {
    type Hash: Copy
        + Eq
        + Ord
        + Hash
        + Debug
        + Default
        + AsRef<[u8]>
        + Send
        + Sync
        + 'static;
    type Signature: Clone
        + Eq
        + Debug
        + Default
        + AsRef<[u8]>
        + Send
        + Sync
        + 'static;
    type KeyId: Copy
        + Eq
        + Ord
        + Hash
        + Debug
        + Default
        + AsRef<[u8]>
        + Send
        + Sync
        + 'static;

    /// Construct a `Hash` from raw bytes. Returns `None` if the byte width
    /// does not match the suite's hash width. Host calls reading guest
    /// memory go through this to convert raw bytes into the suite's
    /// `Hash` type.
    fn hash_from_bytes(bytes: &[u8]) -> Option<Self::Hash>;

    /// Construct a `KeyId` from raw bytes. Same width-validation contract
    /// as `hash_from_bytes`.
    fn key_id_from_bytes(bytes: &[u8]) -> Option<Self::KeyId>;

    /// Construct a `Signature` from raw bytes. Same contract.
    fn signature_from_bytes(bytes: &[u8]) -> Option<Self::Signature>;
}
