//! Core types, constants, and data structures for the JAM protocol.
//!
//! This crate defines the foundational types matching the Gray Paper specification v0.7.2.
//! Greek-letter state components are mapped to descriptive Rust names.

pub mod config;
pub mod constants;
pub mod header;
pub mod serde_utils;
pub mod state;
pub mod validator;
pub mod work;

use std::fmt;

/// Decode a 0x-prefixed hex string to bytes.
pub fn decode_hex(s: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s))
}

/// Decode hex string into a fixed-size array.
pub fn decode_hex_fixed<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let bytes = decode_hex(s).map_err(|e| e.to_string())?;
    if bytes.len() != N {
        return Err(format!("expected {} bytes, got {}", N, bytes.len()));
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Implement Debug (with truncation), Deserialize, and Default (for large arrays) for crypto types.
macro_rules! impl_crypto_type {
    // Fixed-size array with Copy — full hex in Debug
    ($name:ident, $size:expr, copy, $debug_name:expr) => {
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", $debug_name, hex::encode(self.0))
            }
        }
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s: String = serde::Deserialize::deserialize(d)?;
                Ok($name(decode_hex_fixed(&s).map_err(serde::de::Error::custom)?))
            }
        }
    };
    // Large array — truncated Debug, manual Default
    ($name:ident, $size:expr, large, $debug_name:expr) => {
        impl Default for $name {
            fn default() -> Self { Self([0u8; $size]) }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({}...)", $debug_name, hex::encode(&self.0[..8]))
            }
        }
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s: String = serde::Deserialize::deserialize(d)?;
                Ok($name(decode_hex_fixed(&s).map_err(serde::de::Error::custom)?))
            }
        }
    };
}

/// A 32-byte cryptographic hash value (H in the spec).
/// Used for Blake2b-256 output, block hashes, state roots, etc.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    /// The zero hash H₀.
    pub const ZERO: Self = Self([0u8; 32]);

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parse from a hex string (with optional 0x prefix). Panics on invalid input.
    pub fn from_hex(s: &str) -> Self {
        Self(decode_hex_fixed(s).expect("invalid hex for Hash"))
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", hex::encode(self.0))
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl From<[u8; 32]> for Hash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'de> serde::Deserialize<'de> for Hash {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s: String = serde::Deserialize::deserialize(d)?;
        Ok(Hash(decode_hex_fixed(&s).map_err(serde::de::Error::custom)?))
    }
}

impl serde::Serialize for Hash {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("0x{}", hex::encode(self.0)))
    }
}

/// An Ed25519 public key (H̄ in the spec). Subset of B32.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub struct Ed25519PublicKey(pub [u8; 32]);
impl_crypto_type!(Ed25519PublicKey, 32, copy, "Ed25519");

impl Ed25519PublicKey {
    /// Parse from a hex string (with optional 0x prefix). Panics on invalid input.
    pub fn from_hex(s: &str) -> Self {
        Self(decode_hex_fixed(s).expect("invalid hex for Ed25519PublicKey"))
    }
}

/// A Bandersnatch public key (H̃ in the spec). Subset of B32.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct BandersnatchPublicKey(pub [u8; 32]);
impl_crypto_type!(BandersnatchPublicKey, 32, copy, "Bandersnatch");

impl BandersnatchPublicKey {
    /// Parse from a hex string (with optional 0x prefix). Panics on invalid input.
    pub fn from_hex(s: &str) -> Self {
        Self(decode_hex_fixed(s).expect("invalid hex for BandersnatchPublicKey"))
    }
}

/// A BLS12-381 public key (B^BLS in the spec). Subset of B144.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BlsPublicKey(pub [u8; 144]);
impl_crypto_type!(BlsPublicKey, 144, large, "BLS");

/// A Bandersnatch ring root (B° in the spec). Subset of B144.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BandersnatchRingRoot(pub [u8; 144]);
impl_crypto_type!(BandersnatchRingRoot, 144, large, "RingRoot");

impl BandersnatchRingRoot {
    /// Parse from a hex string (with optional 0x prefix). Panics on invalid input.
    pub fn from_hex(s: &str) -> Self {
        Self(decode_hex_fixed(s).expect("invalid hex for BandersnatchRingRoot"))
    }
}

/// An Ed25519 signature. B64.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ed25519Signature(pub [u8; 64]);
impl_crypto_type!(Ed25519Signature, 64, large, "Ed25519Sig");

impl Ed25519Signature {
    /// Parse from a hex string (with optional 0x prefix). Panics on invalid input.
    pub fn from_hex(s: &str) -> Self {
        Self(decode_hex_fixed(s).expect("invalid hex for Ed25519Signature"))
    }
}

/// A Bandersnatch signature. B96.
#[derive(Clone, PartialEq, Eq)]
pub struct BandersnatchSignature(pub [u8; 96]);
impl_crypto_type!(BandersnatchSignature, 96, large, "BanderSig");

/// A Bandersnatch Ring VRF proof. B784.
#[derive(Clone, PartialEq, Eq)]
pub struct BandersnatchRingVrfProof(pub Vec<u8>);

/// A BLS signature.
#[derive(Clone, PartialEq, Eq)]
pub struct BlsSignature(pub Vec<u8>);

/// Balance type: NB = N_{2^64} (eq 4.21).
pub type Balance = u64;

/// Gas type: NG = N_{2^64} (eq 4.23).
pub type Gas = u64;

/// Signed gas type: ZG = Z_{-2^63...2^63} (eq 4.23).
pub type SignedGas = i64;

/// Service identifier: NS = N_{2^32} (eq 9.1).
pub type ServiceId = u32;

/// Timeslot index: NT = N_{2^32} (eq 4.28).
pub type Timeslot = u32;

/// Core index: NC = N_C where C = 341.
pub type CoreIndex = u16;

/// Validator index: NV = N_V where V = 1023.
pub type ValidatorIndex = u16;

/// Register value: NR = N_{2^64} (eq 4.23).
pub type RegisterValue = u64;

/// An opaque blob of bytes.
pub type Blob = Vec<u8>;
