//! Validator key types (Section 6.3 of the Gray Paper).

use crate::{BandersnatchPublicKey, BlsPublicKey, Ed25519PublicKey};

/// Validator key set K = B336 (eq 6.8).
///
/// Components:
/// - kb: Bandersnatch key (bytes 0..32)
/// - ke: Ed25519 key (bytes 32..64)
/// - kl: BLS key (bytes 64..208)
/// - km: Metadata (bytes 208..336)
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
pub struct ValidatorKey {
    /// kb: Bandersnatch public key for block sealing and VRF.
    pub bandersnatch: BandersnatchPublicKey,

    /// ke: Ed25519 public key for signing guarantees, assurances, judgments.
    pub ed25519: Ed25519PublicKey,

    /// kl: BLS12-381 public key for Beefy commitments.
    pub bls: BlsPublicKey,

    /// km: Opaque metadata (128 bytes) including hardware address.
    #[serde(deserialize_with = "crate::serde_utils::hex_metadata")]
    pub metadata: [u8; 128],
}

impl Default for ValidatorKey {
    fn default() -> Self {
        Self {
            bandersnatch: BandersnatchPublicKey::default(),
            ed25519: Ed25519PublicKey::default(),
            bls: BlsPublicKey::default(),
            metadata: [0u8; 128],
        }
    }
}

impl ValidatorKey {
    /// The null key (all zeroes), used when a validator is offending (eq 6.14).
    pub fn null() -> Self {
        Self::default()
    }

    /// Serialize to 336 bytes.
    pub fn to_bytes(&self) -> [u8; 336] {
        let mut bytes = [0u8; 336];
        bytes[0..32].copy_from_slice(&self.bandersnatch.0);
        bytes[32..64].copy_from_slice(&self.ed25519.0);
        bytes[64..208].copy_from_slice(&self.bls.0);
        bytes[208..336].copy_from_slice(&self.metadata);
        bytes
    }

    /// Deserialize from 336 bytes.
    pub fn from_bytes(bytes: &[u8; 336]) -> Self {
        let mut bandersnatch = [0u8; 32];
        bandersnatch.copy_from_slice(&bytes[0..32]);
        let mut ed25519 = [0u8; 32];
        ed25519.copy_from_slice(&bytes[32..64]);
        let mut bls = [0u8; 144];
        bls.copy_from_slice(&bytes[64..208]);
        let mut metadata = [0u8; 128];
        metadata.copy_from_slice(&bytes[208..336]);
        Self {
            bandersnatch: BandersnatchPublicKey(bandersnatch),
            ed25519: Ed25519PublicKey(ed25519),
            bls: BlsPublicKey(bls),
            metadata,
        }
    }
}
