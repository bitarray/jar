//! Validator key types (Section 6.3 of the Gray Paper).

use crate::{BandersnatchPublicKey, BlsPublicKey, Ed25519PublicKey};

/// Validator key set K = B336 (eq 6.8).
///
/// Components:
/// - kb: Bandersnatch key (bytes 0..32)
/// - ke: Ed25519 key (bytes 32..64)
/// - kl: BLS key (bytes 64..208)
/// - km: Metadata (bytes 208..336)
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, scale::Encode, scale::Decode)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_key_is_all_zeros() {
        let k = ValidatorKey::null();
        assert_eq!(k.bandersnatch.0, [0u8; 32]);
        assert_eq!(k.ed25519.0, [0u8; 32]);
        assert_eq!(k.bls.0, [0u8; 144]);
        assert_eq!(k.metadata, [0u8; 128]);
    }

    #[test]
    fn test_to_bytes_length() {
        let k = ValidatorKey::null();
        assert_eq!(k.to_bytes().len(), 336);
    }

    #[test]
    fn test_to_from_bytes_roundtrip() {
        let k = ValidatorKey {
            bandersnatch: BandersnatchPublicKey([0xAA; 32]),
            ed25519: Ed25519PublicKey([0xBB; 32]),
            bls: BlsPublicKey([0xCC; 144]),
            metadata: [0xDD; 128],
        };
        let bytes = k.to_bytes();
        let k2 = ValidatorKey::from_bytes(&bytes);
        assert_eq!(k2.bandersnatch.0, [0xAA; 32]);
        assert_eq!(k2.ed25519.0, [0xBB; 32]);
        assert_eq!(k2.bls.0, [0xCC; 144]);
        assert_eq!(k2.metadata, [0xDD; 128]);
    }

    #[test]
    fn test_to_bytes_field_layout() {
        let k = ValidatorKey {
            bandersnatch: BandersnatchPublicKey([1u8; 32]),
            ed25519: Ed25519PublicKey([2u8; 32]),
            bls: BlsPublicKey([3u8; 144]),
            metadata: [4u8; 128],
        };
        let b = k.to_bytes();
        // Verify field placement per spec: kb(0..32), ke(32..64), kl(64..208), km(208..336)
        assert!(b[0..32].iter().all(|&x| x == 1));
        assert!(b[32..64].iter().all(|&x| x == 2));
        assert!(b[64..208].iter().all(|&x| x == 3));
        assert!(b[208..336].iter().all(|&x| x == 4));
    }

    #[test]
    fn test_default_equals_null() {
        assert_eq!(ValidatorKey::default(), ValidatorKey::null());
    }
}
