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

    mod proptests {
        use super::*;
        use proptest::prelude::*;
        use scale::{Decode, Encode};

        fn assert_codec_roundtrip<T: Encode + Decode>(val: &T) {
            let encoded = val.encode();
            let (decoded, consumed) = T::decode(&encoded).expect("decode should succeed");
            assert_eq!(consumed, encoded.len(), "should consume all bytes");
            assert_eq!(decoded.encode(), encoded, "re-encode should match");
        }

        /// Generate a random ValidatorKey from fill bytes.
        fn arb_validator_key() -> impl Strategy<Value = ValidatorKey> {
            (
                any::<[u8; 32]>(),
                any::<[u8; 32]>(),
                any::<u8>(),
                any::<u8>(),
            )
                .prop_map(|(band, ed, bls_fill, meta_fill)| ValidatorKey {
                    bandersnatch: BandersnatchPublicKey(band),
                    ed25519: Ed25519PublicKey(ed),
                    bls: BlsPublicKey([bls_fill; 144]),
                    metadata: [meta_fill; 128],
                })
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(128))]

            /// ValidatorKey codec encode→decode roundtrip.
            #[test]
            fn validator_key_codec_roundtrip(key in arb_validator_key()) {
                assert_codec_roundtrip(&key);
            }

            /// ValidatorKey to_bytes→from_bytes roundtrip.
            #[test]
            fn validator_key_bytes_roundtrip(key in arb_validator_key()) {
                let bytes = key.to_bytes();
                let recovered = ValidatorKey::from_bytes(&bytes);
                prop_assert_eq!(recovered, key);
            }

            /// to_bytes and codec encode produce consistent field layout.
            /// The codec uses scale encoding (field-by-field), while to_bytes
            /// uses manual concatenation. Both should agree on the content.
            #[test]
            fn validator_key_bytes_fields_match(key in arb_validator_key()) {
                let bytes = key.to_bytes();
                // Verify to_bytes places fields correctly
                prop_assert_eq!(&bytes[0..32], &key.bandersnatch.0);
                prop_assert_eq!(&bytes[32..64], &key.ed25519.0);
                prop_assert_eq!(&bytes[64..208], &key.bls.0);
                prop_assert_eq!(&bytes[208..336], &key.metadata);
            }

            /// BlsPublicKey codec roundtrip.
            #[test]
            fn bls_public_key_roundtrip(fill in any::<u8>()) {
                assert_codec_roundtrip(&BlsPublicKey([fill; 144]));
            }
        }
    }
}
