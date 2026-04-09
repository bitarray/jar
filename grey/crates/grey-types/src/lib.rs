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

/// Signing context strings used in the JAM protocol (Appendix I.4.5).
///
/// Each context is a unique byte prefix mixed into signatures to prevent
/// cross-protocol replay attacks. Centralised here as the single source
/// of truth — all crates import from this module.
pub mod signing_contexts {
    /// XA: Ed25519 availability assurances.
    pub const AVAILABLE: &[u8] = b"jam_available";

    /// XB: BLS accumulate-result-root-MMR commitment.
    pub const BEEFY: &[u8] = b"jam_beefy";

    /// XE: On-chain entropy generation.
    pub const ENTROPY: &[u8] = b"jam_entropy";

    /// XF: Bandersnatch fallback block seal.
    pub const FALLBACK_SEAL: &[u8] = b"jam_fallback_seal";

    /// XG: Ed25519 guarantee statements.
    pub const GUARANTEE: &[u8] = b"jam_guarantee";

    /// XI: Ed25519 audit announcement statements.
    pub const ANNOUNCE: &[u8] = b"jam_announce";

    /// XT: Bandersnatch RingVRF ticket generation and regular block seal.
    pub const TICKET_SEAL: &[u8] = b"jam_ticket_seal";

    /// XU: Bandersnatch audit selection entropy.
    pub const AUDIT: &[u8] = b"jam_audit";

    /// X⊺: Ed25519 judgments for valid work-reports.
    pub const VALID: &[u8] = b"jam_valid";

    /// X⊥: Ed25519 judgments for invalid work-reports.
    pub const INVALID: &[u8] = b"jam_invalid";

    /// GRANDPA prevote context.
    pub const PREVOTE: &[u8] = b"jam_prevote";

    /// GRANDPA precommit context.
    pub const PRECOMMIT: &[u8] = b"jam_precommit";

    /// Build a judgment signing message: (X_⊺ or X_⊥) ⌢ report_hash.
    ///
    /// Used for both signing and verifying valid/invalid work-report judgments.
    pub fn build_judgment_message(is_valid: bool, report_hash: &[u8; 32]) -> Vec<u8> {
        let context: &[u8] = if is_valid { VALID } else { INVALID };
        let mut message = Vec::with_capacity(context.len() + 32);
        message.extend_from_slice(context);
        message.extend_from_slice(report_hash);
        message
    }

    /// Build a guarantee signing message: X_G ⌢ report_hash.
    ///
    /// Used for signing and verifying work-report guarantees (Section 11).
    pub fn build_guarantee_message(report_hash: &[u8; 32]) -> Vec<u8> {
        let mut message = Vec::with_capacity(GUARANTEE.len() + 32);
        message.extend_from_slice(GUARANTEE);
        message.extend_from_slice(report_hash);
        message
    }
}

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
        impl $name {
            /// Parse from a hex string (with optional 0x prefix). Panics on invalid input.
            pub fn from_hex(s: &str) -> Self {
                Self(decode_hex_fixed(s).expect(concat!("invalid hex for ", $debug_name)))
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", $debug_name, hex::encode(self.0))
            }
        }
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s: String = serde::Deserialize::deserialize(d)?;
                Ok($name(
                    decode_hex_fixed(&s).map_err(serde::de::Error::custom)?,
                ))
            }
        }
    };
    // Large array — truncated Debug, manual Default
    ($name:ident, $size:expr, large, $debug_name:expr) => {
        impl $name {
            /// Parse from a hex string (with optional 0x prefix). Panics on invalid input.
            pub fn from_hex(s: &str) -> Self {
                Self(decode_hex_fixed(s).expect(concat!("invalid hex for ", $debug_name)))
            }
        }
        impl Default for $name {
            fn default() -> Self {
                Self([0u8; $size])
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({}...)", $debug_name, hex::encode(&self.0[..8]))
            }
        }
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s: String = serde::Deserialize::deserialize(d)?;
                Ok($name(
                    decode_hex_fixed(&s).map_err(serde::de::Error::custom)?,
                ))
            }
        }
    };
}

/// A 32-byte cryptographic hash value (H in the spec).
/// Used for Blake2b-256 output, block hashes, state roots, etc.
#[derive(
    Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord, scale::Encode, scale::Decode,
)]
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
        Ok(Hash(
            decode_hex_fixed(&s).map_err(serde::de::Error::custom)?,
        ))
    }
}

impl serde::Serialize for Hash {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("0x{}", hex::encode(self.0)))
    }
}

/// An Ed25519 public key (H̄ in the spec). Subset of B32.
#[derive(
    Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord, scale::Encode, scale::Decode,
)]
pub struct Ed25519PublicKey(pub [u8; 32]);
impl_crypto_type!(Ed25519PublicKey, 32, copy, "Ed25519");

/// A Bandersnatch public key (H̃ in the spec). Subset of B32.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, scale::Encode, scale::Decode)]
pub struct BandersnatchPublicKey(pub [u8; 32]);
impl_crypto_type!(BandersnatchPublicKey, 32, copy, "Bandersnatch");

/// A BLS12-381 public key (B^BLS in the spec). Subset of B144.
#[derive(Clone, PartialEq, Eq, Hash, scale::Encode, scale::Decode)]
pub struct BlsPublicKey(pub [u8; 144]);
impl_crypto_type!(BlsPublicKey, 144, large, "BLS");

/// A Bandersnatch ring root (B° in the spec). Subset of B144.
#[derive(Clone, PartialEq, Eq, Hash, scale::Encode, scale::Decode)]
pub struct BandersnatchRingRoot(pub [u8; 144]);
impl_crypto_type!(BandersnatchRingRoot, 144, large, "RingRoot");

/// An Ed25519 signature. B64.
#[derive(Clone, Copy, PartialEq, Eq, scale::Encode, scale::Decode)]
pub struct Ed25519Signature(pub [u8; 64]);
impl_crypto_type!(Ed25519Signature, 64, large, "Ed25519Sig");

/// A Bandersnatch signature. B96.
#[derive(Clone, PartialEq, Eq, scale::Encode, scale::Decode)]
pub struct BandersnatchSignature(pub [u8; 96]);
impl_crypto_type!(BandersnatchSignature, 96, large, "BanderSig");

/// A Bandersnatch Ring VRF proof. B784.
#[derive(Clone, PartialEq, Eq, scale::Encode, scale::Decode)]
pub struct BandersnatchRingVrfProof(pub Vec<u8>);

/// A BLS signature.
#[derive(Clone, PartialEq, Eq, scale::Encode, scale::Decode)]
pub struct BlsSignature(pub Vec<u8>);

// Balance type removed — coinless design. See docs/ideas/coinless-storage-quota.md.

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

/// Shared test helpers for codec roundtrip verification.
#[cfg(test)]
pub(crate) mod test_helpers {
    use scale::{Decode, Encode};

    /// Verify encode→decode→re-encode roundtrip for a given value.
    pub fn assert_codec_roundtrip<T: Encode + Decode>(val: &T) {
        let encoded = val.encode();
        let (decoded, consumed) = T::decode(&encoded).expect("decode should succeed");
        assert_eq!(consumed, encoded.len(), "should consume all bytes");
        assert_eq!(decoded.encode(), encoded, "re-encode should match");
    }

    /// Verify encode→decode→re-encode roundtrip for a Default-constructed value.
    pub fn assert_default_roundtrip<T: Default + Encode + Decode>() {
        assert_codec_roundtrip(&T::default());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::assert_default_roundtrip;
    use scale::{Decode, Encode};

    #[test]
    fn test_hash_roundtrip() {
        assert_default_roundtrip::<Hash>();
        // Also test non-default
        let h = Hash([42u8; 32]);
        let encoded = h.encode();
        let (decoded, _) = Hash::decode(&encoded).unwrap();
        assert_eq!(decoded, h);
    }

    #[test]
    fn test_ed25519_signature_roundtrip() {
        assert_default_roundtrip::<Ed25519Signature>();
    }

    #[test]
    fn test_bandersnatch_signature_roundtrip() {
        assert_default_roundtrip::<BandersnatchSignature>();
    }

    #[test]
    fn test_extrinsic_roundtrip() {
        assert_default_roundtrip::<header::Extrinsic>();
    }

    #[test]
    fn test_disputes_extrinsic_roundtrip() {
        assert_default_roundtrip::<header::DisputesExtrinsic>();
    }

    #[test]
    fn test_privileged_services_roundtrip() {
        assert_default_roundtrip::<state::PrivilegedServices>();
    }

    #[test]
    fn test_judgments_roundtrip() {
        assert_default_roundtrip::<state::Judgments>();
    }

    #[test]
    fn test_validator_statistics_roundtrip() {
        assert_default_roundtrip::<state::ValidatorStatistics>();
    }

    mod proptests {
        use super::*;
        use crate::test_helpers::assert_codec_roundtrip;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(128))]

            #[test]
            fn hash_roundtrip(bytes in proptest::array::uniform32(0u8..)) {
                assert_codec_roundtrip(&Hash(bytes));
            }

            #[test]
            fn ed25519_pubkey_roundtrip(bytes in proptest::array::uniform32(0u8..)) {
                assert_codec_roundtrip(&Ed25519PublicKey(bytes));
            }

            #[test]
            fn bandersnatch_pubkey_roundtrip(bytes in proptest::array::uniform32(0u8..)) {
                assert_codec_roundtrip(&BandersnatchPublicKey(bytes));
            }

            #[test]
            fn ed25519_signature_roundtrip(bytes in proptest::collection::vec(0u8.., 64..=64)) {
                let mut arr = [0u8; 64];
                arr.copy_from_slice(&bytes);
                assert_codec_roundtrip(&Ed25519Signature(arr));
            }

            #[test]
            fn ticket_roundtrip(id in proptest::array::uniform32(0u8..), attempt in 0u8..4) {
                assert_codec_roundtrip(&header::Ticket {
                    id: Hash(id),
                    attempt,
                });
            }

            #[test]
            fn judgment_roundtrip(
                validator_index in 0u16..1023,
                is_valid: bool,
                sig in proptest::collection::vec(0u8.., 64..=64),
            ) {
                let mut sig_arr = [0u8; 64];
                sig_arr.copy_from_slice(&sig);
                assert_codec_roundtrip(&header::Judgment {
                    validator_index,
                    is_valid,
                    signature: Ed25519Signature(sig_arr),
                });
            }

            #[test]
            fn verdict_roundtrip(
                report_hash in proptest::array::uniform32(0u8..),
                age in 0u32..100,
                n_judgments in 0usize..5,
            ) {
                let judgments: Vec<header::Judgment> = (0..n_judgments)
                    .map(|i| header::Judgment {
                        validator_index: i as u16,
                        is_valid: i % 2 == 0,
                        signature: Ed25519Signature([i as u8; 64]),
                    })
                    .collect();
                assert_codec_roundtrip(&header::Verdict {
                    report_hash: Hash(report_hash),
                    age,
                    judgments,
                });
            }

            #[test]
            fn ticket_proof_roundtrip(
                attempt in 0u8..4,
                proof_len in 0usize..100,
            ) {
                let proof = vec![42u8; proof_len];
                assert_codec_roundtrip(&header::TicketProof { attempt, proof });
            }

            #[test]
            fn assurance_roundtrip(
                anchor in proptest::array::uniform32(0u8..),
                bitfield_len in 0usize..50,
                validator_index in 0u16..1023,
                sig in proptest::collection::vec(0u8.., 64..=64),
            ) {
                let mut sig_arr = [0u8; 64];
                sig_arr.copy_from_slice(&sig);
                assert_codec_roundtrip(&header::Assurance {
                    anchor: Hash(anchor),
                    bitfield: vec![0xAA; bitfield_len],
                    validator_index,
                    signature: Ed25519Signature(sig_arr),
                });
            }

            #[test]
            fn header_roundtrip(
                parent in proptest::array::uniform32(0u8..),
                state_root in proptest::array::uniform32(0u8..),
                extrinsic_hash in proptest::array::uniform32(0u8..),
                timeslot in 0u32..100_000,
                author_index in 0u16..1023,
                fill_vrf in any::<u8>(),
                fill_seal in any::<u8>(),
                n_offenders in 0usize..3,
            ) {
                let offenders: Vec<Ed25519PublicKey> = (0..n_offenders)
                    .map(|i| Ed25519PublicKey([i as u8; 32]))
                    .collect();
                assert_codec_roundtrip(&header::Header {
                    data: header::UnsignedHeader {
                        parent_hash: Hash(parent),
                        state_root: Hash(state_root),
                        extrinsic_hash: Hash(extrinsic_hash),
                        timeslot,
                        epoch_marker: None,
                        tickets_marker: None,
                        author_index,
                        vrf_signature: BandersnatchSignature([fill_vrf; 96]),
                        offenders_marker: offenders,
                    },
                    seal: BandersnatchSignature([fill_seal; 96]),
                });
            }

            #[test]
            fn header_with_epoch_marker_roundtrip(
                parent in proptest::array::uniform32(0u8..),
                entropy in proptest::array::uniform32(0u8..),
                entropy_prev in proptest::array::uniform32(0u8..),
                timeslot in 0u32..100_000,
                n_validators in 0usize..5,
            ) {
                let validators: Vec<(BandersnatchPublicKey, Ed25519PublicKey)> = (0..n_validators)
                    .map(|i| (BandersnatchPublicKey([i as u8; 32]), Ed25519PublicKey([(i + 100) as u8; 32])))
                    .collect();
                assert_codec_roundtrip(&header::Header {
                    data: header::UnsignedHeader {
                        parent_hash: Hash(parent),
                        state_root: Hash::ZERO,
                        extrinsic_hash: Hash::ZERO,
                        timeslot,
                        epoch_marker: Some(header::EpochMarker {
                            entropy: Hash(entropy),
                            entropy_previous: Hash(entropy_prev),
                            validators,
                        }),
                        tickets_marker: None,
                        author_index: 0,
                        vrf_signature: BandersnatchSignature([0u8; 96]),
                        offenders_marker: vec![],
                    },
                    seal: BandersnatchSignature([0u8; 96]),
                });
            }

            #[test]
            fn refinement_context_roundtrip(
                anchor in proptest::array::uniform32(0u8..),
                state_root in proptest::array::uniform32(0u8..),
                beefy_root in proptest::array::uniform32(0u8..),
                lookup in proptest::array::uniform32(0u8..),
                lookup_ts in 0u32..100_000,
                n_prereqs in 0usize..4,
            ) {
                let prerequisites: Vec<Hash> = (0..n_prereqs)
                    .map(|i| Hash([i as u8; 32]))
                    .collect();
                assert_codec_roundtrip(&work::RefinementContext {
                    anchor: Hash(anchor),
                    state_root: Hash(state_root),
                    beefy_root: Hash(beefy_root),
                    lookup_anchor: Hash(lookup),
                    lookup_anchor_timeslot: lookup_ts,
                    prerequisites,
                });
            }

            #[test]
            fn work_item_roundtrip(
                service_id in any::<u32>(),
                code_hash in proptest::array::uniform32(0u8..),
                gas_limit in any::<u64>(),
                acc_gas in any::<u64>(),
                exports_count in any::<u16>(),
                payload_len in 0usize..50,
                n_imports in 0usize..4,
                n_extrinsics in 0usize..4,
            ) {
                let imports: Vec<work::ImportSegment> = (0..n_imports)
                    .map(|i| work::ImportSegment {
                        hash: Hash([i as u8; 32]),
                        index: i as u16,
                    })
                    .collect();
                let extrinsics: Vec<(Hash, u32)> = (0..n_extrinsics)
                    .map(|i| (Hash([i as u8; 32]), i as u32))
                    .collect();
                assert_codec_roundtrip(&work::WorkItem {
                    service_id,
                    code_hash: Hash(code_hash),
                    gas_limit,
                    accumulate_gas_limit: acc_gas,
                    exports_count,
                    payload: vec![0xAB; payload_len],
                    imports,
                    extrinsics,
                });
            }

            #[test]
            fn work_report_roundtrip(
                pkg_hash in proptest::array::uniform32(0u8..),
                bundle_len in any::<u32>(),
                erasure_root in proptest::array::uniform32(0u8..),
                exports_root in proptest::array::uniform32(0u8..),
                exports_count in any::<u16>(),
                core_index in 0u16..341,
                auth_hash in proptest::array::uniform32(0u8..),
                auth_gas in any::<u64>(),
                auth_out_len in 0usize..20,
                n_results in 0usize..3,
            ) {
                let results: Vec<work::WorkDigest> = (0..n_results)
                    .map(|i| work::WorkDigest {
                        service_id: i as u32,
                        code_hash: Hash([i as u8; 32]),
                        payload_hash: Hash([(i + 1) as u8; 32]),
                        accumulate_gas: 1000,
                        result: work::WorkResult::Ok(vec![i as u8]),
                        gas_used: 500,
                        imports_count: 0,
                        extrinsics_count: 0,
                        extrinsics_size: 0,
                        exports_count: 0,
                    })
                    .collect();
                assert_codec_roundtrip(&work::WorkReport {
                    package_spec: work::AvailabilitySpec {
                        package_hash: Hash(pkg_hash),
                        bundle_length: bundle_len,
                        erasure_root: Hash(erasure_root),
                        exports_root: Hash(exports_root),
                        exports_count,
                        ..Default::default()
                    },
                    core_index,
                    authorizer_hash: Hash(auth_hash),
                    auth_gas_used: auth_gas,
                    auth_output: vec![0xFF; auth_out_len],
                    results,
                    ..Default::default()
                });
            }

            #[test]
            fn work_package_roundtrip(
                auth_host in any::<u32>(),
                auth_hash in proptest::array::uniform32(0u8..),
                anchor in proptest::array::uniform32(0u8..),
                auth_len in 0usize..20,
                config_len in 0usize..20,
                n_items in 0usize..3,
            ) {
                let items: Vec<work::WorkItem> = (0..n_items)
                    .map(|i| work::WorkItem {
                        service_id: i as u32,
                        code_hash: Hash([i as u8; 32]),
                        gas_limit: 10_000,
                        accumulate_gas_limit: 5_000,
                        exports_count: 0,
                        payload: vec![i as u8; 10],
                        imports: vec![],
                        extrinsics: vec![],
                    })
                    .collect();
                assert_codec_roundtrip(&work::WorkPackage {
                    auth_code_host: auth_host,
                    auth_code_hash: Hash(auth_hash),
                    context: work::RefinementContext {
                        anchor: Hash(anchor),
                        ..Default::default()
                    },
                    authorization: vec![0xAA; auth_len],
                    authorizer_config: vec![0xBB; config_len],
                    items,
                });
            }

            #[test]
            fn guarantee_roundtrip(
                pkg_hash in proptest::array::uniform32(0u8..),
                core_index in 0u16..341,
                timeslot in 0u32..100_000,
                n_credentials in 0usize..5,
            ) {
                let credentials: Vec<(u16, Ed25519Signature)> = (0..n_credentials)
                    .map(|i| (i as u16, Ed25519Signature([i as u8; 64])))
                    .collect();
                assert_codec_roundtrip(&header::Guarantee {
                    report: work::WorkReport {
                        package_spec: work::AvailabilitySpec {
                            package_hash: Hash(pkg_hash),
                            bundle_length: 256,
                            ..Default::default()
                        },
                        core_index,
                        ..Default::default()
                    },
                    timeslot,
                    credentials,
                });
            }

            #[test]
            fn block_roundtrip(
                parent in proptest::array::uniform32(0u8..),
                timeslot in 1u32..100_000,
                author_index in 0u16..1023,
                n_preimages in 0usize..3,
            ) {
                let preimages: Vec<(ServiceId, Vec<u8>)> = (0..n_preimages)
                    .map(|i| (i as u32, vec![i as u8; 10]))
                    .collect();
                assert_codec_roundtrip(&header::Block {
                    header: header::Header {
                        data: header::UnsignedHeader {
                            parent_hash: Hash(parent),
                            state_root: Hash::ZERO,
                            extrinsic_hash: Hash::ZERO,
                            timeslot,
                            epoch_marker: None,
                            tickets_marker: None,
                            author_index,
                            vrf_signature: BandersnatchSignature([0u8; 96]),
                            offenders_marker: vec![],
                        },
                        seal: BandersnatchSignature([0u8; 96]),
                    },
                    extrinsic: header::Extrinsic {
                        tickets: vec![],
                        preimages,
                        guarantees: vec![],
                        assurances: vec![],
                        disputes: header::DisputesExtrinsic::default(),
                    },
                });
            }
        }
    }

    #[cfg(test)]
    mod signing_context_tests {
        use super::signing_contexts::*;

        #[test]
        fn test_build_judgment_message_valid() {
            let hash = [0xAA; 32];
            let msg = build_judgment_message(true, &hash);
            assert!(msg.starts_with(b"jam_valid"));
            assert_eq!(&msg[VALID.len()..], &hash);
            assert_eq!(msg.len(), VALID.len() + 32);
        }

        #[test]
        fn test_build_judgment_message_invalid() {
            let hash = [0xBB; 32];
            let msg = build_judgment_message(false, &hash);
            assert!(msg.starts_with(b"jam_invalid"));
            assert_eq!(&msg[INVALID.len()..], &hash);
            assert_eq!(msg.len(), INVALID.len() + 32);
        }

        #[test]
        fn test_build_guarantee_message() {
            let hash = [0xCC; 32];
            let msg = build_guarantee_message(&hash);
            assert!(msg.starts_with(b"jam_guarantee"));
            assert_eq!(&msg[GUARANTEE.len()..], &hash);
            assert_eq!(msg.len(), GUARANTEE.len() + 32);
        }

        #[test]
        fn test_signing_context_strings() {
            assert_eq!(AVAILABLE, b"jam_available");
            assert_eq!(BEEFY, b"jam_beefy");
            assert_eq!(ENTROPY, b"jam_entropy");
            assert_eq!(FALLBACK_SEAL, b"jam_fallback_seal");
            assert_eq!(GUARANTEE, b"jam_guarantee");
            assert_eq!(TICKET_SEAL, b"jam_ticket_seal");
            assert_eq!(PREVOTE, b"jam_prevote");
            assert_eq!(PRECOMMIT, b"jam_precommit");
        }
    }

    #[cfg(test)]
    mod hex_tests {
        use super::*;

        #[test]
        fn test_decode_hex_with_prefix() {
            let result = decode_hex("0xdeadbeef").unwrap();
            assert_eq!(result, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        }

        #[test]
        fn test_decode_hex_without_prefix() {
            let result = decode_hex("cafebabe").unwrap();
            assert_eq!(result, vec![0xCA, 0xFE, 0xBA, 0xBE]);
        }

        #[test]
        fn test_decode_hex_empty() {
            assert_eq!(decode_hex("").unwrap(), Vec::<u8>::new());
            assert_eq!(decode_hex("0x").unwrap(), Vec::<u8>::new());
        }

        #[test]
        fn test_decode_hex_invalid() {
            assert!(decode_hex("0xGG").is_err());
            assert!(decode_hex("not_hex").is_err());
        }

        #[test]
        fn test_decode_hex_fixed_32() {
            let hex = "0x".to_string() + &"aa".repeat(32);
            let result: [u8; 32] = decode_hex_fixed(&hex).unwrap();
            assert_eq!(result, [0xAA; 32]);
        }

        #[test]
        fn test_decode_hex_fixed_wrong_length() {
            let err = decode_hex_fixed::<32>("0xaabb").unwrap_err();
            assert!(err.contains("expected 32 bytes"));
        }

        #[test]
        fn test_decode_hex_fixed_invalid_hex() {
            assert!(decode_hex_fixed::<4>("0xZZZZ").is_err());
        }
    }
}
