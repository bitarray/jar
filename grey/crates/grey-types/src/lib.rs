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

    /// §17 equivocation evidence countersignature context.
    pub const EQUIVOCATION_EVIDENCE: &[u8] = b"jam:equivocation_evidence";

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

/// Proptest strategies and test utilities.
///
/// Enable with the `testing` feature flag. Other crates should add
/// `grey-types = { workspace = true, features = ["testing"] }` to their
/// **dev-dependencies** to use these helpers in tests.
#[cfg(feature = "testing")]
pub mod testing {
    use crate::Hash;
    use proptest::prop_compose;

    // Strategy for generating an arbitrary Hash.
    //
    // Usage: `use grey_types::testing::arb_hash;`
    //        `proptest! { | h in arb_hash() | { ... } }`
    prop_compose! {
        pub fn arb_hash()(bytes in proptest::array::uniform32(proptest::arbitrary::any::<u8>())) -> Hash {
            Hash(bytes)
        }
    }
}

/// Shared to_hex, from_hex and Deserialize for all crypto types.
macro_rules! impl_crypto_common {
    ($name:ident, $debug_name:expr) => {
        impl $name {
            /// Encode the inner bytes as a bare hex string (no `0x` prefix).
            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }
            /// Parse from a hex string (with optional 0x prefix). Panics on invalid input.
            pub fn from_hex(s: &str) -> Self {
                Self(decode_hex_fixed(s).expect(concat!("invalid hex for ", $debug_name)))
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

/// Implement Debug (with truncation), Deserialize, and Default (for large arrays) for crypto types.
macro_rules! impl_crypto_type {
    // Fixed-size array with Copy — full hex in Debug
    ($name:ident, $size:expr, copy, $debug_name:expr) => {
        impl_crypto_common!($name, $debug_name);
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", $debug_name, self.to_hex())
            }
        }
    };
    // Large array — truncated Debug, manual Default
    ($name:ident, $size:expr, large, $debug_name:expr) => {
        impl_crypto_common!($name, $debug_name);
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

    /// Encode the inner bytes as a bare hex string (no `0x` prefix).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Encode the first 8 bytes as a hex string for log/debug output.
    pub fn short_hex(&self) -> String {
        hex::encode(&self.0[..8])
    }

    /// Parse from a hex string (with optional 0x prefix). Panics on invalid input.
    pub fn from_hex(s: &str) -> Self {
        Self(decode_hex_fixed(s).expect("invalid hex for Hash"))
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", self.to_hex())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", self.to_hex())
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
        s.serialize_str(&format!("0x{}", self.to_hex()))
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

/// Evidence of a same-slot block equivocation, broadcast via §17.
///
/// Both `block_a` and `block_b` exist at `slot` — the same Safrole-designated
/// author signed both. Validators countersign this to build quorum evidence.
#[derive(Debug, Clone, PartialEq, Eq, scale::Encode, scale::Decode)]
pub struct EquivocationEvidence {
    /// The slot at which the equivocation occurred.
    pub slot: Timeslot,
    /// One of the two conflicting block hashes (the lesser hash).
    pub block_a: Hash,
    /// The other conflicting block hash (the greater hash).
    pub block_b: Hash,
}

impl EquivocationEvidence {
    /// Canonical bytes to sign: slot LE32 ++ block_a ++ block_b
    /// block_a < block_b is enforced by the constructor.
    pub fn sign_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(68);
        bytes.extend_from_slice(&self.slot.to_le_bytes());
        bytes.extend_from_slice(&self.block_a.0);
        bytes.extend_from_slice(&self.block_b.0);
        bytes
    }

    /// Build the full signing message: `EQUIVOCATION_EVIDENCE` context ⌢ `sign_bytes()`.
    ///
    /// Ready for ed25519 sign or verify — no need to manually prepend the context.
    pub fn signing_message(&self) -> Vec<u8> {
        let ctx = signing_contexts::EQUIVOCATION_EVIDENCE;
        let payload = self.sign_bytes();
        let mut msg = Vec::with_capacity(ctx.len() + payload.len());
        msg.extend_from_slice(ctx);
        msg.extend_from_slice(&payload);
        msg
    }

    /// Create evidence, normalising so block_a < block_b.
    pub fn new(slot: Timeslot, h1: Hash, h2: Hash) -> Self {
        let (block_a, block_b) = if h1 < h2 { (h1, h2) } else { (h2, h1) };
        Self {
            slot,
            block_a,
            block_b,
        }
    }
}

/// A validator's countersignature on equivocation evidence.
#[derive(Debug, Clone, PartialEq, Eq, scale::Encode, scale::Decode)]
pub struct EquivocationCountersig {
    pub evidence: EquivocationEvidence,
    pub validator_index: ValidatorIndex,
    pub signature: Ed25519Signature,
}

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
    fn test_hash_short_hex() {
        let h = Hash([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]);
        assert_eq!(h.short_hex(), "0123456789abcdef");
        assert_eq!(h.short_hex().len(), 16); // 8 bytes = 16 hex chars

        // Zero hash
        assert_eq!(Hash::ZERO.short_hex(), "0000000000000000");
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

            #[test]
            fn equivocation_evidence_roundtrip(
                slot in 0u32..100_000,
                block_a in proptest::array::uniform32(0u8..),
                block_b in proptest::array::uniform32(0u8..),
            ) {
                // Ensure block_a < block_b for canonical ordering.
                let (a, b) = if block_a <= block_b {
                    (block_a, block_b)
                } else {
                    (block_b, block_a)
                };
                assert_codec_roundtrip(&EquivocationEvidence {
                    slot,
                    block_a: Hash(a),
                    block_b: Hash(b),
                });
            }

            #[test]
            fn equivocation_countersig_roundtrip(
                slot in 0u32..100_000,
                block_a in proptest::array::uniform32(0u8..),
                block_b in proptest::array::uniform32(0u8..),
                validator_index in 0u16..1023,
                sig in proptest::collection::vec(0u8.., 64..=64),
            ) {
                let (a, b) = if block_a <= block_b {
                    (block_a, block_b)
                } else {
                    (block_b, block_a)
                };
                let mut sig_arr = [0u8; 64];
                sig_arr.copy_from_slice(&sig);
                assert_codec_roundtrip(&EquivocationCountersig {
                    evidence: EquivocationEvidence {
                        slot,
                        block_a: Hash(a),
                        block_b: Hash(b),
                    },
                    validator_index,
                    signature: Ed25519Signature(sig_arr),
                });
            }

            #[test]
            fn culprit_roundtrip(
                report_hash in proptest::array::uniform32(0u8..),
                key in proptest::array::uniform32(0u8..),
                sig in proptest::collection::vec(0u8.., 64..=64),
            ) {
                let mut sig_arr = [0u8; 64];
                sig_arr.copy_from_slice(&sig);
                assert_codec_roundtrip(&header::Culprit {
                    report_hash: Hash(report_hash),
                    validator_key: Ed25519PublicKey(key),
                    signature: Ed25519Signature(sig_arr),
                });
            }

            #[test]
            fn fault_roundtrip(
                report_hash in proptest::array::uniform32(0u8..),
                is_valid: bool,
                key in proptest::array::uniform32(0u8..),
                sig in proptest::collection::vec(0u8.., 64..=64),
            ) {
                let mut sig_arr = [0u8; 64];
                sig_arr.copy_from_slice(&sig);
                assert_codec_roundtrip(&header::Fault {
                    report_hash: Hash(report_hash),
                    is_valid,
                    validator_key: Ed25519PublicKey(key),
                    signature: Ed25519Signature(sig_arr),
                });
            }

            #[test]
            fn disputes_extrinsic_roundtrip(
                n_verdicts in 0usize..3,
                n_culprits in 0usize..3,
                n_faults in 0usize..3,
            ) {
                let verdicts: Vec<header::Verdict> = (0..n_verdicts)
                    .map(|i| header::Verdict {
                        report_hash: Hash([i as u8; 32]),
                        age: i as u32,
                        judgments: vec![header::Judgment {
                            validator_index: i as u16,
                            is_valid: true,
                            signature: Ed25519Signature([i as u8; 64]),
                        }],
                    })
                    .collect();
                let culprits: Vec<header::Culprit> = (0..n_culprits)
                    .map(|i| header::Culprit {
                        report_hash: Hash([(i + 10) as u8; 32]),
                        validator_key: Ed25519PublicKey([(i + 20) as u8; 32]),
                        signature: Ed25519Signature([(i + 30) as u8; 64]),
                    })
                    .collect();
                let faults: Vec<header::Fault> = (0..n_faults)
                    .map(|i| header::Fault {
                        report_hash: Hash([(i + 40) as u8; 32]),
                        is_valid: i % 2 == 0,
                        validator_key: Ed25519PublicKey([(i + 50) as u8; 32]),
                        signature: Ed25519Signature([(i + 60) as u8; 64]),
                    })
                    .collect();
                assert_codec_roundtrip(&header::DisputesExtrinsic {
                    verdicts,
                    culprits,
                    faults,
                });
            }

            #[test]
            fn validator_record_roundtrip(
                blocks in any::<u32>(),
                tickets in any::<u32>(),
                preimages in any::<u32>(),
                preimage_bytes in any::<u64>(),
                guarantees in any::<u32>(),
                assurances in any::<u32>(),
            ) {
                assert_codec_roundtrip(&state::ValidatorRecord {
                    blocks_produced: blocks,
                    tickets_introduced: tickets,
                    preimages_introduced: preimages,
                    preimage_bytes,
                    reports_guaranteed: guarantees,
                    assurances_made: assurances,
                });
            }

            #[test]
            fn core_statistics_roundtrip(
                da_load in any::<u64>(),
                popularity in any::<u64>(),
                imports in any::<u64>(),
                extrinsic_count in any::<u64>(),
                extrinsic_size in any::<u64>(),
                exports in any::<u64>(),
                bundle_size in any::<u64>(),
                gas_used in any::<u64>(),
            ) {
                assert_codec_roundtrip(&state::CoreStatistics {
                    da_load,
                    popularity,
                    imports,
                    extrinsic_count,
                    extrinsic_size,
                    exports,
                    bundle_size,
                    gas_used,
                });
            }

            #[test]
            fn service_statistics_roundtrip(
                provided_count in any::<u64>(),
                provided_size in any::<u64>(),
                refinement_count in any::<u64>(),
                refinement_gas_used in any::<u64>(),
                imports in any::<u64>(),
                extrinsic_count in any::<u64>(),
                extrinsic_size in any::<u64>(),
                exports in any::<u64>(),
                accumulate_count in any::<u64>(),
                accumulate_gas_used in any::<u64>(),
            ) {
                assert_codec_roundtrip(&state::ServiceStatistics {
                    provided_count,
                    provided_size,
                    refinement_count,
                    refinement_gas_used,
                    imports,
                    extrinsic_count,
                    extrinsic_size,
                    exports,
                    accumulate_count,
                    accumulate_gas_used,
                });
            }

            #[test]
            fn recent_block_info_roundtrip(
                header_hash in proptest::array::uniform32(0u8..),
                state_root in proptest::array::uniform32(0u8..),
                acc_root in proptest::array::uniform32(0u8..),
                n_packages in 0usize..4,
            ) {
                let reported_packages: std::collections::BTreeMap<Hash, Hash> = (0..n_packages)
                    .map(|i| (Hash([(i as u8).wrapping_add(1); 32]), Hash([(i as u8).wrapping_add(100); 32])))
                    .collect();
                assert_codec_roundtrip(&state::RecentBlockInfo {
                    header_hash: Hash(header_hash),
                    state_root: Hash(state_root),
                    accumulation_root: Hash(acc_root),
                    reported_packages,
                });
            }

            #[test]
            fn seal_key_series_tickets_roundtrip(
                n_tickets in 0usize..5,
            ) {
                let tickets: Vec<header::Ticket> = (0..n_tickets)
                    .map(|i| header::Ticket {
                        id: Hash([i as u8; 32]),
                        attempt: (i % 4) as u8,
                    })
                    .collect();
                assert_codec_roundtrip(&state::SealKeySeries::Tickets(tickets));
            }

            #[test]
            fn seal_key_series_fallback_roundtrip(
                n_keys in 0usize..5,
            ) {
                let keys: Vec<BandersnatchPublicKey> = (0..n_keys)
                    .map(|i| BandersnatchPublicKey([i as u8; 32]))
                    .collect();
                assert_codec_roundtrip(&state::SealKeySeries::Fallback(keys));
            }

            #[test]
            fn recent_blocks_roundtrip(
                n_headers in 0usize..3,
                n_log in 0usize..5,
            ) {
                let headers: Vec<state::RecentBlockInfo> = (0..n_headers)
                    .map(|i| state::RecentBlockInfo {
                        header_hash: Hash([i as u8; 32]),
                        state_root: Hash([(i + 10) as u8; 32]),
                        accumulation_root: Hash([(i + 20) as u8; 32]),
                        reported_packages: std::collections::BTreeMap::new(),
                    })
                    .collect();
                let accumulation_log: Vec<Option<Hash>> = (0..n_log)
                    .map(|i| if i % 2 == 0 { Some(Hash([i as u8; 32])) } else { None })
                    .collect();
                assert_codec_roundtrip(&state::RecentBlocks {
                    headers,
                    accumulation_log,
                });
            }

            #[test]
            fn privileged_services_roundtrip(
                manager in any::<u32>(),
                designator in any::<u32>(),
                registrar in any::<u32>(),
                quota_service in any::<u32>(),
                n_assigners in 0usize..5,
                n_always in 0usize..4,
            ) {
                let assigner: Vec<u32> = (0..n_assigners).map(|i| 100 + i as u32).collect();
                let always_accumulate: std::collections::BTreeMap<u32, u64> = (0..n_always)
                    .map(|i| (200 + i as u32, 1000 * (i as u64 + 1)))
                    .collect();
                assert_codec_roundtrip(&state::PrivilegedServices {
                    manager,
                    assigner,
                    designator,
                    registrar,
                    always_accumulate,
                    quota_service,
                });
            }

            #[test]
            fn judgments_roundtrip(
                n_good in 0usize..4,
                n_bad in 0usize..4,
                n_wonky in 0usize..4,
                n_offenders in 0usize..4,
            ) {
                let good = (0..n_good).map(|i| Hash([i as u8; 32])).collect();
                let bad = (0..n_bad).map(|i| Hash([(i + 50) as u8; 32])).collect();
                let wonky = (0..n_wonky).map(|i| Hash([(i + 100) as u8; 32])).collect();
                let offenders = (0..n_offenders)
                    .map(|i| Ed25519PublicKey([(i + 150) as u8; 32]))
                    .collect();
                assert_codec_roundtrip(&state::Judgments {
                    good,
                    bad,
                    wonky,
                    offenders,
                });
            }

            #[test]
            fn pending_report_roundtrip(
                timeslot in any::<u32>(),
                core_index in any::<u16>(),
                auth_hash in proptest::array::uniform32(0u8..),
            ) {
                use work::*;
                assert_codec_roundtrip(&state::PendingReport {
                    report: WorkReport {
                        core_index,
                        authorizer_hash: Hash(auth_hash),
                        ..WorkReport::default()
                    },
                    timeslot,
                });
            }

            #[test]
            fn safrole_state_roundtrip(
                n_pending in 0usize..3,
                n_tickets in 0usize..4,
                use_fallback in proptest::bool::ANY,
                ring_root_bytes in proptest::collection::vec(0u8.., 144..=144),
            ) {
                let pending_keys: Vec<validator::ValidatorKey> = (0..n_pending)
                    .map(|i| validator::ValidatorKey {
                        bandersnatch: BandersnatchPublicKey([i as u8; 32]),
                        ed25519: Ed25519PublicKey([(i + 10) as u8; 32]),
                        bls: BlsPublicKey({
                            let mut b = [0u8; 144];
                            b[0] = (i + 20) as u8;
                            b
                        }),
                        metadata: [(i + 30) as u8; 128],
                    })
                    .collect();
                let seal_key_series = if use_fallback {
                    state::SealKeySeries::Fallback(
                        (0..n_tickets).map(|i| BandersnatchPublicKey([i as u8; 32])).collect()
                    )
                } else {
                    state::SealKeySeries::Tickets(
                        (0..n_tickets).map(|i| header::Ticket {
                            id: Hash([i as u8; 32]),
                            attempt: (i % 4) as u8,
                        }).collect()
                    )
                };
                let ticket_accumulator: Vec<header::Ticket> = (0..n_tickets)
                    .map(|i| header::Ticket {
                        id: Hash([(i + 50) as u8; 32]),
                        attempt: (i % 4) as u8,
                    })
                    .collect();
                let mut ring_root = [0u8; 144];
                ring_root.copy_from_slice(&ring_root_bytes);
                assert_codec_roundtrip(&state::SafroleState {
                    pending_keys,
                    ring_root: BandersnatchRingRoot(ring_root),
                    seal_key_series,
                    ticket_accumulator,
                });
            }

            #[test]
            fn validator_statistics_roundtrip(
                n_validators in 0usize..4,
                n_cores in 0usize..3,
                n_services in 0usize..3,
            ) {
                let make_record = |i: usize| state::ValidatorRecord {
                    blocks_produced: i as u32,
                    tickets_introduced: (i * 2) as u32,
                    preimages_introduced: (i * 3) as u32,
                    preimage_bytes: (i * 100) as u64,
                    reports_guaranteed: (i * 4) as u32,
                    assurances_made: (i * 5) as u32,
                };
                let current: Vec<state::ValidatorRecord> = (0..n_validators).map(make_record).collect();
                let last: Vec<state::ValidatorRecord> = (0..n_validators).map(|i| make_record(i + 10)).collect();
                let core_stats: Vec<state::CoreStatistics> = (0..n_cores)
                    .map(|i| state::CoreStatistics {
                        da_load: i as u64 * 1000,
                        popularity: i as u64,
                        imports: i as u64 * 10,
                        extrinsic_count: i as u64 * 5,
                        extrinsic_size: i as u64 * 200,
                        exports: i as u64 * 3,
                        bundle_size: i as u64 * 500,
                        gas_used: i as u64 * 10000,
                    })
                    .collect();
                let service_stats: std::collections::BTreeMap<u32, state::ServiceStatistics> = (0..n_services)
                    .map(|i| (i as u32, state::ServiceStatistics {
                        provided_count: i as u64,
                        provided_size: i as u64 * 100,
                        refinement_count: i as u64 * 2,
                        refinement_gas_used: i as u64 * 5000,
                        imports: i as u64,
                        extrinsic_count: i as u64,
                        extrinsic_size: i as u64 * 50,
                        exports: i as u64,
                        accumulate_count: i as u64,
                        accumulate_gas_used: i as u64 * 3000,
                    }))
                    .collect();
                assert_codec_roundtrip(&state::ValidatorStatistics {
                    current,
                    last,
                    core_stats,
                    service_stats,
                });
            }

            #[test]
            fn work_result_all_variants_roundtrip(
                payload_len in 0usize..50,
                variant in 0u8..6,
            ) {
                let result = match variant {
                    0 => work::WorkResult::Ok(vec![0xAB; payload_len]),
                    1 => work::WorkResult::OutOfGas,
                    2 => work::WorkResult::Panic,
                    3 => work::WorkResult::BadExports,
                    4 => work::WorkResult::BadCode,
                    _ => work::WorkResult::CodeOversize,
                };
                assert_codec_roundtrip(&result);
            }

            #[test]
            fn work_digest_roundtrip(
                service_id in any::<u32>(),
                code_hash in proptest::array::uniform32(0u8..),
                payload_hash in proptest::array::uniform32(0u8..),
                acc_gas in any::<u64>(),
                gas_used in any::<u64>(),
                imports in any::<u16>(),
                ext_count in any::<u16>(),
                ext_size in any::<u32>(),
                exports in any::<u16>(),
                result_variant in 0u8..6,
            ) {
                let result = match result_variant {
                    0 => work::WorkResult::Ok(vec![0xFF; 10]),
                    1 => work::WorkResult::OutOfGas,
                    2 => work::WorkResult::Panic,
                    3 => work::WorkResult::BadExports,
                    4 => work::WorkResult::BadCode,
                    _ => work::WorkResult::CodeOversize,
                };
                assert_codec_roundtrip(&work::WorkDigest {
                    service_id,
                    code_hash: Hash(code_hash),
                    payload_hash: Hash(payload_hash),
                    accumulate_gas: acc_gas,
                    result,
                    gas_used,
                    imports_count: imports,
                    extrinsics_count: ext_count,
                    extrinsics_size: ext_size,
                    exports_count: exports,
                });
            }

            #[test]
            fn availability_spec_roundtrip(
                pkg_hash in proptest::array::uniform32(0u8..),
                bundle_len in any::<u32>(),
                erasure_root in proptest::array::uniform32(0u8..),
                exports_root in proptest::array::uniform32(0u8..),
                exports_count in any::<u16>(),
            ) {
                assert_codec_roundtrip(&work::AvailabilitySpec {
                    package_hash: Hash(pkg_hash),
                    bundle_length: bundle_len,
                    erasure_root: Hash(erasure_root),
                    exports_root: Hash(exports_root),
                    exports_count,
                    ..Default::default()
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
