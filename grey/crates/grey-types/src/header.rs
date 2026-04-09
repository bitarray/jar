//! Block header types (Section 5 of the Gray Paper).

use crate::{
    BandersnatchPublicKey, BandersnatchSignature, Ed25519PublicKey, Hash, Timeslot, ValidatorIndex,
};

/// Unsigned header data EU(H) — everything except the seal (eq C.23).
///
/// This is the data that gets signed by the block author.
#[derive(Clone, Debug, scale::Encode, scale::Decode)]
pub struct UnsignedHeader {
    /// HP: Parent header hash.
    pub parent_hash: Hash,

    /// HR: Prior state root.
    pub state_root: Hash,

    /// HX: Extrinsic hash (Merkle commitment).
    pub extrinsic_hash: Hash,

    /// HT: Timeslot index.
    pub timeslot: Timeslot,

    /// HE: Epoch marker (optional).
    pub epoch_marker: Option<EpochMarker>,

    /// HW: Tickets marker (optional, TicketsMark in ASN).
    pub tickets_marker: Option<Vec<Ticket>>,

    /// HI: Block author index into the validator set.
    pub author_index: ValidatorIndex,

    /// HV: Entropy-yielding VRF signature.
    pub vrf_signature: BandersnatchSignature,

    /// HO: Offenders marker — Ed25519 keys of misbehaving validators.
    pub offenders_marker: Vec<Ed25519PublicKey>,
}

/// Block header H (eq 5.1).
///
/// H ≡ (EU(H), HS) = unsigned header data + seal signature.
#[derive(Clone, Debug, scale::Encode, scale::Decode)]
pub struct Header {
    /// Unsigned header data (all fields except seal).
    pub data: UnsignedHeader,

    /// HS: Block seal signature.
    pub seal: BandersnatchSignature,
}

/// Deref to UnsignedHeader so `header.parent_hash` etc. work directly.
impl std::ops::Deref for Header {
    type Target = UnsignedHeader;
    fn deref(&self) -> &UnsignedHeader {
        &self.data
    }
}

impl std::ops::DerefMut for Header {
    fn deref_mut(&mut self) -> &mut UnsignedHeader {
        &mut self.data
    }
}

/// Epoch marker (eq 6.27).
/// Contains next and current epoch randomness plus validator keys for the next epoch.
#[derive(Clone, Debug, scale::Encode, scale::Decode)]
pub struct EpochMarker {
    /// Next epoch randomness (η₀).
    pub entropy: Hash,

    /// Current epoch randomness (η₁).
    pub entropy_previous: Hash,

    /// Validator Bandersnatch + Ed25519 key pairs for next epoch.
    pub validators: Vec<(BandersnatchPublicKey, Ed25519PublicKey)>,
}

/// A seal-key ticket body (TicketBody in ASN, eq 6.6).
/// Combination of a verifiably random identifier and attempt number.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, scale::Encode, scale::Decode)]
pub struct Ticket {
    /// y: Ticket identifier (VRF output hash).
    pub id: Hash,

    /// a: Attempt number (U8 in ASN, ∈ N_N where N = 2).
    pub attempt: u8,
}

/// Block B ≡ (H, E) (eq 4.2).
#[derive(Clone, Debug, scale::Encode, scale::Decode)]
pub struct Block {
    pub header: Header,
    pub extrinsic: Extrinsic,
}

/// Extrinsic data (Extrinsic in ASN, eq 4.3).
/// Field ordering matches ASN: tickets, preimages, guarantees, assurances, disputes.
#[derive(Clone, Debug, Default, scale::Encode, scale::Decode)]
pub struct Extrinsic {
    /// ET: Tickets for seal-key contest.
    pub tickets: TicketsExtrinsic,

    /// EP: Preimage lookups.
    pub preimages: PreimagesExtrinsic,

    /// EG: Work report guarantees.
    pub guarantees: GuaranteesExtrinsic,

    /// EA: Availability assurances.
    pub assurances: AssurancesExtrinsic,

    /// ED: Dispute information.
    pub disputes: DisputesExtrinsic,
}

/// Tickets extrinsic ET (eq 6.29).
pub type TicketsExtrinsic = Vec<TicketProof>;

/// A ticket envelope (TicketEnvelope in ASN): attempt + Ring VRF signature.
#[derive(Clone, Debug, scale::Encode, scale::Decode)]
pub struct TicketProof {
    /// Attempt number (U8 in ASN).
    pub attempt: u8,
    /// Ring VRF signature (784 bytes in ASN).
    pub proof: Vec<u8>,
}

/// Disputes extrinsic ED (Section 10).
#[derive(Clone, Debug, Default, scale::Encode, scale::Decode)]
pub struct DisputesExtrinsic {
    /// Verdicts: (report_hash, judgment_count) pairs.
    pub verdicts: Vec<Verdict>,
    /// Culprits: validators who guaranteed an invalid report.
    pub culprits: Vec<Culprit>,
    /// Faults: validators who made an incorrect judgment.
    pub faults: Vec<Fault>,
}

/// A verdict on a work-report.
#[derive(Clone, Debug, scale::Encode, scale::Decode)]
pub struct Verdict {
    pub report_hash: Hash,
    pub age: u32,
    pub judgments: Vec<Judgment>,
}

impl Verdict {
    /// Count of judgments voting `is_valid == true`.
    pub fn positive_count(&self) -> usize {
        self.judgments.iter().filter(|j| j.is_valid).count()
    }
}

/// A single judgment: (validator Ed25519 key, validator index, signature).
#[derive(Clone, Debug, scale::Encode, scale::Decode)]
pub struct Judgment {
    pub is_valid: bool,
    pub validator_index: ValidatorIndex,
    pub signature: crate::Ed25519Signature,
}

/// A culprit: a validator who guaranteed an invalid report.
/// ASN field order: target, key, signature.
#[derive(Clone, Debug, scale::Encode, scale::Decode)]
pub struct Culprit {
    pub report_hash: Hash,
    pub validator_key: Ed25519PublicKey,
    pub signature: crate::Ed25519Signature,
}

/// A fault: a validator who made an incorrect judgment.
/// ASN field order: target, vote, key, signature.
#[derive(Clone, Debug, scale::Encode, scale::Decode)]
pub struct Fault {
    pub report_hash: Hash,
    pub is_valid: bool,
    pub validator_key: Ed25519PublicKey,
    pub signature: crate::Ed25519Signature,
}

/// Preimages extrinsic EP (eq 12.35).
pub type PreimagesExtrinsic = Vec<(crate::ServiceId, Vec<u8>)>;

/// Assurances extrinsic EA (eq 11.10).
pub type AssurancesExtrinsic = Vec<Assurance>;

/// A single availability assurance (AvailAssurance in ASN).
#[derive(Clone, Debug, scale::Encode, scale::Decode)]
pub struct Assurance {
    /// Anchor (parent hash).
    pub anchor: Hash,
    /// Bitfield: raw bytes, one bit per core.
    pub bitfield: Vec<u8>,
    /// Validator index.
    pub validator_index: ValidatorIndex,
    /// Signature.
    pub signature: crate::Ed25519Signature,
}

impl Assurance {
    /// Check if the bitfield has the bit set for a given core index.
    pub fn has_bit(&self, core: usize) -> bool {
        let byte_idx = core / 8;
        let bit_idx = core % 8;
        byte_idx < self.bitfield.len() && (self.bitfield[byte_idx] & (1 << bit_idx)) != 0
    }
}

/// Guarantees extrinsic EG (eq 11.23).
pub type GuaranteesExtrinsic = Vec<Guarantee>;

/// A single guarantee.
#[derive(Clone, Debug, scale::Encode, scale::Decode)]
pub struct Guarantee {
    /// The work report.
    pub report: crate::work::WorkReport,
    /// Timeslot at which the guarantee was made.
    pub timeslot: Timeslot,
    /// Credentials: (validator_index, signature) pairs.
    pub credentials: Vec<(ValidatorIndex, crate::Ed25519Signature)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::assert_codec_roundtrip;
    use crate::{BandersnatchSignature, Ed25519Signature, Hash};

    #[test]
    fn test_ticket_roundtrip() {
        assert_codec_roundtrip(&Ticket {
            id: Hash([0xAA; 32]),
            attempt: 3,
        });
    }

    #[test]
    fn test_epoch_marker_roundtrip() {
        assert_codec_roundtrip(&EpochMarker {
            entropy: Hash([1u8; 32]),
            entropy_previous: Hash([2u8; 32]),
            validators: vec![(
                crate::BandersnatchPublicKey([3u8; 32]),
                crate::Ed25519PublicKey([4u8; 32]),
            )],
        });
    }

    #[test]
    fn test_assurance_roundtrip() {
        assert_codec_roundtrip(&Assurance {
            anchor: Hash([10u8; 32]),
            bitfield: vec![0b11110000],
            validator_index: 5,
            signature: Ed25519Signature([0xBB; 64]),
        });
    }

    #[test]
    fn test_verdict_roundtrip() {
        assert_codec_roundtrip(&Verdict {
            report_hash: Hash([1u8; 32]),
            age: 42,
            judgments: vec![Judgment {
                is_valid: true,
                validator_index: 3,
                signature: Ed25519Signature([0xCC; 64]),
            }],
        });
    }

    #[test]
    fn test_header_roundtrip() {
        assert_codec_roundtrip(&Header {
            data: UnsignedHeader {
                parent_hash: Hash([1u8; 32]),
                state_root: Hash([2u8; 32]),
                extrinsic_hash: Hash([3u8; 32]),
                timeslot: 100,
                epoch_marker: None,
                tickets_marker: None,
                author_index: 5,
                vrf_signature: BandersnatchSignature([4u8; 96]),
                offenders_marker: vec![],
            },
            seal: BandersnatchSignature([5u8; 96]),
        });
    }

    #[test]
    fn test_block_roundtrip() {
        assert_codec_roundtrip(&Block {
            header: Header {
                data: UnsignedHeader {
                    parent_hash: Hash([1u8; 32]),
                    state_root: Hash([2u8; 32]),
                    extrinsic_hash: Hash([3u8; 32]),
                    timeslot: 1,
                    epoch_marker: None,
                    tickets_marker: None,
                    author_index: 0,
                    vrf_signature: BandersnatchSignature([0u8; 96]),
                    offenders_marker: vec![],
                },
                seal: BandersnatchSignature([0u8; 96]),
            },
            extrinsic: Extrinsic::default(),
        });
    }
}
