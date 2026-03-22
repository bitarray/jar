//! Block header types (Section 5 of the Gray Paper).

use crate::{
    BandersnatchPublicKey, BandersnatchSignature, Ed25519PublicKey, Hash, Timeslot, ValidatorIndex,
};

/// Block header H (eq 5.1).
///
/// H ≡ (HP, HR, HX, HT, HE, HW, HO, HI, HV, HS)
#[derive(Clone, Debug)]
pub struct Header {
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

    /// HS: Block seal signature.
    pub seal: BandersnatchSignature,
}

/// Epoch marker (eq 6.27).
/// Contains next and current epoch randomness plus validator keys for the next epoch.
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
pub struct Ticket {
    /// y: Ticket identifier (VRF output hash).
    pub id: Hash,

    /// a: Attempt number (U8 in ASN, ∈ N_N where N = 2).
    pub attempt: u8,
}

/// Block B ≡ (H, E) (eq 4.2).
#[derive(Clone, Debug)]
pub struct Block {
    pub header: Header,
    pub extrinsic: Extrinsic,
}

/// Extrinsic data (Extrinsic in ASN, eq 4.3).
/// Field ordering matches ASN: tickets, preimages, guarantees, assurances, disputes.
#[derive(Clone, Debug, Default)]
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
#[derive(Clone, Debug)]
pub struct TicketProof {
    /// Attempt number (U8 in ASN).
    pub attempt: u8,
    /// Ring VRF signature (784 bytes in ASN).
    pub proof: Vec<u8>,
}

/// Disputes extrinsic ED (Section 10).
#[derive(Clone, Debug, Default)]
pub struct DisputesExtrinsic {
    /// Verdicts: (report_hash, judgment_count) pairs.
    pub verdicts: Vec<Verdict>,
    /// Culprits: validators who guaranteed an invalid report.
    pub culprits: Vec<Culprit>,
    /// Faults: validators who made an incorrect judgment.
    pub faults: Vec<Fault>,
}

/// A verdict on a work-report.
#[derive(Clone, Debug)]
pub struct Verdict {
    pub report_hash: Hash,
    pub age: u32,
    pub judgments: Vec<Judgment>,
}

/// A single judgment: (validator Ed25519 key, validator index, signature).
#[derive(Clone, Debug)]
pub struct Judgment {
    pub is_valid: bool,
    pub validator_index: ValidatorIndex,
    pub signature: crate::Ed25519Signature,
}

/// A culprit: a validator who guaranteed an invalid report.
/// ASN field order: target, key, signature.
#[derive(Clone, Debug)]
pub struct Culprit {
    pub report_hash: Hash,
    pub validator_key: Ed25519PublicKey,
    pub signature: crate::Ed25519Signature,
}

/// A fault: a validator who made an incorrect judgment.
/// ASN field order: target, vote, key, signature.
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]
pub struct Assurance {
    /// Anchor (parent hash).
    pub anchor: Hash,
    /// Bitfield: raw bytes, one bit per core (fixed-size OCTET STRING in ASN).
    pub bitfield: Vec<u8>,
    /// Validator index.
    pub validator_index: ValidatorIndex,
    /// Signature.
    pub signature: crate::Ed25519Signature,
}

/// Guarantees extrinsic EG (eq 11.23).
pub type GuaranteesExtrinsic = Vec<Guarantee>;

/// A single guarantee.
#[derive(Clone, Debug)]
pub struct Guarantee {
    /// The work report.
    pub report: crate::work::WorkReport,
    /// Timeslot at which the guarantee was made.
    pub timeslot: Timeslot,
    /// Credentials: (validator_index, signature) pairs.
    pub credentials: Vec<(ValidatorIndex, crate::Ed25519Signature)>,
}
