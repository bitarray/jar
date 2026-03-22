//! P2P networking for JAM block propagation using libp2p gossipsub.
//!
//! This crate handles:
//! - Block announcement and propagation via gossipsub
//! - Peer discovery and connection management
//! - GRANDPA-like finality vote propagation

pub mod service;

/// Signing context strings used in the JAM protocol (Appendix I.4.5).
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
}
