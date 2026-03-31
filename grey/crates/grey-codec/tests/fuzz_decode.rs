//! Fuzz-style property tests: feed random bytes to all Decode impls and
//! verify they never panic. Decoding may return Err (expected for garbage
//! input) but must not panic or cause undefined behavior.

use grey_codec::decode::decode_compact;
use grey_codec::{Decode, DecodeWithConfig};
use grey_types::config::Config;
use grey_types::header::{Culprit, Fault, Guarantee, Judgment, Ticket, TicketProof};
use grey_types::work::{
    AvailabilitySpec, ImportSegment, RefinementContext, WorkDigest, WorkItem, WorkPackage,
    WorkReport, WorkResult,
};
use grey_types::{
    BandersnatchPublicKey, BandersnatchRingRoot, BandersnatchSignature, BlsPublicKey,
    Ed25519PublicKey, Ed25519Signature, Hash,
};
use proptest::prelude::*;

/// Generate random byte vectors of 0–1024 bytes.
fn arb_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=1024)
}

proptest! {
    // ── Primitive types ────────────────────────────────────────────────

    #[test]
    fn fuzz_decode_u8(data in arb_bytes()) {
        let _ = u8::decode(&data);
    }

    #[test]
    fn fuzz_decode_u16(data in arb_bytes()) {
        let _ = u16::decode(&data);
    }

    #[test]
    fn fuzz_decode_u32(data in arb_bytes()) {
        let _ = u32::decode(&data);
    }

    #[test]
    fn fuzz_decode_u64(data in arb_bytes()) {
        let _ = u64::decode(&data);
    }

    #[test]
    fn fuzz_decode_bool(data in arb_bytes()) {
        let _ = bool::decode(&data);
    }

    #[test]
    fn fuzz_decode_compact(data in arb_bytes()) {
        let _ = decode_compact(&data);
    }

    // ── Hash and key types ─────────────────────────────────────────────

    #[test]
    fn fuzz_decode_hash(data in arb_bytes()) {
        let _ = Hash::decode(&data);
    }

    #[test]
    fn fuzz_decode_ed25519_public(data in arb_bytes()) {
        let _ = Ed25519PublicKey::decode(&data);
    }

    #[test]
    fn fuzz_decode_bandersnatch_public(data in arb_bytes()) {
        let _ = BandersnatchPublicKey::decode(&data);
    }

    #[test]
    fn fuzz_decode_bls_public(data in arb_bytes()) {
        let _ = BlsPublicKey::decode(&data);
    }

    #[test]
    fn fuzz_decode_ed25519_signature(data in arb_bytes()) {
        let _ = Ed25519Signature::decode(&data);
    }

    #[test]
    fn fuzz_decode_bandersnatch_signature(data in arb_bytes()) {
        let _ = BandersnatchSignature::decode(&data);
    }

    #[test]
    fn fuzz_decode_bandersnatch_ring_root(data in arb_bytes()) {
        let _ = BandersnatchRingRoot::decode(&data);
    }

    // ── Protocol types ─────────────────────────────────────────────────

    #[test]
    fn fuzz_decode_ticket(data in arb_bytes()) {
        let _ = Ticket::decode(&data);
    }

    #[test]
    fn fuzz_decode_ticket_proof(data in arb_bytes()) {
        let _ = TicketProof::decode(&data);
    }

    #[test]
    fn fuzz_decode_work_result(data in arb_bytes()) {
        let _ = WorkResult::decode(&data);
    }

    #[test]
    fn fuzz_decode_work_digest(data in arb_bytes()) {
        let _ = WorkDigest::decode(&data);
    }

    #[test]
    fn fuzz_decode_import_segment(data in arb_bytes()) {
        let _ = ImportSegment::decode(&data);
    }

    #[test]
    fn fuzz_decode_availability_spec(data in arb_bytes()) {
        let _ = AvailabilitySpec::decode(&data);
    }

    #[test]
    fn fuzz_decode_refinement_context(data in arb_bytes()) {
        let _ = RefinementContext::decode(&data);
    }

    #[test]
    fn fuzz_decode_work_item(data in arb_bytes()) {
        let _ = WorkItem::decode(&data);
    }

    #[test]
    fn fuzz_decode_work_report(data in arb_bytes()) {
        let _ = WorkReport::decode(&data);
    }

    #[test]
    fn fuzz_decode_work_package(data in arb_bytes()) {
        let _ = WorkPackage::decode(&data);
    }

    #[test]
    fn fuzz_decode_judgment(data in arb_bytes()) {
        let _ = Judgment::decode(&data);
    }

    #[test]
    fn fuzz_decode_culprit(data in arb_bytes()) {
        let _ = Culprit::decode(&data);
    }

    #[test]
    fn fuzz_decode_fault(data in arb_bytes()) {
        let _ = Fault::decode(&data);
    }

    #[test]
    fn fuzz_decode_guarantee(data in arb_bytes()) {
        let _ = Guarantee::decode(&data);
    }

    // ── Config-dependent types (DecodeWithConfig) ──────────────────────

    #[test]
    fn fuzz_decode_header_tiny(data in arb_bytes()) {
        let config = Config::tiny();
        let _ = grey_types::header::Header::decode_with_config(&data, &config);
    }

    #[test]
    fn fuzz_decode_header_full(data in arb_bytes()) {
        let config = Config::full();
        let _ = grey_types::header::Header::decode_with_config(&data, &config);
    }

    #[test]
    fn fuzz_decode_block_tiny(data in arb_bytes()) {
        let config = Config::tiny();
        let _ = grey_types::header::Block::decode_with_config(&data, &config);
    }

    #[test]
    fn fuzz_decode_extrinsic_tiny(data in arb_bytes()) {
        let config = Config::tiny();
        let _ = grey_types::header::Extrinsic::decode_with_config(&data, &config);
    }

    #[test]
    fn fuzz_decode_assurance_tiny(data in arb_bytes()) {
        let config = Config::tiny();
        let _ = grey_types::header::Assurance::decode_with_config(&data, &config);
    }

    #[test]
    fn fuzz_decode_disputes_tiny(data in arb_bytes()) {
        let config = Config::tiny();
        let _ = grey_types::header::DisputesExtrinsic::decode_with_config(&data, &config);
    }

    #[test]
    fn fuzz_decode_verdict_tiny(data in arb_bytes()) {
        let config = Config::tiny();
        let _ = grey_types::header::Verdict::decode_with_config(&data, &config);
    }
}
