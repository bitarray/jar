//! End-to-end `Kernel::advance` coverage against a minimal genesis.
//!
//! The genesis fixture wires three transact endpoints (block_init,
//! event-receiving, block_final) and one dispatch endpoint, all
//! pointing at the halt smoke blob — host calls today are stubbed,
//! so each Vault.initialize halts cleanly and apply_block's verify-
//! then-process loop walks all three transact slots without faulting.
//!
//! End-to-end host-call coverage (setScore + max-register selection,
//! self-emit DA pattern with collision-defer, mint_attest_cap scope
//! enforcement) lands once the guest fixtures and host-call
//! implementations are wired up — see Stage E2 / Stage D follow-ups.

use jar_kernel::genesis::GenesisBuilder;
use jar_kernel::runtime::{InMemoryBus, InMemoryHardware};
use jar_kernel::{Block, BlockHash, Body, BodyEvent};
use jar_kernel::{BlockOutcome, Kernel};

fn build_kernel() -> Kernel<InMemoryHardware> {
    let g = GenesisBuilder::default().build().expect("genesis ok");
    let hw = InMemoryHardware::new(g.state, InMemoryBus::new());
    Kernel::new(None, hw).expect("kernel new ok")
}

#[test]
fn advance_accepts_an_empty_block() {
    let mut k = build_kernel();
    let block = Block {
        parent: BlockHash::ZERO,
        body: Body::default(),
    };
    let out = k.advance(Some(block), None).unwrap();
    assert!(matches!(out.block_outcome, BlockOutcome::Accepted));
}

#[test]
fn advance_rejects_block_with_wrong_parent() {
    let mut k = build_kernel();
    let bogus_parent = BlockHash::from([0xAB; 32]);
    let block = Block {
        parent: bogus_parent,
        body: Body::default(),
    };
    let out = k.advance(Some(block), None).unwrap();
    match out.block_outcome {
        BlockOutcome::Panicked(reason) => assert!(
            reason.contains("parent hash mismatch"),
            "unexpected reason: {reason}"
        ),
        other => panic!("expected Panicked, got {other:?}"),
    }
}

#[test]
fn advance_rejects_event_targeting_unknown_slot() {
    let mut k = build_kernel();
    // target_path encodes slot 999 — the genesis only has 3 transact
    // endpoints, so this slot is out of range and the post-walk
    // exhaustion check panics the block.
    let body = Body {
        events: vec![BodyEvent {
            target_path: 999u32.to_le_bytes().to_vec(),
            blob: vec![],
            attestation_traces: vec![],
        }],
        ..Body::default()
    };
    let block = Block {
        parent: BlockHash::ZERO,
        body,
    };
    let out = k.advance(Some(block), None).unwrap();
    match out.block_outcome {
        BlockOutcome::Panicked(reason) => assert!(
            reason.contains("body events targeting unknown slots"),
            "unexpected reason: {reason}"
        ),
        other => panic!("expected Panicked, got {other:?}"),
    }
}

#[test]
fn advance_rejects_event_with_malformed_target_path() {
    let mut k = build_kernel();
    // 3-byte target_path is rejected up front — must be 4-byte LE u32.
    let body = Body {
        events: vec![BodyEvent {
            target_path: vec![1, 2, 3],
            blob: vec![],
            attestation_traces: vec![],
        }],
        ..Body::default()
    };
    let block = Block {
        parent: BlockHash::ZERO,
        body,
    };
    let out = k.advance(Some(block), None).unwrap();
    match out.block_outcome {
        BlockOutcome::Panicked(reason) => assert!(
            reason.contains("malformed target_path"),
            "unexpected reason: {reason}"
        ),
        other => panic!("expected Panicked, got {other:?}"),
    }
}

#[test]
fn advance_accepts_event_targeting_known_slot() {
    let mut k = build_kernel();
    // Slot 1 of the genesis transact_endpoints is the event-receiving
    // halt-blob endpoint. With host calls stubbed the verify VM just
    // halts cleanly, so the block is accepted.
    let body = Body {
        events: vec![BodyEvent {
            target_path: 1u32.to_le_bytes().to_vec(),
            blob: b"hello".to_vec(),
            attestation_traces: vec![],
        }],
        ..Body::default()
    };
    let block = Block {
        parent: BlockHash::ZERO,
        body,
    };
    let out = k.advance(Some(block), None).unwrap();
    assert!(matches!(out.block_outcome, BlockOutcome::Accepted));
}

#[test]
fn advance_rejects_duplicate_schedule_traces_for_same_slot() {
    use jar_kernel::ScheduleAttestationTraces;
    let mut k = build_kernel();
    let body = Body {
        schedule_attestation_traces: vec![
            ScheduleAttestationTraces {
                slot_index: 0,
                traces: vec![],
            },
            ScheduleAttestationTraces {
                slot_index: 0,
                traces: vec![],
            },
        ],
        ..Body::default()
    };
    let block = Block {
        parent: BlockHash::ZERO,
        body,
    };
    let out = k.advance(Some(block), None).unwrap();
    match out.block_outcome {
        BlockOutcome::Panicked(reason) => assert!(
            reason.contains("duplicate schedule_attestation_traces"),
            "unexpected reason: {reason}"
        ),
        other => panic!("expected Panicked, got {other:?}"),
    }
}

#[test]
fn proposer_advance_with_empty_pool_produces_empty_body() {
    let mut k = build_kernel();
    let out = k.advance(None, None).unwrap();
    assert!(matches!(out.block_outcome, BlockOutcome::Accepted));
    assert!(out.block.body.events.is_empty());
}
