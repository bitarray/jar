//! End-to-end Kernel::advance tests using a minimal genesis (no PVM blob
//! yet — Transact entrypoints run a smoke VM that halts immediately).

use jar_kernel::genesis::GenesisBuilder;
use jar_kernel::runtime::{InMemoryBus, InMemoryHardware};
use jar_kernel::{Block, BlockHash, Body, Hash};
use jar_kernel::{BlockOutcome, Kernel};

fn build_kernel() -> Kernel<InMemoryHardware> {
    let g = GenesisBuilder::default().build().expect("genesis ok");
    let hw = InMemoryHardware::new(g.state, InMemoryBus::new());
    Kernel::new(None, hw).expect("kernel new ok")
}

fn build_kernel_with_genesis(g: jar_kernel::genesis::GenesisOutput) -> Kernel<InMemoryHardware> {
    let hw = InMemoryHardware::new(g.state, InMemoryBus::new());
    Kernel::new(None, hw).expect("kernel new ok")
}

#[test]
fn advance_accepts_a_minimal_block() {
    let mut k = build_kernel();
    let block = Block {
        parent: BlockHash::ZERO,
        body: Body::default(),
    };
    let out = k.advance(Some(block)).unwrap();
    assert!(
        matches!(out.block_outcome, BlockOutcome::Accepted),
        "expected Accepted, got {:?}",
        out.block_outcome
    );
}

#[test]
fn advance_rejects_wrong_parent_hash() {
    let mut k = build_kernel();
    let parent_claimed = Hash([7u8; 32]);
    let block = Block {
        parent: parent_claimed,
        body: Body::default(),
    };
    let out = k.advance(Some(block)).unwrap();
    match out.block_outcome {
        BlockOutcome::Panicked(reason) => {
            assert!(reason.contains("parent hash"), "unexpected: {}", reason);
        }
        other => panic!("expected Panicked, got {:?}", other),
    }
}

#[test]
fn advance_rejects_unregistered_target() {
    let mut k = build_kernel();
    let body = Body {
        events: vec![(
            jar_kernel::VaultId(9999),
            vec![jar_kernel::Event::default()],
        )],
        ..Default::default()
    };
    let block = Block {
        parent: BlockHash::ZERO,
        body,
    };
    let res = k.advance(Some(block));
    assert!(
        res.is_err(),
        "expected Err for unregistered target, got Ok({:?})",
        res.ok().map(|o| o.block_outcome)
    );
}

#[test]
fn body_events_order_must_match_transact_space_cnode() {
    let g = GenesisBuilder::default().build().unwrap();
    let target = g.transact_vault;
    let mut k = build_kernel_with_genesis(g);
    let block = Block {
        parent: BlockHash::ZERO,
        body: Body {
            events: vec![(target, vec![jar_kernel::Event::default()])],
            ..Default::default()
        },
    };
    let out = k.advance(Some(block)).unwrap();
    assert!(matches!(out.block_outcome, BlockOutcome::Accepted));
}

#[test]
fn body_events_referencing_schedule_slot_is_rejected() {
    let g = GenesisBuilder::default().build().unwrap();
    let target = g.block_init_vault;
    let mut k = build_kernel_with_genesis(g);
    let block = Block {
        parent: BlockHash::ZERO,
        body: Body {
            events: vec![(target, vec![jar_kernel::Event::default()])],
            ..Default::default()
        },
    };
    let res = k.advance(Some(block));
    assert!(
        res.is_err(),
        "expected Err for Schedule-slot reference, got {:?}",
        res.ok().map(|o| o.block_outcome)
    );
}

#[test]
fn transact_event_with_unconsumed_attestation_trace_faults() {
    let g = GenesisBuilder::default().build().unwrap();
    let target = g.transact_vault;
    let mut k = build_kernel_with_genesis(g);
    let block = Block {
        parent: BlockHash::ZERO,
        body: Body {
            events: vec![(
                target,
                vec![jar_kernel::Event {
                    payload: vec![],
                    caps: vec![],
                    attestation_trace: vec![jar_kernel::AttestationEntry::default()],
                    result_trace: vec![],
                }],
            )],
            ..Default::default()
        },
    };
    let res = k.advance(Some(block));
    assert!(
        res.is_err(),
        "expected per-event trace exhaustion fault, got {:?}",
        res.ok().map(|o| o.block_outcome)
    );
}

#[test]
fn state_root_stable_when_schedule_slots_only_halt() {
    // Halt-blob Schedule slots don't mutate σ. Storage caps live in the
    // running VM's cap-table (not the persistent cap-registry), so
    // ephemeral Frame setup no longer perturbs σ. The state-root is
    // stable across a body-less block whose only effect is firing the
    // three halt-blob Schedule slots in σ.transact_space_cnode.
    let mut k = build_kernel();
    let pre_root = k.state_root();
    let block = Block {
        parent: BlockHash::ZERO,
        body: Body::default(),
    };
    let out = k.advance(Some(block)).unwrap();
    assert!(matches!(out.block_outcome, BlockOutcome::Accepted));
    let post_root = k.state_root();
    assert_eq!(pre_root, post_root);
    assert_eq!(out.state_root, post_root);
}

#[test]
fn proposer_mode_drains_dispatches_and_returns_block() {
    // No outstanding dispatches → empty body, but Schedule slots still fire.
    let mut k = build_kernel();
    let out = k.advance(None).unwrap();
    assert!(matches!(out.block_outcome, BlockOutcome::Accepted));
    assert_eq!(out.block.parent, BlockHash::ZERO);
}
