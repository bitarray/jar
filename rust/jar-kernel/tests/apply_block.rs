//! End-to-end apply_block tests using a minimal genesis (no PVM blob yet —
//! Transact entrypoints run a smoke VM that halts immediately).

use jar_kernel::genesis::GenesisBuilder;
use jar_kernel::runtime::{InMemoryBus, InMemoryHardware};
use jar_kernel::{BlockOutcome, apply_block};
use jar_types::{Block, BlockHash, Body, Hash};

fn build_genesis() -> jar_types::State {
    GenesisBuilder::default().build().expect("genesis ok").state
}

fn no_op_hardware() -> InMemoryHardware {
    let bus = InMemoryBus::new();
    InMemoryHardware::new(bus)
}

#[test]
fn apply_block_accepts_a_minimal_block() {
    let state = build_genesis();
    let parent = BlockHash::ZERO;
    let block = Block {
        parent,
        body: Body::default(),
    };
    let hw = no_op_hardware();
    let out = apply_block(&state, parent, &block, &hw).unwrap();
    assert!(
        matches!(out.block_outcome, BlockOutcome::Accepted),
        "expected Accepted, got {:?}",
        out.block_outcome
    );
}

#[test]
fn apply_block_rejects_wrong_parent_hash() {
    let state = build_genesis();
    let parent_actual = BlockHash::ZERO;
    let parent_claimed = Hash([7u8; 32]);
    let block = Block {
        parent: parent_claimed,
        body: Body::default(),
    };
    let hw = no_op_hardware();
    let out = apply_block(&state, parent_actual, &block, &hw).unwrap();
    match out.block_outcome {
        BlockOutcome::Panicked(reason) => {
            assert!(reason.contains("parent hash"), "unexpected: {}", reason);
        }
        other => panic!("expected Panicked, got {:?}", other),
    }
}

#[test]
fn apply_block_rejects_unregistered_target() {
    let state = build_genesis();
    let parent = BlockHash::ZERO;
    let body = Body {
        events: vec![(jar_types::VaultId(9999), vec![jar_types::Event::default()])],
        ..Default::default()
    };
    let block = Block { parent, body };
    let hw = no_op_hardware();
    let res = apply_block(&state, parent, &block, &hw);
    // run_phase returns an Err for unregistered targets (kernel-level fault).
    assert!(
        res.is_err(),
        "expected Err for unregistered target, got Ok({:?})",
        res.ok().map(|o| o.block_outcome)
    );
}

#[test]
fn body_events_order_must_match_transact_space_cnode() {
    // Genesis layout: slot 0 Schedule, slot 1 Transact(t_vault), slot 2 Schedule.
    // Body referencing the Transact slot's vault_id is fine.
    let g = GenesisBuilder::default().build().unwrap();
    let block = Block {
        parent: BlockHash::ZERO,
        body: Body {
            events: vec![(g.transact_vault, vec![jar_types::Event::default()])],
            ..Default::default()
        },
    };
    let hw = no_op_hardware();
    let out = apply_block(&g.state, BlockHash::ZERO, &block, &hw).unwrap();
    assert!(matches!(out.block_outcome, BlockOutcome::Accepted));
}

#[test]
fn body_events_referencing_schedule_slot_is_rejected() {
    // body.events MUST NOT reference a Schedule slot's vault_id.
    let g = GenesisBuilder::default().build().unwrap();
    let block = Block {
        parent: BlockHash::ZERO,
        body: Body {
            events: vec![(g.block_init_vault, vec![jar_types::Event::default()])],
            ..Default::default()
        },
    };
    let hw = no_op_hardware();
    let res = apply_block(&g.state, BlockHash::ZERO, &block, &hw);
    assert!(
        res.is_err(),
        "expected Err for Schedule-slot reference, got {:?}",
        res.ok().map(|o| o.block_outcome)
    );
}

#[test]
fn state_root_advances_with_schedule_slots_firing() {
    // Genesis includes Schedule(block_init) and Schedule(block_final) slots
    // that fire once per block. Each invocation allocates a Frame Storage
    // cap, advancing next_cap_id and therefore the state_root — even for
    // a no-event body.
    let state = build_genesis();
    let pre_root = jar_kernel::state_root(&state);
    let block = Block {
        parent: BlockHash::ZERO,
        body: Body::default(),
    };
    let hw = no_op_hardware();
    let out = apply_block(&state, BlockHash::ZERO, &block, &hw).unwrap();
    let post_root = jar_kernel::state_root(&out.state_next);
    assert_ne!(pre_root, post_root);
    assert_eq!(out.state_root, post_root);
}
