//! Off-chain Dispatch step-2/step-3 pipeline.
//!
//! The smoke step-3 VM emits `slot_clear()` — i.e. the slot is reset to
//! `Empty` after every event. In a real chain, step-3 would emit
//! `AggregatedTransact`; we'll exercise that once a real PVM step-3 guest
//! lands. Until then this test verifies the pipeline mechanics: kernel runs
//! step-2, step-3, updates the slot, emits a BroadcastLite when the slot
//! changes.

use jar_kernel::genesis::GenesisBuilder;
use jar_kernel::runtime::{InMemoryBus, InMemoryHardware, NodeOffchain};
use jar_kernel::{Kernel, SlotContent};
use jar_types::Event;

#[test]
fn handle_inbound_dispatch_runs_step2_step3_then_settles_slot() {
    let g = GenesisBuilder::default().build().unwrap();
    let mut node = NodeOffchain::new();
    let kernel = Kernel::new(InMemoryHardware::new(InMemoryBus::new()));

    node.set_slot(
        g.dispatch_vault,
        SlotContent::AggregatedDispatch {
            payload: b"prev".to_vec(),
            caps: vec![],
            attestation_trace: vec![],
            result_trace: vec![],
        },
    );

    let event = Event {
        payload: b"hello".to_vec(),
        caps: vec![],
        attestation_trace: vec![],
        result_trace: vec![],
    };
    let outcome = kernel
        .handle_inbound_dispatch(&mut node, &g.state, g.dispatch_vault, &event)
        .expect("handle_inbound_dispatch ok");

    assert!(matches!(node.slot(g.dispatch_vault), SlotContent::Empty));
    assert!(outcome.slot_changed);
    assert_eq!(outcome.commands.len(), 1);
}
