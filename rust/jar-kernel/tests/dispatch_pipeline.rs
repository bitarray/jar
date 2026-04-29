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
use jar_kernel::{SlotContent, dispatch};
use jar_types::Event;

#[test]
fn handle_inbound_dispatch_runs_step2_step3_then_settles_slot() {
    let g = GenesisBuilder::<InMemoryHardware>::default().build().unwrap();
    let mut node = NodeOffchain::<InMemoryHardware>::new();
    let bus = InMemoryBus::new();
    let hw = InMemoryHardware::new(bus);

    // Pre-set the slot to a non-Empty value so we can detect the slot_clear.
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
    let outcome =
        dispatch::handle_inbound_dispatch(&mut node, &g.state, g.dispatch_vault, &event, &hw)
            .expect("handle_inbound_dispatch ok");

    // Smoke step-3 emitted slot_clear → SlotContent::Empty.
    assert!(matches!(node.slot(g.dispatch_vault), SlotContent::Empty));
    // The slot changed, so a BroadcastLite command must have fired.
    assert!(outcome.slot_changed);
    assert_eq!(outcome.commands.len(), 1);
}
