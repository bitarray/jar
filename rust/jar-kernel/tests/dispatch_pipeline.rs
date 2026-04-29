//! Off-chain Dispatch step-2 / step-3 pipeline via `Kernel::dispatch`.
//!
//! Genesis defaults wire the `slot_clear` PVM blob as the dispatch
//! entrypoint's code. The blob is phase-aware via `φ[7]`: step-2 (φ[7]=0)
//! halts immediately; step-3 (φ[7]=1) issues `ecalli 19`
//! (`HostCall::SlotClear`) then halts. The kernel runs both phases via real
//! `javm::kernel::InvocationKernel` and resets the slot to `Empty`.
//!
//! Real chains would emit `AggregatedTransact` instead; the slot-clear path
//! exercises the host-call dispatch loop end-to-end.

use jar_kernel::Event;
use jar_kernel::Kernel;
use jar_kernel::genesis::GenesisBuilder;
use jar_kernel::runtime::{InMemoryBus, InMemoryHardware, NetMessage};

#[test]
fn dispatch_runs_step2_step3_and_subscribes_at_construction() {
    let g = GenesisBuilder::default().build().unwrap();
    let dispatch_vault = g.dispatch_vault;
    let bus = InMemoryBus::new();
    let hw_inbox = bus.add_inbox();
    let hw = InMemoryHardware::new(g.state.clone(), bus);
    let mut k = Kernel::new(None, hw).expect("kernel new");

    // Construction subscribed us to dispatch_vault.
    assert!(
        k.hardware()
            .subscriptions_snapshot()
            .contains(&dispatch_vault),
        "kernel did not subscribe to the dispatch entrypoint"
    );

    let event = Event {
        payload: b"hello".to_vec(),
        caps: vec![],
        attestation_trace: vec![],
        result_trace: vec![],
    };
    k.dispatch(dispatch_vault, &event).expect("dispatch ok");

    // Step-3 slot_clear sets the slot to Empty. Initial slot was also Empty,
    // so `slot_changed = false` and no BroadcastLite is emitted. Drain the
    // inbox and assert nothing arrived — proves the kernel didn't accidentally
    // emit a spurious BroadcastLite.
    let mut got_lite = false;
    while let Ok(msg) = hw_inbox.try_recv() {
        if matches!(msg, NetMessage::LiteUpdate { .. }) {
            got_lite = true;
        }
    }
    assert!(
        !got_lite,
        "unexpected LiteUpdate emitted for no-change slot transition"
    );
}
