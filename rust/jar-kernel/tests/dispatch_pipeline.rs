//! Off-chain dispatch coverage: target_path resolution and the
//! verify-then-process arrival pipeline.
//!
//! The genesis fixture wires one dispatch endpoint at slot 0 of
//! σ.dispatch_endpoints, pointing at the halt smoke blob. With host
//! calls still stubbed, verify and process both halt cleanly; this
//! test exercises the routing layer (target_path → endpoint cap_id)
//! and confirms `Kernel::dispatch` doesn't fault on a well-formed
//! arrival. End-to-end coverage of the DA pattern (private dispatch
//! endpoint with self-emit + collision-defer) lands in Stage E2 with
//! the new guest fixtures.

use jar_kernel::Kernel;
use jar_kernel::genesis::GenesisBuilder;
use jar_kernel::runtime::{InMemoryBus, InMemoryHardware};

#[test]
fn kernel_dispatch_routes_to_dispatch_endpoint() {
    let g = GenesisBuilder::default().build().unwrap();
    let dispatch_vault = g.dispatch_vault;
    let hw = InMemoryHardware::new(g.state, InMemoryBus::new());
    let mut k = Kernel::new(None, hw).expect("kernel new");

    // Construction subscribed us to the dispatch endpoint vault.
    assert!(
        k.hardware()
            .subscriptions_snapshot()
            .contains(&dispatch_vault),
        "kernel did not subscribe to the dispatch entrypoint"
    );

    // Genesis places the dispatch endpoint at slot 0 of σ.dispatch_endpoints.
    let target_path = 0u32.to_le_bytes();
    k.dispatch(&target_path, b"hello").expect("dispatch ok");
}
