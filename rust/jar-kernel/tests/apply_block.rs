//! End-to-end Kernel::advance tests.
//!
//! Stub during the event-redesign migration. Full rewrite for the new
//! flat verify/process model lands in Stage E (E1) of the migration:
//! per-slot interleaved verify-then-process, prior-state-root in
//! block_init, per-Schedule attestation_traces, etc.

use jar_kernel::genesis::GenesisBuilder;
use jar_kernel::runtime::{InMemoryBus, InMemoryHardware};
use jar_kernel::{Block, BlockHash, Body};
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
    let out = k.advance(Some(block)).unwrap();
    assert!(matches!(out.block_outcome, BlockOutcome::Accepted));
}
