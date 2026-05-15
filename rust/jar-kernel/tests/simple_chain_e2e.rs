//! End-to-end integration test: build the simple-chain example,
//! transpile it to a `Cap::Image`, run it through `Kernel::apply`,
//! and assert the endpoint's return value.
//!
//! This is the first test that drives the full pipeline (Rust →
//! ELF → transpile → SCALE-decode → kernel bootstrap → memory
//! mappings → interpreter → HALT). Hand-authored byte-PVM tests
//! in `end_to_end.rs` cover the smaller surface (kernel state
//! root evolution, replay determinism).

use jar_cap::image::Image;
use jar_kernel::{Block, Event, EventOutcome, Kernel};
use scale::Decode;

const BLOB: &[u8] = include_bytes!(env!("SIMPLE_CHAIN_BLOB"));

#[test]
fn simple_chain_returns_sum() {
    // Decode the transpiler output as a v3 chain Image.
    let (image, _consumed) =
        Image::decode(BLOB).expect("SCALE-decode the transpiled simple-chain Image");

    // Drive a single event through the kernel.
    let mut kernel = Kernel::from_genesis(image);
    let outcomes = kernel
        .apply(
            &Block {
                events: vec![Event {
                    endpoint_idx: 0,
                    payload: Vec::new(),
                }],
            },
            10_000_000,
            10_000_000,
        )
        .expect("apply succeeds");

    assert_eq!(outcomes.len(), 1);
    match &outcomes[0] {
        EventOutcome::Halt { return_value, .. } => {
            assert_eq!(*return_value, 15u64, "1+2+3+4+5 = 15");
        }
        other => panic!("expected Halt, got {:?}", other),
    }
}
