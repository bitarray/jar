//! End-to-end smoke for the cache-based `Nub::publish_instance` +
//! `Nub::invoke_cached` path. Both backends should publish the same
//! tiny PVM program (`ecalli 42`) and return matching results.

use nub::{Nub, PublishSpec};

fn ecalli_42_publish_spec(hash: [u8; 32]) -> PublishSpec {
    let mut spec = PublishSpec::empty();
    spec.instance_hash = hash;
    spec.code = vec![10u8, 42]; // ecalli (opcode 10), imm = 42
    spec.bitmask = vec![1u8, 0]; // first byte is insn start
    spec.entry_pcs[0] = 0; // endpoint 0 enters at PC=0
    spec
}

#[test]
fn local_invoke_cached_ecalli_42() {
    let hash = [0x42u8; 32];
    let mut nub = Nub::new_local();
    nub.publish_instance(ecalli_42_publish_spec(hash))
        .expect("publish");
    let result = nub
        .invoke_cached(hash, 0, [0; 4], 1_000)
        .expect("invoke_cached");
    assert_eq!(result.exit_reason, 4, "expected HostCall");
    assert_eq!(result.exit_arg, 42, "expected ecalli imm");
}

#[test]
fn hyperlight_invoke_cached_ecalli_42() {
    let hash = [0x77u8; 32];
    let mut nub = Nub::new_hyperlight().expect("hyperlight");
    nub.publish_instance(ecalli_42_publish_spec(hash))
        .expect("publish");
    let result = nub
        .invoke_cached(hash, 0, [0; 4], 1_000)
        .expect("invoke_cached");
    assert_eq!(result.exit_reason, 4, "expected HostCall");
    assert_eq!(result.exit_arg, 42, "expected ecalli imm");
}
