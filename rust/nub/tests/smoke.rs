//! End-to-end smoke for the cache-based publish/invoke path. Both
//! backends publish the same tiny PVM program (`ecalli 42`) via the
//! typed API and check that `invoke_cached` returns the expected
//! `HostCall(42)` result.

use javm_cap::NUM_REGS;
use javm_cap::image::{EndpointDef, Image};
use nub::Nub;
use std::collections::BTreeMap;

/// Build a minimal Image whose endpoint 0 runs `ecalli 42` at PC 1.
/// PC=0 is reserved as the "fallback" PC so endpoints start at >= 1;
/// byte 0 is a NOP and byte 1+ holds the ecalli encoding.
fn ecalli_42_image() -> Image {
    let mut img = Image::empty();
    // PC=0 is the spec's reserved "fallback PC" — a real Image always
    // has *some* instruction there even if the entry_pc points
    // elsewhere. Trap is a valid 1-byte instruction; we never reach it
    // because `endpoint.entry_pc = 1` jumps straight to the ecalli.
    img.code = vec![0u8, 10u8, 42]; // trap, then ecalli (opcode 10), imm = 42
    img.packed_bitmask = vec![0b011]; // bits 0, 1 are instruction starts (byte 2 is ecalli's imm)

    let mut endpoints: BTreeMap<u8, EndpointDef> = BTreeMap::new();
    endpoints.insert(
        0,
        EndpointDef {
            entry_pc: 1,
            arg_registers: 0,
            arg_cnode_size: 0,
            initial_regs: BTreeMap::new(),
        },
    );
    img.endpoints = endpoints;
    img
}

fn publish_and_invoke(nub: &mut Nub) -> nub::InvocationResult {
    let img = ecalli_42_image();
    let image_h = nub.publish_image(&img).expect("publish_image");
    let cnode_h = nub.publish_cnode(0, &[]).expect("publish_cnode");
    let instance_h = nub
        .publish_instance(
            [0u8; 32],
            image_h,
            cnode_h,
            &[],
            4096,
            [0u64; NUM_REGS],
            0,
            0,
        )
        .expect("publish_instance");
    nub.invoke_cached(instance_h, 0, [0; 4], 1_000)
        .expect("invoke_cached")
}

#[test]
fn local_invoke_cached_ecalli_42() {
    let mut nub = Nub::new_local();
    let result = publish_and_invoke(&mut nub);
    assert_eq!(result.exit_reason, 4, "expected HostCall");
    assert_eq!(result.exit_arg, 42, "expected ecalli imm");
}

#[test]
fn hyperlight_invoke_cached_ecalli_42() {
    let mut nub = Nub::new_hyperlight().expect("hyperlight");
    let result = publish_and_invoke(&mut nub);
    assert_eq!(result.exit_reason, 4, "expected HostCall");
    assert_eq!(result.exit_arg, 42, "expected ecalli imm");
}
