//! End-to-end smoke for the cache-based publish/invoke path. Both
//! backends publish the same tiny PVM2 program (`ecalli 42`) via the
//! typed API and check that `invoke_cached` returns the expected
//! `HostCall(42)` result.

use javm_cap::image::{EndpointDef, Image};
use javm_cap::{Cap, Key, NUM_REGS};
use nub::Nub;
use std::collections::BTreeMap;

/// Build a minimal PVM2 Image whose endpoint 0 runs `ecalli 42` at PC 0.
fn ecalli_42_image() -> Image {
    let mut img = Image::empty();
    // PVM2 `ecalli 42` — custom-0 (opcode bits[6:2] = 0b00010), funct3 =
    // 0b010, rd = 0, rs1 = 0, imm = 42. As an I-type 32-bit word:
    //   (42 << 20) | (0b010 << 12) | (0b00010 << 2) | 0b11 = 0x02A0_200B
    img.code = 0x02A0_200Bu32.to_le_bytes().to_vec();
    // Code is mapped at the fixed CODE_BASE; no data mappings.

    let mut endpoints: BTreeMap<Key, EndpointDef> = BTreeMap::new();
    endpoints.insert(
        Key::from(0u8),
        EndpointDef {
            entry_pc: 0,
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
    let image_cap = Cap::image_with_slots(&img, &[], &[]).expect("image_with_slots");
    let image_h = nub.put_cap(&image_cap).expect("put_cap image");
    let cnode_cap = Cap::empty_cnode();
    let cnode_h = nub.put_cap(&cnode_cap).expect("put_cap cnode");
    let instance_cap = Cap::instance_with_mem(
        [0u8; 32],
        image_h,
        cnode_h,
        javm_cap::DataCap::from_bytes_sized(&[], 4096),
        [0u64; NUM_REGS],
        0,
        0,
    );
    let instance_h = nub.put_cap(&instance_cap).expect("put_cap instance");
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
