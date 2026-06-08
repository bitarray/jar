//! The TOP-level frame's own primary gas meter (`gas_slots` → `Gas{root_meter}`)
//! is a first-class meter: `kernel:set_gas_meter` on it reads/writes the LIVE
//! balance, so a chain can self-harvest its root meter (`set_gas_meter(root, 0)`
//! returns the remaining and zeroes it), exactly like a child meter.
//!
//! Regression for the validation finding "the top frame's own meter cannot be
//! read/written via set_gas_meter" (it was stamped active=None and never seeded).
//! With the fix the guest resolves and seeds the root meter from the host budget.
//!
//! Gated to the nub Hyperlight host (linux-x86_64).
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use javm_cap::image::{EndpointDef, Image};
use javm_cap::yield_cap::YK_SET_GAS_METER;
use javm_cap::{gas_handle, yield_sender, CNodeCap, Cap, CapHashOrRef, Key, NUM_REGS};
use nub::Nub;
use std::collections::BTreeMap;

const OP_REPLY: u32 = 0;
const OP_HOST_YIELD: u32 = 16;
const SENDER_SLOT: u8 = 5; // kernel:set_gas_meter YieldSender
const GAS_SLOT: u8 = 8; // the top's primary gas slot → Gas{ROOT_METER}
const ROOT_METER: u8 = 3; // the top's meter_key
const BUDGET: u64 = 1_000_000;

fn ecalli(imm: u32) -> u32 {
    ((imm & 0xFFF) << 20) | (0b010 << 12) | 0b000_1011
}

#[test]
fn root_meter_self_harvest_via_set_gas_meter() {
    let mut nub = Nub::hyperlight().expect("Hyperlight sandbox");

    // The set_gas_meter YieldSender + the top's Gas{ROOT_METER} handle.
    let sender_h = nub
        .put_cap(&Cap::Instance(yield_sender(&Key::from(
            &YK_SET_GAS_METER[..],
        ))))
        .expect("put sender");
    let gas_h = nub
        .put_cap(&Cap::Instance(gas_handle(&Key::from(ROOT_METER))))
        .expect("put gas handle");

    let mut cnode = CNodeCap::new();
    cnode
        .set(&Key::from(SENDER_SLOT), Some(CapHashOrRef::Hash(sender_h)))
        .unwrap();
    cnode
        .set(&Key::from(GAS_SLOT), Some(CapHashOrRef::Hash(gas_h)))
        .unwrap();
    let cnode_h = nub.put_cap(&Cap::CNode(cnode)).expect("put cnode");

    // Top image: primary gas slot = GAS_SLOT; code = `set_gas_meter(ROOT_METER, 0);
    // reply` — harvest-and-zero, returning the previous balance in φ7.
    let mut endpoints = BTreeMap::new();
    endpoints.insert(
        Key::from(0u8),
        EndpointDef {
            entry_pc: 0,
            arg_registers: 0,
            arg_cnode_size: 0,
            initial_regs: BTreeMap::new(),
        },
    );
    let mut code = Vec::new();
    code.extend_from_slice(&ecalli(OP_HOST_YIELD).to_le_bytes());
    code.extend_from_slice(&ecalli(OP_REPLY).to_le_bytes());
    let img = Image {
        code,
        endpoints,
        memory_mappings: Vec::new(),
        pinned_slots: BTreeMap::new(),
        initial_slots: BTreeMap::new(),
        yield_receiver_slot: None,
        gas_slots: vec![Key::from(GAS_SLOT)],
        quota_slots: Vec::new(),
    };
    let image_h = nub
        .put_cap(&Cap::image_with_slots(&img, &[], &[]).expect("image"))
        .expect("put image");
    let mem = img.instance_mem_backing();
    let inst_h = nub
        .put_cap(&Cap::instance_with_mem(
            [0u8; 32],
            image_h,
            cnode_h,
            mem,
            [0u64; NUM_REGS],
            0,
            0,
        ))
        .expect("put instance");

    // Fund the root meter host-side; invoke_cached seeds the run from it.
    nub.set_meter(Key::from(ROOT_METER), BUDGET);

    // φ7=SENDER_SLOT, φ8=ROOT_METER, φ9=0 (the harvest value).
    let r = nub
        .invoke_cached(
            inst_h,
            0,
            [SENDER_SLOT as u64, ROOT_METER as u64, 0, 0],
            BUDGET,
        )
        .expect("invoke");

    // set_gas_meter(root, 0) returned the LIVE remaining (most of BUDGET, minus a
    // little for the one ecall) in φ7 — NOT 0, which is what the bug returned.
    assert!(
        r.return_value > BUDGET / 2 && r.return_value < BUDGET,
        "set_gas_meter(root,0) must return the live remaining, got {}",
        r.return_value,
    );
    // It zeroed the meter: the harvested run leaves the root meter at 0.
    assert_eq!(
        nub.get_meter(&Key::from(ROOT_METER)),
        0,
        "set_gas_meter(root,0) must zero the root meter",
    );
}
