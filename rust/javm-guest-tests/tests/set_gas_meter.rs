//! `kernel:set_gas_meter` + per-frame metering: a chain funds a guest meter via
//! the `set_gas_meter` syscall, then CALLs a child whose primary usable gas slot
//! names that meter — the child runs on the FUNDED balance, not the chain's pool.
//!
//! This is the observable proof of per-frame metering: with the child's meter
//! set to 0 the child OOGs (reason 2) even though the chain's pool is large; if
//! the child instead loaned the chain's pool (the old one-pool model) the
//! 0-meter would be irrelevant and the child would complete. With the meter
//! funded large, the child completes and the chain halts cleanly (reason 4).
//!
//! The chain is `host_yield(set_gas_meter); addi φ7=child_slot; host_call;
//! reply`. `set_gas_meter` returns the previous balance in φ7 (the sender slot),
//! so an `addi` resets φ7 to the child slot before the CALL — exercising real
//! in-guest register setup. φ8=0 serves as both the meter_key and the child
//! endpoint. Gated to the nub Hyperlight host (linux-x86_64).
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use javm_cap::image::{EndpointDef, Image};
use javm_cap::yield_cap::YK_SET_GAS_METER;
use javm_cap::{gas_handle, yield_sender, CNodeCap, Cap, CapHashOrRef, Key, NUM_REGS};
use nub::Nub;
use std::collections::BTreeMap;

const OP_REPLY: u32 = 0;
const OP_HOST_YIELD: u32 = 16;
const OP_HOST_CALL: u32 = 26;

/// Chain root-cnode slots.
const SENDER_SLOT: u8 = 5; // the kernel:set_gas_meter YieldSender
const CHILD_SLOT: u8 = 6; // the metered child (a published Cap::Instance)
const CHILD_GAS_SLOT: u8 = 8; // Gas{meter_key=0} — the child's primary gas slot
/// The meter_key (= 0) the child's Gas handle names. Also the child endpoint and
/// the set_gas_meter meter_key operand, so chain φ8 = 0 serves all three.
const METER_KEY: u8 = 0;
const GAS_BUDGET: u64 = 10_000_000_000;

fn ecalli(imm: u32) -> u32 {
    ((imm & 0xFFF) << 20) | (0b010 << 12) | 0b000_1011
}

/// `addi rd, rs1, imm` (RV opcode 0x13). φ[7] maps to RV x10, so `addi(10, 0,
/// n)` sets φ[7] = n (rs1 = x0 = zero).
fn addi(rd: u8, rs1: u8, imm: i32) -> u32 {
    ((imm as u32 & 0xFFF) << 20) | ((rs1 as u32) << 15) | ((rd as u32) << 7) | 0x13
}

fn endpoint0() -> BTreeMap<Key, EndpointDef> {
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
    endpoints
}

fn image(code: Vec<u8>, gas_slots: Vec<Key>) -> Image {
    Image {
        code,
        endpoints: endpoint0(),
        memory_mappings: Vec::new(),
        pinned_slots: BTreeMap::new(),
        initial_slots: BTreeMap::new(),
        yield_receiver_slot: None,
        gas_slots,
        quota_slots: Vec::new(),
    }
}

/// Invoke a standalone image and return its `(exit_reason, return_value)`.
fn run_image(nub: &mut Nub, code: Vec<u8>, args: [u64; 4]) -> (u32, u64) {
    let img = image(code, Vec::new());
    let image_h = nub
        .put_cap(&Cap::image_with_slots(&img, &[], &[]).expect("image"))
        .expect("put image");
    let mem = img.instance_mem_backing();
    let inst_h = nub
        .put_cap(&Cap::instance_with_mem(
            [0u8; 32],
            image_h,
            [0u8; 32],
            mem,
            [0u64; NUM_REGS],
            0,
            0,
        ))
        .expect("put instance");
    let r = nub
        .invoke_cached(inst_h, 0, args, GAS_BUDGET)
        .expect("invoke");
    (r.exit_reason, r.return_value)
}

/// Run the chain: `set_gas_meter(meter_key=0, meter_value)` then CALL the metered
/// child. Returns the top-level `exit_reason`.
fn run_metered(nub: &mut Nub, meter_value: u64) -> u32 {
    // kernel:set_gas_meter YieldSender, in the chain's root cnode.
    let sender = Cap::Instance(yield_sender(&Key::from(&YK_SET_GAS_METER[..])));
    let sender_h = nub.put_cap(&sender).expect("put set_gas_meter sender");

    // The Gas{meter_key=0} handle the child's primary gas slot resolves to (the
    // child inherits it from the chain's cnode at CALL).
    let gas = Cap::Instance(gas_handle(&Key::from(METER_KEY)));
    let gas_h = nub.put_cap(&gas).expect("put gas handle");

    // The metered child: a bare `reply`, with primary gas slot = CHILD_GAS_SLOT.
    let child_img = image(
        ecalli(OP_REPLY).to_le_bytes().to_vec(),
        vec![Key::from(CHILD_GAS_SLOT)],
    );
    let child_image_h = nub
        .put_cap(&Cap::image_with_slots(&child_img, &[], &[]).expect("child image"))
        .expect("put child image");
    let child_mem = child_img.instance_mem_backing();
    let child_h = nub
        .put_cap(&Cap::instance_with_mem(
            [0u8; 32],
            child_image_h,
            [0u8; 32],
            child_mem,
            [0u64; NUM_REGS],
            0,
            0,
        ))
        .expect("put child instance");

    // Chain root cnode: the set_gas_meter sender, the child, and the Gas handle.
    let mut cnode = CNodeCap::new();
    cnode
        .set(&Key::from(SENDER_SLOT), Some(CapHashOrRef::Hash(sender_h)))
        .unwrap();
    cnode
        .set(&Key::from(CHILD_SLOT), Some(CapHashOrRef::Hash(child_h)))
        .unwrap();
    cnode
        .set(&Key::from(CHILD_GAS_SLOT), Some(CapHashOrRef::Hash(gas_h)))
        .unwrap();
    let cnode_h = nub.put_cap(&Cap::CNode(cnode)).expect("put chain cnode");

    // Chain: host_yield(set_gas_meter); addi φ7=CHILD_SLOT; host_call; reply.
    let mut code = Vec::new();
    code.extend_from_slice(&ecalli(OP_HOST_YIELD).to_le_bytes());
    code.extend_from_slice(&addi(10, 0, CHILD_SLOT as i32).to_le_bytes());
    code.extend_from_slice(&ecalli(OP_HOST_CALL).to_le_bytes());
    code.extend_from_slice(&ecalli(OP_REPLY).to_le_bytes());
    let chain_img = image(code, Vec::new());
    let chain_image_h = nub
        .put_cap(&Cap::image_with_slots(&chain_img, &[], &[]).expect("chain image"))
        .expect("put chain image");
    let chain_mem = chain_img.instance_mem_backing();
    let chain_h = nub
        .put_cap(&Cap::instance_with_mem(
            [0u8; 32],
            chain_image_h,
            cnode_h,
            chain_mem,
            [0u64; NUM_REGS],
            0,
            0,
        ))
        .expect("put chain instance");

    // φ7=SENDER_SLOT, φ8=0 (meter_key + child ep), φ9=meter_value, φ10=0.
    let args = [SENDER_SLOT as u64, 0, meter_value, 0];
    let r = nub
        .invoke_cached(chain_h, 0, args, GAS_BUDGET)
        .expect("invoke chain");
    r.exit_reason
}

#[test]
fn set_gas_meter_funds_per_frame_metering() {
    let mut nub = Nub::hyperlight().expect("Hyperlight sandbox");

    // Probe the φ7→x10 register mapping the chain relies on: `addi(10,0,55);
    // reply` must return 55 in φ7. A wrong mapping here would silently corrupt
    // the chain's host_call slot operand below.
    let (reason, ret) = run_image(
        &mut nub,
        {
            let mut c = Vec::new();
            c.extend_from_slice(&addi(10, 0, 55).to_le_bytes());
            c.extend_from_slice(&ecalli(OP_REPLY).to_le_bytes());
            c
        },
        [0; 4],
    );
    assert_eq!(
        (reason, ret),
        (4, 55),
        "φ7 == x10: addi(10,0,55) must set φ7=55"
    );

    // Funded large: the child runs on its own (ample) meter and completes; the
    // chain resumes and halts cleanly (reason 4).
    assert_eq!(
        run_metered(&mut nub, 1_000_000),
        4,
        "a child with a well-funded meter completes; chain halts cleanly",
    );

    // Funded ZERO: the child runs on its own empty meter and OOGs (reason 2) —
    // even though the chain's pool is large. This is the per-frame-metering
    // proof: a loaned child would ignore the 0-meter and complete.
    assert_eq!(
        run_metered(&mut nub, 0),
        2,
        "a child metered at 0 must OOG on its own meter, not loan the chain pool",
    );
}
