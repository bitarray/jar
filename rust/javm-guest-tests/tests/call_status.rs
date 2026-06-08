//! The kernel writes the caller's φ[8] status on EVERY apply termination (spec
//! §4): Ok on a normal HALT/REPLY return, YIELDED when a routed yield hands
//! control to a catcher. Regression for the validation finding that a stale
//! φ[8]=YIELDED survived a subsequent normal CALL (φ[8] was only ever set on the
//! yield path, never reset to Ok on a normal return).
//!
//! A (catcher of K) CALLs B; B yields K → A runs as handler with φ[8]=YIELDED.
//! A then makes a NORMAL host_call to C and, after C returns, moves φ[8] into
//! φ[7] and REPLYs. With the fix φ[8] is Ok(0) after C's return; the bug would
//! leave the stale YIELDED(1). The clever bit: the normal CALL's endpoint operand
//! IS φ[8] (=1), so C is invoked at endpoint 1 and the stale value is what we
//! observe — no extra register write masks it.
//!
//! Gated to the nub Hyperlight host (linux-x86_64).
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use javm_cap::image::{EndpointDef, Image};
use javm_cap::{yield_receiver, yield_sender, CNodeCap, Cap, CapHashOrRef, Key, NUM_REGS};
use nub::Nub;
use std::collections::BTreeMap;

const OP_REPLY: u32 = 0;
const OP_HOST_YIELD: u32 = 16;
const OP_HOST_CALL: u32 = 26;

const B_SLOT: u8 = 6;
const C_SLOT: u8 = 4;
const SENDER_SLOT: u8 = 5;
const RECEIVER_SLOT: u8 = 9;
const YIELD_KEY: u8 = 0x42;
const GAS_BUDGET: u64 = 10_000_000_000;

fn ecalli(imm: u32) -> u32 {
    ((imm & 0xFFF) << 20) | (0b010 << 12) | 0b000_1011
}

/// `addi rd, rs1, imm`. φ7→x10, φ8→x11.
fn addi(rd: u8, rs1: u8, imm: i32) -> u32 {
    ((imm as u32 & 0xFFF) << 20) | ((rs1 as u32) << 15) | ((rd as u32) << 7) | 0x13
}

/// Endpoints {0} or {0,1}: all entry_pc 0.
fn endpoints(extra1: bool) -> BTreeMap<Key, EndpointDef> {
    let mut e = BTreeMap::new();
    let mk = || EndpointDef {
        entry_pc: 0,
        arg_registers: 0,
        arg_cnode_size: 0,
        initial_regs: BTreeMap::new(),
    };
    e.insert(Key::from(0u8), mk());
    if extra1 {
        e.insert(Key::from(1u8), mk());
    }
    e
}

fn image(code: Vec<u8>, eps: BTreeMap<Key, EndpointDef>, recv: Option<Key>) -> Image {
    let mut img = Image::with_code(code);
    img.endpoints = eps;
    img.yield_receiver_slot = recv;
    img
}

fn put_instance(nub: &mut Nub, img: &Image, cnode_h: [u8; 32]) -> nub::AbiCapHash {
    let image_h = nub
        .put_cap(&Cap::image_with_slots(img, &[], &[]).expect("image"))
        .expect("put image");
    let mem = img.instance_mem_backing();
    nub.put_cap(&Cap::instance_with_mem(
        [0u8; 32],
        image_h,
        cnode_h,
        mem,
        [0u64; NUM_REGS],
        0,
        0,
    ))
    .expect("put instance")
}

#[test]
fn phi8_status_is_ok_after_normal_call() {
    let mut nub = Nub::hyperlight().expect("Hyperlight sandbox");

    let sender_h = nub
        .put_cap(&Cap::Instance(yield_sender(&Key::from(YIELD_KEY))))
        .expect("put sender");
    let receiver_h = nub
        .put_cap(&Cap::Instance(yield_receiver(&[Key::from(YIELD_KEY)])))
        .expect("put receiver");

    // B: host_yield(φ7=sender); reply.
    let mut b_code = Vec::new();
    b_code.extend_from_slice(&ecalli(OP_HOST_YIELD).to_le_bytes());
    b_code.extend_from_slice(&ecalli(OP_REPLY).to_le_bytes());
    let b_h = put_instance(&mut nub, &image(b_code, endpoints(false), None), [0u8; 32]);

    // C: reply. Has endpoint 1 (the normal CALL invokes it at φ8=YIELDED=1).
    let c_h = put_instance(
        &mut nub,
        &image(
            ecalli(OP_REPLY).to_le_bytes().to_vec(),
            endpoints(true),
            None,
        ),
        [0u8; 32],
    );

    // A: host_call(B) [B yields → A handler, φ8=YIELDED]; addi φ7=C_SLOT;
    // host_call(C) [normal CALL, φ8=YIELDED=1 is C's endpoint]; addi φ7=φ8;
    // reply [φ7 = post-return φ8].
    let mut a_code = Vec::new();
    a_code.extend_from_slice(&ecalli(OP_HOST_CALL).to_le_bytes()); // call B
    a_code.extend_from_slice(&addi(10, 0, C_SLOT as i32).to_le_bytes()); // φ7 = C slot
    a_code.extend_from_slice(&ecalli(OP_HOST_CALL).to_le_bytes()); // normal call C @ φ8
    a_code.extend_from_slice(&addi(10, 11, 0).to_le_bytes()); // φ7 = φ8 (status)
    a_code.extend_from_slice(&ecalli(OP_REPLY).to_le_bytes());

    let mut a_cnode = CNodeCap::new();
    for (slot, h) in [
        (B_SLOT, b_h),
        (C_SLOT, c_h),
        (SENDER_SLOT, sender_h),
        (RECEIVER_SLOT, receiver_h),
    ] {
        a_cnode
            .set(&Key::from(slot), Some(CapHashOrRef::Hash(h)))
            .unwrap();
    }
    let a_cnode_h = nub.put_cap(&Cap::CNode(a_cnode)).expect("put A cnode");
    let a_h = put_instance(
        &mut nub,
        &image(a_code, endpoints(false), Some(Key::from(RECEIVER_SLOT))),
        a_cnode_h,
    );

    // φ7=B slot, φ8=ep0, φ9=sender slot (→B.φ7), φ10=0.
    let args = [B_SLOT as u64, 0, SENDER_SLOT as u64, 0];
    let r = nub
        .invoke_cached(a_h, 0, args, GAS_BUDGET)
        .expect("invoke A");

    // After the normal CALL of C returns, A's φ[8] must read Ok(0), not the stale
    // YIELDED(1) it held from catching B's yield. A moved φ[8] into φ[7] (the
    // return value) before REPLY.
    assert_eq!(
        r.return_value, 0,
        "φ[8] must reset to Ok after a normal CALL return, got {} (stale YIELDED=1 if the bug)",
        r.return_value,
    );
}
