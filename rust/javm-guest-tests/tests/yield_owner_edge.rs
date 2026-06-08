//! Owner-edge yield routing. A CALLs B; B first CALLs D so the old physical
//! router would leave a receiver snapshot on B, then B yields to A. While B is
//! still waiting, A runs as `ref[A]` and CALLs C:
//!
//!   physical stack: A -> B -> ref[A] -> C
//!   owner edges:    A -> B, A -> C
//!
//! C's yield must consult the A->C owner edge and never be caught by B.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use javm_cap::image::{EndpointDef, Image};
use javm_cap::yield_cap::{YK_OOG, YK_SET_GAS_METER};
use javm_cap::{
    gas_handle, yield_receiver, yield_sender, CNodeCap, Cap, CapHashOrRef, Key, NUM_REGS,
};
use nub::Nub;
use std::collections::BTreeMap;

const OP_REPLY: u32 = 0;
const OP_HOST_YIELD: u32 = 16;
const OP_HOST_CALL: u32 = 26;
const OP_CALL_RESUME: u32 = 27;

const D_SLOT: u8 = 4;
const B_SENDER_SLOT: u8 = 5;
const B_SLOT: u8 = 6;
const C_SLOT: u8 = 7;
const C_SENDER_SLOT: u8 = 8;
const A_RECEIVER_SLOT: u8 = 9;
const B_RECEIVER_SLOT: u8 = 10;
const SET_GAS_SENDER_SLOT: u8 = 11;
const ROOT_GAS_SLOT: u8 = 12;
const ROOT_METER: u8 = 3;

const B_KEY: u8 = 0x42;
const C_KEY: u8 = 0x43;
const GAS_BUDGET: u64 = 10_000_000_000;

fn ecalli(imm: u32) -> u32 {
    ((imm & 0xFFF) << 20) | (0b010 << 12) | 0b000_1011
}

fn addi(rd: u8, rs1: u8, imm: i32) -> u32 {
    ((imm as u32 & 0xFFF) << 20) | ((rs1 as u32) << 15) | ((rd as u32) << 7) | 0x13
}

fn endpoint0() -> BTreeMap<Key, EndpointDef> {
    let mut e = BTreeMap::new();
    e.insert(
        Key::from(0u8),
        EndpointDef {
            entry_pc: 0,
            arg_registers: 0,
            arg_cnode_size: 0,
            initial_regs: BTreeMap::new(),
        },
    );
    e
}

fn image(code: Vec<u8>, gas_slots: Vec<Key>, yield_receiver_slot: Option<Key>) -> Image {
    let mut img = Image::with_code(code);
    img.endpoints = endpoint0();
    img.yield_receiver_slot = yield_receiver_slot;
    img.gas_slots = gas_slots;
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

fn setup_graph(
    nub: &mut Nub,
    a_keys: &[Key],
    b_keys: &[Key],
    a_code: Vec<u8>,
    a_gas_slots: Vec<Key>,
    extra_caps: &[(u8, [u8; 32])],
) -> [u8; 32] {
    let b_sender_h = nub
        .put_cap(&Cap::Instance(yield_sender(&Key::from(B_KEY))))
        .expect("put B sender");
    let c_sender_h = nub
        .put_cap(&Cap::Instance(yield_sender(&Key::from(C_KEY))))
        .expect("put C sender");
    let a_receiver_h = nub
        .put_cap(&Cap::Instance(yield_receiver(a_keys)))
        .expect("put A receiver");
    let b_receiver_h = nub
        .put_cap(&Cap::Instance(yield_receiver(b_keys)))
        .expect("put B receiver");

    let d_h = put_instance(
        nub,
        &image(ecalli(OP_REPLY).to_le_bytes().to_vec(), Vec::new(), None),
        [0u8; 32],
    );

    let mut b_code = Vec::new();
    b_code.extend_from_slice(&ecalli(OP_HOST_CALL).to_le_bytes());
    b_code.extend_from_slice(&addi(10, 0, B_SENDER_SLOT as i32).to_le_bytes());
    b_code.extend_from_slice(&ecalli(OP_HOST_YIELD).to_le_bytes());
    b_code.extend_from_slice(&ecalli(OP_REPLY).to_le_bytes());
    let b_h = put_instance(
        nub,
        &image(b_code, Vec::new(), Some(Key::from(B_RECEIVER_SLOT))),
        [0u8; 32],
    );

    let mut c_code = Vec::new();
    c_code.extend_from_slice(&addi(10, 0, C_SENDER_SLOT as i32).to_le_bytes());
    c_code.extend_from_slice(&ecalli(OP_HOST_YIELD).to_le_bytes());
    c_code.extend_from_slice(&ecalli(OP_REPLY).to_le_bytes());
    let c_h = put_instance(nub, &image(c_code, Vec::new(), None), [0u8; 32]);

    let mut cnode = CNodeCap::new();
    for (slot, h) in [
        (D_SLOT, d_h),
        (B_SENDER_SLOT, b_sender_h),
        (B_SLOT, b_h),
        (C_SLOT, c_h),
        (C_SENDER_SLOT, c_sender_h),
        (A_RECEIVER_SLOT, a_receiver_h),
        (B_RECEIVER_SLOT, b_receiver_h),
    ] {
        cnode
            .set(&Key::from(slot), Some(CapHashOrRef::Hash(h)))
            .unwrap();
    }
    for (slot, h) in extra_caps {
        cnode
            .set(&Key::from(*slot), Some(CapHashOrRef::Hash(*h)))
            .unwrap();
    }
    let cnode_h = nub.put_cap(&Cap::CNode(cnode)).expect("put A cnode");
    put_instance(
        nub,
        &image(a_code, a_gas_slots, Some(Key::from(A_RECEIVER_SLOT))),
        cnode_h,
    )
}

fn run_c_yield(nub: &mut Nub, a_catches_c: bool) -> (u32, u32) {
    let mut a_code = Vec::new();
    a_code.extend_from_slice(&ecalli(OP_HOST_CALL).to_le_bytes()); // CALL B
    a_code.extend_from_slice(&addi(10, 0, C_SLOT as i32).to_le_bytes());
    a_code.extend_from_slice(&addi(11, 0, 0).to_le_bytes());
    a_code.extend_from_slice(&ecalli(OP_HOST_CALL).to_le_bytes()); // CALL C as ref[A]
    a_code.extend_from_slice(&ecalli(OP_CALL_RESUME).to_le_bytes());
    a_code.extend_from_slice(&ecalli(OP_REPLY).to_le_bytes());

    let a_keys = if a_catches_c {
        vec![Key::from(B_KEY), Key::from(C_KEY)]
    } else {
        vec![Key::from(B_KEY)]
    };
    let a_h = setup_graph(nub, &a_keys, &[Key::from(C_KEY)], a_code, Vec::new(), &[]);
    let r = nub
        .invoke_cached(a_h, 0, [B_SLOT as u64, 0, D_SLOT as u64, 0], GAS_BUDGET)
        .expect("invoke A");
    (r.exit_reason, r.exit_arg)
}

#[test]
fn yielded_owner_call_uses_owner_edge_not_waiting_b() {
    let mut nub = Nub::hyperlight().expect("Hyperlight sandbox");

    let (reason, arg) = run_c_yield(&mut nub, false);
    assert_eq!(
        (reason, arg),
        (7, 70),
        "C's yield must not be caught by waiting B; without A catching it, it is unhandled",
    );

    let (reason, _) = run_c_yield(&mut nub, true);
    assert_eq!(
        reason, 4,
        "when A catches C's key on the A->C owner edge, C resumes and the run halts cleanly",
    );
}

#[test]
fn yielded_owner_oog_is_not_caught_by_waiting_b() {
    let mut nub = Nub::hyperlight().expect("Hyperlight sandbox");

    let set_gas_sender_h = nub
        .put_cap(&Cap::Instance(yield_sender(&Key::from(
            &YK_SET_GAS_METER[..],
        ))))
        .expect("put set_gas sender");
    let root_gas_h = nub
        .put_cap(&Cap::Instance(gas_handle(&Key::from(ROOT_METER))))
        .expect("put root gas");

    let mut a_code = Vec::new();
    a_code.extend_from_slice(&ecalli(OP_HOST_CALL).to_le_bytes()); // CALL B
    a_code.extend_from_slice(&addi(10, 0, SET_GAS_SENDER_SLOT as i32).to_le_bytes());
    a_code.extend_from_slice(&addi(11, 0, ROOT_METER as i32).to_le_bytes());
    a_code.extend_from_slice(&addi(12, 0, 0).to_le_bytes());
    a_code.extend_from_slice(&ecalli(OP_HOST_YIELD).to_le_bytes()); // root meter := 0
    a_code.extend_from_slice(&ecalli(OP_REPLY).to_le_bytes()); // OOG before reply

    let a_h = setup_graph(
        &mut nub,
        &[Key::from(B_KEY)],
        &[Key::from(&YK_OOG[..])],
        a_code,
        vec![Key::from(ROOT_GAS_SLOT)],
        &[
            (SET_GAS_SENDER_SLOT, set_gas_sender_h),
            (ROOT_GAS_SLOT, root_gas_h),
        ],
    );

    let r = nub
        .invoke_cached(a_h, 0, [B_SLOT as u64, 0, D_SLOT as u64, 0], GAS_BUDGET)
        .expect("invoke A");
    assert_eq!(
        r.exit_reason, 2,
        "A's OOG while running as ref[A] must start from A's owner edge, so waiting B cannot catch it",
    );
}
