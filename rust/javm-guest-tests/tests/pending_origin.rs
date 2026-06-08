//! Empty-reserved origin slots for running Instances. CALL moves the callee
//! into a KernelFrame and leaves the origin cnode slot empty but reserved until
//! the callee returns or is discarded.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use javm_cap::image::{EndpointDef, Image};
use javm_cap::yield_cap::YK_MINT_GAS;
use javm_cap::{yield_receiver, yield_sender, CNodeCap, Cap, CapHashOrRef, Key, NUM_REGS};
use nub::Nub;
use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

const OP_REPLY: u32 = 0;
const OP_HOST_YIELD: u32 = 16;
const OP_IMAGE_HASH_CHAIN: u32 = 20;
const OP_HOST_CALL: u32 = 26;
const OP_CALL_RESUME: u32 = 27;
const OP_DROP_RESUME: u32 = 28;

const SENDER_SLOT: u8 = 5;
const B_SLOT: u8 = 6;
const RECEIVER_SLOT: u8 = 9;
const MINT_GAS_SENDER_SLOT: u8 = 10;
const TYPE_DST_SLOT: u8 = 11;
const METER_KEY: u8 = 3;
const YIELD_KEY: u8 = 0x42;
const GAS_BUDGET: u64 = 10_000_000_000;

static HYPERLIGHT_TEST_LOCK: Mutex<()> = Mutex::new(());

fn new_serial_nub() -> (MutexGuard<'static, ()>, Nub) {
    let guard = HYPERLIGHT_TEST_LOCK.lock().expect("hyperlight test mutex");
    let nub = Nub::new_hyperlight().expect("Hyperlight sandbox");
    (guard, nub)
}

fn ecalli(imm: u32) -> u32 {
    ((imm & 0xFFF) << 20) | (0b010 << 12) | 0b000_1011
}

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

fn image(code: Vec<u8>, yield_receiver_slot: Option<Key>) -> Image {
    Image {
        code,
        endpoints: endpoint0(),
        memory_mappings: Vec::new(),
        pinned_slots: BTreeMap::new(),
        initial_slots: BTreeMap::new(),
        yield_receiver_slot,
        gas_slots: Vec::new(),
        quota_slots: Vec::new(),
    }
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

fn b_image() -> Image {
    let mut code = Vec::new();
    code.extend_from_slice(&ecalli(OP_HOST_YIELD).to_le_bytes());
    code.extend_from_slice(&ecalli(OP_REPLY).to_le_bytes());
    image(code, None)
}

fn run_a(a_code: Vec<u8>) -> (u32, u32) {
    let (_guard, mut nub) = new_serial_nub();

    let sender_h = nub
        .put_cap(&Cap::Instance(yield_sender(&Key::from(YIELD_KEY))))
        .expect("put sender");
    let receiver_h = nub
        .put_cap(&Cap::Instance(yield_receiver(&[Key::from(YIELD_KEY)])))
        .expect("put receiver");
    let mint_gas_sender_h = nub
        .put_cap(&Cap::Instance(yield_sender(&Key::from(&YK_MINT_GAS[..]))))
        .expect("put mint_gas sender");
    let b_h = put_instance(&mut nub, &b_image(), [0u8; 32]);

    let mut cnode = CNodeCap::new();
    for (slot, h) in [
        (SENDER_SLOT, sender_h),
        (B_SLOT, b_h),
        (RECEIVER_SLOT, receiver_h),
        (MINT_GAS_SENDER_SLOT, mint_gas_sender_h),
    ] {
        cnode
            .set(&Key::from(slot), Some(CapHashOrRef::Hash(h)))
            .expect("set slot");
    }
    let cnode_h = nub.put_cap(&Cap::CNode(cnode)).expect("put A cnode");
    let a_h = put_instance(
        &mut nub,
        &image(a_code, Some(Key::from(RECEIVER_SLOT))),
        cnode_h,
    );
    let r = nub
        .invoke_cached(
            a_h,
            0,
            [B_SLOT as u64, 0, SENDER_SLOT as u64, 0],
            GAS_BUDGET,
        )
        .expect("invoke A");
    (r.exit_reason, r.exit_arg)
}

#[test]
fn call_running_instance_origin_traps() {
    let mut code = Vec::new();
    code.extend_from_slice(&ecalli(OP_HOST_CALL).to_le_bytes()); // CALL B; B yields.
    code.extend_from_slice(&addi(10, 0, B_SLOT as i32).to_le_bytes());
    code.extend_from_slice(&addi(11, 0, 0).to_le_bytes());
    code.extend_from_slice(&ecalli(OP_HOST_CALL).to_le_bytes()); // CALL B again.
    code.extend_from_slice(&ecalli(OP_REPLY).to_le_bytes());

    assert_eq!(
        run_a(code),
        (7, 0),
        "CALL against B's empty-reserved origin slot must trap",
    );
}

#[test]
fn writing_running_instance_origin_traps() {
    let mut code = Vec::new();
    code.extend_from_slice(&ecalli(OP_HOST_CALL).to_le_bytes()); // CALL B; B yields.
    code.extend_from_slice(&addi(10, 0, MINT_GAS_SENDER_SLOT as i32).to_le_bytes());
    code.extend_from_slice(&addi(11, 0, METER_KEY as i32).to_le_bytes());
    code.extend_from_slice(&addi(12, 0, B_SLOT as i32).to_le_bytes());
    code.extend_from_slice(&ecalli(OP_HOST_YIELD).to_le_bytes()); // mint into B slot.
    code.extend_from_slice(&ecalli(OP_REPLY).to_le_bytes());

    assert_eq!(
        run_a(code),
        (7, 0),
        "writing a cap into B's empty-reserved origin slot must trap",
    );
}

#[test]
fn reading_running_instance_origin_traps() {
    let mut code = Vec::new();
    code.extend_from_slice(&ecalli(OP_HOST_CALL).to_le_bytes()); // CALL B; B yields.
    code.extend_from_slice(&addi(10, 0, B_SLOT as i32).to_le_bytes());
    code.extend_from_slice(&addi(11, 0, TYPE_DST_SLOT as i32).to_le_bytes());
    code.extend_from_slice(&ecalli(OP_IMAGE_HASH_CHAIN).to_le_bytes());
    code.extend_from_slice(&ecalli(OP_REPLY).to_le_bytes());

    assert_eq!(
        run_a(code),
        (7, 0),
        "reading/type-querying B's empty-reserved origin slot must trap",
    );
}

#[test]
fn returned_hash_target_can_be_called_again_as_owned() {
    let mut code = Vec::new();
    code.extend_from_slice(&ecalli(OP_HOST_CALL).to_le_bytes()); // Hash target B yields.
    code.extend_from_slice(&ecalli(OP_CALL_RESUME).to_le_bytes()); // B replies and restores as Owned.
    code.extend_from_slice(&addi(10, 0, B_SLOT as i32).to_le_bytes());
    code.extend_from_slice(&addi(11, 0, 0).to_le_bytes());
    code.extend_from_slice(&addi(12, 0, SENDER_SLOT as i32).to_le_bytes());
    code.extend_from_slice(&ecalli(OP_HOST_CALL).to_le_bytes()); // Re-CALL returned B.
    code.extend_from_slice(&ecalli(OP_CALL_RESUME).to_le_bytes());
    code.extend_from_slice(&ecalli(OP_REPLY).to_le_bytes());

    assert_eq!(
        run_a(code).0,
        4,
        "a hash target must return as an updated owned Instance and be callable again",
    );
}

#[test]
fn drop_resume_clears_reservation_and_leaves_slot_empty() {
    let mut code = Vec::new();
    code.extend_from_slice(&ecalli(OP_HOST_CALL).to_le_bytes()); // CALL B; B yields.
    code.extend_from_slice(&ecalli(OP_DROP_RESUME).to_le_bytes()); // Discard B.
    code.extend_from_slice(&addi(10, 0, MINT_GAS_SENDER_SLOT as i32).to_le_bytes());
    code.extend_from_slice(&addi(11, 0, METER_KEY as i32).to_le_bytes());
    code.extend_from_slice(&addi(12, 0, B_SLOT as i32).to_le_bytes());
    code.extend_from_slice(&ecalli(OP_HOST_YIELD).to_le_bytes()); // Slot is no longer reserved.
    code.extend_from_slice(&ecalli(OP_REPLY).to_le_bytes());

    assert_eq!(
        run_a(code).0,
        4,
        "DROP_RESUME must clear B's reservation while leaving the origin slot empty",
    );
}
