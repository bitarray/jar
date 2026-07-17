//! Ordered Image gas slots: empty slots are skipped, present invalid slots are
//! hard faults, usable meters are exhausted in order before `kernel:oog`, and
//! the OOG resume path returns to the primary usable meter.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use javm::Nub;
use javm_cap::image::{EndpointDef, Image};
use javm_cap::yield_cap::{YK_OOG, YK_SET_GAS_METER};
use javm_cap::{
    gas_handle, yield_receiver, yield_sender, CNodeCap, Cap, CapHashOrRef, Key, NUM_REGS,
};
use std::collections::BTreeMap;

const OP_REPLY: u32 = 0;
const OP_HOST_YIELD: u32 = 16;
const OP_HOST_CALL: u32 = 26;
const OP_CALL_RESUME: u32 = 27;

const SENDER_SLOT: u8 = 5;
const CHILD_SLOT: u8 = 6;
const GAS_SLOT_A: u8 = 8;
const GAS_SLOT_B: u8 = 9;
const EMPTY_SLOT: u8 = 10;
const INVALID_SLOT: u8 = 11;
const RECEIVER_SLOT: u8 = 12;
const METER_A: u8 = 0;
const METER_B: u8 = 1;
const GAS_BUDGET: u64 = 10_000_000_000;
const FUNDED: u64 = 1_000_000;

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

fn put_instance(nub: &mut Nub, img: &Image, cnode_h: [u8; 32]) -> javm::AbiCapHash {
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

fn emit_set_meter(code: &mut Vec<u8>, meter: u8, funded: bool) {
    code.extend_from_slice(&addi(10, 0, SENDER_SLOT as i32).to_le_bytes());
    code.extend_from_slice(&addi(11, 0, meter as i32).to_le_bytes());
    if funded {
        code.extend_from_slice(&addi(12, 13, 0).to_le_bytes());
    } else {
        code.extend_from_slice(&addi(12, 0, 0).to_le_bytes());
    }
    code.extend_from_slice(&ecalli(OP_HOST_YIELD).to_le_bytes());
}

fn run_child(
    nub: &mut Nub,
    gas_slots: Vec<Key>,
    install_a: bool,
    install_b: bool,
    install_invalid: bool,
    meter_sets: &[(u8, bool)],
    catch_oog_and_topup_primary: bool,
) -> (u32, u32) {
    let set_gas_sender_h = nub
        .put_cap(&Cap::Instance(yield_sender(&Key::from(
            &YK_SET_GAS_METER[..],
        ))))
        .expect("put set_gas sender");
    let invalid_h = nub
        .put_cap(&Cap::Instance(yield_sender(&Key::from(0x44u8))))
        .expect("put invalid gas cap");

    let child_img = image(ecalli(OP_REPLY).to_le_bytes().to_vec(), gas_slots, None);
    let child_h = put_instance(nub, &child_img, [0u8; 32]);

    let mut cnode = CNodeCap::new();
    cnode
        .set(
            &Key::from(SENDER_SLOT),
            Some(CapHashOrRef::Hash(set_gas_sender_h)),
        )
        .unwrap();
    cnode
        .set(&Key::from(CHILD_SLOT), Some(CapHashOrRef::Hash(child_h)))
        .unwrap();
    if install_a {
        let gas_h = nub
            .put_cap(&Cap::Instance(gas_handle(&Key::from(METER_A))))
            .expect("put gas A");
        cnode
            .set(&Key::from(GAS_SLOT_A), Some(CapHashOrRef::Hash(gas_h)))
            .unwrap();
    }
    if install_b {
        let gas_h = nub
            .put_cap(&Cap::Instance(gas_handle(&Key::from(METER_B))))
            .expect("put gas B");
        cnode
            .set(&Key::from(GAS_SLOT_B), Some(CapHashOrRef::Hash(gas_h)))
            .unwrap();
    }
    if install_invalid {
        cnode
            .set(
                &Key::from(INVALID_SLOT),
                Some(CapHashOrRef::Hash(invalid_h)),
            )
            .unwrap();
    }
    if catch_oog_and_topup_primary {
        let receiver_h = nub
            .put_cap(&Cap::Instance(yield_receiver(&[Key::from(&YK_OOG[..])])))
            .expect("put receiver");
        cnode
            .set(
                &Key::from(RECEIVER_SLOT),
                Some(CapHashOrRef::Hash(receiver_h)),
            )
            .unwrap();
    }
    let cnode_h = nub.put_cap(&Cap::CNode(cnode)).expect("put cnode");

    let mut code = Vec::new();
    for (meter, funded) in meter_sets {
        emit_set_meter(&mut code, *meter, *funded);
    }
    code.extend_from_slice(&addi(10, 0, CHILD_SLOT as i32).to_le_bytes());
    code.extend_from_slice(&addi(11, 0, 0).to_le_bytes());
    code.extend_from_slice(&ecalli(OP_HOST_CALL).to_le_bytes());
    if catch_oog_and_topup_primary {
        emit_set_meter(&mut code, METER_A, true);
        code.extend_from_slice(&ecalli(OP_CALL_RESUME).to_le_bytes());
    }
    code.extend_from_slice(&ecalli(OP_REPLY).to_le_bytes());

    let receiver_slot = catch_oog_and_topup_primary.then_some(Key::from(RECEIVER_SLOT));
    let chain_img = image(code, Vec::new(), receiver_slot);
    let chain_h = put_instance(nub, &chain_img, cnode_h);
    let r = nub
        .invoke_cached(chain_h, 0, [0, 0, 0, FUNDED], GAS_BUDGET)
        .expect("invoke chain");
    (r.exit_reason, r.exit_arg)
}

#[test]
fn empty_first_slot_skips_to_later_valid_meter() {
    let mut nub = Nub::hyperlight().expect("Hyperlight sandbox");
    assert_eq!(
        run_child(
            &mut nub,
            vec![Key::from(EMPTY_SLOT), Key::from(GAS_SLOT_B)],
            false,
            true,
            false,
            &[(METER_B, true)],
            false,
        )
        .0,
        4,
        "an empty declared gas slot must be skipped in favor of the later valid meter",
    );
}

#[test]
fn exhausted_first_meter_falls_through_to_second_meter() {
    let mut nub = Nub::hyperlight().expect("Hyperlight sandbox");
    assert_eq!(
        run_child(
            &mut nub,
            vec![Key::from(GAS_SLOT_A), Key::from(GAS_SLOT_B)],
            true,
            true,
            false,
            &[(METER_A, false), (METER_B, true)],
            false,
        )
        .0,
        4,
        "OOG on the first usable gas slot must consult the second before yielding kernel:oog",
    );
}

#[test]
fn invalid_non_empty_gas_slot_hard_faults() {
    let mut nub = Nub::hyperlight().expect("Hyperlight sandbox");
    assert_eq!(
        run_child(
            &mut nub,
            vec![Key::from(INVALID_SLOT)],
            false,
            false,
            true,
            &[],
            false,
        ),
        (u32::MAX, 73),
        "a present non-Gas cap in gas_slots must hard fault",
    );
}

#[test]
fn all_empty_declared_gas_slots_hard_fault() {
    let mut nub = Nub::hyperlight().expect("Hyperlight sandbox");
    assert_eq!(
        run_child(
            &mut nub,
            vec![Key::from(EMPTY_SLOT)],
            false,
            false,
            false,
            &[],
            false,
        ),
        (u32::MAX, 72),
        "declaring only empty gas slots leaves no primary OOG payload and must hard fault",
    );
}

#[test]
fn exhausted_all_meters_oog_resumes_from_primary() {
    let mut nub = Nub::hyperlight().expect("Hyperlight sandbox");
    assert_eq!(
        run_child(
            &mut nub,
            vec![Key::from(GAS_SLOT_A), Key::from(GAS_SLOT_B)],
            true,
            true,
            false,
            &[(METER_A, false), (METER_B, false)],
            true,
        )
        .0,
        4,
        "after all meters exhaust, OOG must carry/reset to the primary so a primary top-up resumes",
    );
}
