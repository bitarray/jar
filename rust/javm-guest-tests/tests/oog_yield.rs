//! OOG-as-yield (the lazy-load OOG-catch pattern): a metered child that runs out
//! of gas does NOT bubble a fault — the kernel injects a `kernel:oog` yield
//! (payload = the child's `Gas{meter_key}`) routed to a registered receiver. A
//! chain that catches `kernel:oog` tops up the meter via `set_gas_meter` and
//! `CALL_RESUME`s the child, which re-reads its meter and completes.
//!
//! The chain registers `kernel:oog` in its YieldReceiver, funds the child's
//! meter at 0, then CALLs it. With the handler registered the child OOGs, routes
//! to the chain, gets topped up, and the whole thing halts cleanly (reason 4).
//! WITHOUT the registration (the receiver holds a different key) the OOG finds no
//! catcher and bubbles (reason 2) — the host-stub root catch.
//!
//! The chain is straight-line: it unconditionally tops up + resumes (the
//! resumable-CALL handler shape). It threads the topup amount through φ10 (a
//! register, dodging addi's 12-bit immediate limit) and uses addi to reset the
//! syscall operand registers after the CALL. φ7→x10, φ8→x11, φ9→x12, φ10→x13.
//! Gated to the nub Hyperlight host (linux-x86_64).
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

const SENDER_SLOT: u8 = 5; // kernel:set_gas_meter YieldSender
const CHILD_SLOT: u8 = 6; // the metered child
const CHILD_GAS_SLOT: u8 = 8; // Gas{meter_key=0} — child's primary gas slot
const RECEIVER_SLOT: u8 = 9; // chain's YieldReceiver (catches kernel:oog)
const METER_KEY: u8 = 0; // child meter_key == child endpoint == 0
const GAS_BUDGET: u64 = 10_000_000_000;

fn ecalli(imm: u32) -> u32 {
    ((imm & 0xFFF) << 20) | (0b010 << 12) | 0b000_1011
}

/// `addi rd, rs1, imm` (RV opcode 0x13).
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

/// Run the OOG-catch scenario. `catch_oog` controls whether the chain's
/// YieldReceiver registers `kernel:oog`. Returns the top-level `exit_reason`.
fn run(nub: &mut Nub, catch_oog: bool) -> u32 {
    let sender = Cap::Instance(yield_sender(&Key::from(&YK_SET_GAS_METER[..])));
    let sender_h = nub.put_cap(&sender).expect("put sgm sender");
    let gas = Cap::Instance(gas_handle(&Key::from(METER_KEY)));
    let gas_h = nub.put_cap(&gas).expect("put gas handle");

    // The chain's catch-set: kernel:oog (handler present) or a decoy key (absent).
    let recv_key = if catch_oog {
        Key::from(&YK_OOG[..])
    } else {
        Key::from(99u8)
    };
    let receiver = Cap::Instance(yield_receiver(&[recv_key]));
    let receiver_h = nub.put_cap(&receiver).expect("put receiver");

    // The metered child: a bare `reply`, primary gas slot = CHILD_GAS_SLOT.
    let child_img = image(
        ecalli(OP_REPLY).to_le_bytes().to_vec(),
        vec![Key::from(CHILD_GAS_SLOT)],
        None,
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
        .expect("put child");

    let mut cnode = CNodeCap::new();
    for (slot, h) in [
        (SENDER_SLOT, sender_h),
        (CHILD_SLOT, child_h),
        (CHILD_GAS_SLOT, gas_h),
        (RECEIVER_SLOT, receiver_h),
    ] {
        cnode
            .set(&Key::from(slot), Some(CapHashOrRef::Hash(h)))
            .unwrap();
    }
    let cnode_h = nub.put_cap(&Cap::CNode(cnode)).expect("put chain cnode");

    // Chain: fund child at 0; CALL it (it OOGs -> kernel:oog -> resume here);
    // reset φ7/φ8/φ9 for the topup; set_gas_meter(more); resume; reply.
    let mut code = Vec::new();
    code.extend_from_slice(&ecalli(OP_HOST_YIELD).to_le_bytes()); // set_gas_meter(0,0)
    code.extend_from_slice(&addi(10, 0, CHILD_SLOT as i32).to_le_bytes()); // φ7=child slot
    code.extend_from_slice(&ecalli(OP_HOST_CALL).to_le_bytes()); // CALL child
    code.extend_from_slice(&addi(10, 0, SENDER_SLOT as i32).to_le_bytes()); // φ7=sgm sender
    code.extend_from_slice(&addi(11, 0, METER_KEY as i32).to_le_bytes()); // φ8=meter_key (was YIELDED)
    code.extend_from_slice(&addi(12, 13, 0).to_le_bytes()); // φ9=φ10 (topup amount)
    code.extend_from_slice(&ecalli(OP_HOST_YIELD).to_le_bytes()); // set_gas_meter(more)
    code.extend_from_slice(&ecalli(OP_CALL_RESUME).to_le_bytes()); // resume child
    code.extend_from_slice(&ecalli(OP_REPLY).to_le_bytes()); // chain halts
    let chain_img = image(code, Vec::new(), Some(Key::from(RECEIVER_SLOT)));
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
        .expect("put chain");

    // φ7=SENDER, φ8=0 (meter_key + child ep), φ9=0 (initial fund), φ10=topup.
    let args = [SENDER_SLOT as u64, 0, 0, 1_000_000];
    nub.invoke_cached(chain_h, 0, args, GAS_BUDGET)
        .expect("invoke chain")
        .exit_reason
}

#[test]
fn oog_routes_to_chain_handler_and_resumes() {
    let mut nub = Nub::hyperlight().expect("Hyperlight sandbox");

    // With the chain catching kernel:oog: the child OOGs at meter 0, routes to
    // the chain, the chain tops up + resumes, the child completes, and the chain
    // halts cleanly (reason 4). Requires the whole OOG-yield + per-frame-metering
    // + resume-re-reads-meter loop to work.
    assert_eq!(
        run(&mut nub, true),
        4,
        "kernel:oog caught by the chain must top up and resume to a clean halt",
    );

    // Without the registration: the OOG finds no catcher and bubbles (reason 2,
    // the host-stub root catch). Confirms the clean halt above was the routed
    // topup, not the child silently completing.
    assert_eq!(
        run(&mut nub, false),
        2,
        "an uncaught OOG must bubble EXIT_OOG (host-stub root catch)",
    );
}
