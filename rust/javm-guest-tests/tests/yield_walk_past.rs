//! Depth-3 yield routing that walks PAST a non-catching intermediate frame, plus
//! the handler verbs on a routed-past subtree. A (catcher, registers K) CALLs B;
//! B (catches nothing) CALLs C; C host_yields K, which routes past B to A.
//!
//! - CALL_RESUME: A resumes the actual yielder C (not the wedged intermediate
//!   B); C completes, returns up through B to A → clean halt (reason 4). This
//!   exercises the routing walk's skip-and-continue + the correct multi-frame
//!   resume (the depth-2 tests can't reach a walked-past frame).
//! - DROP_RESUME then CALL_RESUME: drop_resume must discard the WHOLE caught
//!   subtree (B and C), leaving A a plain InstanceEntry — so the following
//!   call_resume faults (reason 7). With the buggy single-entry remove, B stays
//!   wedged and the call_resume would resume B instead (reason 4).
//!
//! B threads C's sender slot into φ9 with an `addi` before its host_call
//! (φ9→x12), since the CALL arg convention only forwards φ7/φ8 to a child. Gated
//! to the nub Hyperlight host (linux-x86_64).
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use javm_cap::image::{EndpointDef, Image};
use javm_cap::{yield_receiver, yield_sender, CNodeCap, Cap, CapHashOrRef, Key, NUM_REGS};
use nub::Nub;
use std::collections::BTreeMap;

const OP_REPLY: u32 = 0;
const OP_HOST_YIELD: u32 = 16;
const OP_HOST_CALL: u32 = 26;
const OP_CALL_RESUME: u32 = 27;
const OP_DROP_RESUME: u32 = 28;

const B_SLOT: u8 = 6; // B in A's cnode
const C_SLOT: u8 = 4; // C in A's cnode (inherited by B)
const SENDER_SLOT: u8 = 5; // YieldSender{K} (inherited A→B→C)
const RECEIVER_SLOT: u8 = 9; // A's YieldReceiver (A.yield_receiver_slot)
const YIELD_KEY: u8 = 0x42;
const GAS_BUDGET: u64 = 10_000_000_000;

fn ecalli(imm: u32) -> u32 {
    ((imm & 0xFFF) << 20) | (0b010 << 12) | 0b000_1011
}

/// `addi rd, rs1, imm`. φ9 maps to RV x12.
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

fn image(code: Vec<u8>, yield_receiver_slot: Option<Key>) -> Image {
    let mut img = Image::with_code(code);
    img.endpoints = endpoint0();
    img.yield_receiver_slot = yield_receiver_slot;
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

/// Run the depth-3 walk-past scenario; `handler_ops` are A's handler-continuation
/// ecalls after its `host_call`. Returns the top-level `exit_reason`.
fn run(nub: &mut Nub, handler_ops: &[u32]) -> u32 {
    let sender_h = nub
        .put_cap(&Cap::Instance(yield_sender(&Key::from(YIELD_KEY))))
        .expect("put sender");
    let receiver_h = nub
        .put_cap(&Cap::Instance(yield_receiver(&[Key::from(YIELD_KEY)])))
        .expect("put receiver");

    // C: host_yield(φ7=sender); reply. Empty root cnode (inherits sender from B).
    let mut c_code = Vec::new();
    c_code.extend_from_slice(&ecalli(OP_HOST_YIELD).to_le_bytes());
    c_code.extend_from_slice(&ecalli(OP_REPLY).to_le_bytes());
    let c_h = put_instance(nub, &image(c_code, None), [0u8; 32]);

    // B: addi φ9=SENDER_SLOT; host_call(φ7=C slot, φ8=ep); reply. Catches nothing.
    let mut b_code = Vec::new();
    b_code.extend_from_slice(&addi(12, 0, SENDER_SLOT as i32).to_le_bytes());
    b_code.extend_from_slice(&ecalli(OP_HOST_CALL).to_le_bytes());
    b_code.extend_from_slice(&ecalli(OP_REPLY).to_le_bytes());
    // B's root cnode: C (inherited by C's CALL) — B also inherits A's cnode, but
    // C and the sender live in A's cnode, so an empty B cnode suffices; B inherits
    // C + sender from A at the A→B CALL.
    let b_h = put_instance(nub, &image(b_code, None), [0u8; 32]);

    // A: host_call(φ7=B slot, φ8=ep); <handler_ops>; reply. Catches K.
    let mut a_code = Vec::new();
    a_code.extend_from_slice(&ecalli(OP_HOST_CALL).to_le_bytes());
    for op in handler_ops {
        a_code.extend_from_slice(&ecalli(*op).to_le_bytes());
    }
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
        nub,
        &image(a_code, Some(Key::from(RECEIVER_SLOT))),
        a_cnode_h,
    );

    // φ7=B slot, φ8=ep, φ9=C slot (→ B.φ7), φ10=ep (→ B.φ8).
    let args = [B_SLOT as u64, 0, C_SLOT as u64, 0];
    nub.invoke_cached(a_h, 0, args, GAS_BUDGET)
        .expect("invoke A")
        .exit_reason
}

#[test]
fn walk_past_intermediate_routing() {
    let mut nub = Nub::hyperlight().expect("Hyperlight sandbox");

    // CALL_RESUME: C's yield routes past B to A; A resumes C (the real yielder),
    // C completes and unwinds C→B→A → clean halt (reason 4).
    assert_eq!(
        run(&mut nub, &[OP_CALL_RESUME]),
        4,
        "a yield routed past a non-catching intermediate must resume the actual yielder and halt cleanly",
    );

    // DROP_RESUME then CALL_RESUME: drop_resume discards the whole caught subtree
    // (B and C), leaving A a plain InstanceEntry, so the trailing call_resume has
    // no outstanding yield and faults (reason 7). A single-entry remove would
    // leave B wedged and resume it here → reason 4.
    assert_eq!(
        run(&mut nub, &[OP_DROP_RESUME, OP_CALL_RESUME]),
        7,
        "drop_resume must discard the routed-past subtree so a following call_resume faults",
    );
}
