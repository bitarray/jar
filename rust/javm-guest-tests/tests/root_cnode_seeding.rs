//! The guest `frame.cnode` is seeded from the instance's **root cnode**, so a
//! `Cap::Instance` — which cannot be pinned (pinned slots are Data/Image only)
//! — flows into a guest slot. This is the prerequisite for cap-flow of
//! YieldSenders / sub-VM handles / authority caps into running instances.
//!
//! Validated via `host_image_hash_chain` (op 20): it reads the cap at a slot,
//! so a clean halt on a slot holding a root-cnode `Cap::Instance` proves the
//! cap was visible; an empty slot traps (negative control — the op traps on an
//! absent src).
//!
//! Gated to the nub Hyperlight host (linux-x86_64).
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use javm::Nub;
use javm_cap::image::{EndpointDef, Image};
use javm_cap::{CNodeCap, Cap, CapHashOrRef, DataCap, Key, NUM_REGS};
use std::collections::BTreeMap;

const OP_IMAGE_HASH_CHAIN: u32 = 20;
const OP_REPLY: u32 = 0;
/// Root-cnode slot holding a `Cap::Instance` (a non-pinnable cap).
const INSTANCE_SLOT: u8 = 5;
/// An empty (unseeded) slot — the negative control.
const EMPTY_SLOT: u8 = 7;
/// Destination for the minted identity DataCap.
const DST_SLOT: u8 = 6;
const GAS_BUDGET: u64 = 10_000_000_000;

fn ecalli(imm: u32) -> u32 {
    ((imm & 0xFFF) << 20) | (0b010 << 12) | 0b000_1011
}

/// Image: `host_image_hash_chain(φ7=src, φ8=dst)` then `REPLY`.
fn prog_image() -> Image {
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
    code.extend_from_slice(&ecalli(OP_IMAGE_HASH_CHAIN).to_le_bytes());
    code.extend_from_slice(&ecalli(OP_REPLY).to_le_bytes());
    let mut img = Image::with_code(code);
    img.endpoints = endpoints;
    img
}

/// Invoke the program with the given src slot; return (exit_reason, exit_arg).
/// The published instance's root cnode holds a `Cap::Instance` at
/// `INSTANCE_SLOT`.
fn run(nub: &mut Nub, src: u8) -> (u32, u32) {
    // A payload Cap::Instance to live in the root cnode (any instance; its
    // identity is what host_image_hash_chain reads).
    let payload = Cap::instance_with_mem(
        [0xAA; 32],
        [0u8; 32],
        [0u8; 32],
        DataCap::empty(),
        [0u64; NUM_REGS],
        0,
        0,
    );
    let payload_h = nub.put_cap(&payload).expect("put payload instance");

    // Root cnode: the payload instance at INSTANCE_SLOT (a non-pinnable cap).
    let mut cnode = CNodeCap::new();
    cnode
        .set(
            &Key::from(INSTANCE_SLOT),
            Some(CapHashOrRef::Hash(payload_h)),
        )
        .expect("set root cnode slot");
    let cnode_h = nub.put_cap(&Cap::CNode(cnode)).expect("put root cnode");

    let img = prog_image();
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

    let result = nub
        .invoke_cached(inst_h, 0, [src as u64, DST_SLOT as u64, 0, 0], GAS_BUDGET)
        .expect("invoke_cached");
    (result.exit_reason, result.exit_arg)
}

#[test]
fn root_cnode_instance_is_visible_to_guest() {
    let mut nub = Nub::hyperlight().expect("Hyperlight sandbox");

    // Positive: the root-cnode Cap::Instance at INSTANCE_SLOT is visible, so
    // host_image_hash_chain reads it and the guest halts cleanly (reason 4,
    // arg 0 — the trailing REPLY).
    let (reason, arg) = run(&mut nub, INSTANCE_SLOT);
    assert_eq!(
        (reason, arg),
        (4, 0),
        "root-cnode Cap::Instance must be visible (clean halt), got reason={reason} arg={arg}",
    );

    // Negative control: an empty slot traps (reason 7) — confirms the op does
    // fault on an absent src, so the positive result isn't a false pass.
    let (reason, _) = run(&mut nub, EMPTY_SLOT);
    assert_eq!(
        reason, 7,
        "host_image_hash_chain on an empty slot must trap (7), got reason={reason}",
    );
}
