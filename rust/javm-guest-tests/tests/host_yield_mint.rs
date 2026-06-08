//! `host_yield` (op 16) with the kernel as the implicit ROOT receiver: a guest
//! places a `kernel:mint_yield` YieldSender in a slot and yields it; the kernel
//! handles the syscall INLINE (mints a YieldSender/YieldReceiver pair into the
//! requested slots) and the guest resumes at the next instruction — the
//! "system call through yield to the kernel" path.
//!
//! Positive: a valid `kernel:mint_yield` yield runs and the guest halts
//! cleanly. Negative: an empty sender slot traps (the op validates its sender).
//!
//! The mint_yield YieldSender is a `Cap::Instance`, so it reaches the guest via
//! the instance's root cnode (see `root_cnode_seeding`). Gated to the nub
//! Hyperlight host (linux-x86_64).
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use javm_cap::image::{EndpointDef, Image};
use javm_cap::yield_cap::YK_MINT_YIELD;
use javm_cap::{yield_sender, CNodeCap, Cap, CapHashOrRef, Key, NUM_REGS};
use nub::Nub;
use std::collections::BTreeMap;

const OP_HOST_YIELD: u32 = 16;
const OP_REPLY: u32 = 0;
/// Root-cnode slot holding the `kernel:mint_yield` YieldSender.
const SENDER_SLOT: u8 = 5;
/// New yield_key (a single user byte) the guest asks the kernel to mint.
const NEW_KEY: u8 = 50;
/// Where the kernel writes the minted YieldSender / YieldReceiver.
const SENDER_DST: u8 = 6;
const RECEIVER_DST: u8 = 7;
/// An empty slot — the negative control sender.
const EMPTY_SLOT: u8 = 9;
const GAS_BUDGET: u64 = 10_000_000_000;

fn ecalli(imm: u32) -> u32 {
    ((imm & 0xFFF) << 20) | (0b010 << 12) | 0b000_1011
}

/// Image: `host_yield(φ7=sender, φ8=new key, φ9=sender dst, φ10=recv dst)`
/// then `REPLY`.
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
    code.extend_from_slice(&ecalli(OP_HOST_YIELD).to_le_bytes());
    code.extend_from_slice(&ecalli(OP_REPLY).to_le_bytes());
    let mut img = Image::with_code(code);
    img.endpoints = endpoints;
    img
}

/// Invoke the program with the given sender slot; return (exit_reason,
/// exit_arg). The published instance's root cnode holds a `kernel:mint_yield`
/// YieldSender at `SENDER_SLOT`.
fn run(nub: &mut Nub, sender_slot: u8) -> (u32, u32) {
    // The kernel:mint_yield YieldSender (a Cap::Instance), placed in the root
    // cnode so it reaches the guest.
    let mint = Cap::Instance(yield_sender(&Key::from(&YK_MINT_YIELD[..])));
    let mint_h = nub.put_cap(&mint).expect("put mint_yield sender");

    let mut cnode = CNodeCap::new();
    cnode
        .set(&Key::from(SENDER_SLOT), Some(CapHashOrRef::Hash(mint_h)))
        .expect("set sender slot");
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

    let args = [
        sender_slot as u64,
        NEW_KEY as u64,
        SENDER_DST as u64,
        RECEIVER_DST as u64,
    ];
    let result = nub
        .invoke_cached(inst_h, 0, args, GAS_BUDGET)
        .expect("invoke_cached");
    (result.exit_reason, result.exit_arg)
}

#[test]
fn host_yield_mint_yield_via_kernel_root() {
    let mut nub = Nub::hyperlight().expect("Hyperlight sandbox");

    // Positive: yielding the kernel:mint_yield sender runs the syscall inline;
    // the guest resumes and halts cleanly (reason 4, arg 0 — the trailing
    // REPLY). A trap or unhandled error here would change the reason.
    let (reason, arg) = run(&mut nub, SENDER_SLOT);
    assert_eq!(
        (reason, arg),
        (4, 0),
        "kernel:mint_yield must be handled inline and resume (clean halt), got reason={reason} arg={arg}",
    );

    // Negative: an empty sender slot makes host_yield trap (reason 7) —
    // confirms the op validates its YieldSender, so the positive isn't a false
    // pass.
    let (reason, _) = run(&mut nub, EMPTY_SLOT);
    assert_eq!(
        reason, 7,
        "host_yield with an empty sender slot must trap (7), got reason={reason}",
    );
}
