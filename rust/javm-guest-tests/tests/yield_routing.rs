//! User-key `host_yield` routing + `CALL_RESUME` — the in-flight suspension
//! core. A (top-level) CALLs B (a sub-VM); B `host_yield`s a user-key
//! `YieldSender`; the kernel walks the call stack, skips B's own frames
//! (emitter-exclusion), and routes the yield to the nearest ancestor whose
//! per-CALL snapshotted `YieldReceiver` contains the key — here A. A resumes at
//! its post-CALL continuation, `CALL_RESUME`s B, B halts, and A halts cleanly.
//!
//! A is deliberately STRAIGHT-LINE — `host_call; call_resume; reply` — which is
//! exactly the resumable-CALL handler shape: when B yields, control lands on the
//! instruction *after* A's `host_call` (its `call_resume`), so no PVM-level
//! branching is needed to drive the resume.
//!
//! Positive: A's `YieldReceiver` catches B's key → routed, resumed, clean halt
//! (reason 4). Negative: A's receiver holds a DIFFERENT key → no ancestor
//! catches → the emitter faults (reason 7) — confirms routing actually consults
//! the catch-set rather than blindly resuming.
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
const OP_CALL_RESUME: u32 = 27;

/// A's root-cnode slots.
const B_SLOT: u8 = 6; // the sub-VM B (a published `Cap::Instance`)
const SENDER_SLOT: u8 = 5; // the user-key `YieldSender` (B inherits it)
const RECEIVER_SLOT: u8 = 9; // A's `YieldReceiver` (A.image.yield_receiver_slot)

/// The user yield_key B emits (single byte; first byte != 0xCE so it is NOT a
/// kernel key and routes to an ancestor receiver).
const YIELD_KEY: u8 = 0x42;
const GAS_BUDGET: u64 = 10_000_000_000;

fn ecalli(imm: u32) -> u32 {
    ((imm & 0xFFF) << 20) | (0b010 << 12) | 0b000_1011
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

/// A: `host_call(φ7=B slot, φ8=endpoint); [call_resume();] reply`. The slot/
/// endpoint operands arrive via the invoke args (φ7..φ10). When `resume` is
/// false A omits the `call_resume` — so when B's yield routes to A, A's handler
/// continuation runs straight to REPLY, exercising the handler-halt guard.
fn a_image(resume: bool) -> Image {
    let mut code = Vec::new();
    code.extend_from_slice(&ecalli(OP_HOST_CALL).to_le_bytes());
    if resume {
        code.extend_from_slice(&ecalli(OP_CALL_RESUME).to_le_bytes());
    }
    code.extend_from_slice(&ecalli(OP_REPLY).to_le_bytes());
    image(code, Some(Key::from(RECEIVER_SLOT)))
}

/// B: `host_yield(φ7=sender slot); reply`. φ7 is threaded from A's φ9 by the
/// CALL arg-passing convention.
fn b_image() -> Image {
    let mut code = Vec::new();
    code.extend_from_slice(&ecalli(OP_HOST_YIELD).to_le_bytes());
    code.extend_from_slice(&ecalli(OP_REPLY).to_le_bytes());
    image(code, None)
}

/// Run the routing scenario with A's receiver registering `receiver_key` and A
/// resuming B iff `resume`. Returns A's `(exit_reason, exit_arg)`.
fn run(nub: &mut Nub, receiver_key: u8, resume: bool) -> (u32, u32) {
    // The user-key YieldSender B will emit, and A's YieldReceiver.
    let sender = Cap::Instance(yield_sender(&Key::from(YIELD_KEY)));
    let sender_h = nub.put_cap(&sender).expect("put sender");
    let receiver = Cap::Instance(yield_receiver(&[Key::from(receiver_key)]));
    let receiver_h = nub.put_cap(&receiver).expect("put receiver");

    // B: a published sub-VM with an empty root cnode (it inherits A's cnode
    // entries — including the YieldSender at SENDER_SLOT — at CALL).
    let b_img = b_image();
    let b_image_h = nub
        .put_cap(&Cap::image_with_slots(&b_img, &[], &[]).expect("b image"))
        .expect("put b image");
    let b_mem = b_img.instance_mem_backing();
    let b_inst_h = nub
        .put_cap(&Cap::instance_with_mem(
            [0u8; 32],
            b_image_h,
            [0u8; 32],
            b_mem,
            [0u64; NUM_REGS],
            0,
            0,
        ))
        .expect("put b instance");

    // A's root cnode: B at B_SLOT, the YieldSender at SENDER_SLOT, A's
    // YieldReceiver at RECEIVER_SLOT (named by A's image yield_receiver_slot).
    let mut a_cnode = CNodeCap::new();
    a_cnode
        .set(&Key::from(B_SLOT), Some(CapHashOrRef::Hash(b_inst_h)))
        .expect("set B");
    a_cnode
        .set(&Key::from(SENDER_SLOT), Some(CapHashOrRef::Hash(sender_h)))
        .expect("set sender");
    a_cnode
        .set(
            &Key::from(RECEIVER_SLOT),
            Some(CapHashOrRef::Hash(receiver_h)),
        )
        .expect("set receiver");
    let a_cnode_h = nub.put_cap(&Cap::CNode(a_cnode)).expect("put A cnode");

    let a_img = a_image(resume);
    let a_image_h = nub
        .put_cap(&Cap::image_with_slots(&a_img, &[], &[]).expect("a image"))
        .expect("put a image");
    let a_mem = a_img.instance_mem_backing();
    let a_inst_h = nub
        .put_cap(&Cap::instance_with_mem(
            [0u8; 32],
            a_image_h,
            a_cnode_h,
            a_mem,
            [0u64; NUM_REGS],
            0,
            0,
        ))
        .expect("put a instance");

    // Invoke args → A.φ7..φ10: φ7=B slot, φ8=B endpoint, φ9=sender slot
    // (becomes B.φ7), φ10 unused.
    let args = [B_SLOT as u64, 0, SENDER_SLOT as u64, 0];
    let result = nub
        .invoke_cached(a_inst_h, 0, args, GAS_BUDGET)
        .expect("invoke_cached");
    (result.exit_reason, result.exit_arg)
}

/// A top-level instance that does `call_resume; reply` with no outstanding
/// yield — exercises the CALL_RESUME guard (the top is an InstanceEntry, not a
/// handler activation). Returns `(exit_reason, exit_arg)`.
fn run_bare_call_resume(nub: &mut Nub) -> (u32, u32) {
    let mut code = Vec::new();
    code.extend_from_slice(&ecalli(OP_CALL_RESUME).to_le_bytes());
    code.extend_from_slice(&ecalli(OP_REPLY).to_le_bytes());
    let img = image(code, None);
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
    let result = nub
        .invoke_cached(inst_h, 0, [0; 4], GAS_BUDGET)
        .expect("invoke_cached");
    (result.exit_reason, result.exit_arg)
}

/// Error code the call loop packs into `exit_arg` when a handler activation
/// HALTs/REPLYs without resuming its yielder (the deferred multi-frame unwind).
const ERR_HANDLER_HALT: u32 = 72;

#[test]
fn user_key_yield_routes_to_ancestor_and_resumes() {
    let mut nub = Nub::new_hyperlight().expect("Hyperlight sandbox");

    // Positive: A's receiver registers YIELD_KEY, so B's yield routes to A
    // (skipping B's frames), A resumes B, B halts, A halts cleanly (reason 4 —
    // the trailing REPLY). A trap/unhandled here would change the reason.
    let (reason, _) = run(&mut nub, YIELD_KEY, true);
    assert_eq!(
        reason, 4,
        "a user-key yield caught by an ancestor must route, resume, and halt cleanly, got reason={reason}",
    );

    // Negative: A's receiver registers a DIFFERENT key, so no ancestor catches
    // B's yield → the emitter faults (reason 7). Confirms routing consults the
    // snapshotted catch-set, so the positive isn't a false pass.
    let (reason, _) = run(&mut nub, YIELD_KEY.wrapping_add(1), true);
    assert_eq!(
        reason, 7,
        "a user-key yield no ancestor catches must fault the emitter (7), got reason={reason}",
    );

    // Handler-halt guard: A catches B's yield but REPLYs without `call_resume`.
    // Folding A's HALT up while B waits is the deferred multi-frame unwind → a
    // clean trap (reason 7, exit_arg = ERR_HANDLER_HALT) rather than a panic.
    let (reason, arg) = run(&mut nub, YIELD_KEY, false);
    assert_eq!(
        (reason, arg),
        (7, ERR_HANDLER_HALT),
        "a handler that halts without resuming must trap with ERR_HANDLER_HALT, got reason={reason} arg={arg}",
    );

    // CALL_RESUME guard: a top-level instance with no outstanding yield faults
    // (the top is an InstanceEntry, not a handler activation).
    let (reason, _) = run_bare_call_resume(&mut nub);
    assert_eq!(
        reason, 7,
        "call_resume with no outstanding yield must fault (7), got reason={reason}",
    );
}
