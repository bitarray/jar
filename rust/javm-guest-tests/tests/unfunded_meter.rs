//! A child that DECLARES a primary gas meter (`gas_slots` → `Gas{k}`) but whose meter
//! `k` was never funded (no `set_gas_meter`) runs metered on an EFFECTIVE-ZERO
//! balance and OOGs immediately — it must NOT silently loan and spend the
//! caller's pool. (Spec: an absent meter entry == balance 0; only an instance
//! with NO gas slot loans the caller's pool.)
//!
//! Regression for the validation finding "never-funded meter loans the caller
//! pool". Control: the same child with NO gas slot loans and completes.
//!
//! Gated to the nub Hyperlight host (linux-x86_64).
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use javm::Nub;
use javm_cap::image::{EndpointDef, Image};
use javm_cap::{gas_handle, CNodeCap, Cap, CapHashOrRef, Key, NUM_REGS};
use std::collections::BTreeMap;

const OP_REPLY: u32 = 0;
const OP_HOST_CALL: u32 = 26;
const CHILD_SLOT: u8 = 6;
const CHILD_GAS_SLOT: u8 = 8;
const METER_KEY: u8 = 0;
const GAS_BUDGET: u64 = 10_000_000_000;

fn ecalli(imm: u32) -> u32 {
    ((imm & 0xFFF) << 20) | (0b010 << 12) | 0b000_1011
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

fn image(code: Vec<u8>, gas_slots: Vec<Key>) -> Image {
    let mut img = Image::with_code(code);
    img.endpoints = endpoint0();
    img.gas_slots = gas_slots;
    img
}

/// Run a chain (top frame, host-budgeted) that CALLs a `reply` child. If
/// `declare_meter` the child declares a primary gas slot → an UNFUNDED `Gas{0}`;
/// otherwise it declares no gas slot. Returns the top-level `exit_reason`.
fn run(nub: &mut Nub, declare_meter: bool) -> u32 {
    let gas_slots = if declare_meter {
        vec![Key::from(CHILD_GAS_SLOT)]
    } else {
        Vec::new()
    };
    let child_img = image(ecalli(OP_REPLY).to_le_bytes().to_vec(), gas_slots);
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

    // Chain cnode: the child + (when declared) an UNFUNDED Gas{0} handle the
    // child inherits at CALL. No set_gas_meter is ever emitted.
    let mut cnode = CNodeCap::new();
    cnode
        .set(&Key::from(CHILD_SLOT), Some(CapHashOrRef::Hash(child_h)))
        .unwrap();
    if declare_meter {
        let gas_h = nub
            .put_cap(&Cap::Instance(gas_handle(&Key::from(METER_KEY))))
            .expect("put gas handle");
        cnode
            .set(&Key::from(CHILD_GAS_SLOT), Some(CapHashOrRef::Hash(gas_h)))
            .unwrap();
    }
    let cnode_h = nub.put_cap(&Cap::CNode(cnode)).expect("put chain cnode");

    // Chain: host_call(child); reply.
    let mut code = Vec::new();
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
        .expect("put chain");

    // φ7=child slot, φ8=endpoint 0.
    nub.invoke_cached(chain_h, 0, [CHILD_SLOT as u64, 0, 0, 0], GAS_BUDGET)
        .expect("invoke chain")
        .exit_reason
}

#[test]
fn unfunded_declared_meter_oogs_not_loans() {
    let mut nub = Nub::hyperlight().expect("Hyperlight sandbox");

    // Declared-but-unfunded meter: the child runs metered@0 and OOGs; with no
    // kernel:oog receiver it bubbles (reason 2). If it had instead loaned the
    // chain's (large) pool it would complete (reason 4) — that is the bug.
    assert_eq!(
        run(&mut nub, true),
        2,
        "a declared-but-unfunded meter must run @0 and OOG, not loan the caller pool",
    );

    // Control: NO gas slot → the child loans the chain's pool and completes
    // (reason 4). Confirms the OOG above is specifically the metered-@0 behavior,
    // not the child failing for an unrelated reason.
    assert_eq!(
        run(&mut nub, false),
        4,
        "a child with no gas slot loans the caller pool and completes",
    );
}
