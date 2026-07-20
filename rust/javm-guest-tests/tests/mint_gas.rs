//! `kernel:mint_gas` / `kernel:mint_quota` inline syscalls (via `host_yield`):
//! a guest places a `kernel:mint_gas` (or `kernel:mint_quota`) YieldSender in a
//! slot and yields it; the kernel, as the implicit ROOT receiver, mints a
//! `Gas{meter_key}` (or `Quota{quota_key}`) unit handle into the requested slot
//! INLINE and the guest resumes — pure-cap syscalls in the same family as
//! `kernel:mint_yield`.
//!
//! Positive: a `kernel:mint_gas` / `kernel:mint_quota` yield into a free slot
//! runs and the guest halts cleanly (reason 4). Negative: minting into a PINNED
//! slot traps (reason 7) — confirms the op validates its dst.
//!
//! The mint_gas/mint_quota YieldSenders are `Cap::Instance`s, so they reach the
//! guest via the instance's root cnode (see `root_cnode_seeding`). Gated to the
//! nub Hyperlight host (linux-x86_64).
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use javm::Nub;
use javm_cap::image::{EndpointDef, Image, ImageBuilder};
use javm_cap::yield_cap::{YK_MINT_GAS, YK_MINT_QUOTA};
use javm_cap::{yield_sender, CNodeCap, Cap, CapHashOrRef, Key, NUM_REGS};
use std::collections::BTreeMap;

const OP_HOST_YIELD: u32 = 16;
const OP_REPLY: u32 = 0;
/// Root-cnode slot holding the mint_gas / mint_quota YieldSender.
const SENDER_SLOT: u8 = 5;
/// The meter_key / quota_key byte the guest asks the kernel to name.
const KEY_BYTE: u8 = 7;
/// A free dst slot for the minted handle (the positive case).
const FREE_DST: u8 = 6;
/// A pinned dst slot (holds a `Cap::Data`) — the negative case.
const PINNED_DST: u8 = 66;
const GAS_BUDGET: u64 = 10_000_000_000;

fn ecalli(imm: u32) -> u32 {
    ((imm & 0xFFF) << 20) | (0b010 << 12) | 0b000_1011
}

/// Image: `host_yield(φ7=sender, φ8=key, φ9=dst); reply`, with a pinned
/// `Cap::Data` at PINNED_DST so the negative run targets a read-only slot.
fn prog_image() -> Image {
    let mut code = Vec::new();
    code.extend_from_slice(&ecalli(OP_HOST_YIELD).to_le_bytes());
    code.extend_from_slice(&ecalli(OP_REPLY).to_le_bytes());
    ImageBuilder::new()
        .code(code)
        .endpoint(
            Key::from(0u8),
            EndpointDef {
                entry_pc: 0,
                arg_registers: 0,
                arg_cnode_size: 0,
                initial_regs: BTreeMap::new(),
            },
        )
        .pinned_data(Key::from(PINNED_DST), vec![0xAB; 16], 4096)
        .build()
}

/// Invoke the program: `mint_key` selects mint_gas vs mint_quota; `dst` is the
/// handle destination slot. Returns `(exit_reason, exit_arg)`.
fn run(nub: &mut Nub, mint_key: &[u8], dst: u8) -> (u32, u32) {
    let sender = Cap::Instance(yield_sender(&Key::from(mint_key)));
    let sender_h = nub.put_cap(&sender).expect("put mint sender");

    let mut cnode = CNodeCap::new();
    cnode
        .set(&Key::from(SENDER_SLOT), Some(CapHashOrRef::Hash(sender_h)))
        .expect("set sender slot");
    let cnode_h = nub.put_cap(&Cap::CNode(cnode)).expect("put root cnode");

    let img = prog_image();
    let data_h = nub
        .put_cap(&Cap::data_inline_with_size(&[0xAB; 16], 4096))
        .expect("put pinned data");
    let image_h = nub
        .put_cap(
            &Cap::image_with_slots(&img, &[(Key::from(PINNED_DST), data_h)], &[]).expect("image"),
        )
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

    let args = [SENDER_SLOT as u64, KEY_BYTE as u64, dst as u64, 0];
    let result = nub
        .invoke_cached(inst_h, 0, args, GAS_BUDGET)
        .expect("invoke_cached");
    (result.exit_reason, result.exit_arg)
}

#[test]
fn mint_gas_and_quota_via_kernel_root() {
    let mut nub = Nub::hyperlight().expect("Hyperlight sandbox");

    // Positive: kernel:mint_gas into a free slot is handled inline and resumes
    // → clean halt (reason 4, arg 0 — the trailing REPLY).
    let (reason, arg) = run(&mut nub, &YK_MINT_GAS[..], FREE_DST);
    assert_eq!(
        (reason, arg),
        (4, 0),
        "kernel:mint_gas must mint inline and resume, got reason={reason} arg={arg}",
    );

    // kernel:mint_quota into a free slot — same inline path, different handle.
    let (reason, arg) = run(&mut nub, &YK_MINT_QUOTA[..], FREE_DST);
    assert_eq!(
        (reason, arg),
        (4, 0),
        "kernel:mint_quota must mint inline and resume, got reason={reason} arg={arg}",
    );

    // Negative: minting into a PINNED slot traps (reason 7) — confirms the op
    // rejects a read-only dst, so the positives aren't false passes.
    let (reason, _) = run(&mut nub, &YK_MINT_GAS[..], PINNED_DST);
    assert_eq!(
        reason, 7,
        "kernel:mint_gas into a pinned dst must trap (7), got reason={reason}",
    );
}
