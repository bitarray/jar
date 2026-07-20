//! `host_image_hash_chain` (op 20): read a cap's kernel-attested type identity
//! (an Instance's cumulative `image_hash_chain`, or — as here — an Image's
//! content hash) and write a `Cap::Data` of its 32 raw bytes at `dst`.
//!
//! This op reclaims the removed `HOST_SAME_TYPE`/`HOST_TYPE_OF` ABI slots: with
//! `Cap::Type` gone, type identity is read as plain bytes and compared in
//! userspace (memcmp), so there is no separate type cap kind or same-type op.
//!
//! Two cases, mirroring `derive_spawn_pinned`'s trap-discipline check:
//!   1. writing the result into a PINNED dst slot TRAPs (exit_reason 7), and
//!   2. a valid call (src = pinned Cap::Image, dst = empty mutable slot) runs
//!      and HALTs cleanly via the trailing `ecalli 0` (exit_reason 4, arg 0).
//!
//! Gated to the nub Hyperlight host (linux-x86_64), like the other guest tests.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use javm::Nub;
use javm_cap::image::{EndpointDef, Image, ImageBuilder};
use javm_cap::{Cap, CapHash, Key, NUM_REGS};
use std::collections::BTreeMap;

const OP_IMAGE_HASH_CHAIN: u32 = 20;
const OP_REPLY: u32 = 0;
/// A pinned `Cap::Image` slot — a valid `src` (read its content-hash identity).
const IMAGE_SLOT: u8 = 3;
/// A pinned `Cap::Data` slot — an illegal `dst` (write must trap).
const PINNED_DST: u8 = 66;
/// An empty, unpinned slot — a legal `dst`.
const NORMAL_DST: u8 = 5;
const GAS_BUDGET: u64 = 10_000_000_000;

/// custom-0 `ecalli imm` encoding (funct3=010, opcode=0x0b), mirroring the
/// transpiler's `encode_custom0_ecalli`.
fn ecalli(imm: u32) -> u32 {
    ((imm & 0xFFF) << 20) | (0b010 << 12) | 0b000_1011
}

/// The child image pinned at `IMAGE_SLOT` — minimal; never executed (it is only
/// read as the `host_image_hash_chain` source).
fn child_image() -> Image {
    Image::empty()
}

/// Parent image: `ecalli OP_IMAGE_HASH_CHAIN` then `ecalli OP_REPLY` (clean
/// halt). `IMAGE_SLOT` is a pinned `Cap::Image` (the src); `PINNED_DST` is a
/// pinned `Cap::Data`. Endpoint args φ[7]=src, φ[8]=dst.
fn parent_image(child_hash: CapHash) -> Image {
    let mut code = Vec::new();
    code.extend_from_slice(&ecalli(OP_IMAGE_HASH_CHAIN).to_le_bytes());
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
        .pinned_image(Key::from(IMAGE_SLOT), child_hash)
        .pinned_data(Key::from(PINNED_DST), vec![0xAB; 16], 4096)
        .build()
}

/// Publish the parent instance and invoke endpoint 0 with the given
/// (src, dst) slot args, returning the JIT exit_reason / exit_arg.
///
/// `Nub::hyperlight()` reserves a fixed host VA range, so only one sandbox
/// can exist at a time; the single `#[test]` below threads one `nub` through
/// both cases (the harness would otherwise race two sandboxes — see
/// `conformance.rs`'s shared-sandbox note).
fn run(nub: &mut Nub, src: u8, dst: u8) -> (u32, u32) {
    let child_cap = Cap::image_with_slots(&child_image(), &[], &[]).expect("child image");
    let child_hash = nub.put_cap(&child_cap).expect("put child image");
    let data_hash = nub
        .put_cap(&Cap::data_inline_with_size(&[0xAB; 16], 4096))
        .expect("put pinned data");

    let parent = parent_image(child_hash);
    let pinned_hashes = [
        (Key::from(IMAGE_SLOT), child_hash),
        (Key::from(PINNED_DST), data_hash),
    ];
    let parent_cap = Cap::image_with_slots(&parent, &pinned_hashes, &[]).expect("parent image");
    let image_h = nub.put_cap(&parent_cap).expect("put parent image");
    let cnode_h = nub.put_cap(&Cap::empty_cnode()).expect("put cnode");

    let mem = parent.instance_mem_backing();
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
        .invoke_cached(inst_h, 0, [src as u64, dst as u64, 0, 0], GAS_BUDGET)
        .expect("invoke_cached");
    (result.exit_reason, result.exit_arg)
}

#[test]
fn image_hash_chain_traps_on_pinned_and_halts_on_valid() {
    let mut nub = Nub::hyperlight().expect("Hyperlight sandbox");

    // 1. Writing the identity DataCap into a PINNED dst slot traps.
    // JIT codegen ABI: `ExitReason::Trap` surfaces as exit_reason 7.
    const EXIT_TRAP: u32 = 7;
    let (reason, arg) = run(&mut nub, IMAGE_SLOT, PINNED_DST);
    assert_eq!(
        reason, EXIT_TRAP,
        "host_image_hash_chain into a pinned dst must Trap (7), got reason={reason} arg={arg}",
    );

    // 2. A valid call runs, writes the identity DataCap, and reaches the
    // trailing `ecalli 0` (REPLY/HALT) — surfaced by the JIT as HostCall(0):
    // reason 4, arg 0.
    let (reason, arg) = run(&mut nub, IMAGE_SLOT, NORMAL_DST);
    assert_eq!(
        (reason, arg),
        (4, 0),
        "valid host_image_hash_chain must halt via REPLY (reason 4, arg 0), got reason={reason} arg={arg}",
    );
}
