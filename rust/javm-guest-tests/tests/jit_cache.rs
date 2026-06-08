//! Smoke test for the resident per-Image JIT cache: a compiled Image can be
//! evicted from its `CachedCap` and rebuilt on the next invoke.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use javm_cap::image::{EndpointDef, Image};
use javm_cap::{Cap, Key, NUM_REGS};
use nub::Nub;
use std::collections::BTreeMap;

const OP_REPLY: u32 = 0;
const GAS_BUDGET: u64 = 1_000_000;

fn ecalli(imm: u32) -> u32 {
    ((imm & 0xFFF) << 20) | (0b010 << 12) | 0b000_1011
}

fn reply_image() -> Image {
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
    Image {
        code: ecalli(OP_REPLY).to_le_bytes().to_vec(),
        endpoints,
        memory_mappings: Vec::new(),
        pinned_slots: BTreeMap::new(),
        initial_slots: BTreeMap::new(),
        yield_receiver_slot: None,
        gas_slots: Vec::new(),
        quota_slots: Vec::new(),
    }
}

#[test]
fn evict_jit_cache_then_reinvoke_rebuilds_image_cache() {
    let nub = Nub::hyperlight().expect("Hyperlight sandbox");
    let img = reply_image();
    let image_h = nub
        .put_cap(&Cap::image_with_slots(&img, &[], &[]).expect("image"))
        .expect("put image");
    let cnode_h = nub.put_cap(&Cap::empty_cnode()).expect("put cnode");
    let inst_h = nub
        .put_cap(&Cap::instance_with_mem(
            [0u8; 32],
            image_h,
            cnode_h,
            img.instance_mem_backing(),
            [0u64; NUM_REGS],
            0,
            0,
        ))
        .expect("put instance");

    let first = nub
        .invoke_cached(inst_h, 0, [0; 4], GAS_BUDGET)
        .expect("first invoke");
    assert_eq!((first.exit_reason, first.exit_arg), (4, 0));

    nub.evict_jit_all().expect("evict jit cache");

    let second = nub
        .invoke_cached(inst_h, 0, [0; 4], GAS_BUDGET)
        .expect("second invoke after eviction");
    assert_eq!((second.exit_reason, second.exit_arg), (4, 0));
}
