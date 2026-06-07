//! Kernel gas-meter mapping: `invoke_cached` resolves the running Instance's
//! `gas_slots[0]` → `Gas{meter_key}` handle, seeds the run from the kernel meter
//! mapping (not the call-supplied budget), and writes the remaining gas back.

use javm_cap::image::{EndpointDef, Image};
use javm_cap::{
    CNodeCap, Cap, CapHashOrRef, DataCap, KernelImage, Key, NUM_REGS, kernel_image_hash,
    key_to_regs,
};
use nub::Nub;
use std::collections::BTreeMap;

const GAS_SLOT: u8 = 5;

/// `ecalli 42` at PC 0 (exits `HostCall(42)` after consuming a fixed amount of
/// gas). `gas_slots[0]` optionally names the slot holding the `Gas` handle.
fn ecalli_42_image(with_gas_slot: bool) -> Image {
    let mut img = Image::empty();
    img.code = 0x02A0_200Bu32.to_le_bytes().to_vec();
    let mut endpoints: BTreeMap<Key, EndpointDef> = BTreeMap::new();
    endpoints.insert(
        Key::from(0u8),
        EndpointDef {
            entry_pc: 0,
            arg_registers: 0,
            arg_cnode_size: 0,
            initial_regs: BTreeMap::new(),
        },
    );
    img.endpoints = endpoints;
    if with_gas_slot {
        img.gas_slots = vec![Key::from(GAS_SLOT)];
    }
    img
}

/// Publish a plain instance (no gas slot) and return its hash.
fn publish_plain(nub: &mut Nub) -> nub::AbiCapHash {
    let img = ecalli_42_image(false);
    let image_h = nub
        .put_cap(&Cap::image_with_slots(&img, &[], &[]).unwrap())
        .unwrap();
    let cnode_h = nub.put_cap(&Cap::empty_cnode()).unwrap();
    let inst = Cap::instance_with_mem(
        [0u8; 32],
        image_h,
        cnode_h,
        DataCap::from_bytes_sized(&[], 4096),
        [0u64; NUM_REGS],
        0,
        0,
    );
    nub.put_cap(&inst).unwrap()
}

/// Publish an instance whose `gas_slots[0]` holds a `Gas{meter_key}` handle.
fn publish_metered(nub: &mut Nub, meter_key: &Key) -> nub::AbiCapHash {
    // Gas unit handle: a Cap::Instance with the well-known Gas image-hash chain
    // and the meter_key packed into regs[0..1].
    let (packed, len) = key_to_regs(meter_key);
    let mut gas_regs = [0u64; NUM_REGS];
    gas_regs[0] = packed;
    gas_regs[1] = len;
    let gas_cap = Cap::instance_with_mem(
        kernel_image_hash(KernelImage::Gas),
        [0u8; 32],
        [0u8; 32],
        DataCap::empty(),
        gas_regs,
        0,
        0,
    );
    let gas_h = nub.put_cap(&gas_cap).unwrap();

    let mut cnode = CNodeCap::new();
    cnode
        .set(&Key::from(GAS_SLOT), Some(CapHashOrRef::Hash(gas_h)))
        .unwrap();
    let cnode_h = nub.put_cap(&Cap::CNode(cnode)).unwrap();

    let img = ecalli_42_image(true);
    let image_h = nub
        .put_cap(&Cap::image_with_slots(&img, &[], &[]).unwrap())
        .unwrap();
    let inst = Cap::instance_with_mem(
        [0u8; 32],
        image_h,
        cnode_h,
        DataCap::from_bytes_sized(&[], 4096),
        [0u64; NUM_REGS],
        0,
        0,
    );
    nub.put_cap(&inst).unwrap()
}

fn meter_drives_gas(mut nub: Nub) {
    const BUDGET: u64 = 1_000_000;
    const WRONG: u64 = BUDGET + 5_000_000;

    // Reference: a plain instance run on `BUDGET` directly (no meter).
    let plain = publish_plain(&mut nub);
    let ref_run = nub.invoke_cached(plain, 0, [0; 4], BUDGET).unwrap();
    assert_eq!(ref_run.exit_reason, 4, "ecalli 42 → HostCall");
    let ref_remaining = ref_run.gas_remaining;
    assert!(ref_remaining < BUDGET, "the guest consumed some gas");

    // Metered instance: seed the meter to BUDGET, but pass a deliberately wrong
    // `initial_gas`. If the meter is consulted, the run ignores WRONG and lands
    // at the same remaining as the reference.
    let meter_key = Key::from(&[0xAB, 0xCD, 0xEF][..]);
    nub.set_meter(meter_key.clone(), BUDGET);
    let metered = publish_metered(&mut nub, &meter_key);
    let run = nub.invoke_cached(metered, 0, [0; 4], WRONG).unwrap();

    assert_eq!(
        run.gas_remaining, ref_remaining,
        "ran on the meter budget ({BUDGET}), not the call-supplied {WRONG}"
    );
    assert_eq!(
        nub.get_meter(&meter_key),
        run.gas_remaining,
        "meter written back to the remaining gas at frame exit"
    );
}

#[test]
fn meter_drives_gas_local() {
    meter_drives_gas(Nub::new_local());
}

#[test]
fn meter_drives_gas_hyperlight() {
    meter_drives_gas(Nub::new_hyperlight().expect("hyperlight"));
}

#[test]
fn no_gas_slot_uses_call_budget() {
    // Without a gas slot the call-supplied budget is used and no meter touched.
    let mut nub = Nub::new_local();
    let plain = publish_plain(&mut nub);
    let r = nub.invoke_cached(plain, 0, [0; 4], 1_000_000).unwrap();
    assert!(r.gas_remaining < 1_000_000 && r.gas_remaining > 0);
}
