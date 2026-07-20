//! Top-level invocation gas is task-local: `invoke_cached` seeds the new kernel
//! task from its call-supplied `initial_gas`. A published `Gas{meter_key}` handle
//! in an image's `gas_slots` participates in guest-side meter routing, but the
//! host `Nub` does not keep a shared meter map across invocations.

use javm::{InvokeRequest, Nub, NubOptions};
use javm_cap::image::{EndpointDef, Image};
use javm_cap::{
    CNodeCap, Cap, CapHashOrRef, DataCap, KernelImage, Key, NUM_REGS, kernel_image_hash,
    key_to_regs,
};
use std::collections::BTreeMap;

const GAS_SLOT: u8 = 5;

/// `ecalli 42` at PC 0 (exits `HostCall(42)` after consuming a fixed amount of
/// gas). `gas_slots[0]` optionally names the slot holding the `Gas` handle.
fn ecalli_42_image(with_gas_slot: bool) -> Image {
    let mut img = Image::with_code(0x02A0_200Bu32.to_le_bytes().to_vec());
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
fn publish_plain(nub: &Nub) -> javm::AbiCapHash {
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
fn publish_metered_image(nub: &Nub, img: Image, meter_key: &Key) -> javm::AbiCapHash {
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

fn publish_metered(nub: &Nub, meter_key: &Key) -> javm::AbiCapHash {
    publish_metered_image(nub, ecalli_42_image(true), meter_key)
}

fn initial_gas_funds_metered_invocation(nub: &Nub) {
    const BUDGET: u64 = 1_000_000;
    const TOPPED_UP: u64 = BUDGET + 5_000_000;

    let meter_key = Key::from(&[0xAB, 0xCD, 0xEF][..]);
    let metered = publish_metered(nub, &meter_key);
    let funded = nub.invoke_cached(metered, 0, [0; 4], BUDGET).unwrap();
    let topped_up = nub.invoke_cached(metered, 0, [0; 4], TOPPED_UP).unwrap();

    assert_eq!(funded.exit_reason, 4, "ecalli 42 -> HostCall");
    assert_eq!(topped_up.exit_reason, 4, "ecalli 42 -> HostCall");
    assert!(
        funded.gas_remaining < BUDGET,
        "the guest should consume gas from the call-supplied budget"
    );
    assert_eq!(
        TOPPED_UP - topped_up.gas_remaining,
        BUDGET - funded.gas_remaining,
        "the same metered image should consume the same amount from each task-local budget"
    );
}

#[test]
fn initial_gas_funds_metered_invocation_local() {
    let nub = Nub::local();
    initial_gas_funds_metered_invocation(&nub);
}

#[test]
fn initial_gas_funds_metered_invocation_hyperlight() {
    let nub =
        Nub::hyperlight_with_options(NubOptions::new().with_vcpu_count(2)).expect("hyperlight");
    initial_gas_funds_metered_invocation(&nub);
}

#[test]
fn no_gas_slot_uses_call_budget() {
    // Without a gas slot the call-supplied budget is used and no meter touched.
    let nub = Nub::local();
    let plain = publish_plain(&nub);
    let r = nub.invoke_cached(plain, 0, [0; 4], 1_000_000).unwrap();
    assert!(r.gas_remaining < 1_000_000 && r.gas_remaining > 0);
}

#[test]
fn concurrent_invokes_sharing_gas_handle_are_independent() {
    let nub = Nub::local();
    concurrent_invokes_sharing_gas_handle_are_independent_for(&nub);
}

#[test]
fn hyperlight_concurrent_invokes_sharing_gas_handle_are_independent() {
    let nub =
        Nub::hyperlight_with_options(NubOptions::new().with_vcpu_count(2)).expect("hyperlight");
    concurrent_invokes_sharing_gas_handle_are_independent_for(&nub);
}

fn concurrent_invokes_sharing_gas_handle_are_independent_for(nub: &Nub) {
    let meter_key = Key::from(&[0xAA, 0xBB, 0xCC][..]);
    let metered = publish_metered_image(nub, ecalli_42_image(true), &meter_key);
    const BASE_BUDGET: u64 = 1_000_000;

    let jobs: Vec<_> = (0..16)
        .map(|i| {
            nub.submit_invoke(InvokeRequest {
                root: metered,
                endpoint_idx: 0,
                args: [0; 4],
                initial_gas: BASE_BUDGET + i,
            })
            .expect("submit metered invoke")
        })
        .collect();

    let mut consumed = None;
    for (i, job) in jobs.into_iter().enumerate() {
        let result = job.wait().expect("shared gas handle invoke");
        assert_eq!(result.exit_reason, 4, "ecalli 42 -> HostCall");
        let budget = BASE_BUDGET + i as u64;
        let this_consumed = budget - result.gas_remaining;
        match consumed {
            Some(expected) => assert_eq!(
                this_consumed, expected,
                "each invoke should draw from its own task-local budget"
            ),
            None => consumed = Some(this_consumed),
        }
    }
}
