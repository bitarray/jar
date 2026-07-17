//! End-to-end smoke for the `javm-guest-x86-tests` guest binary.
//!
//! Loads the test guest binary via [`Nub::hyperlight_tests`],
//! calls the `nub_smoke` RPC, and verifies it returns `42u64`.
//! Together with `tests/smoke.rs` (which exercises the production
//! `invoke_cached` path), this gives us coverage of both the
//! production and test guest binaries.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use javm::{Nub, NubOptions};
use javm_guest_x86::test_abi::FN_ID_TEST_INVOKE_TWO_SERIAL;
use nub_arch_x86::test_abi::FN_ID_TEST_SMOKE;
use nub_arch_x86_abi::{InvocationResult, InvokePacket};
use rkyv::primitive::ArchivedU64;
use std::collections::BTreeMap;

use javm_cap::image::{EndpointDef, Image};
use javm_cap::{Cap, DataCap, Key, NUM_REGS};

fn test_nub() -> Nub {
    Nub::hyperlight_tests_with_options(NubOptions::new().with_vcpu_count(2))
        .expect("hyperlight tests bin")
}

#[test]
fn test_bin_smoke_returns_42() {
    let nub = test_nub();
    let bytes = nub.call_raw(FN_ID_TEST_SMOKE, &[]).expect("smoke rpc");
    let mut aligned = rkyv::util::AlignedVec::<16>::with_capacity(bytes.len());
    aligned.extend_from_slice(&bytes);
    let archived =
        rkyv::access::<ArchivedU64, rkyv::rancor::Error>(aligned.as_slice()).expect("rkyv access");
    assert_eq!(archived.to_native(), 42);
}

#[test]
fn test_bin_smoke_returns_42_on_second_vcpu() {
    let nub = test_nub();
    let bytes = nub
        .call_raw_on_vcpu(1, FN_ID_TEST_SMOKE, &[])
        .expect("smoke rpc on vcpu 1");
    let mut aligned = rkyv::util::AlignedVec::<16>::with_capacity(bytes.len());
    aligned.extend_from_slice(&bytes);
    let archived =
        rkyv::access::<ArchivedU64, rkyv::rancor::Error>(aligned.as_slice()).expect("rkyv access");
    assert_eq!(archived.to_native(), 42);
}

fn ecalli_image(imm: u32) -> Image {
    let instr = (imm << 20) | (0b010 << 12) | (0b00010 << 2) | 0b11;
    let mut img = Image::with_code(instr.to_le_bytes().to_vec());
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
    img
}

fn publish_ecalli(nub: &mut Nub, imm: u32) -> javm::AbiCapHash {
    let img = ecalli_image(imm);
    let image_h = nub
        .put_cap(&Cap::image_with_slots(&img, &[], &[]).expect("image_with_slots"))
        .expect("put image");
    let cnode_h = nub.put_cap(&Cap::empty_cnode()).expect("put cnode");
    nub.put_cap(&Cap::instance_with_mem(
        [0u8; 32],
        image_h,
        cnode_h,
        DataCap::from_bytes_sized(&[], 4096),
        [0u64; NUM_REGS],
        0,
        0,
    ))
    .expect("put instance")
}

fn scheduler_probe(
    nub: &mut Nub,
    first: javm::AbiCapHash,
    first_gas: u64,
    second: javm::AbiCapHash,
    second_gas: u64,
) -> [InvocationResult; 2] {
    let first = InvokePacket {
        instance_hash: first,
        endpoint_idx: 0,
        _pad: 0,
        args: [0; 4],
        initial_gas: first_gas,
    };
    let second = InvokePacket {
        instance_hash: second,
        endpoint_idx: 0,
        _pad: 0,
        args: [0; 4],
        initial_gas: second_gas,
    };
    let mut payload = Vec::with_capacity(InvokePacket::SIZE * 2);
    payload.extend_from_slice(first.as_bytes());
    payload.extend_from_slice(second.as_bytes());

    let bytes = nub
        .call_raw(FN_ID_TEST_INVOKE_TWO_SERIAL, &payload)
        .expect("scheduler probe rpc");
    let mut aligned = rkyv::util::AlignedVec::<16>::with_capacity(bytes.len());
    aligned.extend_from_slice(&bytes);
    let archived = rkyv::access::<rkyv::Archived<[InvocationResult; 2]>, rkyv::rancor::Error>(
        aligned.as_slice(),
    )
    .expect("rkyv access scheduler results");
    [
        InvocationResult {
            exit_reason: archived[0].exit_reason.to_native(),
            exit_arg: archived[0].exit_arg.to_native(),
            return_value: archived[0].return_value.to_native(),
            gas_remaining: archived[0].gas_remaining.to_native(),
            scratchpad_head: archived[0].scratchpad_head,
        },
        InvocationResult {
            exit_reason: archived[1].exit_reason.to_native(),
            exit_arg: archived[1].exit_arg.to_native(),
            return_value: archived[1].return_value.to_native(),
            gas_remaining: archived[1].gas_remaining.to_native(),
            scratchpad_head: archived[1].scratchpad_head,
        },
    ]
}

#[test]
fn test_scheduler_probe_runs_two_tasks() {
    let mut nub = test_nub();
    let first = publish_ecalli(&mut nub, 42);
    let second = publish_ecalli(&mut nub, 43);
    let results = scheduler_probe(&mut nub, first, 1_000, second, 1_000);
    assert_eq!(results[0].exit_reason, 4);
    assert_eq!(results[0].exit_arg, 42);
    assert_eq!(results[1].exit_reason, 4);
    assert_eq!(results[1].exit_arg, 43);
}

#[test]
fn test_scheduler_probe_keeps_task_gas_local_after_oog() {
    let mut nub = test_nub();
    let first = publish_ecalli(&mut nub, 42);
    let second = publish_ecalli(&mut nub, 43);
    let results = scheduler_probe(&mut nub, first, 0, second, 1_000);
    assert_eq!(results[0].exit_reason, 2);
    assert_eq!(results[1].exit_reason, 4);
    assert_eq!(results[1].exit_arg, 43);
}
