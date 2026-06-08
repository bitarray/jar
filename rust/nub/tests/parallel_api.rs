//! Cloneable Nub handle and invoke job API smoke tests.

use javm_cap::image::{EndpointDef, Image};
use javm_cap::{Cap, DataCap, Key, NUM_REGS};
use nub::{InvokeRequest, Nub};
use std::collections::BTreeMap;
use std::thread;

fn ecalli_imm_image(imm: u32) -> Image {
    let mut img = Image::empty();
    let instr = (imm << 20) | (0b010 << 12) | (0b00010 << 2) | 0b11;
    img.code = instr.to_le_bytes().to_vec();
    img.endpoints.insert(
        Key::from(0u8),
        EndpointDef {
            entry_pc: 0,
            arg_registers: 0,
            arg_cnode_size: 0,
            initial_regs: BTreeMap::new(),
        },
    );
    img
}

fn publish(nub: &Nub, imm: u32) -> nub::AbiCapHash {
    let image_h = nub
        .put_cap(&Cap::image_with_slots(&ecalli_imm_image(imm), &[], &[]).expect("image"))
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

#[test]
fn cloned_local_nub_handles_can_blocking_invoke_from_many_threads() {
    let nub = Nub::new_local();
    let inst = publish(&nub, 42);

    let handles: Vec<_> = (0..4)
        .map(|_| {
            let nub = nub.clone();
            thread::spawn(move || {
                nub.invoke_cached(inst, 0, [0; 4], 1_000)
                    .expect("invoke_cached")
            })
        })
        .collect();

    for handle in handles {
        let result = handle.join().expect("invoke thread");
        assert_eq!(result.exit_reason, 4);
        assert_eq!(result.exit_arg, 42);
    }
}

#[test]
fn invoke_job_wait_returns_result() {
    let nub = Nub::new_local();
    let inst = publish(&nub, 43);
    let job = nub
        .submit_invoke(InvokeRequest {
            instance_hash: inst,
            endpoint_idx: 0,
            args: [0; 4],
            initial_gas: 1_000,
        })
        .expect("submit invoke");

    assert_eq!(job.id().0, 1);
    let result = job.wait().expect("job wait");
    assert_eq!(result.exit_reason, 4);
    assert_eq!(result.exit_arg, 43);
}

#[test]
fn cloned_local_nub_handles_can_idempotently_publish_from_many_threads() {
    let nub = Nub::new_local();
    let cap = Cap::empty_cnode();
    let hash = nub.put_cap(&cap).expect("initial put");

    let handles: Vec<_> = (0..8)
        .map(|_| {
            let nub = nub.clone();
            let cap = cap.clone();
            thread::spawn(move || {
                nub.put_cap_with_hash(hash, &cap)
                    .expect("idempotent put_cap_with_hash")
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("put thread");
    }
}
