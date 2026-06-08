#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use javm_cap::image::{EndpointDef, Image};
use javm_cap::{Cap, DataCap, Key, NUM_REGS};
use nub::{InvokeRequest, Nub, NubOptions};
use std::collections::BTreeMap;
use std::thread;

fn ecalli_imm_image(imm: u32) -> Image {
    let instr = (imm << 20) | (0b010 << 12) | (0b00010 << 2) | 0b11;
    let mut img = Image::with_code(instr.to_le_bytes().to_vec());
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
fn hyperlight_parallel_workers_complete_two_simple_invokes() {
    let nub = Nub::hyperlight_tests_with_options(NubOptions::new().with_vcpu_count(2))
        .expect("Hyperlight test sandbox");
    let a = publish(&nub, 71);
    let b = publish(&nub, 72);

    let job_a = nub
        .submit_invoke(InvokeRequest {
            instance_hash: a,
            endpoint_idx: 0,
            args: [0; 4],
            initial_gas: 1_000,
        })
        .expect("submit A");
    let job_b = nub
        .submit_invoke(InvokeRequest {
            instance_hash: b,
            endpoint_idx: 0,
            args: [0; 4],
            initial_gas: 1_000,
        })
        .expect("submit B");

    let result_a = job_a.wait().expect("wait A");
    let result_b = job_b.wait().expect("wait B");
    assert_eq!((result_a.exit_reason, result_a.exit_arg), (4, 71));
    assert_eq!((result_b.exit_reason, result_b.exit_arg), (4, 72));

    let c = publish(&nub, 73);
    let result_c = nub
        .invoke_cached(c, 0, [0; 4], 1_000)
        .expect("invoke C after worker stop/restart");
    assert_eq!((result_c.exit_reason, result_c.exit_arg), (4, 73));

    let threaded: Vec<_> = (0..4).map(|i| publish(&nub, 80 + i)).collect();
    let handles: Vec<_> = threaded
        .into_iter()
        .enumerate()
        .map(|(i, inst)| {
            let nub = nub.clone();
            thread::spawn(move || {
                let result = nub
                    .invoke_cached(inst, 0, [0; 4], 1_000)
                    .expect("threaded invoke_cached");
                (i as u32, result)
            })
        })
        .collect();

    for handle in handles {
        let (i, result) = handle.join().expect("invoke thread");
        assert_eq!((result.exit_reason, result.exit_arg), (4, 80 + i));
    }
}

#[test]
fn cloned_hyperlight_nub_handles_can_idempotently_publish_from_many_threads() {
    let nub = Nub::hyperlight_tests_with_options(NubOptions::new().with_vcpu_count(2))
        .expect("Hyperlight test sandbox");
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
