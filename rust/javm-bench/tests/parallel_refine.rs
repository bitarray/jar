//! End-to-end refine-style API smoke over one cloneable Hyperlight Nub.
//!
//! This test prepublishes several independent compute workloads, submits them
//! through cloned `Nub` handles, checks the pinned serial results, then runs one
//! normal follow-up invoke on the same singleton. Today the host call boundary
//! still serializes inside the sandbox; this test locks in the public API shape
//! that the guest multi-lane worker will use for true KVM parallelism.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use javm_cap::CapHash;
use javm_cap::image::Image;
use nub::{InvokeRequest, Nub, NubOptions};
use ssz::Decode;

#[derive(Clone, Copy)]
struct PublishedWorkload {
    name: &'static str,
    instance_hash: CapHash,
    endpoint_idx: u8,
    expected_value: u64,
    expected_gas_used: u64,
}

fn publish(
    nub: &Nub,
    name: &'static str,
    blob: &[u8],
    expected_value: u64,
    expected_gas_used: u64,
) -> PublishedWorkload {
    let image = Image::from_ssz_bytes(blob).unwrap_or_else(|e| panic!("[{name}] decode: {e:?}"));
    let built = javm_bench::BuiltCaps::for_image(&image, 0);
    built.put_into(nub);
    PublishedWorkload {
        name,
        instance_hash: built.instance_hash,
        endpoint_idx: built.endpoint_idx,
        expected_value,
        expected_gas_used,
    }
}

fn assert_result(workload: PublishedWorkload, result: nub::InvocationResult) {
    assert_eq!(
        (result.exit_reason, result.exit_arg),
        (4, 0),
        "[{}] expected clean HostCall(0)",
        workload.name,
    );
    assert_eq!(
        result.return_value, workload.expected_value,
        "[{}] return value drifted",
        workload.name,
    );
    assert_eq!(
        javm_bench::INITIAL_GAS - result.gas_remaining,
        workload.expected_gas_used,
        "[{}] gas drifted",
        workload.name,
    );
}

#[test]
fn cloned_nub_handles_run_compute_refine_jobs_then_serial_accumulate() {
    let nub = Nub::hyperlight_with_options(NubOptions::new().with_vcpu_count(2))
        .expect("Hyperlight sandbox");
    let workloads = [
        publish(
            &nub,
            "prime_sieve",
            include_bytes!(env!("PRIME_SIEVE_BLOB")),
            0x2578,
            8_972_959,
        ),
        publish(
            &nub,
            "keccak",
            include_bytes!(env!("KECCAK_BLOB")),
            0x39e5_0259,
            100_934,
        ),
        publish(
            &nub,
            "blake2b",
            include_bytes!(env!("BLAKE2B_BLOB")),
            0xee1f_55f1,
            62_396,
        ),
        publish(
            &nub,
            "goldilocks_mul",
            include_bytes!(env!("GOLDILOCKS_MUL_BLOB")),
            0x2cf7_3e57,
            2_400_166,
        ),
    ];

    let jobs = workloads.map(|workload| {
        let handle = nub.clone();
        let job = handle
            .submit_invoke(InvokeRequest {
                instance_hash: workload.instance_hash,
                endpoint_idx: workload.endpoint_idx,
                args: [0; 4],
                initial_gas: javm_bench::INITIAL_GAS,
            })
            .expect("submit refine invoke");
        (workload, job)
    });

    for (workload, job) in jobs {
        assert_result(workload, job.wait().expect("refine job wait"));
    }

    let accumulate = workloads[0];
    let result = nub
        .invoke_cached(
            accumulate.instance_hash,
            accumulate.endpoint_idx,
            [0; 4],
            javm_bench::INITIAL_GAS,
        )
        .expect("serial accumulate invoke");
    assert_result(accumulate, result);
}
