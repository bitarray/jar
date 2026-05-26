//! Phase-2 smoke test: load the PVM2-built prime-sieve blob and run
//! one invocation through the Hyperlight JIT. Exits 0 on success,
//! panics with the failure reason otherwise.

#![cfg_attr(not(all(target_os = "linux", target_arch = "x86_64")), allow(unused))]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use javm_bench::BuiltCaps;
use javm_cap::image::Image;
use nub::Nub;
use ssz::Decode;

fn main() {
    let blob_path = env!("PRIME_SIEVE_PVM2_BLOB");
    let blob = std::fs::read(blob_path).expect("read PRIME_SIEVE_PVM2_BLOB");
    let image = Image::from_ssz_bytes(&blob).expect("decode PVM2 Image");

    println!(
        "PVM2 prime-sieve: code={}B bitmask={}B jump_table={}B endpoints={}",
        image.code.len(),
        image.packed_bitmask.len(),
        image.jump_table.len(),
        image.endpoints.len(),
    );
    for (idx, ep) in &image.endpoints {
        println!(
            "  endpoint {idx}: entry_pc={:#x} arg_registers={} arg_cnode_size={}",
            ep.entry_pc, ep.arg_registers, ep.arg_cnode_size
        );
    }
    println!(
        "  pinned_slots={} initial_slots={} memory_mappings={}",
        image.pinned_slots.len(),
        image.initial_slots.len(),
        image.memory_mappings.len(),
    );

    // Also load the PVM blob for comparison.
    let pvm_blob_path = env!("PRIME_SIEVE_BLOB");
    let pvm_blob = std::fs::read(pvm_blob_path).expect("read PRIME_SIEVE_BLOB");
    let pvm_image = Image::from_ssz_bytes(&pvm_blob).expect("decode PVM Image");
    println!(
        "PVM prime-sieve (reference): code={}B bitmask={}B jump_table={}B",
        pvm_image.code.len(),
        pvm_image.packed_bitmask.len(),
        pvm_image.jump_table.len(),
    );
    for (idx, ep) in &pvm_image.endpoints {
        println!("  PVM endpoint {idx}: entry_pc={:#x}", ep.entry_pc);
    }
    assert!(
        image.packed_bitmask.is_empty(),
        "PVM2 path expects empty bitmask"
    );
    assert!(
        image.jump_table.is_empty(),
        "PVM2 path expects empty jump_table"
    );

    let built = BuiltCaps::for_image(&image, 0);
    let mut nub = Nub::new_hyperlight().expect("Nub::new_hyperlight");
    built.put_into(&mut nub);
    let result = nub
        .invoke_cached(built.instance_hash, 0, [0; 4], javm_bench::INITIAL_GAS)
        .expect("invoke_cached");
    println!(
        "result: exit_reason={} exit_arg={} return_value={} gas_remaining={}",
        result.exit_reason, result.exit_arg, result.return_value, result.gas_remaining
    );
    // prime_sieve returns π(100000) = 9592 (Sieve of Eratosthenes).
    assert_eq!(
        result.return_value, 9592,
        "unexpected return_value (expected 9592, got {})",
        result.return_value
    );
    println!("PVM2 prime-sieve smoke: PASS");
}
