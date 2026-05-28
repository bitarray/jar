//! Time predecode vs compile on each bench guest to validate the
//! cold-path optimization hypothesis (see
//! `~/docs/pvm-isa/discussions/optimization-plans.md`).

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use javm_cap::image::Image;
use javm_exec::predecode::predecode;
use javm_recompiler_x86::codegen::{Compiler, HelperFns};
use ssz::Decode;
use std::time::Instant;

fn dummy_helpers() -> HelperFns {
    // We don't execute the compiled code, just measure its emission;
    // any non-zero pointers are fine.
    HelperFns {
        mem_read_u8: 0x1000,
        mem_read_u16: 0x1000,
        mem_read_u32: 0x1000,
        mem_read_u64: 0x1000,
        mem_write_u8: 0x1000,
        mem_write_u16: 0x1000,
        mem_write_u32: 0x1000,
        mem_write_u64: 0x1000,
        sbrk_helper: 0x1000,
    }
}

fn profile_one(name: &str, blob: &[u8]) {
    let image = Image::from_ssz_bytes(blob).expect("decode Image");
    let code = &image.code[..];
    let jt_offsets = &image.jump_table_offsets[..];

    // Warm-up + report native_code size.
    let native_size = {
        let c = Compiler::new(dummy_helpers(), code.len(), 0x4000_0000, 1);
        let r = c.compile(code, jt_offsets);
        r.native_code.len()
    };

    const ITERS: u32 = 64;
    let mut comp_ns: u128 = 0;
    let mut pre_only_ns: u128 = 0;

    for _ in 0..ITERS {
        let t0 = Instant::now();
        let c = Compiler::new(dummy_helpers(), code.len(), 0x4000_0000, 1);
        let _ = c.compile(code, jt_offsets);
        let t1 = Instant::now();
        comp_ns += (t1 - t0).as_nanos();

        // Also time predecode on its own for comparison.
        let t2 = Instant::now();
        let _ = predecode(code);
        let t3 = Instant::now();
        pre_only_ns += (t3 - t2).as_nanos();
    }

    let comp_us = comp_ns as f64 / ITERS as f64 / 1000.0;
    let pre_us = pre_only_ns as f64 / ITERS as f64 / 1000.0;
    let n_insts = {
        let pd = predecode(code);
        pd.insts.len()
    };

    println!(
        "{:<22} code={:>6}B  native={:>6}B  ({:.1}x)  insts={:>6}  streaming_compile={:>7.1}µs  (predecode_rv_alone={:>7.1}µs)",
        name,
        code.len(),
        native_size,
        native_size as f64 / code.len() as f64,
        n_insts,
        comp_us,
        pre_us,
    );
}

macro_rules! workload {
    ($name:literal, $env:literal) => {
        profile_one($name, include_bytes!(env!($env)));
    };
}

fn main() {
    println!("PVM2 compile-path profile (predecode vs compile)");
    println!();
    workload!("prime_sieve", "PRIME_SIEVE_BLOB");
    workload!("keccak", "KECCAK_BLOB");
    workload!("blake2b", "BLAKE2B_BLOB");
    workload!("goldilocks_mul", "GOLDILOCKS_MUL_BLOB");
    workload!("sub_vm_recurse", "SUB_VM_RECURSE_BLOB");
    workload!("sub_vm_data_recurse", "SUB_VM_DATA_RECURSE_BLOB");
    workload!("ed25519", "ED25519_BLOB");
    workload!("ecrecover", "ECRECOVER_BLOB");
    workload!("poseidon2_perm", "POSEIDON2_PERM_BLOB");
    workload!("mini_verifier", "MINI_VERIFIER_BLOB");
    workload!("poly_eval", "POLY_EVAL_BLOB");
    workload!("fri_fold_tree", "FRI_FOLD_TREE_BLOB");
}
