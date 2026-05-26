//! Phase-2 smoke test: load each PVM2-built bench blob and verify
//! its result-value matches the corresponding PVM blob. Catches both
//! `link_elf_rv` regressions and codegen miscompiles.

#![cfg_attr(not(all(target_os = "linux", target_arch = "x86_64")), allow(unused))]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use javm_bench::BuiltCaps;
use javm_cap::image::Image;
use nub::Nub;
use ssz::Decode;

struct Workload {
    name: &'static str,
    pvm: &'static [u8],
    pvm2: &'static [u8],
}

const WORKLOADS: &[Workload] = &[
    Workload {
        name: "prime_sieve",
        pvm: include_bytes!(env!("PRIME_SIEVE_BLOB")),
        pvm2: include_bytes!(env!("PRIME_SIEVE_PVM2_BLOB")),
    },
    Workload {
        name: "ed25519",
        pvm: include_bytes!(env!("ED25519_BLOB")),
        pvm2: include_bytes!(env!("ED25519_PVM2_BLOB")),
    },
    Workload {
        name: "keccak",
        pvm: include_bytes!(env!("KECCAK_BLOB")),
        pvm2: include_bytes!(env!("KECCAK_PVM2_BLOB")),
    },
    Workload {
        name: "blake2b",
        pvm: include_bytes!(env!("BLAKE2B_BLOB")),
        pvm2: include_bytes!(env!("BLAKE2B_PVM2_BLOB")),
    },
    Workload {
        name: "ecrecover",
        pvm: include_bytes!(env!("ECRECOVER_BLOB")),
        pvm2: include_bytes!(env!("ECRECOVER_PVM2_BLOB")),
    },
    Workload {
        name: "goldilocks_mul",
        pvm: include_bytes!(env!("GOLDILOCKS_MUL_BLOB")),
        pvm2: include_bytes!(env!("GOLDILOCKS_MUL_PVM2_BLOB")),
    },
    Workload {
        name: "poseidon2_perm",
        pvm: include_bytes!(env!("POSEIDON2_PERM_BLOB")),
        pvm2: include_bytes!(env!("POSEIDON2_PERM_PVM2_BLOB")),
    },
    Workload {
        name: "mini_verifier",
        pvm: include_bytes!(env!("MINI_VERIFIER_BLOB")),
        pvm2: include_bytes!(env!("MINI_VERIFIER_PVM2_BLOB")),
    },
    Workload {
        name: "poly_eval",
        pvm: include_bytes!(env!("POLY_EVAL_BLOB")),
        pvm2: include_bytes!(env!("POLY_EVAL_PVM2_BLOB")),
    },
    Workload {
        name: "fri_fold_tree",
        pvm: include_bytes!(env!("FRI_FOLD_TREE_BLOB")),
        pvm2: include_bytes!(env!("FRI_FOLD_TREE_PVM2_BLOB")),
    },
    Workload {
        name: "sub_vm_recurse",
        pvm: include_bytes!(env!("SUB_VM_RECURSE_BLOB")),
        pvm2: include_bytes!(env!("SUB_VM_RECURSE_PVM2_BLOB")),
    },
    Workload {
        name: "sub_vm_data_recurse",
        pvm: include_bytes!(env!("SUB_VM_DATA_RECURSE_BLOB")),
        pvm2: include_bytes!(env!("SUB_VM_DATA_RECURSE_PVM2_BLOB")),
    },
];

fn run_one(blob: &[u8], nub: &mut Nub) -> (u32, u32, u64, i64) {
    let image = Image::from_ssz_bytes(blob).expect("decode Image");
    let built = BuiltCaps::for_image(&image, 0);
    built.put_into(nub);
    let r = nub
        .invoke_cached(built.instance_hash, 0, [0; 4], javm_bench::INITIAL_GAS)
        .expect("invoke_cached");
    (
        r.exit_reason,
        r.exit_arg,
        r.return_value,
        (javm_bench::INITIAL_GAS as i64) - (r.gas_remaining as i64),
    )
}

fn main() {
    let mut nub = Nub::new_hyperlight().expect("Nub::new_hyperlight");
    let mut passes = 0usize;
    let mut fails: Vec<(&str, String)> = Vec::new();

    for w in WORKLOADS {
        eprintln!("=== {} ===", w.name);
        let pvm_img = Image::from_ssz_bytes(w.pvm).expect("decode PVM");
        let pvm2_img = Image::from_ssz_bytes(w.pvm2).expect("decode PVM2");
        eprintln!(
            "  PVM:  code={}B bitmask={}B jt={}",
            pvm_img.code.len(),
            pvm_img.packed_bitmask.len(),
            pvm_img.jump_table.len(),
        );
        eprintln!(
            "  PVM2: code={}B bitmask={}B jt={}",
            pvm2_img.code.len(),
            pvm2_img.packed_bitmask.len(),
            pvm2_img.jump_table.len(),
        );

        let (er_pvm, ea_pvm, rv_pvm, gas_pvm) = run_one(w.pvm, &mut nub);
        let (er_pvm2, ea_pvm2, rv_pvm2, gas_pvm2) = run_one(w.pvm2, &mut nub);
        eprintln!(
            "  PVM:  exit_reason={} exit_arg={} return_value={:#x} gas_used={}",
            er_pvm, ea_pvm, rv_pvm, gas_pvm,
        );
        eprintln!(
            "  PVM2: exit_reason={} exit_arg={} return_value={:#x} gas_used={}",
            er_pvm2, ea_pvm2, rv_pvm2, gas_pvm2,
        );

        if er_pvm == er_pvm2 && rv_pvm == rv_pvm2 {
            passes += 1;
            eprintln!("  PASS");
        } else {
            fails.push((
                w.name,
                format!(
                    "exit_reason {} vs {}, return_value {:#x} vs {:#x}",
                    er_pvm, er_pvm2, rv_pvm, rv_pvm2
                ),
            ));
            eprintln!("  FAIL");
        }
    }

    println!();
    println!("Summary: {} pass / {} fail", passes, fails.len());
    for (n, msg) in &fails {
        println!("  FAIL {n}: {msg}");
    }
    if !fails.is_empty() {
        std::process::exit(1);
    }
}
