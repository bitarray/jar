//! Smoke test: load each PVM2-built bench blob, run it via both the
//! interpreter (Local backend) and the recompiler (Hyperlight JIT),
//! assert exit reason / return value / `gas_used` are bit-identical
//! between the two — the PVM2 conformance invariant.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {
    eprintln!("smoke is Linux x86-64 only");
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn main() {
    imp::main();
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod imp {
    use javm_bench::BuiltCaps;
    use javm_cap::image::Image;
    use nub::Nub;
    use ssz::Decode;

    struct Workload {
        name: &'static str,
        blob: &'static [u8],
    }

    const WORKLOADS: &[Workload] = &[
        Workload {
            name: "prime_sieve",
            blob: include_bytes!(env!("PRIME_SIEVE_BLOB")),
        },
        Workload {
            name: "ed25519",
            blob: include_bytes!(env!("ED25519_BLOB")),
        },
        Workload {
            name: "keccak",
            blob: include_bytes!(env!("KECCAK_BLOB")),
        },
        Workload {
            name: "blake2b",
            blob: include_bytes!(env!("BLAKE2B_BLOB")),
        },
        Workload {
            name: "ecrecover",
            blob: include_bytes!(env!("ECRECOVER_BLOB")),
        },
        Workload {
            name: "goldilocks_mul",
            blob: include_bytes!(env!("GOLDILOCKS_MUL_BLOB")),
        },
        Workload {
            name: "poseidon2_perm",
            blob: include_bytes!(env!("POSEIDON2_PERM_BLOB")),
        },
        Workload {
            name: "mini_verifier",
            blob: include_bytes!(env!("MINI_VERIFIER_BLOB")),
        },
        Workload {
            name: "poly_eval",
            blob: include_bytes!(env!("POLY_EVAL_BLOB")),
        },
        Workload {
            name: "fri_fold_tree",
            blob: include_bytes!(env!("FRI_FOLD_TREE_BLOB")),
        },
        Workload {
            name: "sub_vm_recurse",
            blob: include_bytes!(env!("SUB_VM_RECURSE_BLOB")),
        },
        Workload {
            name: "sub_vm_data_recurse",
            blob: include_bytes!(env!("SUB_VM_DATA_RECURSE_BLOB")),
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

    pub fn main() {
        let mut interp = Nub::new_local();
        // One long-lived Hyperlight sandbox for every workload — never torn
        // down and rebuilt (that re-mmap'd the snapshot at the same fixed guest
        // VA and corrupted host heap). It publishes all workloads' caps cleanly.
        let mut recomp = Nub::hyperlight().expect("Nub::hyperlight");
        let mut passes = 0usize;
        let mut fails: Vec<(&str, String)> = Vec::new();

        for w in WORKLOADS {
            eprintln!("=== {} ===", w.name);
            let img = Image::from_ssz_bytes(w.blob).expect("decode Image");
            eprintln!("  code={}B", img.code.len);

            let (er_r, ea_r, rv_r, gas_r) = run_one(w.blob, &mut recomp);
            let (er_i, ea_i, rv_i, gas_i) = run_one(w.blob, &mut interp);
            eprintln!(
                "  recomp: exit_reason={} exit_arg={} return_value={:#x} gas_used={}",
                er_r, ea_r, rv_r, gas_r,
            );
            eprintln!(
                "  interp: exit_reason={} exit_arg={} return_value={:#x} gas_used={}",
                er_i, ea_i, rv_i, gas_i,
            );

            if er_r == er_i && ea_r == ea_i && rv_r == rv_i && gas_r == gas_i {
                passes += 1;
                eprintln!("  PASS");
            } else {
                fails.push((
                    w.name,
                    format!(
                        "exit {}/{} vs {}/{}, return {:#x} vs {:#x}, gas {} vs {}",
                        er_r, ea_r, er_i, ea_i, rv_r, rv_i, gas_r, gas_i,
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
}
