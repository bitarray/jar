//! Dump the rewritten PVM2 code as a raw .bin so it can be disassembled
//! with llvm-objdump --disassemble-symbols.

#![cfg_attr(not(all(target_os = "linux", target_arch = "x86_64")), allow(unused))]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use javm_cap::image::Image;
use ssz::Decode;

fn main() {
    let which = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "goldilocks_mul".into());
    let blob_bytes: &[u8] = match which.as_str() {
        "goldilocks_mul" => include_bytes!(env!("GOLDILOCKS_MUL_PVM2_BLOB")),
        "poly_eval" => include_bytes!(env!("POLY_EVAL_PVM2_BLOB")),
        "ed25519" => include_bytes!(env!("ED25519_PVM2_BLOB")),
        "poseidon2_perm" => include_bytes!(env!("POSEIDON2_PERM_PVM2_BLOB")),
        "mini_verifier" => include_bytes!(env!("MINI_VERIFIER_PVM2_BLOB")),
        "fri_fold_tree" => include_bytes!(env!("FRI_FOLD_TREE_PVM2_BLOB")),
        "ecrecover" => include_bytes!(env!("ECRECOVER_PVM2_BLOB")),
        _ => panic!("unknown guest"),
    };
    let img = Image::from_ssz_bytes(blob_bytes).unwrap();
    let out = std::env::args()
        .nth(2)
        .unwrap_or_else(|| format!("/tmp/pvm2_{}.bin", which));
    std::fs::write(&out, &img.code).unwrap();
    println!("wrote {} bytes to {}", img.code.len(), out);
}
