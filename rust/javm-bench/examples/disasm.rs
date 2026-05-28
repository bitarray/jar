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
        "goldilocks_mul" => include_bytes!(env!("GOLDILOCKS_MUL_BLOB")),
        "poly_eval" => include_bytes!(env!("POLY_EVAL_BLOB")),
        "ed25519" => include_bytes!(env!("ED25519_BLOB")),
        "poseidon2_perm" => include_bytes!(env!("POSEIDON2_PERM_BLOB")),
        "mini_verifier" => include_bytes!(env!("MINI_VERIFIER_BLOB")),
        "fri_fold_tree" => include_bytes!(env!("FRI_FOLD_TREE_BLOB")),
        "ecrecover" => include_bytes!(env!("ECRECOVER_BLOB")),
        _ => panic!("unknown guest"),
    };
    let img = Image::from_ssz_bytes(blob_bytes).unwrap();
    let out = std::env::args()
        .nth(2)
        .unwrap_or_else(|| format!("/tmp/pvm2_{}.bin", which));
    std::fs::write(&out, &img.code).unwrap();
    println!("wrote {} bytes to {}", img.code.len(), out);
}
