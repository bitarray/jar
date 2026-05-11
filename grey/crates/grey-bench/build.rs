fn main() {
    let javm_ecrecover = build_javm::build("../../services/benches/ecrecover", "bench-ecrecover");
    let pvm_ecrecover = build_pvm::build("../../services/benches/ecrecover");
    let javm_sieve = build_javm::build("../../services/benches/prime-sieve", "bench-prime-sieve");
    let pvm_sieve = build_pvm::build("../../services/benches/prime-sieve");
    let javm_ed25519 = build_javm::build("../../services/benches/ed25519", "bench-ed25519");
    let pvm_ed25519 = build_pvm::build("../../services/benches/ed25519");
    let javm_blake2b = build_javm::build("../../services/benches/blake2b", "bench-blake2b");
    let pvm_blake2b = build_pvm::build("../../services/benches/blake2b");
    let javm_keccak = build_javm::build("../../services/benches/keccak", "bench-keccak");
    let pvm_keccak = build_pvm::build("../../services/benches/keccak");
    let javm_mini_verifier = build_javm::build(
        "../../services/benches/mini-verifier",
        "bench-mini-verifier",
    );
    let pvm_mini_verifier = build_pvm::build("../../services/benches/mini-verifier");
    let javm_goldilocks_mul = build_javm::build(
        "../../services/benches/goldilocks-mul",
        "bench-goldilocks-mul",
    );
    let pvm_goldilocks_mul = build_pvm::build("../../services/benches/goldilocks-mul");
    let javm_poseidon2_perm = build_javm::build(
        "../../services/benches/poseidon2-perm",
        "bench-poseidon2-perm",
    );
    let pvm_poseidon2_perm = build_pvm::build("../../services/benches/poseidon2-perm");
    let javm_poly_eval = build_javm::build("../../services/benches/poly-eval", "bench-poly-eval");
    let pvm_poly_eval = build_pvm::build("../../services/benches/poly-eval");
    let javm_fri_fold_tree = build_javm::build(
        "../../services/benches/fri-fold-tree",
        "bench-fri-fold-tree",
    );
    let pvm_fri_fold_tree = build_pvm::build("../../services/benches/fri-fold-tree");
    let service_blob =
        build_javm::build_service("../../services/samples/sample-service", "sample-service");

    let out_dir = std::env::var("OUT_DIR").unwrap();
    std::fs::write(
        format!("{out_dir}/guest_blobs.rs"),
        format!(
            "const GREY_ECRECOVER_BLOB: &[u8] = include_bytes!(\"{}\");\n\
             const POLKAVM_ECRECOVER_BLOB: &[u8] = include_bytes!(\"{}\");\n\
             const GREY_SIEVE_BLOB: &[u8] = include_bytes!(\"{}\");\n\
             const POLKAVM_SIEVE_BLOB: &[u8] = include_bytes!(\"{}\");\n\
             const GREY_ED25519_BLOB: &[u8] = include_bytes!(\"{}\");\n\
             const POLKAVM_ED25519_BLOB: &[u8] = include_bytes!(\"{}\");\n\
             const GREY_BLAKE2B_BLOB: &[u8] = include_bytes!(\"{}\");\n\
             const POLKAVM_BLAKE2B_BLOB: &[u8] = include_bytes!(\"{}\");\n\
             const GREY_KECCAK_BLOB: &[u8] = include_bytes!(\"{}\");\n\
             const POLKAVM_KECCAK_BLOB: &[u8] = include_bytes!(\"{}\");\n\
             const GREY_MINI_VERIFIER_BLOB: &[u8] = include_bytes!(\"{}\");\n\
             const POLKAVM_MINI_VERIFIER_BLOB: &[u8] = include_bytes!(\"{}\");\n\
             const GREY_GOLDILOCKS_MUL_BLOB: &[u8] = include_bytes!(\"{}\");\n\
             const POLKAVM_GOLDILOCKS_MUL_BLOB: &[u8] = include_bytes!(\"{}\");\n\
             const GREY_POSEIDON2_PERM_BLOB: &[u8] = include_bytes!(\"{}\");\n\
             const POLKAVM_POSEIDON2_PERM_BLOB: &[u8] = include_bytes!(\"{}\");\n\
             const GREY_POLY_EVAL_BLOB: &[u8] = include_bytes!(\"{}\");\n\
             const POLKAVM_POLY_EVAL_BLOB: &[u8] = include_bytes!(\"{}\");\n\
             const GREY_FRI_FOLD_TREE_BLOB: &[u8] = include_bytes!(\"{}\");\n\
             const POLKAVM_FRI_FOLD_TREE_BLOB: &[u8] = include_bytes!(\"{}\");\n\
             const SAMPLE_SERVICE_BLOB: &[u8] = include_bytes!(\"{}\");\n",
            javm_ecrecover.display(),
            pvm_ecrecover.display(),
            javm_sieve.display(),
            pvm_sieve.display(),
            javm_ed25519.display(),
            pvm_ed25519.display(),
            javm_blake2b.display(),
            pvm_blake2b.display(),
            javm_keccak.display(),
            pvm_keccak.display(),
            javm_mini_verifier.display(),
            pvm_mini_verifier.display(),
            javm_goldilocks_mul.display(),
            pvm_goldilocks_mul.display(),
            javm_poseidon2_perm.display(),
            pvm_poseidon2_perm.display(),
            javm_poly_eval.display(),
            pvm_poly_eval.display(),
            javm_fri_fold_tree.display(),
            pvm_fri_fold_tree.display(),
            service_blob.display(),
        ),
    )
    .unwrap();
}
