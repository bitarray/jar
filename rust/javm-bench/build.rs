fn main() {
    let javm_ecrecover = build_javm::build("../../components/benches/ecrecover", "bench-ecrecover");
    let pvm_ecrecover = build_pvm::build("../../components/benches/ecrecover");
    let javm_sieve = build_javm::build("../../components/benches/prime-sieve", "bench-prime-sieve");
    let pvm_sieve = build_pvm::build("../../components/benches/prime-sieve");
    let javm_ed25519 = build_javm::build("../../components/benches/ed25519", "bench-ed25519");
    let pvm_ed25519 = build_pvm::build("../../components/benches/ed25519");
    let javm_blake2b = build_javm::build("../../components/benches/blake2b", "bench-blake2b");
    let pvm_blake2b = build_pvm::build("../../components/benches/blake2b");
    let javm_keccak = build_javm::build("../../components/benches/keccak", "bench-keccak");
    let pvm_keccak = build_pvm::build("../../components/benches/keccak");

    let out_dir = std::env::var("OUT_DIR").unwrap();
    std::fs::write(
        format!("{out_dir}/guest_blobs.rs"),
        format!(
            "const JAVM_ECRECOVER_BLOB: &[u8] = include_bytes!(\"{}\");\n\
             const POLKAVM_ECRECOVER_BLOB: &[u8] = include_bytes!(\"{}\");\n\
             const JAVM_SIEVE_BLOB: &[u8] = include_bytes!(\"{}\");\n\
             const POLKAVM_SIEVE_BLOB: &[u8] = include_bytes!(\"{}\");\n\
             const JAVM_ED25519_BLOB: &[u8] = include_bytes!(\"{}\");\n\
             const POLKAVM_ED25519_BLOB: &[u8] = include_bytes!(\"{}\");\n\
             const JAVM_BLAKE2B_BLOB: &[u8] = include_bytes!(\"{}\");\n\
             const POLKAVM_BLAKE2B_BLOB: &[u8] = include_bytes!(\"{}\");\n\
             const JAVM_KECCAK_BLOB: &[u8] = include_bytes!(\"{}\");\n\
             const POLKAVM_KECCAK_BLOB: &[u8] = include_bytes!(\"{}\");\n",
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
        ),
    )
    .unwrap();
}
