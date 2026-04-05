fn main() {
    let javm_ecrecover = build_javm::build_v2("../../services/benches/ecrecover", "bench-ecrecover");
    let pvm_ecrecover = build_pvm::build("../../services/benches/ecrecover");
    let javm_sieve = build_javm::build_v2("../../services/benches/prime-sieve", "bench-prime-sieve");
    let pvm_sieve = build_pvm::build("../../services/benches/prime-sieve");
    let javm_ed25519 = build_javm::build_v2("../../services/benches/ed25519", "bench-ed25519");
    let pvm_ed25519 = build_pvm::build("../../services/benches/ed25519");
    let javm_blake2b = build_javm::build_v2("../../services/benches/blake2b", "bench-blake2b");
    let pvm_blake2b = build_pvm::build("../../services/benches/blake2b");
    let javm_keccak = build_javm::build_v2("../../services/benches/keccak", "bench-keccak");
    let pvm_keccak = build_pvm::build("../../services/benches/keccak");
    let service_blob =
        build_javm::build_service_v2("../../services/samples/sample-service", "sample-service");

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
            service_blob.display(),
        ),
    )
    .unwrap();
}
