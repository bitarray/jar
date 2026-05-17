//! Cross-compile `nub-guest` for `x86_64-unknown-none` and expose
//! the ELF path to the host binary via the `NUB_GUEST_BLOB`
//! environment variable.

fn main() {
    if std::env::var("BUILD_CRATE_GUEST_BUILD").is_ok() {
        return;
    }
    let elf = build_nub::build("../nub-guest", "nub-guest");
    println!("cargo:rustc-env=NUB_GUEST_BLOB={}", elf.display());
    println!("cargo:rerun-if-changed=../nub-guest/src");
    println!("cargo:rerun-if-changed=../nub-guest/Cargo.toml");
}
