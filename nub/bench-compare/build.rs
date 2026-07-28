//! Build the flat personality's guest kernel, so the `nub_jit` row has
//! a sandbox to run in.
//!
//! Linux x86-64 only: the sandbox path is KVM-specific. Elsewhere the
//! env var is absent and the JIT rows drop out of the registry.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        // Recursion guard: this build script runs cargo.
        if std::env::var("BUILD_CRATE_GUEST_BUILD").is_ok() {
            return;
        }
        let blob = nub_build::build("../nub-flat-guest-x86", "nub-flat-guest-x86", &[]);
        println!("cargo:rustc-env=NUB_FLAT_GUEST_BLOB={}", blob.display());
        for dir in [
            "../nub-flat-guest-x86",
            "../nub-flat",
            "../nub-arch-x86",
            "../nub-recompiler-x86",
            "../nub-exec",
            "../nub-program",
        ] {
            println!("cargo:rerun-if-changed={dir}/src");
        }
    }
}
