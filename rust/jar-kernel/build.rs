//! Build the smoke PVM blob the kernel uses for the default genesis
//! fixture.
//!
//! `halt`: empty blob that ecallis IPC-slot (REPLY) → halts immediately.
//! Used as the default code blob for every genesis vault, including
//! the dispatch entrypoint.

fn main() {
    let halt = build_javm::build_service("../jar-test-services/halt", "jar-test-halt");
    println!("cargo:rustc-env=JAR_HALT_BLOB_PATH={}", halt.display());
}
