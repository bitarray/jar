//! Build the smoke PVM blobs the kernel uses for default genesis fixtures.
//!
//! `halt`: empty blob that ecallis IPC-slot (REPLY) → halts immediately. Used
//! as the default code blob for every reserved vault except the dispatch
//! entrypoint.
//!
//! `slot_clear`: ecallis Protocol cap id=19 (`HostCall::SlotClear`), then
//! REPLY-halts. Wired as the dispatch entrypoint's default code blob so the
//! existing dispatch pipeline test produces a `slot_emission =
//! Some(SlotContent::Empty)` via real javm execution.

fn main() {
    let halt = build_javm::build_service("../jar-test-services/halt", "jar-test-halt");
    let slot_clear =
        build_javm::build_service("../jar-test-services/slot_clear", "jar-test-slot-clear");
    println!("cargo:rustc-env=JAR_HALT_BLOB_PATH={}", halt.display());
    println!(
        "cargo:rustc-env=JAR_SLOT_CLEAR_BLOB_PATH={}",
        slot_clear.display()
    );
}
