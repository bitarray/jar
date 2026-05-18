// Vendored from hyperlight-host 0.15.0 (Apache-2.0). F2.1 stripped the
// Windows surrogate sub-build and the mshv3 / windows cfg aliases.
// F2.2 stripped build-metadata, gdb, crashdump, unshared_snapshot_mem
// cfg aliases (their features are gone).

use anyhow::Result;

fn main() -> Result<()> {
    println!("cargo:rerun-if-changed=build.rs");

    cfg_aliases::cfg_aliases! {
        kvm: { all(feature = "kvm", target_os = "linux") },
        // print_debug feature is aliased with debug_assertions to make it only available in debug-builds.
        print_debug: { all(feature = "print_debug", debug_assertions) },
    }

    Ok(())
}
