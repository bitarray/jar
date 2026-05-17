// Vendored from hyperlight-host 0.15.0 (Apache-2.0). F2.1 stripped the
// Windows hyperlight-surrogate.exe sub-build and the mshv3 / windows
// cfg aliases.

use anyhow::Result;
#[cfg(feature = "build-metadata")]
use built::write_built_file;

fn main() -> Result<()> {
    println!("cargo:rerun-if-changed=build.rs");

    cfg_aliases::cfg_aliases! {
        gdb: { all(feature = "gdb", debug_assertions, target_arch = "x86_64") },
        kvm: { all(feature = "kvm", target_os = "linux") },
        crashdump: { all(feature = "crashdump", target_arch = "x86_64") },
        // print_debug feature is aliased with debug_assertions to make it only available in debug-builds.
        print_debug: { all(feature = "print_debug", debug_assertions) },
        // the nanvix-unstable and gdb features both (only
        // temporarily!) need to use writable/un-shared snapshot
        // memories, and so can't share
        unshared_snapshot_mem: { any(feature = "nanvix-unstable", feature = "gdb") },
    }

    #[cfg(feature = "build-metadata")]
    write_built_file()?;

    Ok(())
}
