#![cfg_attr(target_env = "javm", no_std)]
#![cfg_attr(target_env = "javm", no_main)]

#[cfg(target_env = "javm")]
subsoil::entry!(javm_main);

#[cfg(target_env = "javm")]
#[no_mangle]
extern "C" fn javm_main() -> u32 {
    bench_keccak::keccak_bench()
}

#[cfg(not(target_env = "javm"))]
fn main() {}
