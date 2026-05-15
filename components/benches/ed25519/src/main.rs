#![cfg_attr(target_env = "javm", no_std)]
#![cfg_attr(target_env = "javm", no_main)]

#[cfg(target_env = "javm")]
subsoil::entry!(javm_main);

#[cfg(target_env = "javm")]
#[no_mangle]
#[subsoil::endpoint(0)]
fn javm_main(_args_len: u64) -> u64 {
    bench_ed25519::ed25519_verify_bench() as u64
}

#[cfg(not(target_env = "javm"))]
fn main() {}
