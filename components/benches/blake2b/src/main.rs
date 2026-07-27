#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
#[subsoil::endpoint(0)]
fn javm_main(_args_len: u64) -> u64 {
    bench_blake2b::blake2b_bench() as u64
}

#[cfg(not(target_os = "none"))]
fn main() {}
