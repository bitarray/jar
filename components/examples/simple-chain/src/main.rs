#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

use subsoil as _;

#[cfg(target_os = "none")]
#[subsoil::endpoint(0)]
fn simple_chain_main(_args_len: u64) -> u64 {
    simple_chain::simple_chain_sum()
}

#[cfg(not(target_os = "none"))]
fn main() {
    // Host build: print the sum so this stays a runnable binary.
    println!("{}", simple_chain::simple_chain_sum());
}
