#![cfg_attr(target_env = "javm", no_std)]
#![cfg_attr(target_env = "javm", no_main)]

use spawn_child_s as _;
use subsoil as _;

#[cfg(target_env = "javm")]
mod kernel_abi;

#[cfg(all(target_env = "javm", target_os = "none"))]
const INPUT_BUF_SIZE: usize = 64;
#[cfg(all(target_env = "javm", target_os = "none"))]
static mut INPUT_BUF: [u8; INPUT_BUF_SIZE] = [0u8; INPUT_BUF_SIZE];
#[cfg(all(target_env = "javm", target_os = "none"))]
static mut RESULT_BUF: [u8; 1] = [0u8];

#[cfg(all(target_env = "javm", target_os = "none"))]
#[subsoil::endpoint(0)]
fn javm_main(_args_len: u64) -> u64 {
    use kernel_abi::*;

    // 1. Read input DataCap (delivered via CALL into our slot[0])
    //    into a fixed buffer.
    let buf_ptr = (&raw mut INPUT_BUF) as *mut u8;
    let buf_addr = buf_ptr as u32;
    let n_read = unsafe { host_read_data_cap(0, buf_addr, INPUT_BUF_SIZE as u64) };

    // 2. Wrapping byte-sum.
    let bytes = unsafe { core::slice::from_raw_parts(buf_ptr, n_read as usize) };
    let mut sum: u8 = 0;
    let mut i = 0;
    while i < bytes.len() {
        sum = sum.wrapping_add(bytes[i]);
        i += 1;
    }

    // 3. Write the single-byte result to RESULT_BUF; mint a fresh
    //    DataCap from it; place at slot[0] so the kernel reflects
    //    it back into the parent's slot[0] on HALT.
    let res_ptr = (&raw mut RESULT_BUF) as *mut u8;
    unsafe { *res_ptr = sum };
    let res_addr = res_ptr as u32;
    unsafe { host_mint_data_cap(res_addr, 1, 0, 0) };

    sum as u64
}

#[cfg(not(target_env = "javm"))]
fn main() {}
