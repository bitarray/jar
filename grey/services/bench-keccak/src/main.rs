//! Keccak-256 hashing benchmark.

#![no_std]
#![no_main]

const MSG_LEN: usize = 1024;

#[cfg(not(target_env = "polkavm"))]
core::arch::global_asm!(
    ".global _start",
    "_start:",
    "call keccak_bench",
    "lui t0, 0xffff0",
    "jr t0",
);

#[cfg(target_env = "polkavm")]
core::arch::global_asm!(
    ".global _start",
    "_start:",
    "unimp",
);

use sha3::{Digest, Keccak256};

/// Keccak-256 of 1KB message.
#[cfg_attr(target_env = "polkavm", polkavm_derive::polkavm_export)]
#[no_mangle]
pub extern "C" fn keccak_bench() -> u32 {
    let mut msg = [0u8; MSG_LEN];
    let mut i: usize = 0;
    while i < MSG_LEN {
        msg[i] = (i & 0xFF) as u8;
        i += 1;
    }

    let mut hasher = Keccak256::new();
    hasher.update(&msg);
    let result = hasher.finalize();
    u32::from_le_bytes([result[0], result[1], result[2], result[3]])
}

#[no_mangle]
pub unsafe extern "C" fn memset(dst: *mut u8, val: i32, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n { unsafe { *dst.add(i) = val as u8; } i += 1; }
    dst
}

#[no_mangle]
pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n { unsafe { *dst.add(i) = *src.add(i); } i += 1; }
    dst
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    let mut i = 0;
    while i < n {
        let a = unsafe { *s1.add(i) };
        let b = unsafe { *s2.add(i) };
        if a != b { return a as i32 - b as i32; }
        i += 1;
    }
    0
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { core::arch::asm!("li a0, 0xDEAD", "unimp", options(noreturn)); }
}
