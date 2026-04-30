//! Blake2b-256 hashing benchmark.

#![cfg_attr(target_os = "none", no_std)]

use javm_builtins as _;

use blake2::digest::{consts::U32, Digest};
use blake2::Blake2b;

type Blake2b256 = Blake2b<U32>;

const MSG_LEN: usize = 1024;

#[cfg(target_env = "polkavm")]
mod polkavm;

/// Hash a 1KB message with Blake2b-256. Returns first 4 bytes of hash as u32.
pub fn blake2b_bench() -> u32 {
    let mut msg = [0u8; MSG_LEN];
    let mut i: usize = 0;
    while i < MSG_LEN {
        msg[i] = (i & 0xFF) as u8;
        i += 1;
    }

    let mut hasher = Blake2b256::new();
    hasher.update(msg);
    let result = hasher.finalize();

    u32::from_le_bytes([result[0], result[1], result[2], result[3]])
}
