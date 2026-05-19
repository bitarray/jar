//! Poseidon2-WIDTH8 permutation-only benchmark — runs `PERM_COUNT`
//! permutations on a chained state so each iteration's input depends
//! on the previous output. Decomposes the hash cost out of the
//! mini-verifier composite workload.

#![cfg_attr(target_os = "none", no_std)]

use subsoil as _;

use gp::{canonical, permute};

const PERM_COUNT: u32 = 1_000;

pub fn poseidon2_perm_bench() -> u32 {
    let mut state: [u64; 8] = [
        0xdeadbeef_00000000,
        0xdeadbeef_00000001,
        0xdeadbeef_00000002,
        0xdeadbeef_00000003,
        0xdeadbeef_00000004,
        0xdeadbeef_00000005,
        0xdeadbeef_00000006,
        0xdeadbeef_00000007,
    ];
    let mut i = 0;
    while i < PERM_COUNT {
        permute(&mut state);
        i += 1;
    }
    (canonical(state[0]) & 0xFFFF_FFFF) as u32
}
