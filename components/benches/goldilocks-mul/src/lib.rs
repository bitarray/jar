//! Goldilocks-multiplication-only benchmark — runs `MUL_COUNT`
//! multiplications in a chain so each iteration's input depends on
//! the previous output. Decomposes the field-arithmetic cost out of
//! the mini-verifier composite workload so per-VM differences in
//! handling `u64 * u64 -> u128 -> mod p_G` can be seen in isolation.

#![cfg_attr(target_os = "none", no_std)]

use nub_rt as _;

use gp::{canonical, mul};

const MUL_COUNT: u32 = 100_000;
const SEED: u64 = 0x123456789abcdef0;
const MULTIPLIER: u64 = 0x9E3779B97F4A7C15;

pub fn goldilocks_mul_bench() -> u32 {
    let mut acc = SEED;
    let mut i = 0;
    while i < MUL_COUNT {
        acc = mul(acc, MULTIPLIER);
        i += 1;
    }
    (canonical(acc) & 0xFFFF_FFFF) as u32
}
