//! Polynomial evaluation via Horner's method — mirrors
//! `p3_uni_stark::verify`'s AIR constraint polynomial evaluation at
//! FRI challenge points.
//!
//! For each of `NUM_POINTS` challenge points `x`, evaluate a degree-
//! `(DEGREE - 1)` polynomial
//! `p(x) = c_0 + c_1·x + c_2·x² + … + c_{DEGREE-1}·x^(DEGREE-1)` via
//! Horner's method. Memory access is a sequential streaming read of
//! `coeffs[]` (4096 × u64 = 32 KiB, fits in L1). Compute: `DEGREE-1`
//! chained `mul + add` per point — totally dependent (each step
//! needs the previous result).
//!
//! Complements:
//!   - `goldilocks-mul`: chained mul, no add, no memory
//!   - `mini-verifier`: closed-form constraint eval (no memory access)
//!   - `fri-fold-tree`: scattered memory access

#![cfg_attr(target_os = "none", no_std)]

use nub_rt as _;

#[cfg(target_os = "none")]
extern crate alloc;

#[cfg(target_os = "none")]
use alloc::vec::Vec;

use gp::{add, canonical, mul, ZERO};

const DEGREE: usize = 4096;
const NUM_POINTS: usize = 64;
const SEED_COEFFS: u64 = 0x123456789abcdef0;
const SEED_POINTS: u64 = 0xfedcba9876543210;
const MULTIPLIER: u64 = 0x9E3779B97F4A7C15;

pub fn poly_eval_bench() -> u32 {
    let mut coeffs: Vec<u64> = Vec::with_capacity(DEGREE);
    let mut x = SEED_COEFFS;
    let mut i = 0;
    while i < DEGREE {
        x = mul(x, MULTIPLIER);
        coeffs.push(x);
        i += 1;
    }

    let mut points: [u64; NUM_POINTS] = [0; NUM_POINTS];
    let mut y = SEED_POINTS;
    let mut j = 0;
    while j < NUM_POINTS {
        y = mul(y, MULTIPLIER);
        points[j] = y;
        j += 1;
    }

    let mut accum = ZERO;
    let mut k = 0;
    while k < NUM_POINTS {
        let z = points[k];
        let mut result = coeffs[DEGREE - 1];
        let mut idx = DEGREE - 1;
        while idx > 0 {
            idx -= 1;
            result = add(mul(result, z), coeffs[idx]);
        }
        accum = add(accum, result);
        k += 1;
    }

    (canonical(accum) & 0xFFFF_FFFF) as u32
}
