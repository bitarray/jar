//! Shared no_std Goldilocks + Poseidon2-WIDTH8 implementation used
//! across the mini-verifier / goldilocks-mul / poseidon2-perm STARK
//! benches. See per-module docs for algorithm details.

#![no_std]

mod field;
mod poseidon2;

pub use field::{add, canonical, double, inv, mul, pow, square, sub, ONE, P, ZERO};
pub use poseidon2::{permute, WIDTH};
