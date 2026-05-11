// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) Rostro Foundation

//! Shared no_std-no-atomics Goldilocks + Poseidon2-WIDTH8 implementation
//! used across the rostro-vm-bench mini-verifier / goldilocks-mul /
//! poseidon2-perm services. See per-module docs for algorithm details.

#![no_std]

mod field;
mod poseidon2;

pub use field::{ONE, P, ZERO, add, canonical, double, mul, square, sub};
pub use poseidon2::{WIDTH, permute};
