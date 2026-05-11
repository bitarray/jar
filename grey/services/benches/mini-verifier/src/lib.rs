//! Plonky3 STARK-verifier-shaped workload — Fiat-Shamir transcript +
//! FRI-fold linear combinations + AIR constraint evaluation, all in
//! Goldilocks field with WIDTH=8 Poseidon2 hash. Mirrors what
//! `p3_uni_stark::verify` does in its hot loop without dragging in the
//! full uni-stark machinery.
//!
//! The Goldilocks + Poseidon2 implementation lives in `bench-goldilocks-poseidon2`
//! and is hand-written rather than pulled from `p3-goldilocks` /
//! `p3-poseidon2` because Plonky3's crates transitively depend on
//! `tracing`, which requires atomic-pointer-width support — incompatible
//! with javm's `max-atomic-width: 0` target. Bit-exact with
//! `default_goldilocks_poseidon2_8` (same constants, same MDS, same S-box).
//!
//! ## Workload proportions per `mini_verifier_bench()` call
//!
//!   - 16 transcript Poseidon2 permutations (Fiat-Shamir derives)
//!   - 32 FRI queries × 12 fold steps = 384 permutations + 384 linear combs
//!   - 32 constraint-eval chains × 50 mul-add ops = 1600 Goldilocks ops
//!
//! Total ≈ 400 permutations + ~2400 Goldilocks field ops per call —
//! representative of one moderate STARK verify.

#![cfg_attr(target_os = "none", no_std)]

use javm_builtins as _;

#[cfg(target_env = "polkavm")]
mod polkavm;

use gp::{add, canonical, mul, permute, sub, ONE, WIDTH, ZERO};

const TRANSCRIPT_PERMS: usize = 16;
const FRI_QUERIES: usize = 32;
const FRI_FOLDS_PER_QUERY: usize = 12;
const CONSTRAINT_EVALS: usize = 32;
const CONSTRAINT_OPS_PER_EVAL: usize = 50;

/// One STARK-verifier-shaped pass. Returns low 32 bits of the accumulator
/// for cross-VM correctness checking.
pub fn mini_verifier_bench() -> u32 {
	// Deterministic seed — every cell distinct so all-zero collisions
	// don't hide bugs.
	let mut state: [u64; WIDTH] = [
		0xdeadbeef_00000000,
		0xdeadbeef_00000001,
		0xdeadbeef_00000002,
		0xdeadbeef_00000003,
		0xdeadbeef_00000004,
		0xdeadbeef_00000005,
		0xdeadbeef_00000006,
		0xdeadbeef_00000007,
	];

	let mut i = 0u64;
	while i < TRANSCRIPT_PERMS as u64 {
		let slot = (i as usize) % WIDTH;
		state[slot] = add(state[slot], i.wrapping_mul(0x9E3779B97F4A7C15));
		permute(&mut state);
		i += 1;
	}

	let mut accum = ZERO;
	let mut q = 0;
	while q < FRI_QUERIES {
		let mut left = state[0];
		let mut right = state[1];
		let mut sibling = state[2];
		let mut fold = 0;
		while fold < FRI_FOLDS_PER_QUERY {
			permute(&mut state);
			let challenge = state[(q + fold) % WIDTH];
			let one_minus_c = sub(ONE, challenge);
			left = add(mul(one_minus_c, left), mul(challenge, right));
			right = sibling;
			sibling = state[3];
			fold += 1;
		}
		accum = add(accum, left);
		q += 1;
	}

	let coeff_a = state[3];
	let coeff_b = state[5];
	let mut k = 0;
	while k < CONSTRAINT_EVALS {
		let mut x = state[k % WIDTH];
		let mut j = 0;
		while j < CONSTRAINT_OPS_PER_EVAL {
			x = add(mul(x, coeff_a), coeff_b);
			j += 1;
		}
		accum = add(accum, x);
		k += 1;
	}

	(canonical(accum) & 0xFFFF_FFFF) as u32
}
