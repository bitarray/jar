// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) Rostro Foundation

//! Poseidon2-Goldilocks WIDTH=8 permutation, bit-exact with Plonky3's
//! `default_goldilocks_poseidon2_8`.
//!
//! Round structure:
//!   - 1 initial MDS-light permutation
//!   - 4 external-initial rounds: add RC, S-box (x^7), MDS-light
//!   - 22 internal rounds: add RC[r] to state[0], S-box state[0], internal-MDS
//!   - 4 external-final rounds: add RC, S-box (x^7), MDS-light
//!
//! Round constants (`GOLDILOCKS_POSEIDON2_RC_8_*`) and the internal
//! diagonal matrix (`MATRIX_DIAG_8_GOLDILOCKS`) come verbatim from
//! `p3_goldilocks::poseidon2`.

use crate::field::{add, double, mul, square};

pub const WIDTH: usize = 8;

// Round constants — copied verbatim from
// `p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL` etc.

const RC_INITIAL: [[u64; WIDTH]; 4] = [
	[
		0xdd5743e7f2a5a5d9, 0xcb3a864e58ada44b, 0xffa2449ed32f8cdc, 0x42025f65d6bd13ee,
		0x7889175e25506323, 0x34b98bb03d24b737, 0xbdcc535ecc4faa2a, 0x5b20ad869fc0d033,
	],
	[
		0xf1dda5b9259dfcb4, 0x27515210be112d59, 0x4227d1718c766c3f, 0x26d333161a5bd794,
		0x49b938957bf4b026, 0x4a56b5938b213669, 0x1120426b48c8353d, 0x6b323c3f10a56cad,
	],
	[
		0xce57d6245ddca6b2, 0xb1fc8d402bba1eb1, 0xb5c5096ca959bd04, 0x6db55cd306d31f7f,
		0xc49d293a81cb9641, 0x1ce55a4fe979719f, 0xa92e60a9d178a4d1, 0x002cc64973bcfd8c,
	],
	[
		0xcea721cce82fb11b, 0xe5b55eb8098ece81, 0x4e30525c6f1ddd66, 0x43c6702827070987,
		0xaca68430a7b5762a, 0x3674238634df9c93, 0x88cee1c825e33433, 0xde99ae8d74b57176,
	],
];

const RC_FINAL: [[u64; WIDTH]; 4] = [
	[
		0x014ef1197d341346, 0x9725e20825d07394, 0xfdb25aef2c5bae3b, 0xbe5402dc598c971e,
		0x93a5711f04cdca3d, 0xc45a9a5b2f8fb97b, 0xfe8946a924933545, 0x2af997a27369091c,
	],
	[
		0xaa62c88e0b294011, 0x058eb9d810ce9f74, 0xb3cb23eced349ae4, 0xa3648177a77b4a84,
		0x43153d905992d95d, 0xf4e2a97cda44aa4b, 0x5baa2702b908682f, 0x082923bdf4f750d1,
	],
	[
		0x98ae09a325893803, 0xf8a6475077968838, 0xceb0735bf00b2c5f, 0x0a1a5d953888e072,
		0x2fcb190489f94475, 0xb5be06270dec69fc, 0x739cb934b09acf8b, 0x537750b75ec7f25b,
	],
	[
		0xe9dd318bae1f3961, 0xf7462137299efe1a, 0xb1f6b8eee9adb940, 0xbdebcc8a809dfe6b,
		0x40fc1f791b178113, 0x3ac1c3362d014864, 0x9a016184bdb8aeba, 0x95f2394459fbc25e,
	],
];

const RC_INTERNAL: [u64; 22] = [
	0x488897d85ff51f56, 0x1140737ccb162218, 0xa7eeb9215866ed35, 0x9bd2976fee49fcc9,
	0xc0c8f0de580a3fcc, 0x4fb2dae6ee8fc793, 0x343a89f35f37395b, 0x223b525a77ca72c8,
	0x56ccb62574aaa918, 0xc4d507d8027af9ed, 0xa080673cf0b7e95c, 0xf0184884eb70dcf8,
	0x044f10b0cb3d5c69, 0xe9e3f7993938f186, 0x1b761c80e772f459, 0x606cec607a1b5fac,
	0x14a0c2e1d45f03cd, 0x4eace8855398574f, 0xf905ca7103eff3e6, 0xf8c8f8d20862c059,
	0xb524fe8bdd678e5a, 0xfbb7865901a1ec41,
];

/// MATRIX_DIAG_8_GOLDILOCKS from p3-goldilocks. Diagonal of the internal
/// linear-layer matrix (which is `1 + diag(MATRIX_DIAG_8_GOLDILOCKS)`).
const MATRIX_DIAG: [u64; WIDTH] = [
	0xfffffffeffffffff, // -2
	0x0000000000000001, // 1
	0x0000000000000002, // 2
	0x7fffffff80000001, // 1/2
	0x0000000000000003, // 3
	0x7fffffff80000000, // -1/2
	0xfffffffefffffffe, // -3
	0xfffffffefffffffd, // -4
];

/// `x^7` S-box, decomposed into squares + multiplies for low constraint
/// degree (matches the AIR layout in `rostro-poseidon-air`).
#[inline(always)]
fn sbox(x: u64) -> u64 {
	let x2 = square(x);
	let x4 = square(x2);
	let x6 = mul(x4, x2);
	mul(x6, x)
}

/// 4×4 MDS matrix multiply (Plonky3's `apply_mat4`):
///   [ 2 3 1 1 ]
///   [ 1 2 3 1 ]
///   [ 1 1 2 3 ]
///   [ 3 1 1 2 ]
#[inline(always)]
fn apply_mat4(x: &mut [u64; 4]) {
	let t01 = add(x[0], x[1]);
	let t23 = add(x[2], x[3]);
	let t0123 = add(t01, t23);
	let t01123 = add(t0123, x[1]);
	let t01233 = add(t0123, x[3]);
	// Order matters — write x[3] and x[1] before x[0] and x[2].
	let new_x3 = add(t01233, double(x[0])); // 3*x[0] + x[1] + x[2] + 2*x[3]
	let new_x1 = add(t01123, double(x[2])); // x[0] + 2*x[1] + 3*x[2] + x[3]
	x[0] = add(t01123, t01); // 2*x[0] + 3*x[1] + x[2] + x[3]
	x[2] = add(t01233, t23); // x[0] + x[1] + 2*x[2] + 3*x[3]
	x[1] = new_x1;
	x[3] = new_x3;
}

/// MDS-light permutation for WIDTH=8: apply mat4 to each 4-block, then
/// for each i add the sum of state[i] and state[i+4].
#[inline(always)]
fn mds_light(state: &mut [u64; WIDTH]) {
	let (head, tail) = state.split_at_mut(4);
	let h: &mut [u64; 4] = head.try_into().unwrap();
	let t: &mut [u64; 4] = tail.try_into().unwrap();
	apply_mat4(h);
	apply_mat4(t);
	let sums: [u64; 4] = [
		add(state[0], state[4]),
		add(state[1], state[5]),
		add(state[2], state[6]),
		add(state[3], state[7]),
	];
	let mut i = 0;
	while i < WIDTH {
		state[i] = add(state[i], sums[i % 4]);
		i += 1;
	}
}

/// One external round: add RC, S-box every cell, MDS-light.
#[inline(always)]
fn external_round(state: &mut [u64; WIDTH], rc: &[u64; WIDTH]) {
	let mut i = 0;
	while i < WIDTH {
		state[i] = sbox(add(state[i], rc[i]));
		i += 1;
	}
	mds_light(state);
}

/// One internal round: add RC[r] to state[0] only, S-box state[0] only,
/// then internal MDS (`(1 + diag(MATRIX_DIAG)) * state`).
#[inline(always)]
fn internal_round(state: &mut [u64; WIDTH], rc: u64) {
	state[0] = sbox(add(state[0], rc));
	// matmul_internal: sum + state[i] * diag[i]
	let mut sum = state[0];
	let mut i = 1;
	while i < WIDTH {
		sum = add(sum, state[i]);
		i += 1;
	}
	i = 0;
	while i < WIDTH {
		state[i] = add(mul(state[i], MATRIX_DIAG[i]), sum);
		i += 1;
	}
}

/// Full Poseidon2-Goldilocks-WIDTH8 permutation in place.
pub fn permute(state: &mut [u64; WIDTH]) {
	mds_light(state);
	let mut r = 0;
	while r < 4 {
		external_round(state, &RC_INITIAL[r]);
		r += 1;
	}
	let mut r = 0;
	while r < 22 {
		internal_round(state, RC_INTERNAL[r]);
		r += 1;
	}
	let mut r = 0;
	while r < 4 {
		external_round(state, &RC_FINAL[r]);
		r += 1;
	}
}
