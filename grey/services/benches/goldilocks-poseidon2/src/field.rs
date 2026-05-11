// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) Rostro Foundation

//! Goldilocks field arithmetic — `F_p` with `p = 2^64 - 2^32 + 1`.
//!
//! Values are stored as `u64` and may be in `[0, 2^64)` (non-canonical) —
//! the operations preserve correctness mod p but don't canonicalize on
//! every step (canonicalization only at output via [`canonical`]).
//! This matches Plonky3's `Goldilocks` representation.

pub const P: u64 = 0xFFFF_FFFF_0000_0001;

/// `2^64 - p = 2^32 - 1`. The "wrap-around correction" used in additions
/// and the `* EPSILON` step of the reduction.
const EPSILON: u64 = 0xFFFF_FFFF;

pub const ZERO: u64 = 0;
pub const ONE: u64 = 1;

/// Add a + b mod p. Result may be non-canonical (in `[0, 2^64)`).
#[inline(always)]
pub fn add(a: u64, b: u64) -> u64 {
    let (r, c) = a.overflowing_add(b);
    if c {
        // (a+b) wrapped past 2^64. Equivalent: result is r + (2^64 - p) = r + EPSILON.
        // This may itself wrap past 2^64 if r is very large, but the
        // double-wrap result is still correct mod p (and stays in u64).
        r.wrapping_add(EPSILON)
    } else {
        r
    }
}

/// Subtract a - b mod p. Result may be non-canonical.
#[inline(always)]
pub fn sub(a: u64, b: u64) -> u64 {
    let (r, c) = a.overflowing_sub(b);
    if c {
        // a < b. Result is r + p (mod 2^64) = r - EPSILON.
        r.wrapping_sub(EPSILON)
    } else {
        r
    }
}

/// Multiply a * b mod p. Result may be non-canonical.
#[inline(always)]
pub fn mul(a: u64, b: u64) -> u64 {
    reduce128((a as u128) * (b as u128))
}

/// Reduce a 128-bit value mod p (Goldilocks fast reduction).
///
/// Decomposition: `x = lo + hi * 2^64`, with `hi = hi_hi * 2^32 + hi_lo`.
/// Modular identities:
///   `2^64  ≡ 2^32 - 1   (mod p)`  → `hi_lo * 2^64 ≡ hi_lo * (2^32 - 1)`
///   `2^96  ≡ -1         (mod p)`  → `hi_hi * 2^96 ≡ -hi_hi`
///
/// So `x mod p = lo - hi_hi + hi_lo * (2^32 - 1)`.
#[inline(always)]
fn reduce128(x: u128) -> u64 {
    let lo = x as u64;
    let hi = (x >> 64) as u64;
    let hi_hi = hi >> 32;
    let hi_lo = hi & EPSILON;

    let (t0, borrow) = lo.overflowing_sub(hi_hi);
    let t0 = if borrow { t0.wrapping_sub(EPSILON) } else { t0 };

    let t1 = hi_lo.wrapping_mul(EPSILON);
    let (r, carry) = t0.overflowing_add(t1);
    if carry {
        r.wrapping_add(EPSILON)
    } else {
        r
    }
}

/// Canonicalize: return the unique representative in `[0, p)`.
#[inline(always)]
pub fn canonical(a: u64) -> u64 {
    if a >= P {
        a.wrapping_sub(P)
    } else {
        a
    }
}

/// `x * x` shorthand — same cost as `mul(x, x)`, kept separate for
/// readability in the S-box.
#[inline(always)]
pub fn square(x: u64) -> u64 {
    mul(x, x)
}

/// 2 * x via `add(x, x)` — keeps the implementation in pure field ops
/// rather than relying on the storage representation.
#[inline(always)]
pub fn double(x: u64) -> u64 {
    add(x, x)
}
