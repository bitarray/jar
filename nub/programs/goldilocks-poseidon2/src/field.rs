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
#[cfg(not(target_arch = "bpf"))]
#[inline(always)]
pub fn mul(a: u64, b: u64) -> u64 {
    reduce128((a as u128) * (b as u128))
}

/// The same product, without `u128`.
///
/// LLVM's BPF backend cannot lower a 64x64 widening multiply: it calls
/// `__multi3`, and the backend rejects it with "A call to built-in
/// function '__multi3' is not supported" at every CPU level it accepts.
/// Since this function is the field backend for five of the ten
/// benchmark kernels, sBPF would otherwise be unable to run half the
/// suite.
///
/// The decomposition is exact — four 32x32 partial products reassembled
/// into the same (lo, hi) pair `(a as u128) * (b as u128)` would
/// produce — so [`reduce`] below yields bit-identical results and the
/// kernels return the same values as on every other engine. Verified
/// against the `u128` path in this module's tests.
///
/// **This is the one place the sBPF row does not run the same code as
/// the other engines.** Its numbers on the `gp`-backed kernels reflect
/// a different multiply implementation, and the report says so.
#[cfg(target_arch = "bpf")]
#[inline(always)]
pub fn mul(a: u64, b: u64) -> u64 {
    let (a_lo, a_hi) = (a & 0xffff_ffff, a >> 32);
    let (b_lo, b_hi) = (b & 0xffff_ffff, b >> 32);
    let ll = a_lo * b_lo;
    let lh = a_lo * b_hi;
    let hl = a_hi * b_lo;
    let hh = a_hi * b_hi;
    // Each addend is < 2^32, so the sum is < 2^34 and cannot overflow.
    let mid = (ll >> 32) + (lh & 0xffff_ffff) + (hl & 0xffff_ffff);
    let lo = (ll & 0xffff_ffff) | (mid << 32);
    let hi = hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
    reduce(lo, hi)
}

/// Reduce a 128-bit value mod p (Goldilocks fast reduction).
///
/// Decomposition: `x = lo + hi * 2^64`, with `hi = hi_hi * 2^32 + hi_lo`.
/// Modular identities:
///   `2^64  ≡ 2^32 - 1   (mod p)`  → `hi_lo * 2^64 ≡ hi_lo * (2^32 - 1)`
///   `2^96  ≡ -1         (mod p)`  → `hi_hi * 2^96 ≡ -hi_hi`
///
/// So `x mod p = lo - hi_hi + hi_lo * (2^32 - 1)`.
#[cfg(not(target_arch = "bpf"))]
#[inline(always)]
fn reduce128(x: u128) -> u64 {
    reduce(x as u64, (x >> 64) as u64)
}

/// The reduction itself, over an already-split 128-bit value.
///
/// Split out so the `bpf` multiply above — which has to build `(lo, hi)`
/// by hand because that backend has no widening multiply — shares this
/// exact arithmetic rather than restating it. `#[inline(always)]` on
/// both means the non-bpf path optimizes to what it always did; the
/// pinned `(value, gas)` vectors are the check on that.
#[inline(always)]
fn reduce(lo: u64, hi: u64) -> u64 {
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

/// `base ^ exp` mod p via right-to-left binary square-and-multiply.
///
/// Used by [`inv`] for Fermat's-little-theorem inversion. Naïve
/// algorithm (~64 squares + popcount(exp) muls) — Plonky3 uses a
/// faster addition chain for inversion specifically, but for a
/// benchmark of "how each VM handles exponentiation hot loops" this
/// is what we want: predictable branchy dependent multiplies,
/// exactly what the unoptimized algorithm looks like.
#[inline]
pub fn pow(base: u64, exp: u64) -> u64 {
    if exp == 0 {
        return ONE;
    }
    let mut result = ONE;
    let mut b = base;
    let mut e = exp;
    while e > 0 {
        if e & 1 == 1 {
            result = mul(result, b);
        }
        b = mul(b, b);
        e >>= 1;
    }
    result
}

/// Field inverse via Fermat's little theorem: `x^(p-2) mod p`.
///
/// `p - 2 = 0xFFFF_FFFE_FFFF_FFFF` — popcount = 63, so ~63 muls + ~64
/// squares per inversion. Heavy: a single inverse costs ~127 mul-
/// shaped ops. Montgomery's batch trick amortizes this to ~3 muls
/// per inverse over N elements.
#[inline]
pub fn inv(x: u64) -> u64 {
    pow(x, P - 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `bpf` multiply reassembles the 128-bit product from four
    /// 32x32 partial products because that backend has no widening
    /// multiply. It has to be *exactly* the same function as the `u128`
    /// path, or the sBPF row would return different values from every
    /// other engine and `bench-compare validate` would fail.
    ///
    /// This test compiles the bpf decomposition on the host and checks
    /// it against `u128` directly, so the property is verified on every
    /// `cargo test` rather than only when someone cross-compiles.
    fn widening_mul_bpf(a: u64, b: u64) -> (u64, u64) {
        let (a_lo, a_hi) = (a & 0xffff_ffff, a >> 32);
        let (b_lo, b_hi) = (b & 0xffff_ffff, b >> 32);
        let ll = a_lo * b_lo;
        let lh = a_lo * b_hi;
        let hl = a_hi * b_lo;
        let hh = a_hi * b_hi;
        let mid = (ll >> 32) + (lh & 0xffff_ffff) + (hl & 0xffff_ffff);
        let lo = (ll & 0xffff_ffff) | (mid << 32);
        let hi = hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
        (lo, hi)
    }

    #[test]
    fn bpf_widening_mul_matches_u128() {
        // Edges first: the carry chain through `mid` is where a
        // schoolbook decomposition goes wrong.
        let edges = [
            0u64,
            1,
            u64::MAX,
            u32::MAX as u64,
            u32::MAX as u64 + 1,
            P,
            P - 1,
            EPSILON,
            1 << 63,
            (1 << 32) | 1,
        ];
        for &a in &edges {
            for &b in &edges {
                let want = (a as u128) * (b as u128);
                let (lo, hi) = widening_mul_bpf(a, b);
                assert_eq!(
                    (lo, hi),
                    (want as u64, (want >> 64) as u64),
                    "widening_mul({a:#x}, {b:#x})"
                );
                assert_eq!(reduce(lo, hi), reduce128(want), "reduce({a:#x}, {b:#x})");
            }
        }

        // Then a deterministic sweep, so a regression is reproducible.
        let mut x = 0x2545_F491_4F6C_DD1Du64;
        for _ in 0..200_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let mut y = x.rotate_left(31) ^ 0x9E37_79B9_7F4A_7C15;
            y = y.wrapping_mul(0xBF58_476D_1CE4_E5B9);
            let want = (x as u128) * (y as u128);
            let (lo, hi) = widening_mul_bpf(x, y);
            assert_eq!((lo, hi), (want as u64, (want >> 64) as u64));
            assert_eq!(reduce(lo, hi), mul(x, y));
        }
    }
}
