//! Sieve of Eratosthenes benchmark — counts primes up to N.

#![cfg_attr(target_os = "none", no_std)]

use javm_builtins as _;

const N: usize = 100_000;

#[cfg(target_env = "polkavm")]
mod polkavm;

/// Sieve of Eratosthenes: count primes up to N.
/// Returns the prime count (π(100000) = 9592).
pub fn prime_sieve() -> u32 {
    // Use static mut to avoid 100KB stack allocation — PVM stack is limited.
    // Initialized to 1 (prime) — reset to 0 for composites during sieve.
    static mut IS_PRIME: [u8; N] = [1; N];

    #[allow(static_mut_refs)]
    let is_prime = unsafe { &mut IS_PRIME };
    // Re-initialize each call (static persists across calls in the same instance)
    let mut i: usize = 0;
    while i < N {
        is_prime[i] = 1;
        i += 1;
    }
    is_prime[0] = 0;
    if N > 1 {
        is_prime[1] = 0;
    }

    // Sieve: mark multiples of each prime starting from p*p
    let mut p: usize = 2;
    while p * p < N {
        if is_prime[p] != 0 {
            let mut j = p * p;
            while j < N {
                is_prime[j] = 0;
                j += p;
            }
        }
        p += 1;
    }

    // Count primes
    let mut count: u32 = 0;
    let mut i: usize = 0;
    while i < N {
        count += is_prime[i] as u32;
        i += 1;
    }
    count
}
