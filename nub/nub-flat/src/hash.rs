//! Content-addressing for the flat personality.
//!
//! # This is not a cryptographic hash
//!
//! It is FNV-1a run four times under different seeds and concatenated.
//! FNV is trivially collidable by construction — anyone who can choose
//! two inputs can make them collide. A personality that accepts objects
//! from an untrusted party **must** use a real cryptographic hash
//! (JAVM uses BLAKE2 through `javm-cap`); using this one there would let
//! an attacker substitute one program for another.
//!
//! It is here because the flat personality's job is to be the smallest
//! complete example of the `Personality`/`GuestPersonality` pair, and to
//! make nub's own benchmarks runnable. In that setting there is no
//! adversary, and a dependency-free 40-line hash keeps the example
//! readable and keeps the guest build free of a crate that would want
//! CPU feature detection on `x86_64-unknown-none`.
//!
//! The one real constraint it must satisfy: host and guest compute the
//! *same* value, since the host publishes by hash and invokes by hash.
//! That is what the round-trip test pins.

/// 32-byte object identity, matching `nub_kernel::ObjHash`'s shape.
pub type Hash = [u8; 32];

/// The wire's put-failure sentinel. `GuestStore::put_object` must never
/// return this value for a real object; with four independent 64-bit
/// lanes the odds of hitting all-ones are nil, but
/// [`content_hash`] forces a bit clear rather than relying on that.
pub const ERROR_SENTINEL: Hash = [0xFF; 32];

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Domain separators, one per output lane, so the four passes cannot
/// degenerate into the same function.
const SEEDS: [u64; 4] = [
    0x9E37_79B9_7F4A_7C15,
    0xBF58_476D_1CE4_E5B9,
    0x94D0_49BB_1331_11EB,
    0x2545_F491_4F6C_DD1D,
];

/// Content-address `bytes`.
///
/// See the module docs: adequate for identity, useless against an
/// adversary.
pub fn content_hash(bytes: &[u8]) -> Hash {
    let mut out = [0u8; 32];
    for (lane, seed) in SEEDS.iter().enumerate() {
        let mut h = FNV_OFFSET ^ seed;
        // Length first, so appending zeros cannot leave the digest
        // unchanged the way a pure byte fold would.
        for b in (bytes.len() as u64).to_le_bytes() {
            h = (h ^ u64::from(b)).wrapping_mul(FNV_PRIME);
        }
        for &b in bytes {
            h = (h ^ u64::from(b)).wrapping_mul(FNV_PRIME);
        }
        out[lane * 8..lane * 8 + 8].copy_from_slice(&h.to_le_bytes());
    }
    // Keep the all-ones sentinel unreachable, so a legitimate object can
    // never be mistaken for a put failure on the wire.
    out[31] &= 0x7F;
    out
}
