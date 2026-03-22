//! Cryptographic primitives for JAM (Section 3.8 of the Gray Paper).
//!
//! Provides:
//! - Blake2b-256 hashing (H)
//! - Keccak-256 hashing (HK)
//! - Ed25519 signatures
//! - Fisher-Yates shuffle (Appendix F)

pub mod bandersnatch;
pub mod blake2b;
pub mod bls;
pub mod ed25519;
pub mod keccak;
pub mod shuffle;

pub use bandersnatch::BandersnatchKeypair;
pub use blake2b::blake2b_256;
pub use bls::BlsKeypair;
pub use ed25519::{ed25519_verify, Ed25519Keypair};
pub use keccak::keccak_256;
