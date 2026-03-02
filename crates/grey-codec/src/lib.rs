//! JAM serialization codec (Appendix C of the Gray Paper).
//!
//! Implements the JAM-specific encoding and decoding for all protocol types.
//! Key encoding rules:
//! - Fixed-width integers: little-endian (eq C.12)
//! - Sequences: length-prefixed with variable-length natural (eq C.1-C.4)
//! - Tuples: concatenation of element encodings
//! - Optionals: discriminator byte + payload (eq C.5-C.7)

pub mod decode;
pub mod encode;
pub mod error;

pub use decode::{Decode, DecodeWithConfig};
pub use encode::Encode;
pub use error::CodecError;
