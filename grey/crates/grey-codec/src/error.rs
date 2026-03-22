//! Codec error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CodecError {
    #[error("unexpected end of input: needed {needed} bytes, got {available}")]
    UnexpectedEof { needed: usize, available: usize },

    #[error("invalid discriminator byte: {0}")]
    InvalidDiscriminator(u8),

    #[error("sequence length {0} exceeds maximum {1}")]
    SequenceTooLong(usize, usize),

    #[error("invalid encoding: {0}")]
    InvalidEncoding(String),
}
