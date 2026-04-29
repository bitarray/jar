/// Errors during SCALE decoding.
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("unexpected end of input")]
    UnexpectedEof,

    #[error("invalid discriminator byte: {0}")]
    InvalidDiscriminator(u8),

    #[error("sequence count {count} exceeds remaining bytes {remaining}")]
    SequenceTooLong { count: u32, remaining: u32 },

    #[error("set elements not in strictly ascending order")]
    NotSorted,
}
