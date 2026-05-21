//! Errors during SSZ decoding.

/// Errors encountered while decoding an SSZ-encoded byte slice.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// Input ended before the entire value could be read.
    #[error("unexpected end of input (expected {expected} bytes, got {actual})")]
    UnexpectedEof { expected: usize, actual: usize },

    /// Input contained more bytes than the expected value occupies.
    #[error("trailing bytes after value (expected {expected} bytes, got {actual})")]
    TrailingBytes { expected: usize, actual: usize },

    /// A length offset pointed outside the input slice or below the fixed region.
    #[error("invalid offset {offset} (data length {len}, fixed region {fixed})")]
    InvalidOffset {
        offset: usize,
        len: usize,
        fixed: usize,
    },

    /// Offsets must be monotonically non-decreasing.
    #[error("offsets not monotonic: {prev} > {curr}")]
    OffsetsNotMonotonic { prev: usize, curr: usize },

    /// A variable-length object exceeded its compile-time cap.
    #[error("list length {len} exceeds bound {bound}")]
    BoundExceeded { len: u64, bound: u64 },

    /// A fixed-length vector was given the wrong number of elements.
    #[error("fixed vector length mismatch (expected {expected}, got {actual})")]
    LengthMismatch { expected: usize, actual: usize },

    /// Union/Option selector outside the allowed range.
    #[error("invalid selector byte {0}")]
    InvalidSelector(u8),

    /// Bool byte was not 0 or 1.
    #[error("invalid bool byte {0}")]
    InvalidBool(u8),

    /// Bitlist sentinel `1` bit was missing.
    #[error("bitlist missing trailing sentinel bit")]
    MissingBitlistSentinel,

    /// Bitvector/Bitlist contained set bits beyond the declared length.
    #[error("excess bits set beyond declared length")]
    ExcessBits,

    /// Sorted-collection keys were not strictly ascending.
    #[error("keys not in strictly ascending order")]
    NotSorted,

    /// `NonZeroU32` decoded as zero.
    #[error("expected NonZeroU32 but got 0")]
    ZeroNonZero,

    /// Custom decode error from a user implementation.
    #[error("custom decode error: {0}")]
    Custom(&'static str),
}
