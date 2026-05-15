//! Errors raised by execution-engine APIs.

use thiserror::Error;

/// Errors constructing or validating a `PvmProgram`.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProgramError {
    #[error("bitmask length {bitmask_len} does not match code length {code_len}")]
    BitmaskLenMismatch { code_len: usize, bitmask_len: usize },
}
