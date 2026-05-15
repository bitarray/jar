//! Errors for cap operations.

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CapError {
    #[error("slot index {0} out of range for cnode of size 2^{1}")]
    SlotOutOfRange(u32, u8),
    #[error("invalid cnode size_log {0}; must be in [0, 16]")]
    InvalidCNodeSize(u8),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OpError {
    #[error("source slot is empty")]
    SourceEmpty,
    #[error("destination slot is occupied")]
    DestinationOccupied,
    #[error("slot {0} is pinned and cannot be mutated by generic MGMT ops")]
    SlotPinned(u32),
    #[error("MGMT_CNODE_SWAP must operate within a single cnode")]
    CrossCnodeSwap,
    #[error(transparent)]
    Cap(#[from] CapError),
}
