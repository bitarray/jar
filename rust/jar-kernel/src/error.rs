//! Errors surfaced by the v3 jar-kernel.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum KernelError {
    #[error("vm error: {0}")]
    Vm(#[from] javm::VmError),
    #[error("cap-table operation failed: {0}")]
    Cap(#[from] javm_cap::CapError),
    #[error("mgmt op failed: {0}")]
    Op(#[from] javm_cap::OpError),
    #[error("cache error: {0}")]
    TypedCache(#[from] javm_cap::CacheError),
    #[error("image conversion failed: {0}")]
    ImageConvert(#[from] javm_cap::ImageConvertError),
    #[error("file_id {0} not found in cache")]
    FileNotFound(u64),
    #[error(
        "storage quota exhausted (quota_id {0}): tried to write {1} bytes, only {2} available)"
    )]
    StorageExhausted(u64, u64, u64),
    #[error("invariant violated: {0}")]
    Invariant(&'static str),
    #[error("blob format error: {0}")]
    BlobFormat(&'static str),
}
