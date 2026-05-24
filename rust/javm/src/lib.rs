//! JAR v3 integration crate.
//!
//! Composes the foundational cap system (`javm-cap`) and the pure
//! execution engine (`javm-exec`) into a call-stack-aware VM driver
//! that implements the v3 kernel ABI.
//!
//! This crate is what `jar-kernel-v3` will call into for every CALL,
//! CALL_RESUME, host call, and yield routing.
//!
//! `Vm::invoke_cached` is the canonical entry point: callers publish
//! caps into a `TypedCache<Global>` (via `javm_cap::TypedCache::publish_*`)
//! and then ask the Vm to drive a published instance by hash. The
//! Vm holds only the call-stack-side working state; cap content
//! lives in the cache.

pub mod callstack;
pub mod ecall;
pub mod error;
pub mod frame;
pub mod image_cache;
pub mod kernel_assist;
pub mod vm;

pub use callstack::{
    CallStack, DEFAULT_MAX_DEPTH, Entry, EntryStatus, InstanceEntry, ReferenceEntry,
};
pub use error::VmError;
pub use frame::{BareFrame, MainFrame};
pub use image_cache::ImageCache;
pub use kernel_assist::{
    InProcessKernelAssist, KernelAssist, KernelImage, MeterId, QuotaId, kernel_image_hash,
    recognize_kernel_image,
};
pub use vm::{CallResult, Vm};
