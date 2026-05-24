//! Guest-side cache implementation.
//!
//! The guest-side [`super::Cache`] doesn't own the mmap region (that
//! lives in the host process) — it's just a pointer into the
//! kernel-mapped `STATE_CACHE_VA`. The caller is responsible for
//! ensuring the kernel page-table mapping has been installed before
//! constructing a `Cache` (see `nub-arch-x86`'s
//! `state_cache::init_guest_cache`).
//!
//! The guest's distinguishing state is the per-RPC [`ScratchTracker`]
//! that lets `clear_scratch` free entries published during one
//! `nub_invoke_cached` call when the RPC returns.

#![cfg(target_os = "none")]

extern crate alloc;

use alloc::vec::Vec;
use core::ptr::NonNull;

use super::Cache;
use super::STATE_CACHE_VA;

/// One scratch entry tracked for end-of-RPC cleanup. Until the
/// Cache's `publish_*` API is fleshed out in Commit 3 this is the
/// stub shape; the real `Blob { hash, entry }` / `Instance {
/// slot_idx, entry }` variants will land alongside the new typed
/// publish helpers.
pub(crate) enum ScratchEntry {
    /// Reserved — see module-level comment.
    _Placeholder,
}

/// Per-RPC tracker of guest-published cap entries.
pub(crate) struct ScratchTracker {
    pub(crate) entries: Vec<ScratchEntry>,
}

impl ScratchTracker {
    pub(crate) const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl Cache {
    /// Construct a `Cache` for the guest side. The caller must have
    /// already installed the kernel mapping for `STATE_CACHE_VA →
    /// STATE_CACHE_GPA`; the host must have initialised the
    /// `CacheHeader` at offset 0.
    ///
    /// # Safety
    ///
    /// - The cache region must be mapped at `STATE_CACHE_VA`.
    /// - The host must have called [`super::header::CacheHeader::init_at`]
    ///   already and claimed the talc heap.
    pub unsafe fn from_mapped_region() -> Self {
        // SAFETY: caller asserts the region is mapped + initialised.
        let base = unsafe { NonNull::new_unchecked(STATE_CACHE_VA as *mut u8) };
        Self {
            base,
            scratch: ScratchTracker::new(),
        }
    }
}

impl Drop for Cache {
    fn drop(&mut self) {
        // Per-RPC sweep: free all entries this RPC published.
        // Fully implemented in Commit 3 once publish_* is wired up.
        self.scratch.entries.clear();
    }
}
