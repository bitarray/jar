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

use javm_cap::{CapHash, CapHashOrRef, CapRef};

use super::Cache;
use super::STATE_CACHE_VA;

/// One scratch entry — a directory key that should be `decref`-ed at
/// end of RPC. The directory holds the actual Box; clear_scratch
/// drops the box when refcount hits zero.
pub(crate) enum ScratchEntry {
    Blob(CapHash),
    Instance(CapRef),
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

    /// Sweep all entries this RPC published. For each tracked key:
    /// decref it; if refcount drops to zero the directory's HashMap
    /// removes the entry and Drop frees the talc-allocated Box.
    /// Idempotent — safe to call multiple times.
    pub fn clear_scratch(&mut self) {
        // We can't hold the directory lock across the whole sweep
        // because `decref` re-takes it internally. Drain into a local
        // vec instead.
        let entries = core::mem::take(&mut self.scratch.entries);
        for entry in entries {
            let key = match entry {
                ScratchEntry::Blob(h) => CapHashOrRef::Hash(h),
                ScratchEntry::Instance(r) => CapHashOrRef::Ref(r),
            };
            // Best-effort: ignore "missing" errors (already cleaned up).
            let _ = self.decref(key);
        }
    }

    /// Track a directory key for end-of-RPC cleanup.
    pub(crate) fn track_scratch_blob(&mut self, h: CapHash) {
        self.scratch.entries.push(ScratchEntry::Blob(h));
    }

    pub(crate) fn track_scratch_instance(&mut self, r: CapRef) {
        self.scratch.entries.push(ScratchEntry::Instance(r));
    }
}

impl Drop for Cache {
    fn drop(&mut self) {
        self.clear_scratch();
    }
}
