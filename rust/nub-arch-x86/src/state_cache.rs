//! Guest-side cache plumbing.
//!
//! Installs a kernel-mode mapping for the host's state cache region
//! (`STATE_CACHE_VA → STATE_CACHE_GPA`, 1 GiB, no USER bit) so
//! kernel-mode RPC dispatchers can read cache memory by offset.
//! Persistent — survives across per-invocation page-table rebuilds
//! via the shallow-PML4-copy mechanism in
//! [`crate::paging::PageTable::new`].
//!
//! Host and guest both map the region at the same VA
//! ([`STATE_CACHE_VA`]) via `MAP_FIXED_NOREPLACE` on the host side,
//! so every pointer the host wrote inside the region is directly
//! dereferenceable here. The cap directory (a `hashbrown::HashMap`
//! parameterised on the shared talc allocator) lives inside
//! `CacheHeader` at the region's base; both sides operate on the
//! same struct through the unified [`Cache`].

#![cfg(target_os = "none")]

use core::sync::atomic::{AtomicBool, Ordering};

use nub_host_common::cache::{Cache, STATE_CACHE_GPA, STATE_CACHE_SIZE, STATE_CACHE_VA};

use crate::paging::{Perm, install_persistent_kernel_mapping};

static CACHE_MAPPED: AtomicBool = AtomicBool::new(false);

/// Errors raised by guest-side `Cache` construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheErr {
    /// `install_persistent_kernel_mapping` couldn't add the region
    /// mapping.
    MapNotInstalled,
}

/// Idempotent: install the default cache mapping (`STATE_CACHE_VA →
/// STATE_CACHE_GPA`) in the active PML4 if not already done.
fn ensure_default_mapped() -> Result<(), CacheErr> {
    if CACHE_MAPPED.load(Ordering::Acquire) {
        return Ok(());
    }
    let perm = Perm::kernel_rw();
    // SAFETY: STATE_CACHE_VA / STATE_CACHE_GPA / size are agreed-upon
    // constants; the persistent kernel mapping is a one-time install
    // that the per-invocation page-table builder copies forward.
    unsafe {
        install_persistent_kernel_mapping(
            STATE_CACHE_VA,
            STATE_CACHE_GPA,
            STATE_CACHE_SIZE as u64,
            perm,
        )
        .ok_or(CacheErr::MapNotInstalled)?;
    }
    CACHE_MAPPED.store(true, Ordering::Release);
    Ok(())
}

/// Construct a guest-side [`Cache`] handle. Installs the persistent
/// kernel mapping for the cache region if not already done, then
/// returns the unified `Cache` (which views the host-initialised
/// `CacheHeader` at `STATE_CACHE_VA`).
pub fn init_guest_cache() -> Result<Cache, CacheErr> {
    ensure_default_mapped()?;
    // SAFETY: `ensure_default_mapped` just installed the mapping;
    // the host has initialised the `CacheHeader` at offset 0 of the
    // region before sharing it with us.
    Ok(unsafe { Cache::from_mapped_region() })
}
