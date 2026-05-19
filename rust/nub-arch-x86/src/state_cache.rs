//! Guest-side state-cache plumbing.
//!
//! At boot we install a kernel-mode mapping for the host's state
//! cache region (`STATE_CACHE_VA → STATE_CACHE_GPA`, 1 GiB, no USER
//! bit) so kernel-mode RPC dispatchers can read cache memory by
//! offset. Persistent — survives across per-invocation page-table
//! rebuilds via the shallow-PML4-copy mechanism in
//! [`crate::paging::PageTable::new`].
//!
//! In V0 the JIT does not read directly from the cache region; the
//! `nub_invoke_cached` dispatcher copies slabs into per-call Vec<u8>s
//! and hands those to the existing `jit_run::run_pvm_with_mem`. A
//! follow-up can flip the cache mapping to USER|RW so the JIT can
//! reference cache VAs directly.

#![cfg(target_os = "none")]

use core::sync::atomic::{AtomicBool, Ordering};

use nub_host_common::cache::{
    INSTANCE_INDEX_OFFSET, IndexSlot, InstanceIndex, MAX_INDEX_SLOTS, STATE_CACHE_GPA,
    STATE_CACHE_SIZE, STATE_CACHE_VA,
};

use crate::paging::{Perm, install_persistent_kernel_mapping};

static CACHE_MAPPED: AtomicBool = AtomicBool::new(false);

/// Idempotent: install the cache mapping in the active PML4 if not
/// already done. Called lazily from the first `nub_invoke_cached`
/// dispatch. Boot path doesn't depend on cache, so we defer until
/// first use.
pub fn ensure_mapped() -> Result<(), &'static str> {
    if CACHE_MAPPED.load(Ordering::Acquire) {
        return Ok(());
    }
    // Kernel-only (no USER) — V0 dispatcher reads from kernel mode.
    let perm = Perm::kernel_rw();
    unsafe {
        install_persistent_kernel_mapping(
            STATE_CACHE_VA,
            STATE_CACHE_GPA,
            STATE_CACHE_SIZE as u64,
            perm,
        )
        .ok_or("install_persistent_kernel_mapping failed")?;
    }
    CACHE_MAPPED.store(true, Ordering::Release);
    Ok(())
}

/// Read-only view into the cache's InstanceIndex.
fn index_ptr() -> *const InstanceIndex {
    (STATE_CACHE_VA + INSTANCE_INDEX_OFFSET as u64) as *const InstanceIndex
}

/// Look up an IndexSlot by instance hash. Returns a copy of the slot
/// (`#[repr(C)]` plain data).
pub fn lookup(hash: &[u8; 32]) -> Option<IndexSlot> {
    ensure_mapped().ok()?;
    let idx = index_ptr();
    for i in 0..MAX_INDEX_SLOTS {
        let slot_ptr = unsafe { core::ptr::addr_of!((*idx).slots[i]) };
        let slot_hash = unsafe { (*slot_ptr).instance_hash };
        if &slot_hash == hash {
            return Some(unsafe { core::ptr::read(slot_ptr) });
        }
    }
    None
}

/// Resolve a `(off, len)` slot field into a borrowed byte slice
/// pointing into cache memory.
///
/// # Safety
///
/// `ensure_mapped()` must have succeeded. `off + len` must be within
/// the cache region.
pub unsafe fn slab_bytes(off: u32, len: u32) -> &'static [u8] {
    let base = STATE_CACHE_VA + off as u64;
    unsafe { core::slice::from_raw_parts(base as *const u8, len as usize) }
}
