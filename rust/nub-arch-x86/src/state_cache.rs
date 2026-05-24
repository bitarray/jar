//! Guest-side state-cache plumbing.
//!
//! At boot we install a kernel-mode mapping for the host's state
//! cache region (`STATE_CACHE_VA → STATE_CACHE_GPA`, 1 GiB, no USER
//! bit) so kernel-mode RPC dispatchers can read cache memory by
//! offset. Persistent — survives across per-invocation page-table
//! rebuilds via the shallow-PML4-copy mechanism in
//! [`crate::paging::PageTable::new`].
//!
//! Host and guest both map the region at the same VA
//! ([`STATE_CACHE_VA`]) via `MAP_FIXED_NOREPLACE` on the host side,
//! which means every pointer the host wrote inside the region is
//! directly dereferenceable here. The directory at
//! [`CACHE_DIRECTORY_OFFSET`] holds `(CapHash, entry_va)` /
//! `(CapRef, entry_va)` pairs that resolve cap queries into a
//! `&CacheEntry<TalcAlloc>` we can walk by pointer.
//!
//! ## Public API: the [`GuestCache`] struct
//!
//! All in-kernel cache access goes through [`GuestCache`] — its methods
//! return `&Cap` / `&mut Cap` borrows whose lifetime is tied to
//! `&GuestCache` / `&mut GuestCache`. The borrow checker enforces "no
//! eviction during read": while a `&Cap` is live, any `&mut GuestCache`
//! op (publish / promote / clone / clear) is rejected by the
//! compiler.
//!
//! `GuestCache` is just a pointer to the cache region's base. The
//! default constructor picks [`STATE_CACHE_VA`]; every dereference
//! goes through `self.base` so multi-region setups can be added by
//! introducing an alternate constructor when needed.

#![cfg(target_os = "none")]

extern crate alloc;

use alloc::vec::Vec;
use allocator_api2::alloc::Allocator;
use allocator_api2::boxed::Box as ABox;
use core::cell::UnsafeCell;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering};

use javm_cap::cap::{Cap, CapHashOrRef};
use javm_cap::entry::CacheEntry;
use nub_host_common::cache::{
    CACHE_DIRECTORY_OFFSET, CacheDirectory, STATE_CACHE_GPA, STATE_CACHE_SIZE, STATE_CACHE_VA,
};
use nub_talc_util::{CacheTalcLock, TalcAlloc};

use crate::paging::{Perm, install_persistent_kernel_mapping};

static CACHE_MAPPED: AtomicBool = AtomicBool::new(false);

/// One scratch entry tracked for end-of-RPC cleanup. Blobs are
/// removed by content hash (via [`CacheDirectory::remove_blob`])
/// because the open-addressed directory may shift slots during
/// other deletions in the same RPC. Instances are removed by slot
/// index (the instance table is direct-indexed and stable). The
/// `CacheEntry` storage is reclaimed when the corresponding cleanup
/// fires — provided no live handle still references it.
enum ScratchEntry {
    Blob {
        hash: [u8; 32],
        entry: NonNull<CacheEntry<TalcAlloc>>,
    },
    Instance {
        slot_idx: usize,
        entry: NonNull<CacheEntry<TalcAlloc>>,
    },
}

/// Per-RPC tracker of guest-published cap entries so we can clear
/// them at end of dispatch. The guest writes new caps into the
/// host-visible `CacheDirectory` for the duration of one
/// `nub_invoke_cached` call (e.g., children minted by in-kernel
/// `derive_spawn`); they're cleared before the RPC returns so the
/// host doesn't see stale "scratch" entries.
struct ScratchTracker {
    entries: Vec<ScratchEntry>,
}

/// SAFETY: single-threaded guest (Hyperlight serialises calls).
unsafe impl Sync for ScratchTracker {}

struct ScratchCell {
    inner: UnsafeCell<ScratchTracker>,
}

/// SAFETY: single-threaded guest.
unsafe impl Sync for ScratchCell {}

static SCRATCH: ScratchCell = ScratchCell {
    inner: UnsafeCell::new(ScratchTracker {
        entries: Vec::new(),
    }),
};

/// Idempotent: install the default cache mapping (`STATE_CACHE_VA →
/// STATE_CACHE_GPA`) in the active PML4 if not already done. Called
/// from [`GuestCache::new`].
fn ensure_default_mapped() -> Result<(), &'static str> {
    if CACHE_MAPPED.load(Ordering::Acquire) {
        return Ok(());
    }
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

/// Read-only view into a cache region's `CacheDirectory`.
fn directory_ptr(base: NonNull<u8>) -> *const CacheDirectory {
    // SAFETY: caller guarantees `base` points at a live cache region
    // of size at least `CACHE_DIRECTORY_OFFSET + size_of::<CacheDirectory>()`.
    unsafe { base.as_ptr().add(CACHE_DIRECTORY_OFFSET).cast() }
}

/// Mutable view into a cache region's `CacheDirectory`.
fn directory_mut_ptr(base: NonNull<u8>) -> *mut CacheDirectory {
    // SAFETY: same as `directory_ptr`.
    unsafe { base.as_ptr().add(CACHE_DIRECTORY_OFFSET).cast() }
}

/// `TalcAlloc` handle for a given cache region. Cheap (wraps a pointer).
fn talc_alloc(base: NonNull<u8>) -> TalcAlloc {
    let lock_ptr = base.cast::<CacheTalcLock>();
    // SAFETY: caller guarantees `base` points at a cache region whose
    // first bytes are a live `CacheTalcLock` (initialised by the host
    // before the region is shared).
    unsafe { TalcAlloc::from_raw(lock_ptr) }
}

/// Look up a blob (content-addressed cap) by hash. Returns a borrowed
/// reference to the `CacheEntry` living in cache memory. The
/// `'static` lifetime is a polite fiction tightened to the
/// surrounding `&GuestCache` borrow by [`GuestCache::read_blob`].
fn lookup_blob<A: Allocator + Clone>(
    base: NonNull<u8>,
    hash: &[u8; 32],
) -> Option<&'static CacheEntry<A>> {
    let dir = directory_ptr(base);
    // SAFETY: dir is a live pointer; find_blob just scans the array.
    let (_, slot_ptr) = unsafe { CacheDirectory::find_blob(dir, hash) }?;
    let va = unsafe { (*slot_ptr).entry_va };
    if va == 0 {
        return None;
    }
    // SAFETY: the host wrote a valid CacheEntry<TalcAlloc> at this VA;
    // host VA == guest VA so the pointer is directly dereferenceable.
    Some(unsafe { &*(va as *const CacheEntry<A>) })
}

/// Resolve an instance ref to its `CacheEntry`. Same lifetime
/// caveat as [`lookup_blob`].
fn lookup_instance<A: Allocator + Clone>(
    base: NonNull<u8>,
    ref_id: u64,
) -> Option<&'static CacheEntry<A>> {
    let dir = directory_ptr(base);
    let (_, slot_ptr) = unsafe { CacheDirectory::find_instance(dir, ref_id) }?;
    let va = unsafe { (*slot_ptr).entry_va };
    if va == 0 {
        return None;
    }
    Some(unsafe { &*(va as *const CacheEntry<A>) })
}

/// Publish a `Cap<TalcAlloc>` to the shared cache region by writing
/// a fresh `CacheEntry<TalcAlloc>` to the talc heap and recording
/// `(hash, entry_va)` in the host-visible `CacheDirectory`.
///
/// Tracks the published entry in [`SCRATCH`] so [`clear_scratch`]
/// can free + zero the directory slot at end of RPC.
///
/// V1: the host's `TypedCache<TalcAlloc>` BTreeMap is NOT updated — the
/// guest's view is via the directory only. The host doesn't query
/// guest-published caps mid-RPC (Hyperlight serialises calls), and
/// the cleanup at end-of-RPC ensures no stale entries leak across
/// invocations.
fn publish_blob(
    base: NonNull<u8>,
    hash: [u8; 32],
    cap: Cap<TalcAlloc>,
) -> Result<(), &'static str> {
    let alloc = talc_alloc(base);
    let entry = CacheEntry::new(cap);
    let boxed = ABox::try_new_in(entry, alloc).map_err(|_| "publish_blob: alloc failed")?;
    // Leak the Box so the cache owns the entry; the pointer is
    // recorded in `SCRATCH` and freed in `clear_scratch`.
    let entry_ptr: *mut CacheEntry<TalcAlloc> = ABox::into_raw(boxed);
    let entry_nn = NonNull::new(entry_ptr).expect("just allocated");
    let entry_va = entry_ptr as u64;

    let dir_ptr = directory_mut_ptr(base);
    // SAFETY: directory ptr is in the persistent kernel mapping.
    // `insert_blob` does the probe + write under one call.
    if unsafe { CacheDirectory::insert_blob(dir_ptr, hash, entry_va) }.is_none() {
        // Roll back the entry allocation on directory-full.
        // SAFETY: we just got `entry_ptr` from `ABox::into_raw`.
        unsafe {
            let restored = ABox::from_raw_in(entry_ptr, talc_alloc(base));
            drop(restored);
        }
        return Err("publish_blob: directory full");
    }

    // Record for cleanup at end of RPC.
    // SAFETY: single-threaded guest.
    let tracker = unsafe { &mut *SCRATCH.inner.get() };
    tracker.entries.push(ScratchEntry::Blob {
        hash,
        entry: entry_nn,
    });
    Ok(())
}

/// Publish a fresh `Cap::Instance` (or any mutable Cap variant) to
/// the shared cache's instance bucket. Allocates a `CapRef` via the
/// directory's shared `alloc_ref`, writes the `(ref_id, entry_va)`
/// pair to the instance slot, and records the entry in [`SCRATCH`]
/// for end-of-RPC cleanup.
///
/// Returns the assigned `CapRef` for cnode-slot insertion etc.
fn publish_instance(base: NonNull<u8>, cap: Cap<TalcAlloc>) -> Result<u64, &'static str> {
    let alloc = talc_alloc(base);
    let entry = CacheEntry::new(cap);
    let boxed = ABox::try_new_in(entry, alloc).map_err(|_| "publish_instance: alloc failed")?;
    let entry_ptr: *mut CacheEntry<TalcAlloc> = ABox::into_raw(boxed);
    let entry_nn = NonNull::new(entry_ptr).expect("just allocated");
    let entry_va = entry_ptr as u64;

    let dir_ptr = directory_mut_ptr(base);
    // SAFETY: dir_ptr is in the persistent kernel mapping; alloc_ref
    // takes a const ptr and works through atomic ops.
    let (ref_id, slot_idx) = match unsafe { CacheDirectory::alloc_ref(dir_ptr) } {
        Some(pair) => pair,
        None => {
            // Roll back the allocation we made before bailing.
            // SAFETY: we just got `entry_ptr` from `ABox::into_raw`.
            unsafe {
                let restored = ABox::from_raw_in(entry_ptr, talc_alloc(base));
                drop(restored);
            }
            return Err("publish_instance: instance directory full");
        }
    };
    // SAFETY: slot_idx < MAX_INSTANCE_SLOTS; alloc_ref's contract
    // guarantees the slot is currently empty.
    unsafe {
        let slot = CacheDirectory::instance_slot_ptr(dir_ptr, slot_idx);
        (*slot).ref_id = ref_id;
        (*slot).entry_va = entry_va;
        (*dir_ptr).instance_count_incr();
    }

    // Record for cleanup at end of RPC.
    // SAFETY: single-threaded guest.
    let tracker = unsafe { &mut *SCRATCH.inner.get() };
    tracker.entries.push(ScratchEntry::Instance {
        slot_idx,
        entry: entry_nn,
    });
    Ok(ref_id)
}

/// Clear all entries this RPC published via [`publish_blob`] /
/// [`publish_instance`]. Walks the scratch tracker; for each entry:
///
/// 1. If the entry's refcount is still > 1 (a [`CapHandle`] outside
///    the now-dropped per-RPC stack still references it), log via
///    debug-assert and SKIP the slot — leaving it live for the host
///    to reclaim out of band. This is a safety net for bugs; in a
///    well-disciplined RPC the stack drop should bring every handle
///    down to refcount==1 (the scratch tracker's own reference).
/// 2. Otherwise zero the directory slot and free the talc-heap
///    `CacheEntry` storage.
///
/// MUST be called AFTER the call-loop's `Vec<KernelFrame>` has been
/// dropped, so frame-held handles decrement their refcounts first.
fn clear_scratch(base: NonNull<u8>) {
    let alloc = talc_alloc(base);
    let dir_ptr = directory_mut_ptr(base);

    // SAFETY: single-threaded guest.
    let tracker = unsafe { &mut *SCRATCH.inner.get() };
    for scratch in tracker.entries.drain(..) {
        // Refcount safety net: if anyone still holds a handle, leave
        // the entry alone. The publish protocol initialises refcount
        // to 1 ("the scratch tracker's reference"); a refcount > 1
        // means a live CapHandle is still pointing here.
        let entry_ptr = match &scratch {
            ScratchEntry::Blob { entry, .. } => entry.as_ptr(),
            ScratchEntry::Instance { entry, .. } => entry.as_ptr(),
        };
        let count = unsafe { (*entry_ptr).refcount.load(Ordering::Acquire) };
        if count > 1 {
            // Leak rather than free under a live handle.
            debug_assert!(
                false,
                "clear_scratch: entry still held (refcount={count}); skipping free"
            );
            continue;
        }

        match scratch {
            ScratchEntry::Blob { hash, entry } => {
                // SAFETY: directory ptr is valid; `remove_blob` does
                // backward-shift to keep probe chains dense.
                let removed = unsafe { CacheDirectory::remove_blob(dir_ptr, &hash) };
                debug_assert!(removed, "scratch blob missing from directory at cleanup");
                // SAFETY: allocated via `ABox::try_new_in` in publish.
                unsafe {
                    let boxed = ABox::from_raw_in(entry.as_ptr(), alloc);
                    drop(boxed);
                }
            }
            ScratchEntry::Instance { slot_idx, entry } => {
                // SAFETY: slot_idx < MAX_INSTANCE_SLOTS by construction.
                unsafe {
                    CacheDirectory::free_instance(dir_ptr, slot_idx);
                    (*dir_ptr).instance_count_decr();
                }
                // SAFETY: allocated via `ABox::try_new_in` in publish.
                unsafe {
                    let boxed = ABox::from_raw_in(entry.as_ptr(), alloc);
                    drop(boxed);
                }
            }
        }
    }
}

// ============================================================
// `GuestCache` struct — the lifetime-correct, no-SSZ-Merkle API
// ============================================================

/// Cap-not-found / invalid-state errors returned by `GuestCache` methods.
/// Kept as a small enum so callers can branch on the cause without
/// matching on string literals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheErr {
    /// The requested hash or ref isn't present in the directory.
    NotFound,
    /// `promote_blob` was called on an immutable cap kind
    /// (`Cap::Image`, `Cap::Type`).
    NotMutable,
    /// Directory ran out of slots (blob bucket full, or instance
    /// `alloc_ref` collided every retry).
    DirectoryFull,
    /// Allocator returned `AllocError`.
    AllocFailed,
    /// `ensure_default_mapped` couldn't install the persistent kernel mapping.
    MapNotInstalled,
}

/// Guest-side cache handle. Holds a pointer to the cache region's
/// base; methods derive the talc-lock pointer (offset 0) and the
/// `CacheDirectory` pointer (offset [`CACHE_DIRECTORY_OFFSET`]) from
/// it. No method body hardcodes [`STATE_CACHE_VA`] — that's only the
/// default that [`GuestCache::new`] uses to construct `base`.
///
/// `GuestCache` exists as a Rust-level marker so callers can take
/// `&GuestCache` / `&mut GuestCache` borrows; Rust's borrow checker then
/// prevents publish/promote/clear ops from running while a `&Cap`
/// read borrow is live (no eviction during reads).
///
/// Construct via [`GuestCache::new`] at kernel boot. Pass `&mut GuestCache` to
/// the call loop; pass `&GuestCache` to read-only paths.
pub struct GuestCache {
    base: NonNull<u8>,
}

// SAFETY: `base` addresses the shared cache region; single-threaded
// guest (Hyperlight serialises host↔guest calls) means there's no
// cross-thread access from the guest side.
unsafe impl Send for GuestCache {}

impl GuestCache {
    /// Construct a `GuestCache` handle for the default region at
    /// [`STATE_CACHE_VA`], installing the persistent kernel mapping
    /// if not already done. Cheap to call repeatedly.
    pub fn new() -> Result<Self, CacheErr> {
        ensure_default_mapped().map_err(|_| CacheErr::MapNotInstalled)?;
        let base = NonNull::new(STATE_CACHE_VA as *mut u8).expect("STATE_CACHE_VA is non-null");
        Ok(Self { base })
    }

    /// Allocator handle for the shared talc heap. Cheap to clone.
    pub fn allocator(&self) -> TalcAlloc {
        talc_alloc(self.base)
    }

    /// Look up a content-addressed blob. Returns `&Cap` with
    /// lifetime tied to `&self`; the borrow checker stops anyone
    /// from publishing / promoting / clearing while it lives.
    pub fn read_blob(&self, h: &javm_cap::CapHash) -> Option<&Cap<TalcAlloc>> {
        let entry = lookup_blob::<TalcAlloc>(self.base, h)?;
        Some(&entry.cap)
    }

    /// Look up an identity-addressed instance.
    pub fn read_instance(&self, r: javm_cap::CapRef) -> Option<&Cap<TalcAlloc>> {
        let entry = lookup_instance::<TalcAlloc>(self.base, r)?;
        Some(&entry.cap)
    }

    /// Dispatch a `CapHashOrRef` to the matching bucket.
    pub fn read_cap(&self, k: CapHashOrRef) -> Option<&Cap<TalcAlloc>> {
        match k {
            CapHashOrRef::Hash(h) => self.read_blob(&h),
            CapHashOrRef::Ref(r) => self.read_instance(r),
        }
    }

    /// Mutable access to an instance. Implements Arc-`make_mut`
    /// semantics on the entry's refcount: refcount==1 → mutate in
    /// place; refcount>1 → shallow-clone the cap into a fresh entry,
    /// install in the same directory slot, drop the old entry's
    /// refcount by 1 (other holders keep observing the original).
    ///
    /// Currently unused — wired in once the spec defines the
    /// scratchpad-cnode return mechanism. See the data-flow
    /// principle commentary in `call_loop.rs`.
    #[allow(dead_code)]
    pub fn mut_instance(&mut self, r: javm_cap::CapRef) -> Result<&mut Cap<TalcAlloc>, CacheErr> {
        let dir_ptr = directory_mut_ptr(self.base);
        // SAFETY: dir_ptr is live for the cache's lifetime.
        let (slot_idx, _slot_ptr) =
            unsafe { CacheDirectory::find_instance(dir_ptr, r) }.ok_or(CacheErr::NotFound)?;
        // SAFETY: slot is present (we just located it) — entry_va is non-zero.
        let entry_va = unsafe { (*CacheDirectory::instance_slot_ptr(dir_ptr, slot_idx)).entry_va };
        if entry_va == 0 {
            return Err(CacheErr::NotFound);
        }
        let entry_ptr = entry_va as *mut CacheEntry<TalcAlloc>;
        // SAFETY: entry_ptr is live by directory contract.
        let refcount = unsafe { (*entry_ptr).refcount.load(Ordering::Acquire) };
        if refcount == 1 {
            // Sole owner: mutate in place.
            // SAFETY: we hold &mut self; no other &GuestCache borrow can
            // be live, so nothing else dereferences this entry.
            return Ok(unsafe { &mut (*entry_ptr).cap });
        }
        // Shared: clone via shallow_clone_cap; install fresh entry
        // in the same slot; drop original refcount by 1.
        let alloc = self.allocator();
        let cloned: Cap<TalcAlloc> = {
            // SAFETY: as above.
            let orig_cap = unsafe { &(*entry_ptr).cap };
            javm_cap::cache::shallow_clone_cap(orig_cap, alloc)
                .map_err(|_| CacheErr::AllocFailed)?
        };
        let new_entry = CacheEntry::new(cloned);
        let new_boxed =
            ABox::try_new_in(new_entry, self.allocator()).map_err(|_| CacheErr::AllocFailed)?;
        let new_entry_ptr = ABox::into_raw(new_boxed);
        let new_entry_nn = NonNull::new(new_entry_ptr).expect("just allocated");
        let new_entry_va = new_entry_ptr as u64;

        // Swap the directory slot to point at the new entry, then
        // decrement the old entry's refcount.
        // SAFETY: same slot we located above; valid for the cache.
        unsafe {
            let slot = CacheDirectory::instance_slot_ptr(dir_ptr, slot_idx);
            (*slot).entry_va = new_entry_va;
            (*entry_ptr).refcount.fetch_sub(1, Ordering::Release);
        }

        // Record the new entry in scratch (so clear_scratch frees it).
        // SAFETY: single-threaded guest.
        let tracker = unsafe { &mut *SCRATCH.inner.get() };
        tracker.entries.push(ScratchEntry::Instance {
            slot_idx,
            entry: new_entry_nn,
        });

        // SAFETY: we just published it; no one else has a reference.
        Ok(unsafe { &mut (*new_entry_ptr).cap })
    }

    /// Promote a blob (Hash-keyed) into the instance bucket
    /// (Ref-keyed). Move-promote when the blob's refcount is 1 (sole
    /// holder is the cache itself); shallow-clone otherwise. Returns
    /// the fresh `CapRef` either way. Mirrors host-side
    /// `GuestCache::get_mut`.
    ///
    /// Currently unused — wired in once the spec defines the
    /// scratchpad-cnode return mechanism.
    #[allow(dead_code)]
    pub fn promote_blob(&mut self, h: &javm_cap::CapHash) -> Result<javm_cap::CapRef, CacheErr> {
        let dir_ptr = directory_mut_ptr(self.base);
        // SAFETY: dir_ptr in persistent kernel mapping.
        let (_, slot_ptr) =
            unsafe { CacheDirectory::find_blob(dir_ptr, h) }.ok_or(CacheErr::NotFound)?;
        let entry_va = unsafe { (*slot_ptr).entry_va };
        if entry_va == 0 {
            return Err(CacheErr::NotFound);
        }
        let entry_ptr = entry_va as *mut CacheEntry<TalcAlloc>;
        // SAFETY: live by directory contract.
        match unsafe { &(*entry_ptr).cap } {
            Cap::Image(_) | Cap::Type(_) => return Err(CacheErr::NotMutable),
            _ => {}
        }
        // SAFETY: same.
        let refcount = unsafe { (*entry_ptr).refcount.load(Ordering::Acquire) };
        if refcount == 1 {
            // Move-promote: remove blob slot (backward-shift), allocate
            // fresh instance ref, point it at the existing entry. No clone.
            let (ref_id, inst_slot_idx) =
                unsafe { CacheDirectory::alloc_ref(dir_ptr) }.ok_or(CacheErr::DirectoryFull)?;
            // SAFETY: directory ops.
            unsafe {
                CacheDirectory::remove_blob(dir_ptr, h);
                let islot = CacheDirectory::instance_slot_ptr(dir_ptr, inst_slot_idx);
                (*islot).ref_id = ref_id;
                (*islot).entry_va = entry_va;
                (*dir_ptr).instance_count_incr();
            }
            // Record in scratch so clear_scratch can release.
            // SAFETY: single-threaded guest.
            let tracker = unsafe { &mut *SCRATCH.inner.get() };
            let entry_nn = NonNull::new(entry_ptr).expect("non-null");
            tracker.entries.push(ScratchEntry::Instance {
                slot_idx: inst_slot_idx,
                entry: entry_nn,
            });
            return Ok(ref_id);
        }
        // Shared: shallow-clone the cap, publish under fresh CapRef.
        let alloc = self.allocator();
        let cloned: Cap<TalcAlloc> = {
            // SAFETY: as above.
            let orig_cap = unsafe { &(*entry_ptr).cap };
            javm_cap::cache::shallow_clone_cap(orig_cap, alloc)
                .map_err(|_| CacheErr::AllocFailed)?
        };
        self.publish_instance(cloned)
    }

    /// Allocate a fresh `CapRef` pointing at the same entry as `r`.
    /// Bumps the entry's refcount by 1. Cheap pointer-clone — no
    /// `Cap` content is duplicated. Will be used by cnode inheritance
    /// once `dispatch_host_call` switches from value-copy to
    /// ref-clone semantics (gated on scratchpad mechanism).
    #[allow(dead_code)]
    pub fn clone_instance(&mut self, r: javm_cap::CapRef) -> Result<javm_cap::CapRef, CacheErr> {
        let dir_ptr = directory_mut_ptr(self.base);
        let (slot_idx, _) =
            unsafe { CacheDirectory::find_instance(dir_ptr, r) }.ok_or(CacheErr::NotFound)?;
        // SAFETY: directory.
        let entry_va = unsafe { (*CacheDirectory::instance_slot_ptr(dir_ptr, slot_idx)).entry_va };
        if entry_va == 0 {
            return Err(CacheErr::NotFound);
        }
        let entry_ptr = entry_va as *mut CacheEntry<TalcAlloc>;
        // Bump refcount before publishing the new slot — keeps the
        // entry alive even if some other holder drops to zero between
        // now and the slot write.
        // SAFETY: entry live.
        unsafe { (*entry_ptr).refcount.fetch_add(1, Ordering::Relaxed) };
        // Allocate a fresh ref + slot.
        let (new_ref, new_slot_idx) =
            unsafe { CacheDirectory::alloc_ref(dir_ptr) }.ok_or_else(|| {
                // Roll back the refcount bump on directory-full.
                // SAFETY: same entry.
                unsafe { (*entry_ptr).refcount.fetch_sub(1, Ordering::Release) };
                CacheErr::DirectoryFull
            })?;
        // SAFETY: directory.
        unsafe {
            let slot = CacheDirectory::instance_slot_ptr(dir_ptr, new_slot_idx);
            (*slot).ref_id = new_ref;
            (*slot).entry_va = entry_va;
            (*dir_ptr).instance_count_incr();
        }
        let entry_nn = NonNull::new(entry_ptr).expect("non-null");
        // SAFETY: single-threaded guest.
        let tracker = unsafe { &mut *SCRATCH.inner.get() };
        tracker.entries.push(ScratchEntry::Instance {
            slot_idx: new_slot_idx,
            entry: entry_nn,
        });
        Ok(new_ref)
    }

    /// Publish a fresh blob (content-addressed). Wraps the legacy
    /// `publish_blob` free function with `&mut self` to participate
    /// in the borrow checker's no-eviction-during-read invariant.
    ///
    /// Currently unused by the in-kernel path (the data-flow
    /// principle keeps SSZ-Merkle out of the kernel); will be used
    /// by future scratchpad code that commits ref→blob at RPC end.
    #[allow(dead_code)]
    pub fn publish_blob(
        &mut self,
        hash: javm_cap::CapHash,
        cap: Cap<TalcAlloc>,
    ) -> Result<(), CacheErr> {
        publish_blob(self.base, hash, cap).map_err(|_| CacheErr::AllocFailed)
    }

    /// Publish a fresh instance (identity-addressed). Returns the
    /// allocated `CapRef`.
    pub fn publish_instance(&mut self, cap: Cap<TalcAlloc>) -> Result<javm_cap::CapRef, CacheErr> {
        publish_instance(self.base, cap).map_err(|_| CacheErr::AllocFailed)
    }

    /// Sweep all scratch entries this RPC published. Same semantics
    /// as the legacy `clear_scratch` — see its doc for the refcount
    /// safety-net behaviour.
    pub fn clear_scratch(&mut self) {
        clear_scratch(self.base);
    }
}

/// `GuestCache::Drop` fires the per-RPC scratch sweep. Construct one
/// `GuestCache` at the top of an RPC (e.g. inside `nub_invoke_cached`)
/// and pass `&mut GuestCache` to the call loop; when the variable goes
/// out of scope after `run_top` returns, the kernel-frame stack has
/// already unwound and any cnode-held entries with refcount==1 are
/// reclaimed here.
impl Drop for GuestCache {
    fn drop(&mut self) {
        self.clear_scratch();
    }
}
