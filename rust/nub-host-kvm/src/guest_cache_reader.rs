//! Host-side read-only view of the guest's heap-resident cap
//! directory.
//!
//! After Commit 2, the guest kernel is linked into the per-process
//! [`GUEST_VA`] reservation at a canonical low-half VA. The host
//! process can mmap-shadow the kernel image at the same VA, so any
//! kernel-mode pointer (e.g. the address of the
//! `nub_arch_x86::state_cache::CACHE` `CacheDirectory<FixedState>`)
//! is directly dereferenceable from host code.
//!
//! [`GuestCacheReader`] wraps the directory VA published by the
//! guest in its [`BootInfo`] block ([`MultiUseSandbox::boot_info`]
//! later — for now this module just exposes the type for
//! Commit 4's wiring) and exposes a `get(hash) -> Option<&Cap>`
//! helper. The directory is a [`CacheDirectory<FixedState>`] on
//! both sides — both host and guest see the same
//! `Box<CacheEntry>` cells through the same `FixedState` seed, so
//! bucket assignments match and the host's view of the table is
//! byte-identical to the guest's.
//!
//! ## Safety
//!
//! - The construction is `unsafe`: the caller must promise the
//!   `directory_va` is correct (came from a verified
//!   [`BootInfo::magic`] + matching `directory_type_id`).
//! - The reader holds no lock on its own. To read consistently, the
//!   caller must ensure no concurrent guest-mode mutation is in
//!   flight (V0: the host only reads when no guest call is
//!   executing — Hyperlight serialises host/guest exclusively).
//! - Returned `&Cap` borrows live until the next time the host hands
//!   control back to the guest. After that the directory's contents
//!   may change and any retained pointer is stale.

use core::ptr::NonNull;

use foldhash::fast::FixedState;
use javm_cap::cache::CacheDirectory;
use javm_cap::{Cap, CapHash, CapHashOrRef};
use nub_arch_x86_abi::BootInfo;

/// The directory's concrete type. Must match
/// `nub_arch_x86::state_cache::CACHE`'s inner type exactly —
/// `CacheDirectory`'s layout depends on its hasher parameter, so
/// any divergence would silently produce nonsense reads.
type GuestDirectory = CacheDirectory<FixedState>;

/// Read-only view of the guest's heap-resident cap directory.
pub struct GuestCacheReader {
    /// Pointer to the guest's CacheDirectory living at `directory_va`.
    /// The pointer is valid only while the sandbox is alive and the
    /// guest's kernel-mode VA mapping is still in place.
    directory: NonNull<GuestDirectory>,
}

impl GuestCacheReader {
    /// Construct a reader from a [`BootInfo`] block.
    ///
    /// # Safety
    ///
    /// - `boot_info.magic` must equal [`BootInfo::MAGIC`].
    /// - `boot_info.directory_va` must point at a `GuestDirectory`
    ///   value living in the same address space (= the host's
    ///   process), allocated through the same `FixedState` seed as
    ///   the guest's `DIRECTORY_HASHER_SEED`.
    /// - The reader must not outlive the sandbox that owns the
    ///   directory.
    pub unsafe fn new(boot_info: &BootInfo) -> Result<Self, GuestCacheReaderError> {
        if boot_info.magic != BootInfo::MAGIC {
            return Err(GuestCacheReaderError::BadMagic);
        }
        if boot_info.directory_va == 0 {
            return Err(GuestCacheReaderError::UninitialisedDirectoryVa);
        }
        let ptr = boot_info.directory_va as usize as *mut GuestDirectory;
        let nn = NonNull::new(ptr).ok_or(GuestCacheReaderError::NullPointer)?;
        Ok(Self { directory: nn })
    }

    /// Number of blob entries in the guest's directory.
    ///
    /// # Safety
    ///
    /// Implicit: see the type's safety section. We declare this
    /// `pub` (not `unsafe`) on the strength of the `new` contract
    /// — once you have a [`GuestCacheReader`], every read assumes
    /// the directory is quiescent.
    pub fn len(&self) -> usize {
        // SAFETY: `directory` is `NonNull<GuestDirectory>`; the
        // construction contract requires it points at a valid
        // directory in the host's address space.
        unsafe { self.directory.as_ref().blob_count() }
    }

    /// `true` iff the directory holds no blob entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Look up a cap by content hash. Returns `None` if absent.
    ///
    /// The borrow is bounded by `&self`. After the borrow ends, the
    /// caller may hand control back to the guest; do not retain
    /// `&Cap` pointers across that boundary.
    pub fn get(&self, hash: &CapHash) -> Option<&Cap> {
        // SAFETY: directory is valid (see construction contract);
        // `CacheDirectory::get` is safe on `&self` and the returned
        // `&Cap` borrow is bounded by the `&Self` borrow we hold.
        let dir: &GuestDirectory = unsafe { self.directory.as_ref() };
        dir.get(CapHashOrRef::Hash(*hash))
    }

    /// Whether a hash is present, without dereferencing the value.
    pub fn contains(&self, hash: &CapHash) -> bool {
        let dir: &GuestDirectory = unsafe { self.directory.as_ref() };
        dir.contains_blob(hash)
    }
}

/// Failures from [`GuestCacheReader::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GuestCacheReaderError {
    /// The [`BootInfo`] magic field didn't match
    /// [`BootInfo::MAGIC`].
    #[error("boot info magic mismatch")]
    BadMagic,
    /// The directory VA in [`BootInfo`] was zero — the guest hasn't
    /// run `init_directory_va` yet. Call any RPC that triggers the
    /// init hook (e.g. `nub_get_boot_info`) and retry.
    #[error("boot info directory_va is zero (guest hasn't initialised)")]
    UninitialisedDirectoryVa,
    /// The directory VA was non-zero but, after the
    /// `directory_va -> *mut GuestDirectory` cast, resulted in a
    /// null pointer. Shouldn't be observable in practice; covers
    /// the cast hazard for completeness.
    #[error("directory_va decoded to a null pointer")]
    NullPointer,
}
