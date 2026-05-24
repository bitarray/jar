//! Host-side cache implementation.
//!
//! Provides [`HostRegion`] (RAII lease over the singleton mmap'd
//! cache region) and the host-only impl block for [`super::Cache`].
//!
//! This module compiles only on `not(target_os = "none")` because it
//! pulls in `libc::mmap` and `getrandom`.

#![cfg(feature = "std")]

use core::ptr::NonNull;
use std::sync::{Mutex, MutexGuard, OnceLock};

use allocate::talc::Span;

use super::header::CacheHeader;
use super::{Cache, STATE_CACHE_SIZE, STATE_CACHE_VA};

/// Errors raised while constructing a [`Cache`] on the host.
#[derive(Debug, thiserror::Error)]
pub enum HostCacheError {
    #[error("mmap({va:#x}, {size} bytes, MAP_FIXED_NOREPLACE) failed: {err}")]
    Mmap {
        va: u64,
        size: usize,
        err: std::io::Error,
    },
    #[error("mmap returned {got:#x}, expected {expected:#x} (MAP_FIXED_NOREPLACE fallback)")]
    MmapAddrMismatch { got: u64, expected: u64 },
    // `getrandom::Error` doesn't implement `core::error::Error` in
    // `no_std` mode, which trips `thiserror`'s `#[from]` codegen. We
    // store the inner code (a `NonZeroRawOsError` wrapper) but render
    // it via `Display` and don't claim a source chain.
    #[error("getrandom for hasher seed failed: {0}")]
    Getrandom(getrandom::Error),
    #[error("talc heap claim failed")]
    TalcClaim,
}

impl From<getrandom::Error> for HostCacheError {
    fn from(e: getrandom::Error) -> Self {
        Self::Getrandom(e)
    }
}

// --- Process-singleton mmap region ---

static REGION_BASE: OnceLock<usize> = OnceLock::new();
static REGION_LEASE: Mutex<()> = Mutex::new(());

/// Lazily map the cache region at `STATE_CACHE_VA`. Calls into the
/// kernel exactly once across the entire process; subsequent callers
/// just read the cached address.
fn map_region_once(size: usize) -> Result<NonNull<u8>, HostCacheError> {
    if let Some(&addr) = REGION_BASE.get() {
        // SAFETY: addr was checked non-null at map time.
        return Ok(unsafe { NonNull::new_unchecked(addr as *mut u8) });
    }
    // SAFETY: mmap is a kernel call; we check the result before use.
    let ptr = unsafe {
        libc::mmap(
            STATE_CACHE_VA as *mut libc::c_void,
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err(HostCacheError::Mmap {
            va: STATE_CACHE_VA,
            size,
            err: std::io::Error::last_os_error(),
        });
    }
    if ptr as u64 != STATE_CACHE_VA {
        // Older glibc fallback path: NOREPLACE was ignored.
        unsafe {
            libc::munmap(ptr, size);
        }
        return Err(HostCacheError::MmapAddrMismatch {
            got: ptr as u64,
            expected: STATE_CACHE_VA,
        });
    }
    let _ = REGION_BASE.set(ptr as usize);
    // SAFETY: ptr is non-null (we checked MAP_FAILED).
    Ok(unsafe { NonNull::new_unchecked(ptr as *mut u8) })
}

/// RAII handle over the singleton cache region. While held, the
/// process-wide [`REGION_LEASE`] mutex is locked so no other
/// `HostRegion` can be constructed concurrently. The mmap itself
/// stays mapped for the process lifetime — only the lease is
/// scoped.
pub struct HostRegion {
    _lease: MutexGuard<'static, ()>,
    base: NonNull<u8>,
}

// SAFETY: the base pointer addresses process-global memory under the
// exclusive lease; concurrent access is impossible while the lease
// is held.
unsafe impl Send for HostRegion {}

impl HostRegion {
    /// Allocate the cache region (mmap once + lease) and zero-fill
    /// so a fresh `HostRegion` starts from a known state.
    pub fn acquire() -> Result<Self, HostCacheError> {
        let lease = REGION_LEASE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let base = map_region_once(STATE_CACHE_SIZE)?;
        // Wipe so the new region starts fresh.
        // SAFETY: base + STATE_CACHE_SIZE is the live mmap region.
        unsafe {
            core::ptr::write_bytes(base.as_ptr(), 0, STATE_CACHE_SIZE);
        }
        Ok(Self {
            _lease: lease,
            base,
        })
    }

    pub fn base(&self) -> NonNull<u8> {
        self.base
    }
}

// --- Host-only Cache constructor ---

impl Cache {
    /// Map the cache region (if not already mapped), initialise the
    /// `CacheHeader` with a freshly random hasher seed, claim the
    /// talc heap with the post-header region, and return a `Cache`.
    pub fn new() -> Result<Self, HostCacheError> {
        let region = HostRegion::acquire()?;
        let base = region.base();

        let mut seed_bytes = [0u8; 8];
        getrandom::fill(&mut seed_bytes)?;
        let seed = u64::from_le_bytes(seed_bytes);

        // SAFETY: `base` is the start of a `STATE_CACHE_SIZE`-byte
        // mmap region we just zero-filled, page-aligned, exclusively
        // owned via the `HostRegion` lease.
        let header_ptr = base.as_ptr().cast::<CacheHeader>();
        unsafe {
            CacheHeader::init_at(header_ptr, seed);
        }

        // Claim the talc heap region (everything past the header).
        let heap_base = unsafe { base.as_ptr().add(CacheHeader::SIZE) };
        let heap_size = STATE_CACHE_SIZE - CacheHeader::SIZE;
        // SAFETY: heap_base..heap_base+heap_size lies within the mmap
        // region; `ErrOnOom` source permits manual claim.
        unsafe {
            (*header_ptr)
                .talc
                .lock()
                .claim(Span::from_base_size(heap_base, heap_size))
                .map_err(|()| HostCacheError::TalcClaim)?;
        }

        Ok(Self {
            base,
            _region: region,
            pinned: smallvec::SmallVec::new(),
        })
    }
}

// --- Host-only convenience API ---

use javm_cap::cap::Cap;
use javm_cap::{CacheError, CapHash, CapHashOrRef};

/// Errors raised by host-only Cache methods that go beyond
/// `CacheError`/`HostCacheError` (e.g., pin asserts the cap exists).
#[derive(Debug, thiserror::Error)]
pub enum CachePinError {
    #[error("cache: cannot pin unpublished hash")]
    NotPublished,
}

impl Cache {
    /// Convenience: hash + deep-clone-into-talc + publish_blob. Lets
    /// host callers hand in a heap-built `Cap<Global>` in one call.
    pub fn put_cap(&mut self, cap: &Cap<allocate::Global>) -> Result<CapHash, CacheError> {
        let mut dir = self.directory();
        dir.put_cap(cap)
    }

    /// Pre-hashed variant: caller asserts `hash == cap_hash(cap)`.
    pub fn put_cap_with_hash(
        &mut self,
        hash: CapHash,
        cap: &Cap<allocate::Global>,
    ) -> Result<(), CacheError> {
        let mut dir = self.directory();
        dir.put_cap_with_hash(hash, cap)?;
        Ok(())
    }

    /// Resolve cap references nested inside an instance to their
    /// content-addressed hashes, graduating descendants from
    /// `instances` to `blobs`. See `CacheDirectory::settle`.
    pub fn settle(&mut self, key: CapHashOrRef) -> Result<CapHash, CacheError> {
        let mut dir = self.directory();
        dir.settle(key)
    }

    /// Pin a published hash so eviction (future stage) skips it
    /// during an active call.
    pub fn pin(&mut self, hash: CapHash) -> Result<(), CachePinError> {
        if !self.contains(&hash) {
            return Err(CachePinError::NotPublished);
        }
        self.pinned.push(hash);
        Ok(())
    }

    /// Unpin (counterpart to `pin`). Silent no-op on unknown hashes.
    pub fn unpin(&mut self, hash: CapHash) {
        if let Some(pos) = self.pinned.iter().rposition(|h| *h == hash) {
            self.pinned.swap_remove(pos);
        }
    }

    /// Number of pinned hashes (for tests/diagnostics).
    pub fn pinned_count(&self) -> usize {
        self.pinned.len()
    }
}
