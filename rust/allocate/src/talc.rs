//! Talc allocator integration.
//!
//! `TalcAlloc` is a **type alias** for `&'static CacheTalcLock`. Talc's
//! `Talck` already implements `allocator_api2::alloc::Allocator`, and
//! `&'static T` inherits that impl. The whole "allocator handle" is
//! just a borrow — `Copy + Clone + Send + Sync` for free.
//!
//! Construction is one line at the call site:
//!
//! - **Tests**: `&TALC` where
//!   `static TALC: CacheTalcLock = new_cache_talc_lock();` (see the
//!   `test_arena` helper).
//! - **Production**: the talc lives at a fixed VA (mmap'd, pinned for
//!   the process lifetime):
//!   ```ignore
//!   let alloc: TalcAlloc =
//!       unsafe { &*(STATE_CACHE_VA as *const CacheTalcLock) };
//!   ```
//!   The single `unsafe { &*VA }` cast asserts the `'static` lifetime
//!   that the mmap pinning guarantees.

pub use lock_api::{Mutex, MutexGuard};
pub use spinning_top::RawSpinlock;
pub use talc::{ClaimOnOom, ErrOnOom, OomHandler, Span, Talc, Talck};

/// Concrete `Talck` flavour used by the shared state-cache region.
///
/// `spinning_top::RawSpinlock` for serialisation (no `lock_api` direct
/// dep needed downstream); `ErrOnOom` so OOM returns `Err` rather than
/// attempting heap extension — callers hand talc its backing memory up
/// front via `Talc::claim`.
pub type CacheTalcLock = Talck<spinning_top::RawSpinlock, ErrOnOom>;

/// Workspace allocator handle. Just a `'static` borrow of a
/// [`CacheTalcLock`] — `Copy + Clone + Send + Sync` by reference, and
/// the underlying `Talck` already impls
/// `allocator_api2::alloc::Allocator`.
pub type TalcAlloc = &'static CacheTalcLock;

/// Const constructor for a fresh empty [`CacheTalcLock`]. Suitable for
/// a `static` binding; backing memory must be supplied at runtime via
/// `lock.lock().claim(Span::from_array(...))`.
#[inline]
pub const fn new_cache_talc_lock() -> CacheTalcLock {
    Talc::new(ErrOnOom).lock()
}
