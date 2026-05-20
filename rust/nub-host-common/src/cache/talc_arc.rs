//! `TalcArc<T>`: a hand-rolled `Arc<T>` whose backing storage lives
//! in talc memory.
//!
//! `T` must implement [`TalcRefCounted`] to expose an `AtomicU32`
//! refcount field at a known location. Drop atomically decrements;
//! the last drop runs `T`'s destructor and frees the slab.
//!
//! Why not stock `alloc::sync::Arc`? Two reasons:
//!
//! 1. Stock `Arc` allocates from the global Rust allocator. The
//!    state-cache region uses its own [`CacheTalcLock`] instance;
//!    putting an `Arc<T>` whose header is in the global heap but
//!    payload is in talc memory (or vice versa) would deadlock the
//!    cache layout.
//! 2. Stock `Arc`'s `ArcInner<T>` layout is private; we can't
//!    construct one in shared memory and hand both host and guest a
//!    pointer-stable handle.
//!
//! `TalcArc<T>` is the minimum we need: one `NonNull<T>` + a refcount
//! living inside `T` + Drop that returns the slab to talc. Used by
//! `javm-cap::cap::PageRef` to share DataCap page bytes between CoW
//! clones.

use alloc::alloc::Layout;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, Ordering, fence};

use super::talc_box::CacheTalcLock;

/// Trait implemented by types that carry their own `AtomicU32`
/// refcount field. Required to live inside [`TalcArc`].
///
/// The trait is intentionally narrow — one method returning a shared
/// reference to the refcount field. Implementations should expose
/// the field as `pub refcount: AtomicU32` and return `&self.refcount`.
pub trait TalcRefCounted {
    fn refcount(&self) -> &AtomicU32;
}

/// Shared, reference-counted handle to a `T` allocated in talc
/// memory. Cheap to clone (one atomic increment); Drop atomically
/// decrements and frees on the last reference.
pub struct TalcArc<T: TalcRefCounted> {
    ptr: NonNull<T>,
    talc: NonNull<CacheTalcLock>,
}

unsafe impl<T: TalcRefCounted + Send + Sync> Send for TalcArc<T> {}
unsafe impl<T: TalcRefCounted + Send + Sync> Sync for TalcArc<T> {}

impl<T: TalcRefCounted> TalcArc<T> {
    /// Allocate space for a `T` from `talc`, move `value` in, and
    /// return a handle.
    ///
    /// **The caller must construct `value` with `refcount` already
    /// initialised to `1`.** This is the responsibility of `T`'s
    /// constructor — `TalcArc::new_in` doesn't touch the refcount
    /// field, so we honour whatever the caller wrote.
    ///
    /// # Safety
    ///
    /// `talc` must point at a live, properly-claimed
    /// [`CacheTalcLock`] that outlives the returned handle and all
    /// its clones.
    pub unsafe fn new_in(value: T, talc: NonNull<CacheTalcLock>) -> Option<Self> {
        debug_assert_eq!(
            value.refcount().load(Ordering::Relaxed),
            1,
            "TalcArc::new_in expects value.refcount() == 1",
        );
        let layout = Layout::new::<T>();
        let raw = unsafe { (*talc.as_ptr()).lock().allocate(layout)? };
        let ptr = raw.cast::<T>();
        unsafe {
            ptr.as_ptr().write(value);
        }
        Some(Self { ptr, talc })
    }

    /// Increment the refcount and return a new handle pointing at
    /// the same `T`.
    pub fn clone_ref(&self) -> Self {
        unsafe {
            (*self.ptr.as_ptr()).refcount().fetch_add(1, Ordering::Relaxed);
        }
        Self {
            ptr: self.ptr,
            talc: self.talc,
        }
    }

    /// Current refcount. Mostly useful in tests and `make_mut`-style
    /// branches.
    pub fn refcount(&self) -> u32 {
        unsafe { (*self.ptr.as_ptr()).refcount().load(Ordering::Acquire) }
    }

    /// Shared reference to the `T`.
    #[inline]
    pub fn get(&self) -> &T {
        unsafe { &*self.ptr.as_ptr() }
    }

    /// Mutable reference to the `T`. Caller is responsible for
    /// confirming exclusive access (e.g. by checking
    /// `self.refcount() == 1`).
    ///
    /// # Safety
    ///
    /// The caller must guarantee no other `TalcArc` references the
    /// same `T` for the duration of the returned reference's lifetime.
    pub unsafe fn as_mut_unchecked(&mut self) -> &mut T {
        unsafe { &mut *self.ptr.as_ptr() }
    }

    /// Raw pointer to the underlying `T`. Useful for embedding the
    /// VA in the cache directory.
    #[inline]
    pub fn as_ptr(&self) -> *mut T {
        self.ptr.as_ptr()
    }
}

impl<T: TalcRefCounted> Drop for TalcArc<T> {
    fn drop(&mut self) {
        let prev = unsafe {
            (*self.ptr.as_ptr())
                .refcount()
                .fetch_sub(1, Ordering::Release)
        };
        if prev != 1 {
            return;
        }
        // We were the last reference. Pair the Release fences from
        // prior decrements with an Acquire here so anything those
        // threads observed becomes visible before we drop / free.
        fence(Ordering::Acquire);
        unsafe {
            core::ptr::drop_in_place(self.ptr.as_ptr());
            (*self.talc.as_ptr())
                .lock()
                .deallocate(self.ptr.as_ptr().cast::<u8>(), Layout::new::<T>());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::talc_box::CacheTalcLock;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use talc::source::Manual;

    struct Arena {
        _backing: alloc::vec::Vec<u8>,
        talc: alloc::boxed::Box<CacheTalcLock>,
    }
    impl Arena {
        fn new(size: usize) -> Self {
            let backing = alloc::vec![0u8; size];
            let talc = alloc::boxed::Box::new(CacheTalcLock::new(Manual));
            let base = backing.as_ptr() as *mut u8;
            unsafe {
                let _ = talc.lock().claim(base, size).expect("claim");
            }
            Self {
                _backing: backing,
                talc,
            }
        }
        fn ptr(&self) -> NonNull<CacheTalcLock> {
            NonNull::from(&*self.talc)
        }
    }

    #[repr(C)]
    struct Counted<'a> {
        refcount: AtomicU32,
        drop_counter: &'a AtomicUsize,
        payload: u64,
    }
    impl TalcRefCounted for Counted<'_> {
        fn refcount(&self) -> &AtomicU32 {
            &self.refcount
        }
    }
    impl Drop for Counted<'_> {
        fn drop(&mut self) {
            self.drop_counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn drops_after_last_clone() {
        let arena = Arena::new(64 * 1024);
        let drops = AtomicUsize::new(0);
        let arc = unsafe {
            TalcArc::new_in(
                Counted {
                    refcount: AtomicU32::new(1),
                    drop_counter: &drops,
                    payload: 7,
                },
                arena.ptr(),
            )
        }
        .unwrap();
        assert_eq!(arc.refcount(), 1);
        assert_eq!(arc.get().payload, 7);

        let cloned = arc.clone_ref();
        assert_eq!(arc.refcount(), 2);
        assert_eq!(cloned.get().payload, 7);

        drop(cloned);
        assert_eq!(arc.refcount(), 1);
        assert_eq!(drops.load(Ordering::Relaxed), 0);

        drop(arc);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn three_clones_three_drops_then_destruct() {
        let arena = Arena::new(64 * 1024);
        let drops = AtomicUsize::new(0);
        let arc = unsafe {
            TalcArc::new_in(
                Counted {
                    refcount: AtomicU32::new(1),
                    drop_counter: &drops,
                    payload: 0,
                },
                arena.ptr(),
            )
        }
        .unwrap();
        let a = arc.clone_ref();
        let b = arc.clone_ref();
        let c = arc.clone_ref();
        assert_eq!(arc.refcount(), 4);
        drop(a);
        drop(b);
        drop(c);
        assert_eq!(arc.refcount(), 1);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        drop(arc);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
}
