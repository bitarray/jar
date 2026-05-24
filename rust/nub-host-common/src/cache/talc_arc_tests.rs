//! Tests for [`Aarc`].

use super::talc_alloc::TalcAlloc;
use super::talc_arc::{Aarc, AarcRefCounted};
use super::talc_box::CacheTalcLock;
use allocator_api2::alloc::Global;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
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
    fn alloc(&self) -> TalcAlloc {
        unsafe { TalcAlloc::from_raw(NonNull::from(&*self.talc)) }
    }
}

#[repr(C)]
struct Counted<'a> {
    refcount: AtomicU32,
    drop_counter: &'a AtomicUsize,
    payload: u64,
}
impl AarcRefCounted for Counted<'_> {
    fn refcount(&self) -> &AtomicU32 {
        &self.refcount
    }
}
impl Drop for Counted<'_> {
    fn drop(&mut self) {
        self.drop_counter.fetch_add(1, Ordering::Relaxed);
    }
}
impl Clone for Counted<'_> {
    fn clone(&self) -> Self {
        // Fresh refcount of 1 — `make_mut` resets it anyway, but
        // this matches the `Aarc::new_in` invariant the
        // debug-assert checks for.
        Counted {
            refcount: AtomicU32::new(1),
            drop_counter: self.drop_counter,
            payload: self.payload,
        }
    }
}

#[test]
fn talc_backed_drops_after_last_clone() {
    let arena = Arena::new(64 * 1024);
    let drops = AtomicUsize::new(0);
    let arc = Aarc::new_in(
        Counted {
            refcount: AtomicU32::new(1),
            drop_counter: &drops,
            payload: 7,
        },
        arena.alloc(),
    )
    .unwrap();
    assert_eq!(arc.refcount(), 1);
    assert_eq!(arc.get().payload, 7);

    let cloned = arc.clone();
    assert_eq!(arc.refcount(), 2);
    assert_eq!(cloned.get().payload, 7);

    drop(cloned);
    assert_eq!(arc.refcount(), 1);
    assert_eq!(drops.load(Ordering::Relaxed), 0);

    drop(arc);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
}

#[test]
fn make_mut_in_place_when_sole_owner() {
    let drops = AtomicUsize::new(0);
    let mut arc = Aarc::new_in(
        Counted {
            refcount: AtomicU32::new(1),
            drop_counter: &drops,
            payload: 11,
        },
        Global,
    )
    .unwrap();
    // Sole owner: make_mut returns a mutable ref to the same slab,
    // no clone happens (drop counter unchanged).
    {
        let m = Aarc::make_mut(&mut arc).unwrap();
        assert_eq!(m.payload, 11);
        m.payload = 22;
    }
    assert_eq!(arc.get().payload, 22);
    assert_eq!(arc.refcount(), 1);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
}

#[test]
fn make_mut_clones_when_shared() {
    let drops = AtomicUsize::new(0);
    let mut arc = Aarc::new_in(
        Counted {
            refcount: AtomicU32::new(1),
            drop_counter: &drops,
            payload: 7,
        },
        Global,
    )
    .unwrap();
    let other = arc.clone();
    assert_eq!(arc.refcount(), 2);
    {
        let m = Aarc::make_mut(&mut arc).unwrap();
        // Sees the deep-cloned value initially, then we mutate it.
        assert_eq!(m.payload, 7);
        m.payload = 42;
    }
    // `arc` now points at the fresh slab; the original is still
    // alive via `other`.
    assert_eq!(arc.get().payload, 42);
    assert_eq!(other.get().payload, 7);
    assert_eq!(arc.refcount(), 1);
    assert_eq!(other.refcount(), 1);
    drop(arc);
    drop(other);
    assert_eq!(drops.load(Ordering::Relaxed), 2);
}

#[test]
fn global_backed_drops_after_last_clone() {
    let drops = AtomicUsize::new(0);
    let arc = Aarc::new_in(
        Counted {
            refcount: AtomicU32::new(1),
            drop_counter: &drops,
            payload: 99,
        },
        Global,
    )
    .unwrap();
    let a = arc.clone();
    let b = arc.clone();
    assert_eq!(arc.refcount(), 3);
    drop(a);
    drop(b);
    assert_eq!(arc.refcount(), 1);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    drop(arc);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
}
