//! Tests for [`Arc`].

use crate::sync::Arc;
use crate::talc::{CacheTalcLock, Manual, TalcAlloc};

use core::sync::atomic::{AtomicUsize, Ordering};

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
        unsafe { TalcAlloc::from_raw(core::ptr::NonNull::from(&*self.talc)) }
    }
}

struct DropCounter<'a> {
    counter: &'a AtomicUsize,
    payload: u64,
}
impl<'a> Drop for DropCounter<'a> {
    fn drop(&mut self) {
        self.counter.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn arc_in_global_drops_once() {
    let drops = AtomicUsize::new(0);
    let a = Arc::new(DropCounter {
        counter: &drops,
        payload: 7,
    });
    let b = a.clone();
    assert_eq!(Arc::strong_count(&a), 2);
    assert_eq!(a.payload, 7);
    assert_eq!(b.payload, 7);
    drop(a);
    drop(b);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
}

#[test]
fn arc_in_talc() {
    let arena = Arena::new(64 * 1024);
    let drops = AtomicUsize::new(0);
    let a: Arc<DropCounter, TalcAlloc> = Arc::new_in(
        DropCounter {
            counter: &drops,
            payload: 99,
        },
        arena.alloc(),
    );
    let b = a.clone();
    assert_eq!(Arc::strong_count(&a), 2);
    drop(a);
    drop(b);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
}

#[test]
fn arc_make_mut_in_place_when_sole() {
    let mut a = Arc::new(42u32);
    *Arc::make_mut(&mut a) = 99;
    assert_eq!(*a, 99);
    assert_eq!(Arc::strong_count(&a), 1);
}

#[test]
fn arc_make_mut_clones_when_shared() {
    let mut a = Arc::new(42u32);
    let b = a.clone();
    assert_eq!(Arc::strong_count(&a), 2);
    *Arc::make_mut(&mut a) = 99;
    assert_eq!(*a, 99);
    assert_eq!(*b, 42);
    // `a` is now sole owner of a fresh slab.
    assert_eq!(Arc::strong_count(&a), 1);
    assert_eq!(Arc::strong_count(&b), 1);
}
