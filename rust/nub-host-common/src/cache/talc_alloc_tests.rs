//! Tests for [`TalcAlloc`].

use super::talc_alloc::*;
use super::talc_box::CacheTalcLock;
use allocator_api2::boxed::Box;
use allocator_api2::vec::Vec;
use core::ptr::NonNull;
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

#[test]
fn vec_with_talc_alloc_round_trips() {
    let arena = Arena::new(64 * 1024);
    let alloc = arena.alloc();

    let mut v: Vec<u32, TalcAlloc> = Vec::new_in(alloc);
    for i in 0..16 {
        v.push(i * 3);
    }
    assert_eq!(v.len(), 16);
    for (i, &x) in v.iter().enumerate() {
        assert_eq!(x as usize, i * 3);
    }
}

#[test]
fn box_with_talc_alloc_round_trips() {
    let arena = Arena::new(64 * 1024);
    let alloc = arena.alloc();

    let b: Box<[u64; 4], TalcAlloc> = Box::new_in([10, 20, 30, 40], alloc);
    assert_eq!(*b, [10, 20, 30, 40]);
}

#[test]
fn freed_memory_is_reclaimed() {
    let arena = Arena::new(8 * 1024);
    let alloc = arena.alloc();
    // Repeated alloc-drop cycles should not exhaust the heap.
    for _ in 0..1024 {
        let _v: Vec<u8, TalcAlloc> = Vec::with_capacity_in(256, alloc);
    }
}
