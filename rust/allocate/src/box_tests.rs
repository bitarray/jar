//! Tests for [`Box`].

use super::*;
use crate::talc_alloc::Manual;

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

#[test]
fn box_in_global() {
    let b = Box::new(42u32);
    assert_eq!(*b, 42);
}

#[test]
fn box_in_talc() {
    let arena = Arena::new(64 * 1024);
    let b: Box<u32, TalcAlloc> = Box::new_in(7, arena.alloc());
    assert_eq!(*b, 7);
}

#[test]
fn box_into_raw_round_trips() {
    let arena = Arena::new(64 * 1024);
    let alloc = arena.alloc();
    let b: Box<u64, TalcAlloc> = Box::new_in(0xDEAD_BEEF, alloc);
    let (raw, recovered_alloc) = Box::into_raw_with_allocator(b);
    // SAFETY: raw came from a Box we just constructed; not yet freed.
    let restored = unsafe { Box::from_raw_in(raw, recovered_alloc) };
    assert_eq!(*restored, 0xDEAD_BEEF);
}
