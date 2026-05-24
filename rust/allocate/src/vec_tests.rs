//! Tests for [`Vec`].

use crate::talc::{CacheTalcLock, Manual, TalcAlloc};
use crate::vec::Vec;

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
fn vec_in_global() {
    let mut v = Vec::new();
    for i in 0..16u32 {
        v.push(i * 3);
    }
    assert_eq!(v.len(), 16);
    for (i, &x) in v.iter().enumerate() {
        assert_eq!(x as usize, i * 3);
    }
}

#[test]
fn vec_in_talc() {
    let arena = Arena::new(64 * 1024);
    let mut v: Vec<u32, TalcAlloc> = Vec::new_in(arena.alloc());
    for i in 0..16u32 {
        v.push(i * 3);
    }
    assert_eq!(v.len(), 16);
    assert_eq!(v[7], 21);
}

#[test]
fn vec_extend_from_slice() {
    let arena = Arena::new(64 * 1024);
    let mut v: Vec<u8, TalcAlloc> = Vec::new_in(arena.alloc());
    v.extend_from_slice(&[1, 2, 3, 4, 5]);
    assert_eq!(&v[..], &[1, 2, 3, 4, 5]);
}

#[test]
fn vec_freed_memory_is_reclaimed() {
    let arena = Arena::new(8 * 1024);
    let alloc = arena.alloc();
    for _ in 0..1024 {
        let _v: Vec<u8, TalcAlloc> = Vec::with_capacity_in(256, alloc);
    }
}
