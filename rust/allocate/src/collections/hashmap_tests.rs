//! Tests for [`HashMap`].

use super::HashMap;
use crate::talc::{CacheTalcLock, Manual, TalcAlloc};

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
fn hashmap_in_global() {
    let mut m = HashMap::<u32, &'static str>::new();
    assert!(m.is_empty());
    m.insert(1, "one");
    m.insert(2, "two");
    assert_eq!(m.len(), 2);
    assert_eq!(m.get(&1), Some(&"one"));
    assert_eq!(m.remove(&2), Some("two"));
    assert!(!m.contains_key(&2));
}

#[test]
fn hashmap_in_talc() {
    let arena = Arena::new(64 * 1024);
    let alloc = arena.alloc();
    let mut m: HashMap<u32, u64, TalcAlloc> = HashMap::new_in(alloc);
    for i in 0..256u32 {
        m.insert(i, (i as u64) * 3);
    }
    assert_eq!(m.len(), 256);
    for i in 0..256u32 {
        assert_eq!(m.get(&i), Some(&((i as u64) * 3)));
    }
}

#[test]
fn hashmap_with_capacity_doesnt_realloc() {
    let arena = Arena::new(64 * 1024);
    let mut m: HashMap<u32, u32, TalcAlloc> = HashMap::with_capacity_in(64, arena.alloc());
    let pre = m.capacity();
    for i in 0..32u32 {
        m.insert(i, i);
    }
    assert_eq!(m.capacity(), pre, "should not have reallocated");
}
