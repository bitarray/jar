//! Tests for [`BTreeMap`].

use super::BTreeMap;
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
fn btreemap_in_global() {
    let mut m = BTreeMap::<u32, &'static str>::new();
    assert!(m.is_empty());
    m.insert(2, "two");
    m.insert(1, "one");
    m.insert(3, "three");
    assert_eq!(m.len(), 3);
    assert_eq!(m.get(&1), Some(&"one"));
    assert_eq!(m.remove(&2), Some("two"));
    assert!(!m.contains_key(&2));
}

#[test]
fn btreemap_iter_is_sorted() {
    let arena = Arena::new(64 * 1024);
    let mut m: BTreeMap<u32, u32, TalcAlloc> = BTreeMap::new_in(arena.alloc());
    for k in [5u32, 1, 3, 4, 2] {
        m.insert(k, k * 10);
    }
    let collected: alloc::vec::Vec<u32> = m.iter().map(|(&k, _)| k).collect();
    assert_eq!(collected, alloc::vec![1u32, 2, 3, 4, 5]);
}

#[test]
fn btreemap_in_talc() {
    let arena = Arena::new(64 * 1024);
    let alloc = arena.alloc();
    let mut m: BTreeMap<u32, u64, TalcAlloc> = BTreeMap::new_in(alloc);
    for i in 0..256u32 {
        m.insert(i, (i as u64) * 3);
    }
    assert_eq!(m.len(), 256);
    for i in 0..256u32 {
        assert_eq!(m.get(&i), Some(&((i as u64) * 3)));
    }
}
