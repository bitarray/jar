//! Tests for [`HashMap`].

use super::{DefaultHashBuilder, HashMap};
use crate::talc::TalcAlloc;
use crate::test_arena::test_talc;

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
    let mut m: HashMap<u32, u64, DefaultHashBuilder, TalcAlloc> = HashMap::new_in(test_talc());
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
    let mut m: HashMap<u32, u32, DefaultHashBuilder, TalcAlloc> =
        HashMap::with_capacity_in(64, test_talc());
    let pre = m.capacity();
    for i in 0..32u32 {
        m.insert(i, i);
    }
    assert_eq!(m.capacity(), pre, "should not have reallocated");
}
