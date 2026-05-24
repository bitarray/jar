//! Tests for [`Vec`].

use crate::talc::TalcAlloc;
use crate::test_arena::test_talc;
use crate::vec::Vec;

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
    let mut v: Vec<u32, TalcAlloc> = Vec::new_in(test_talc());
    for i in 0..16u32 {
        v.push(i * 3);
    }
    assert_eq!(v.len(), 16);
    assert_eq!(v[7], 21);
}

#[test]
fn vec_extend_from_slice() {
    let mut v: Vec<u8, TalcAlloc> = Vec::new_in(test_talc());
    v.extend_from_slice(&[1, 2, 3, 4, 5]);
    assert_eq!(&v[..], &[1, 2, 3, 4, 5]);
}

#[test]
fn vec_freed_memory_is_reclaimed() {
    let alloc = test_talc();
    for _ in 0..1024 {
        let _v: Vec<u8, TalcAlloc> = Vec::with_capacity_in(256, alloc);
    }
}
