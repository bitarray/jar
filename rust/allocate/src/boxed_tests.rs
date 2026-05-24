//! Tests for [`Box`].

use crate::boxed::Box;
use crate::talc::TalcAlloc;
use crate::test_arena::test_talc;

#[test]
fn box_in_global() {
    let b = Box::new(42u32);
    assert_eq!(*b, 42);
}

#[test]
fn box_in_talc() {
    let b: Box<u32, TalcAlloc> = Box::new_in(7, test_talc());
    assert_eq!(*b, 7);
}

#[test]
fn box_into_raw_round_trips() {
    let alloc = test_talc();
    let b: Box<u64, TalcAlloc> = Box::new_in(0xDEAD_BEEF, alloc);
    let (raw, recovered_alloc) = Box::into_raw_with_allocator(b);
    // SAFETY: raw came from a Box we just constructed; not yet freed.
    let restored = unsafe { Box::from_raw_in(raw, recovered_alloc) };
    assert_eq!(*restored, 0xDEAD_BEEF);
}
