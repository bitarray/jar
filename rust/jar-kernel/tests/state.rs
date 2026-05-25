use jar_kernel::state::{State, state_root};

#[test]
fn empty_state_root_is_deterministic() {
    let s1 = State::new();
    let s2 = State::new();
    assert_eq!(state_root(&s1), state_root(&s2));
}

#[test]
fn state_root_changes_with_published_data() {
    let s = State::new();
    let r0 = state_root(&s);
    s.caps
        .put_cap(&javm_cap::Cap::data_inline(b"hello"))
        .unwrap();
    let r1 = state_root(&s);
    assert_ne!(r0, r1);
}
