//! Skeleton smoke tests: exercise both `Nub` backends end-to-end and
//! assert they return the same stub value (42). The point isn't the
//! number — it's that the `Arch` trait + uniform handle wire all the
//! way through both substrates.

use nub::{InstanceRef, InvokeOptions, Nub};

#[test]
fn local_invoke_returns_42() {
    let mut nub = Nub::new_local();
    let outcome = nub
        .invoke(
            InstanceRef::from_hash([0; 32]),
            0,
            &[],
            InvokeOptions::default(),
        )
        .unwrap();
    assert_eq!(outcome.return_value, 42);
}

#[test]
fn hyperlight_invoke_returns_42() {
    let mut nub = Nub::new_hyperlight().expect("hyperlight sandbox should open");
    let outcome = nub
        .invoke(
            InstanceRef::from_hash([0; 32]),
            0,
            &[],
            InvokeOptions::default(),
        )
        .unwrap();
    assert_eq!(outcome.return_value, 42);
}
