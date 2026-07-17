use nub_exec::GasCounter;

#[test]
fn new_remaining_matches_initial() {
    assert_eq!(GasCounter::new(1000).remaining(), 1000);
}

#[test]
fn charge_within_budget_succeeds() {
    let mut g = GasCounter::new(100);
    assert!(g.charge(30).is_ok());
    assert_eq!(g.remaining(), 70);
    assert!(g.charge(70).is_ok());
    assert_eq!(g.remaining(), 0);
}

#[test]
fn charge_over_budget_fails_and_exhausts() {
    let mut g = GasCounter::new(50);
    assert!(g.charge(100).is_err());
    assert_eq!(g.remaining(), 0);
    // Subsequent charges also fail.
    assert!(g.charge(1).is_err());
}

#[test]
fn set_replaces_remaining() {
    let mut g = GasCounter::new(0);
    g.set(500);
    assert_eq!(g.remaining(), 500);
}
