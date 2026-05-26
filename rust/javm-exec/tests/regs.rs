use javm_exec::{REG_COUNT, Regs};

#[test]
fn new_is_zero() {
    let r = Regs::new();
    assert_eq!(r.pc, 0);
    for i in 0..REG_COUNT {
        assert_eq!(r.read(i), 0);
    }
}

#[test]
fn read_write_round_trip() {
    let mut r = Regs::new();
    r.write(7, 0xDEAD_BEEF);
    assert_eq!(r.read(7), 0xDEAD_BEEF);
}

#[test]
fn out_of_range_read_returns_zero() {
    let r = Regs::new();
    assert_eq!(r.read(99), 0);
}

#[test]
fn out_of_range_write_is_noop() {
    let mut r = Regs::new();
    r.write(99, 1);
    // No panic; no state change.
    for i in 0..REG_COUNT {
        assert_eq!(r.read(i), 0);
    }
}
