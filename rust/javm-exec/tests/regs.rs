use javm_exec::regs::{
    REG_SLOT_LUT, RegClass, reg_class, reg_is_reserved, reg_is_spilled, reg_slot_or_ff,
};
use javm_exec::{REG_COUNT, Regs};

#[test]
fn reg_classification_is_the_single_source() {
    // Slot map: x0 and reserved (x16..x31) → 0xFF (no slot); x1→0, x2→1,
    // x5..x15→2..12, and the two host-spilled regs x3→13, x4→14. These exact
    // values are the consensus gas contract — the recompiler's
    // `REG_SLOT_LUT` and the interpreter's `rv_slot_u8` both read them, so
    // the 13 commonly-used slots must stay bit-identical (x3/x4 are appended
    // in the high slots so conformant code's masks never change).
    assert_eq!(reg_slot_or_ff(0), 0xFF); // x0
    assert_eq!(reg_slot_or_ff(1), 0);
    assert_eq!(reg_slot_or_ff(2), 1);
    assert_eq!(reg_slot_or_ff(3), 13); // x3 → high spill slot
    assert_eq!(reg_slot_or_ff(4), 14); // x4 → high spill slot
    for x in 5..=15u8 {
        assert_eq!(reg_slot_or_ff(x), x - 3); // x5..x15 → 2..12
    }
    for x in 16..=31u8 {
        assert_eq!(reg_slot_or_ff(x), 0xFF); // x16..x31 don't exist in RV64E
    }

    // Reserved set is exactly {x16..x31} — NOT x0, and NOT x3/x4 (now valid).
    for x in 0..=31u8 {
        assert_eq!(reg_is_reserved(x), x >= 16, "x{x}");
    }
    assert!(!reg_is_reserved(0)); // x0 lacks a slot but is valid, not reserved
    assert!(!reg_is_reserved(3)); // x3/x4 are valid registers now
    assert!(!reg_is_reserved(4));

    // Spilled set is exactly {x3, x4}.
    for x in 0..=31u8 {
        assert_eq!(reg_is_spilled(x), x == 3 || x == 4, "x{x}");
    }

    // The const-folded LUT equals the function for every index (no drift).
    for x in 0..32u8 {
        assert_eq!(REG_SLOT_LUT[x as usize], reg_slot_or_ff(x), "x{x}");
    }

    // The derived views agree with the classification.
    assert_eq!(reg_class(0), RegClass::Zero);
    assert_eq!(reg_class(1), RegClass::Gpr(0));
    assert_eq!(reg_class(15), RegClass::Gpr(12));
    assert_eq!(reg_class(3), RegClass::Gpr(13));
    assert_eq!(reg_class(4), RegClass::Gpr(14));
    assert_eq!(reg_class(16), RegClass::Reserved);
    assert_eq!(reg_class(31), RegClass::Reserved);
}

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
