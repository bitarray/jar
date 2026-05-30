use javm_exec::regs::{REG_SLOT_LUT, RegClass, reg_class, reg_is_reserved, reg_slot_or_ff};
use javm_exec::{REG_COUNT, Regs};

#[test]
fn reg_classification_is_the_single_source() {
    // Slot map: x0 and reserved → 0xFF (no slot); x1→0, x2→1, x5..x15→2..12.
    // These exact values are the consensus gas contract — the recompiler's
    // `REG_SLOT_LUT` and the interpreter's `rv_slot_u8` both read them, so
    // they must stay bit-identical with the pre-unification tables.
    assert_eq!(reg_slot_or_ff(0), 0xFF); // x0
    assert_eq!(reg_slot_or_ff(1), 0);
    assert_eq!(reg_slot_or_ff(2), 1);
    assert_eq!(reg_slot_or_ff(3), 0xFF); // reserved
    assert_eq!(reg_slot_or_ff(4), 0xFF); // reserved
    for x in 5..=15u8 {
        assert_eq!(reg_slot_or_ff(x), x - 3); // x5..x15 → 2..12
    }
    for x in 16..=31u8 {
        assert_eq!(reg_slot_or_ff(x), 0xFF); // x16..x31 don't exist in RV64E
    }

    // Reserved set is exactly {x3, x4, x16..x31} — and crucially NOT x0.
    for x in 0..=31u8 {
        assert_eq!(reg_is_reserved(x), x == 3 || x == 4 || x >= 16, "x{x}");
    }
    assert!(!reg_is_reserved(0)); // x0 lacks a slot but is valid, not reserved

    // The const-folded LUT equals the function for every index (no drift).
    for x in 0..32u8 {
        assert_eq!(REG_SLOT_LUT[x as usize], reg_slot_or_ff(x), "x{x}");
    }

    // The derived views agree with the classification.
    assert_eq!(reg_class(0), RegClass::Zero);
    assert_eq!(reg_class(1), RegClass::Gpr(0));
    assert_eq!(reg_class(15), RegClass::Gpr(12));
    assert_eq!(reg_class(4), RegClass::Reserved);
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
