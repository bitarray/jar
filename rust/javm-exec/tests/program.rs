use javm_exec::{PvmProgram, compute_mem_cycles, unpack_bitmask};

#[test]
fn new_validates_bitmask_len() {
    assert!(PvmProgram::new(vec![0u8; 4], vec![1u8; 4], vec![], 25).is_ok());
    let err = PvmProgram::new(vec![0u8; 4], vec![1u8; 3], vec![], 25).unwrap_err();
    assert!(matches!(
        err,
        javm_exec::ProgramError::BitmaskLenMismatch { .. }
    ));
}

#[test]
fn is_insn_start_indexes_bitmask() {
    let p = PvmProgram::new(vec![0u8, 1, 0, 1], vec![1u8, 0, 1, 0], vec![], 25).unwrap();
    assert!(p.is_insn_start(0));
    assert!(!p.is_insn_start(1));
    assert!(p.is_insn_start(2));
    assert!(!p.is_insn_start(3));
    // Out of range → false.
    assert!(!p.is_insn_start(99));
}

#[test]
fn compute_mem_cycles_tiers() {
    assert_eq!(compute_mem_cycles(0), 25);
    assert_eq!(compute_mem_cycles(2048), 25);
    assert_eq!(compute_mem_cycles(2049), 50);
    assert_eq!(compute_mem_cycles(8192), 50);
    assert_eq!(compute_mem_cycles(8193), 75);
    assert_eq!(compute_mem_cycles(65536), 75);
    assert_eq!(compute_mem_cycles(65537), 100);
    assert_eq!(compute_mem_cycles(u32::MAX), 100);
}

#[test]
fn unpack_bitmask_round_trip() {
    // Pack [1, 0, 1, 1, 0, 0, 0, 1] into a single byte: 0b1000_1101
    // Bits are packed LSB-first per v2: bit 0 = pos 0, bit 1 = pos 1, ...
    let packed = [0b1000_1101u8];
    let unpacked = unpack_bitmask(&packed, 8);
    assert_eq!(unpacked, vec![1, 0, 1, 1, 0, 0, 0, 1]);
}

#[test]
fn unpack_bitmask_short_code() {
    // 3-byte code → 1 byte of packed bitmask, 3 entries unpacked.
    let packed = [0b101u8];
    let unpacked = unpack_bitmask(&packed, 3);
    assert_eq!(unpacked, vec![1, 0, 1]);
}
