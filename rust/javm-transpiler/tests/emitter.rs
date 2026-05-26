use javm_transpiler::emitter::*;

#[test]
fn test_pack_bitmask() {
    assert_eq!(pack_bitmask(&[1, 1, 1]), vec![0x07]);
    assert_eq!(pack_bitmask(&[1, 0, 1, 0, 1, 0, 1, 0]), vec![0x55]);
    assert_eq!(pack_bitmask(&[1, 0, 1, 0, 1, 0, 1, 0, 1]), vec![0x55, 0x01]);
}
