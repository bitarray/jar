//! Integration tests for scale derive macros.

use scale::{Decode, Encode};

// ============================================================================
// Struct tests
// ============================================================================

#[derive(Debug, PartialEq, Encode, Decode)]
struct SimpleStruct {
    a: u32,
    b: u16,
    c: u8,
}

#[test]
fn test_simple_struct_roundtrip() {
    let val = SimpleStruct {
        a: 0xDEADBEEF,
        b: 0x1234,
        c: 0x42,
    };
    let encoded = val.encode();
    assert_eq!(encoded.len(), 4 + 2 + 1);
    let (decoded, consumed) = SimpleStruct::decode(&encoded).unwrap();
    assert_eq!(decoded, val);
    assert_eq!(consumed, 7);
}

#[derive(Debug, PartialEq, Encode, Decode)]
struct WithVec {
    name: u32,
    data: Vec<u8>,
}

#[test]
fn test_struct_with_vec_roundtrip() {
    let val = WithVec {
        name: 42,
        data: vec![1, 2, 3, 4, 5],
    };
    let encoded = val.encode();
    // u32 name + u32 count(5) + 5 bytes
    assert_eq!(encoded.len(), 4 + 4 + 5);
    let (decoded, consumed) = WithVec::decode(&encoded).unwrap();
    assert_eq!(decoded, val);
    assert_eq!(consumed, 13);
}

#[derive(Debug, PartialEq, Encode, Decode)]
struct WithOption {
    a: u32,
    b: Option<u16>,
}

#[test]
fn test_struct_with_option_none() {
    let val = WithOption { a: 1, b: None };
    let encoded = val.encode();
    assert_eq!(encoded, [1, 0, 0, 0, 0]); // u32 + discriminator 0
    let (decoded, _) = WithOption::decode(&encoded).unwrap();
    assert_eq!(decoded, val);
}

#[test]
fn test_struct_with_option_some() {
    let val = WithOption {
        a: 1,
        b: Some(0x1234),
    };
    let encoded = val.encode();
    assert_eq!(encoded, [1, 0, 0, 0, 1, 0x34, 0x12]); // u32 + discriminator 1 + u16
    let (decoded, _) = WithOption::decode(&encoded).unwrap();
    assert_eq!(decoded, val);
}

#[derive(Debug, PartialEq, Default, Encode, Decode)]
struct WithSkip {
    a: u32,
    #[codec(skip)]
    cached: u64,
    b: u16,
}

#[test]
fn test_struct_with_skip() {
    let val = WithSkip {
        a: 10,
        cached: 999,
        b: 20,
    };
    let encoded = val.encode();
    // Only a (u32) + b (u16), cached is skipped
    assert_eq!(encoded.len(), 4 + 2);
    assert_eq!(encoded, [10, 0, 0, 0, 20, 0]);
    let (decoded, consumed) = WithSkip::decode(&encoded).unwrap();
    assert_eq!(decoded.a, 10);
    assert_eq!(decoded.cached, 0); // default
    assert_eq!(decoded.b, 20);
    assert_eq!(consumed, 6);
}

#[derive(Debug, PartialEq, Encode, Decode)]
struct WithFixedArray {
    hash: [u8; 32],
    value: u64,
}

#[test]
fn test_struct_with_fixed_array() {
    let val = WithFixedArray {
        hash: [0xAB; 32],
        value: 42,
    };
    let encoded = val.encode();
    assert_eq!(encoded.len(), 32 + 8);
    let (decoded, consumed) = WithFixedArray::decode(&encoded).unwrap();
    assert_eq!(decoded, val);
    assert_eq!(consumed, 40);
}

// ============================================================================
// Enum tests
// ============================================================================

#[derive(Debug, PartialEq, Encode, Decode)]
enum SimpleEnum {
    #[codec(index = 0)]
    A,
    #[codec(index = 1)]
    B(u32),
    #[codec(index = 2)]
    C(Vec<u8>),
}

#[test]
fn test_enum_unit_variant() {
    let val = SimpleEnum::A;
    let encoded = val.encode();
    assert_eq!(encoded, [0]);
    let (decoded, consumed) = SimpleEnum::decode(&encoded).unwrap();
    assert_eq!(decoded, val);
    assert_eq!(consumed, 1);
}

#[test]
fn test_enum_tuple_variant() {
    let val = SimpleEnum::B(42);
    let encoded = val.encode();
    assert_eq!(encoded, [1, 42, 0, 0, 0]);
    let (decoded, consumed) = SimpleEnum::decode(&encoded).unwrap();
    assert_eq!(decoded, val);
    assert_eq!(consumed, 5);
}

#[test]
fn test_enum_vec_variant() {
    let val = SimpleEnum::C(vec![10, 20, 30]);
    let encoded = val.encode();
    // discriminator(1) + u32 count(3) + 3 bytes
    assert_eq!(encoded, [2, 3, 0, 0, 0, 10, 20, 30]);
    let (decoded, consumed) = SimpleEnum::decode(&encoded).unwrap();
    assert_eq!(decoded, val);
    assert_eq!(consumed, 8);
}

#[test]
fn test_enum_invalid_discriminator() {
    let result = SimpleEnum::decode(&[99]);
    assert!(result.is_err());
}

// ============================================================================
// Nested structs
// ============================================================================

#[derive(Debug, PartialEq, Encode, Decode)]
struct Inner {
    x: u16,
    y: u16,
}

#[derive(Debug, PartialEq, Encode, Decode)]
struct Outer {
    id: u32,
    inner: Inner,
    items: Vec<Inner>,
}

#[test]
fn test_nested_struct_roundtrip() {
    let val = Outer {
        id: 1,
        inner: Inner { x: 10, y: 20 },
        items: vec![Inner { x: 30, y: 40 }, Inner { x: 50, y: 60 }],
    };
    let encoded = val.encode();
    // u32(1) + Inner(4) + u32 count(2) + 2*Inner(4) = 4+4+4+8 = 20
    assert_eq!(encoded.len(), 20);
    let (decoded, consumed) = Outer::decode(&encoded).unwrap();
    assert_eq!(decoded, val);
    assert_eq!(consumed, 20);
}

// ============================================================================
// Tuple struct
// ============================================================================

#[derive(Debug, PartialEq, Encode, Decode)]
struct TupleStruct(u32, u16);

#[test]
fn test_tuple_struct_roundtrip() {
    let val = TupleStruct(42, 7);
    let encoded = val.encode();
    assert_eq!(encoded, [42, 0, 0, 0, 7, 0]);
    let (decoded, consumed) = TupleStruct::decode(&encoded).unwrap();
    assert_eq!(decoded, val);
    assert_eq!(consumed, 6);
}

// ============================================================================
// Generics
// ============================================================================

#[derive(Debug, PartialEq, Encode, Decode)]
struct GenericStruct<T: scale::Encode + scale::Decode> {
    value: T,
    count: u32,
}

#[test]
fn test_generic_struct() {
    let val = GenericStruct {
        value: 42u64,
        count: 1,
    };
    let encoded = val.encode();
    assert_eq!(encoded.len(), 8 + 4);
    let (decoded, _) = GenericStruct::<u64>::decode(&encoded).unwrap();
    assert_eq!(decoded, val);
}
