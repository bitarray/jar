//! Property-based roundtrip tests for derive-generated Encode/Decode types.
//!
//! Verifies that `decode(encode(x)) == x` holds for random inputs across
//! structs, enums, tuple structs, nested types, and generics.

use proptest::prelude::*;
use scale::{Decode, Encode};

// ============================================================================
// Test types (derive Encode + Decode)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
struct FlatStruct {
    a: u8,
    b: u16,
    c: u32,
    d: u64,
    e: bool,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
struct VecStruct {
    id: u32,
    data: Vec<u8>,
    tags: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
struct OptionStruct {
    required: u32,
    optional_val: Option<u64>,
    optional_vec: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
struct FixedArrayStruct {
    hash: [u8; 32],
    short: [u8; 4],
    value: u64,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
struct TupleStruct(u32, u16, u8);

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
struct Inner {
    x: u16,
    y: u32,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
struct Nested {
    id: u64,
    inner: Inner,
    items: Vec<Inner>,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
enum TestEnum {
    #[codec(index = 0)]
    Empty,
    #[codec(index = 1)]
    Single(u32),
    #[codec(index = 2)]
    Pair(u16, u64),
    #[codec(index = 3)]
    WithVec(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
struct DeepNested {
    label: u32,
    nested: Nested,
    flag: bool,
}

// ============================================================================
// Strategies
// ============================================================================

fn arb_flat_struct() -> impl Strategy<Value = FlatStruct> {
    (
        any::<u8>(),
        any::<u16>(),
        any::<u32>(),
        any::<u64>(),
        any::<bool>(),
    )
        .prop_map(|(a, b, c, d, e)| FlatStruct { a, b, c, d, e })
}

fn arb_vec_struct() -> impl Strategy<Value = VecStruct> {
    (
        any::<u32>(),
        prop::collection::vec(any::<u8>(), 0..64),
        prop::collection::vec(any::<u16>(), 0..32),
    )
        .prop_map(|(id, data, tags)| VecStruct { id, data, tags })
}

fn arb_option_struct() -> impl Strategy<Value = OptionStruct> {
    (
        any::<u32>(),
        proptest::option::of(any::<u64>()),
        proptest::option::of(prop::collection::vec(any::<u8>(), 0..32)),
    )
        .prop_map(|(required, optional_val, optional_vec)| OptionStruct {
            required,
            optional_val,
            optional_vec,
        })
}

fn arb_fixed_array_struct() -> impl Strategy<Value = FixedArrayStruct> {
    (
        prop::array::uniform32(any::<u8>()),
        prop::array::uniform4(any::<u8>()),
        any::<u64>(),
    )
        .prop_map(|(hash, short, value)| FixedArrayStruct { hash, short, value })
}

fn arb_tuple_struct() -> impl Strategy<Value = TupleStruct> {
    (any::<u32>(), any::<u16>(), any::<u8>()).prop_map(|(a, b, c)| TupleStruct(a, b, c))
}

fn arb_inner() -> impl Strategy<Value = Inner> {
    (any::<u16>(), any::<u32>()).prop_map(|(x, y)| Inner { x, y })
}

fn arb_nested() -> impl Strategy<Value = Nested> {
    (
        any::<u64>(),
        arb_inner(),
        prop::collection::vec(arb_inner(), 0..16),
    )
        .prop_map(|(id, inner, items)| Nested { id, inner, items })
}

fn arb_test_enum() -> impl Strategy<Value = TestEnum> {
    prop_oneof![
        Just(TestEnum::Empty),
        any::<u32>().prop_map(TestEnum::Single),
        (any::<u16>(), any::<u64>()).prop_map(|(a, b)| TestEnum::Pair(a, b)),
        prop::collection::vec(any::<u8>(), 0..64).prop_map(TestEnum::WithVec),
    ]
}

fn arb_deep_nested() -> impl Strategy<Value = DeepNested> {
    (any::<u32>(), arb_nested(), any::<bool>()).prop_map(|(label, nested, flag)| DeepNested {
        label,
        nested,
        flag,
    })
}

// ============================================================================
// Roundtrip helper
// ============================================================================

fn roundtrip<T: Encode + Decode + PartialEq + core::fmt::Debug>(val: &T) {
    let encoded = val.encode();
    let (decoded, consumed) = T::decode(&encoded).expect("decode should succeed");
    assert_eq!(&decoded, val, "roundtrip mismatch");
    assert_eq!(consumed, encoded.len(), "should consume all bytes");
}

// ============================================================================
// Property tests
// ============================================================================

proptest! {
    #[test]
    fn flat_struct_roundtrip(v in arb_flat_struct()) {
        roundtrip(&v);
    }

    #[test]
    fn vec_struct_roundtrip(v in arb_vec_struct()) {
        roundtrip(&v);
    }

    #[test]
    fn option_struct_roundtrip(v in arb_option_struct()) {
        roundtrip(&v);
    }

    #[test]
    fn fixed_array_struct_roundtrip(v in arb_fixed_array_struct()) {
        roundtrip(&v);
    }

    #[test]
    fn tuple_struct_roundtrip(v in arb_tuple_struct()) {
        roundtrip(&v);
    }

    #[test]
    fn nested_struct_roundtrip(v in arb_nested()) {
        roundtrip(&v);
    }

    #[test]
    fn enum_roundtrip(v in arb_test_enum()) {
        roundtrip(&v);
    }

    #[test]
    fn deep_nested_roundtrip(v in arb_deep_nested()) {
        roundtrip(&v);
    }

    /// Encoding is deterministic: encoding the same value twice produces identical bytes.
    #[test]
    fn encoding_deterministic(v in arb_deep_nested()) {
        let a = v.encode();
        let b = v.encode();
        prop_assert_eq!(&a, &b);
    }

    /// Decode rejects truncated input for structs.
    #[test]
    fn truncated_flat_struct_fails(v in arb_flat_struct()) {
        let encoded = v.encode();
        if encoded.len() > 1 {
            let truncated = &encoded[..encoded.len() - 1];
            prop_assert!(FlatStruct::decode(truncated).is_err());
        }
    }

    /// Decode rejects truncated input for enums.
    #[test]
    fn truncated_enum_fails(v in arb_test_enum()) {
        let encoded = v.encode();
        if encoded.len() > 1 {
            let truncated = &encoded[..encoded.len() - 1];
            prop_assert!(TestEnum::decode(truncated).is_err());
        }
    }
}
