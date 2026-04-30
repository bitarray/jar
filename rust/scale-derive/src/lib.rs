//! Derive macros for SCALE Encode/Decode traits.
//!
//! # Struct example
//! ```ignore
//! #[derive(Encode, Decode)]
//! struct MyStruct {
//!     field_a: u32,
//!     field_b: Hash,
//!     #[codec(skip)]
//!     cached: u64,  // not encoded
//! }
//! ```
//!
//! # Enum example
//! ```ignore
//! #[derive(Encode, Decode)]
//! enum MyEnum {
//!     #[codec(index = 0)]
//!     Variant0,
//!     #[codec(index = 1)]
//!     Variant1(Vec<u8>),
//!     #[codec(index = 2)]
//!     Variant2 { a: u32, b: u64 },
//! }
//! ```

use proc_macro::TokenStream;
use syn::{DeriveInput, parse_macro_input};

mod decode;
mod encode;
mod parse;

/// Derive the `Encode` trait for a struct or enum.
#[proc_macro_derive(Encode, attributes(codec))]
pub fn derive_encode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    encode::derive_encode_impl(&input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

/// Derive the `Decode` trait for a struct or enum.
#[proc_macro_derive(Decode, attributes(codec))]
pub fn derive_decode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    decode::derive_decode_impl(&input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}
