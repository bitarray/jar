//! Derive macros for SSZ `Encode`, `Decode`, and `HashTreeRoot` traits.
//!
//! # Struct example
//! ```ignore
//! #[derive(Encode, Decode, HashTreeRoot)]
//! struct MyStruct {
//!     fixed_field: u32,
//!     var_field: ssz::List<u8, 1024>,
//!     #[ssz(skip)]
//!     cached: u64,
//! }
//! ```
//!
//! # Newtype passthrough
//! ```ignore
//! #[derive(Encode, Decode, HashTreeRoot)]
//! struct SlotIdx(#[ssz(transparent)] NonZeroU32);
//! ```
//!
//! # Enum example (SSZ Union)
//! ```ignore
//! #[derive(Encode, Decode, HashTreeRoot)]
//! enum Cap {
//!     #[ssz(selector = 0)]
//!     Instance(InstanceCap),
//!     #[ssz(selector = 1)]
//!     Image(ImageCap),
//! }
//! ```

use proc_macro::TokenStream;
use syn::{DeriveInput, parse_macro_input};

mod decode;
mod encode;
mod hash_tree_root;
mod parse;

/// Derive the `ssz::Encode` trait for a struct or enum.
#[proc_macro_derive(Encode, attributes(ssz))]
pub fn derive_encode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    encode::derive_encode_impl(&input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

/// Derive the `ssz::Decode` trait for a struct or enum.
#[proc_macro_derive(Decode, attributes(ssz))]
pub fn derive_decode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    decode::derive_decode_impl(&input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

/// Derive the `ssz::HashTreeRoot` trait for a struct or enum.
#[proc_macro_derive(HashTreeRoot, attributes(ssz))]
pub fn derive_hash_tree_root(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    hash_tree_root::derive_hash_tree_root_impl(&input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}
