//! Shared codegen for SSZ container bodies.
//!
//! A "container body" is the inner code that encodes / decodes / hashes a
//! sequence of named-or-positional fields using the standard SSZ container
//! layout (fixed-length fields inline, variable-length fields referenced via
//! a 4-byte LE offset table with their payloads appended after the fixed
//! region).
//!
//! These helpers are parameterised by *reference accessors*: each accessor is
//! a token-stream expression that already evaluates to a `&T` for the field
//! (so callers pass `&self.foo` for structs and a bound pattern ident like
//! `foo` for enum variants, since matching on `&self` binds fields as
//! references).
//!
//! See `encode_struct` and `decode_struct` (the canonical struct paths) for
//! the layout these helpers implement.
//!
//! [GP-style SSZ container layout, Appendix C of consensus-specs.]

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

/// Emit the body of `ssz_append` for an anonymous SSZ container with the
/// given field reference expressions / types.
///
/// The emitted code expects `buf: &mut allocator_api2::vec::Vec<u8, __A>` to
/// be in scope and appends the container encoding (fixed region + variable
/// payloads) to it.
pub(crate) fn container_encode_body(accessors: &[TokenStream], tys: &[TokenStream]) -> TokenStream {
    debug_assert_eq!(accessors.len(), tys.len());
    let n = accessors.len();
    if n == 0 {
        return quote! {};
    }

    let tmp_idents: Vec<syn::Ident> = (0..n).map(|i| format_ident!("__field_{}", i)).collect();

    // Pre-encode each field into a temporary Global-allocated buffer so we
    // can compute offsets without re-running encode.
    let pre_encode =
        accessors
            .iter()
            .zip(tys.iter())
            .zip(tmp_idents.iter())
            .map(|((acc, ty), tmp)| {
                quote! {
                    let mut #tmp: allocator_api2::vec::Vec<u8, allocator_api2::alloc::Global> =
                        allocator_api2::vec::Vec::new_in(allocator_api2::alloc::Global);
                    <#ty as ssz::Encode>::ssz_append(#acc, &mut #tmp);
                }
            });

    // Fixed-region size: each field contributes either its `ssz_fixed_len`
    // (fixed fields) or `BYTES_PER_LENGTH_OFFSET` (variable fields).
    let fixed_size_terms = tys.iter().map(|ty| {
        quote! {
            if <#ty as ssz::Encode>::is_ssz_fixed_len() {
                <#ty as ssz::Encode>::ssz_fixed_len()
            } else {
                ssz::BYTES_PER_LENGTH_OFFSET
            }
        }
    });

    // Walk fields in declaration order; emit either inline bytes (fixed) or
    // the current `__var_cursor` as a 4-byte LE offset (variable).
    let write_fixed = tys.iter().zip(tmp_idents.iter()).map(|(ty, tmp)| {
        quote! {
            if <#ty as ssz::Encode>::is_ssz_fixed_len() {
                buf.extend_from_slice(&#tmp);
            } else {
                buf.extend_from_slice(&(__var_cursor as u32).to_le_bytes());
                __var_cursor += #tmp.len();
            }
        }
    });

    // Variable payloads after the fixed region.
    let write_var = tys.iter().zip(tmp_idents.iter()).map(|(ty, tmp)| {
        quote! {
            if !<#ty as ssz::Encode>::is_ssz_fixed_len() {
                buf.extend_from_slice(&#tmp);
            }
        }
    });

    quote! {
        #(#pre_encode)*
        let __fixed_size: usize = 0usize #(+ #fixed_size_terms)*;
        let mut __var_cursor: usize = __fixed_size;
        #(#write_fixed)*
        #(#write_var)*
    }
}

/// Emit an expression that computes `ssz_bytes_len` for an anonymous SSZ
/// container with the given field reference expressions / types.
///
/// The expression evaluates to `usize` and may be used in any expression
/// context — it expands to a block.
pub(crate) fn container_bytes_len_expr(
    accessors: &[TokenStream],
    tys: &[TokenStream],
) -> TokenStream {
    debug_assert_eq!(accessors.len(), tys.len());
    // Fixed slot size per field: ssz_fixed_len OR BYTES_PER_LENGTH_OFFSET.
    let fixed_terms = tys.iter().map(|ty| {
        quote! {
            if <#ty as ssz::Encode>::is_ssz_fixed_len() {
                <#ty as ssz::Encode>::ssz_fixed_len()
            } else {
                ssz::BYTES_PER_LENGTH_OFFSET
            }
        }
    });
    // Variable payloads: add ssz_bytes_len for each variable field.
    let var_terms = accessors.iter().zip(tys.iter()).map(|(acc, ty)| {
        quote! {
            if !<#ty as ssz::Encode>::is_ssz_fixed_len() {
                __total += ssz::Encode::ssz_bytes_len(#acc);
            }
        }
    });
    quote! {{
        let mut __total: usize = 0usize #(+ #fixed_terms)*;
        #(#var_terms)*
        __total
    }}
}

/// Emit a statement block that decodes an anonymous SSZ container from
/// `bytes: &[u8]` (in scope) using `alloc: __A` (in scope) and binds locals
/// `__val_0 .. __val_{n-1}` of type `Option<T_i>` set to `Some(decoded)`.
///
/// Errors are reported via `return Err(...)` — callers should wrap this in a
/// function returning `Result<_, ssz::DecodeError>`.
pub(crate) fn container_decode_body(tys: &[TokenStream]) -> TokenStream {
    let n = tys.len();
    if n == 0 {
        return quote! {
            if !bytes.is_empty() {
                return Err(ssz::DecodeError::TrailingBytes {
                    expected: 0, actual: bytes.len(),
                });
            }
        };
    }

    let val_idents: Vec<syn::Ident> = (0..n).map(|i| format_ident!("__val_{}", i)).collect();
    let off_idents: Vec<syn::Ident> = (0..n).map(|i| format_ident!("__off_{}", i)).collect();

    // Total fixed region size.
    let fixed_size_terms = tys.iter().map(|ty| {
        quote! {
            if <#ty as ssz::Decode>::is_ssz_fixed_len() {
                <#ty as ssz::Decode>::ssz_fixed_len()
            } else {
                ssz::BYTES_PER_LENGTH_OFFSET
            }
        }
    });

    // Pass 1: walk fixed region — store fixed values or capture offsets.
    let pass1 = tys
        .iter()
        .zip(val_idents.iter())
        .zip(off_idents.iter())
        .map(|((ty, val), off)| {
            quote! {
                let mut #val: ::core::option::Option<#ty> = None;
                let mut #off: ::core::option::Option<usize> = None;
                if <#ty as ssz::Decode>::is_ssz_fixed_len() {
                    let __sz = <#ty as ssz::Decode>::ssz_fixed_len();
                    if __cursor + __sz > bytes.len() {
                        return Err(ssz::DecodeError::UnexpectedEof {
                            expected: __cursor + __sz,
                            actual: bytes.len(),
                        });
                    }
                    #val = Some(<#ty as ssz::Decode>::from_ssz_bytes_in(
                        &bytes[__cursor..__cursor + __sz], alloc.clone(),
                    )?);
                    __cursor += __sz;
                } else {
                    if __cursor + 4 > bytes.len() {
                        return Err(ssz::DecodeError::UnexpectedEof {
                            expected: __cursor + 4,
                            actual: bytes.len(),
                        });
                    }
                    let mut __ob = [0u8; 4];
                    __ob.copy_from_slice(&bytes[__cursor..__cursor + 4]);
                    #off = Some(u32::from_le_bytes(__ob) as usize);
                    __cursor += 4;
                }
            }
        });

    // Capture variable offsets in declaration order.
    let push_var_offs = tys
        .iter()
        .zip(off_idents.iter())
        .enumerate()
        .map(|(i, (ty, off))| {
            quote! {
                if !<#ty as ssz::Decode>::is_ssz_fixed_len() {
                    __var_positions.push((#i, #off.unwrap()));
                }
            }
        });

    // Pass 2: decode variable fields using offset windows.
    let pass2 = tys
        .iter()
        .zip(val_idents.iter())
        .zip(off_idents.iter())
        .enumerate()
        .map(|(i, ((ty, val), off))| {
            quote! {
                if !<#ty as ssz::Decode>::is_ssz_fixed_len() {
                    let __start = #off.unwrap();
                    let __idx_in_var = __var_positions
                        .iter()
                        .position(|(j, _)| *j == #i)
                        .expect("variable field in var_positions");
                    let __end = if __idx_in_var + 1 < __var_positions.len() {
                        __var_positions[__idx_in_var + 1].1
                    } else {
                        bytes.len()
                    };
                    if __start > __end {
                        return Err(ssz::DecodeError::OffsetsNotMonotonic {
                            prev: __start, curr: __end,
                        });
                    }
                    #val = Some(<#ty as ssz::Decode>::from_ssz_bytes_in(
                        &bytes[__start..__end], alloc.clone(),
                    )?);
                }
            }
        });

    quote! {
        let mut __cursor: usize = 0;
        let __fixed_size: usize = 0usize #(+ #fixed_size_terms)*;
        #(#pass1)*
        debug_assert_eq!(__cursor, __fixed_size);

        let mut __var_positions: allocator_api2::vec::Vec<(usize, usize)> =
            allocator_api2::vec::Vec::new();
        #(#push_var_offs)*
        for __pair in __var_positions.windows(2) {
            if __pair[1].1 < __pair[0].1 {
                return Err(ssz::DecodeError::OffsetsNotMonotonic {
                    prev: __pair[0].1, curr: __pair[1].1,
                });
            }
        }
        if let Some(&(_, __first)) = __var_positions.first() {
            if __first != __fixed_size {
                return Err(ssz::DecodeError::InvalidOffset {
                    offset: __first, len: bytes.len(), fixed: __fixed_size,
                });
            }
        } else {
            if bytes.len() != __fixed_size {
                return Err(ssz::DecodeError::TrailingBytes {
                    expected: __fixed_size, actual: bytes.len(),
                });
            }
        }

        #(#pass2)*
    }
}

/// Emit an expression returning `merkleize::<__D>(&field_roots, n_fields)`
/// for an anonymous SSZ container with the given field reference accessors /
/// types.
///
/// The expression evaluates to `[u8; 32]`. Empty containers produce
/// `[0u8; 32]` (the depth-0 zero hash).
pub(crate) fn container_hash_root_expr(
    accessors: &[TokenStream],
    tys: &[TokenStream],
) -> TokenStream {
    debug_assert_eq!(accessors.len(), tys.len());
    let n = accessors.len();
    if n == 0 {
        return quote! { [0u8; 32] };
    }
    let roots = accessors.iter().zip(tys.iter()).map(|(acc, ty)| {
        quote! { <#ty as ssz::HashTreeRoot>::hash_tree_root::<__D>(#acc) }
    });
    quote! {{
        let __roots: [[u8; 32]; #n] = [#(#roots),*];
        ssz::merkleize::<__D>(&__roots, #n)
    }}
}
